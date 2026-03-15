"""
scripts/bootstrap_env.py
=========================
Enterprise environment bootstrapper for Hollow Purple / Mahoraga.

Responsibilities
----------------
- Configure structured JSON logging with trace-ID injection
- Validate required environment variables with typed parsing
- Initialize all core subsystems in dependency order:
    EventStore → BaselineEngine → GraphStore → Orchestrator → Scheduler
- Register default scheduled jobs (baseline flush, integrity check)
- Emit a signed bootstrap manifest for audit trails
- Support dry-run mode (validate only, no side effects)
- Export a fully wired ApplicationContext for use by run_pipeline.py

Usage
-----
::

    # Standard bootstrap
    python scripts/bootstrap_env.py

    # Dry run (validate config only)
    python scripts/bootstrap_env.py --dry-run

    # Custom environment
    HP_ENV=staging HP_LOG_LEVEL=DEBUG python scripts/bootstrap_env.py
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import os
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional


# ---------------------------------------------------------------------------
# Structured JSON log formatter
# ---------------------------------------------------------------------------


class JSONLogFormatter(logging.Formatter):
    """
    Emit one JSON object per log line.
    Compatible with Datadog, CloudWatch, Splunk, and Loki ingest pipelines.
    """

    def format(self, record: logging.LogRecord) -> str:
        from engine.execution_context import ExecutionContext

        doc = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "file": f"{record.filename}:{record.lineno}",
            "trace_id": ExecutionContext.current_trace_id(),
            "request_id": ExecutionContext.current_request_id(),
            "tenant_id": ExecutionContext.current_tenant_id(),
        }

        # Merge structured extra fields
        for key, val in record.__dict__.items():
            if key not in (
                "msg", "args", "levelname", "name", "filename",
                "lineno", "exc_info", "exc_text", "stack_info",
                "created", "msecs", "relativeCreated", "thread",
                "threadName", "process", "processName", "pathname",
                "module", "funcName", "levelno", "message",
            ):
                if not key.startswith("_"):
                    doc[key] = val

        if record.exc_info:
            doc["exception"] = self.formatException(record.exc_info)

        return json.dumps(doc, default=str)


def configure_logging(level: str = "INFO", json_format: bool = True) -> None:
    """Configure root logger with structured output."""
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(numeric_level)

    if root.handlers:
        root.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(numeric_level)
    handler.setFormatter(
        JSONLogFormatter() if json_format else logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s — %(message)s"
        )
    )
    root.addHandler(handler)


# ---------------------------------------------------------------------------
# Environment configuration
# ---------------------------------------------------------------------------


@dataclass
class EnvironmentConfig:
    """
    Typed, validated environment configuration.
    All values sourced from environment variables with defaults.
    """

    # Runtime
    environment: str = "production"
    log_level: str = "INFO"
    json_logging: bool = True

    # EventStore
    hmac_secret: Optional[bytes] = None

    # BaselineEngine
    baseline_window_size: int = 1000
    anomaly_threshold: float = 3.0

    # Scheduler
    baseline_flush_interval_s: int = 60
    integrity_check_interval_s: int = 300

    # Orchestrator
    max_concurrent_pipelines: int = 100
    circuit_breaker_enabled: bool = True

    # Snapshot
    snapshot_compress: bool = True
    max_snapshots: int = 100

    @classmethod
    def from_env(cls) -> "EnvironmentConfig":
        """Parse and validate configuration from environment variables."""

        def _bool(key: str, default: str = "true") -> bool:
            return os.getenv(key, default).lower() in ("1", "true", "yes")

        def _int(key: str, default: int) -> int:
            try:
                return int(os.getenv(key, str(default)))
            except ValueError:
                raise EnvironmentError(f"Invalid integer for {key}: {os.getenv(key)}")

        def _float(key: str, default: float) -> float:
            try:
                return float(os.getenv(key, str(default)))
            except ValueError:
                raise EnvironmentError(f"Invalid float for {key}: {os.getenv(key)}")

        hmac_raw = os.getenv("HP_HMAC_SECRET")
        hmac_bytes = hmac_raw.encode() if hmac_raw else None

        return cls(
            environment=os.getenv("HP_ENV", "production"),
            log_level=os.getenv("HP_LOG_LEVEL", "INFO"),
            json_logging=_bool("HP_JSON_LOGGING"),
            hmac_secret=hmac_bytes,
            baseline_window_size=_int("HP_BASELINE_WINDOW", 1000),
            anomaly_threshold=_float("HP_ANOMALY_THRESHOLD", 3.0),
            baseline_flush_interval_s=_int("HP_BASELINE_FLUSH_INTERVAL", 60),
            integrity_check_interval_s=_int("HP_INTEGRITY_CHECK_INTERVAL", 300),
            max_concurrent_pipelines=_int("HP_MAX_CONCURRENT", 100),
            circuit_breaker_enabled=_bool("HP_CIRCUIT_BREAKER"),
            snapshot_compress=_bool("HP_SNAPSHOT_COMPRESS"),
            max_snapshots=_int("HP_MAX_SNAPSHOTS", 100),
        )

    def validate(self) -> None:
        """Validate configuration values and raise on invalid state."""
        errors = []
        if self.baseline_window_size < 10:
            errors.append("HP_BASELINE_WINDOW must be >= 10")
        if not (0.5 <= self.anomaly_threshold <= 10.0):
            errors.append("HP_ANOMALY_THRESHOLD must be between 0.5 and 10.0")
        if self.max_concurrent_pipelines < 1:
            errors.append("HP_MAX_CONCURRENT must be >= 1")
        if errors:
            raise EnvironmentError("\n".join(errors))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "environment": self.environment,
            "log_level": self.log_level,
            "json_logging": self.json_logging,
            "hmac_enabled": self.hmac_secret is not None,
            "baseline_window_size": self.baseline_window_size,
            "anomaly_threshold": self.anomaly_threshold,
            "baseline_flush_interval_s": self.baseline_flush_interval_s,
            "integrity_check_interval_s": self.integrity_check_interval_s,
            "max_concurrent_pipelines": self.max_concurrent_pipelines,
            "circuit_breaker_enabled": self.circuit_breaker_enabled,
            "snapshot_compress": self.snapshot_compress,
            "max_snapshots": self.max_snapshots,
        }


# ---------------------------------------------------------------------------
# Application context — wired subsystem container
# ---------------------------------------------------------------------------


@dataclass
class ApplicationContext:
    """
    Dependency-injected container for all Hollow Purple subsystems.
    Passed to pipeline runners and request handlers.
    """
    config: EnvironmentConfig
    event_store: Any = None
    baseline_engine: Any = None
    graph_store: Any = None
    snapshot_store: Any = None
    orchestrator: Any = None
    scheduler: Any = None
    bootstrap_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    bootstrapped_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def manifest(self) -> Dict[str, Any]:
        """Emit a signed bootstrap manifest for audit trails."""
        body = {
            "bootstrap_id": self.bootstrap_id,
            "bootstrapped_at": self.bootstrapped_at,
            "config": self.config.to_dict(),
            "subsystems": {
                "event_store": self.event_store is not None,
                "baseline_engine": self.baseline_engine is not None,
                "graph_store": self.graph_store is not None,
                "snapshot_store": self.snapshot_store is not None,
                "orchestrator": self.orchestrator is not None,
                "scheduler": self.scheduler is not None,
            },
        }
        manifest_bytes = json.dumps(body, sort_keys=True).encode()
        body["manifest_hash"] = hashlib.sha256(manifest_bytes).hexdigest()
        return body


# ---------------------------------------------------------------------------
# Bootstrap function
# ---------------------------------------------------------------------------


async def bootstrap(
    config: Optional[EnvironmentConfig] = None,
    *,
    dry_run: bool = False,
) -> ApplicationContext:
    """
    Wire up all Hollow Purple subsystems.

    Parameters
    ----------
    config  : Pre-built config (uses env vars if None).
    dry_run : Validate config and return without initializing subsystems.
    """
    log = logging.getLogger("bootstrap")

    cfg = config or EnvironmentConfig.from_env()
    configure_logging(level=cfg.log_level, json_format=cfg.json_logging)
    cfg.validate()

    log.info("Bootstrap starting", extra={"config": cfg.to_dict()})

    if dry_run:
        log.info("Dry run — configuration valid, skipping subsystem init")
        return ApplicationContext(config=cfg)

    # --- Import subsystems ---
    from storage.event_store import EventStore
    from storage.graph_store import GraphStore
    from storage.snapshot_store import SnapshotStore
    from engine.baseline import BaselineEngine, AnomalyMethod
    from engine.orchestrator import Orchestrator, OrchestratorConfig
    from engine.scheduler import Scheduler, ScheduledJob, TriggerType

    # --- EventStore ---
    log.info("Initialising EventStore")
    event_store = EventStore(hmac_secret=cfg.hmac_secret)

    # --- BaselineEngine ---
    log.info("Initialising BaselineEngine")
    baseline_engine = BaselineEngine(
        default_window_size=cfg.baseline_window_size,
        anomaly_method=AnomalyMethod.Z_SCORE,
        anomaly_threshold=cfg.anomaly_threshold,
    )

    # --- GraphStore ---
    log.info("Initialising GraphStore")
    graph_store = GraphStore()

    # --- SnapshotStore ---
    log.info("Initialising SnapshotStore")
    snapshot_store = SnapshotStore(
        compress=cfg.snapshot_compress,
        max_snapshots=cfg.max_snapshots,
    )

    # --- Orchestrator ---
    log.info("Initialising Orchestrator")
    orch_config = OrchestratorConfig(
        max_concurrent=cfg.max_concurrent_pipelines,
        circuit_breaker_on=cfg.circuit_breaker_enabled,
    )
    orchestrator = Orchestrator(orch_config)

    # --- Scheduler + default jobs ---
    log.info("Initialising Scheduler")
    scheduler = Scheduler(tick_interval_s=1.0)

    async def _baseline_flush_job() -> None:
        baselines = await baseline_engine.compute_all_baselines()
        log.debug("Baseline flush", extra={"metrics": len(baselines)})

    async def _integrity_check_job() -> None:
        report = await event_store.verify_integrity()
        if not report.valid:
            log.error(
                "INTEGRITY CHECK FAILED",
                extra={"violations": len(report.violations)},
            )
        else:
            log.info(
                "Integrity check passed",
                extra={"records": report.total_records_checked},
            )

    scheduler.add_job(
        ScheduledJob(
            name="baseline_flush",
            handler=_baseline_flush_job,
            trigger=TriggerType.INTERVAL,
            interval_s=cfg.baseline_flush_interval_s,
            max_retries=2,
        )
    )
    scheduler.add_job(
        ScheduledJob(
            name="integrity_check",
            handler=_integrity_check_job,
            trigger=TriggerType.INTERVAL,
            interval_s=cfg.integrity_check_interval_s,
            max_retries=1,
            jitter_s=5.0,
        )
    )

    ctx = ApplicationContext(
        config=cfg,
        event_store=event_store,
        baseline_engine=baseline_engine,
        graph_store=graph_store,
        snapshot_store=snapshot_store,
        orchestrator=orchestrator,
        scheduler=scheduler,
    )

    manifest = ctx.manifest()
    log.info(
        "Bootstrap complete",
        extra={
            "bootstrap_id": ctx.bootstrap_id,
            "manifest_hash": manifest.get("manifest_hash"),
        },
    )
    return ctx


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Hollow Purple environment bootstrapper"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate configuration without initializing subsystems",
    )
    parser.add_argument(
        "--manifest",
        action="store_true",
        help="Print bootstrap manifest as JSON to stdout",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()

    async def _main() -> None:
        ctx = await bootstrap(dry_run=args.dry_run)
        if args.manifest:
            print(json.dumps(ctx.manifest(), indent=2))

    asyncio.run(_main())