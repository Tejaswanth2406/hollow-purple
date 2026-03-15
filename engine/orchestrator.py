"""
engine/orchestrator.py
======================
Central runtime orchestration engine for Hollow Purple / Mahoraga.

Responsibilities
----------------
- Pipeline registry and lifecycle management
- Execution context injection per pipeline run
- Metric emission to the BaselineEngine
- Concurrent pipeline execution with per-tenant isolation
- Health reporting and operational dashboards
- Circuit-breaker pattern per pipeline
- Event emission for external subscribers (audit bus)

Design principles
-----------------
- Single Orchestrator per process (singleton-friendly)
- All execution paths are coroutine-safe
- Zero tight coupling to any storage or transport layer
- Emits structured events that external subscribers can consume
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Awaitable

from .baseline import BaselineEngine
from .execution_context import ExecutionContext
from .pipeline import Pipeline, PipelineResult, PipelineMode


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Circuit breaker state
# ---------------------------------------------------------------------------


class CircuitState(str, Enum):
    CLOSED = "closed"       # Normal operation
    OPEN = "open"           # Rejecting requests
    HALF_OPEN = "half_open" # Probing recovery


@dataclass
class CircuitBreaker:
    """
    Simple per-pipeline circuit breaker.

    Opens after ``failure_threshold`` consecutive failures.
    Resets to HALF_OPEN after ``recovery_timeout_s`` seconds.
    A single success in HALF_OPEN moves it back to CLOSED.
    """

    name: str
    failure_threshold: int = 5
    recovery_timeout_s: float = 30.0

    _state: CircuitState = field(default=CircuitState.CLOSED, repr=False)
    _consecutive_failures: int = field(default=0, repr=False)
    _opened_at: float = field(default=0.0, repr=False)

    @property
    def state(self) -> CircuitState:
        if self._state == CircuitState.OPEN:
            if time.monotonic() - self._opened_at >= self.recovery_timeout_s:
                self._state = CircuitState.HALF_OPEN
        return self._state

    def record_success(self) -> None:
        self._consecutive_failures = 0
        if self._state in (CircuitState.OPEN, CircuitState.HALF_OPEN):
            logger.info("Circuit breaker CLOSED", extra={"pipeline": self.name})
        self._state = CircuitState.CLOSED

    def record_failure(self) -> None:
        self._consecutive_failures += 1
        if (
            self._state == CircuitState.CLOSED
            and self._consecutive_failures >= self.failure_threshold
        ):
            self._state = CircuitState.OPEN
            self._opened_at = time.monotonic()
            logger.error(
                "Circuit breaker OPENED",
                extra={
                    "pipeline": self.name,
                    "failures": self._consecutive_failures,
                },
            )
        elif self._state == CircuitState.HALF_OPEN:
            self._state = CircuitState.OPEN
            self._opened_at = time.monotonic()

    def is_open(self) -> bool:
        return self.state == CircuitState.OPEN


# ---------------------------------------------------------------------------
# Execution event — emitted to audit bus subscribers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExecutionEvent:
    """Immutable record of a pipeline execution, suitable for audit logging."""

    event_id: str
    pipeline_name: str
    tenant_id: Optional[str]
    user_id: Optional[str]
    request_id: str
    trace_id: str
    success: bool
    elapsed_ms: float
    occurred_at: str
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "pipeline": self.pipeline_name,
            "tenant_id": self.tenant_id,
            "user_id": self.user_id,
            "request_id": self.request_id,
            "trace_id": self.trace_id,
            "success": self.success,
            "elapsed_ms": round(self.elapsed_ms, 3),
            "occurred_at": self.occurred_at,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Orchestrator configuration
# ---------------------------------------------------------------------------


@dataclass
class OrchestratorConfig:
    """
    Top-level configuration for the Orchestrator.

    Parameters
    ----------
    max_concurrent       : Global semaphore cap on simultaneous pipeline runs.
    circuit_breaker_on   : Enable per-pipeline circuit breakers.
    cb_failure_threshold : Failures before a circuit opens.
    cb_recovery_s        : Seconds before a circuit attempts recovery.
    default_window_size  : Sliding window for the baseline engine.
    anomaly_threshold    : Z-score threshold for anomaly alerts.
    """

    max_concurrent: int = 100
    circuit_breaker_on: bool = True
    cb_failure_threshold: int = 5
    cb_recovery_s: float = 30.0
    default_window_size: Optional[int] = 1000
    anomaly_threshold: float = 3.0


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


class Orchestrator:
    """
    Central coordination engine.

    Quick start
    -----------
    ::

        config = OrchestratorConfig(max_concurrent=50)
        orch = Orchestrator(config)

        pipeline = Pipeline(name="ingest")
        pipeline.add_stage("validate", validate_fn)
        pipeline.add_stage("store",    store_fn, max_retries=2)

        orch.register_pipeline(pipeline)

        result = await orch.run("ingest", payload, tenant_id="acme")
    """

    def __init__(self, config: Optional[OrchestratorConfig] = None):
        self._config = config or OrchestratorConfig()
        self._pipelines: Dict[str, Pipeline] = {}
        self._circuit_breakers: Dict[str, CircuitBreaker] = {}
        self._baseline = BaselineEngine(
            default_window_size=self._config.default_window_size,
            anomaly_threshold=self._config.anomaly_threshold,
        )
        self._semaphore = asyncio.Semaphore(self._config.max_concurrent)
        self._event_subscribers: List[Callable[[ExecutionEvent], Awaitable[None]]] = []
        self._lock = asyncio.Lock()

        logger.info(
            "Orchestrator initialised",
            extra={
                "max_concurrent": self._config.max_concurrent,
                "circuit_breaker": self._config.circuit_breaker_on,
            },
        )

    # ---------------------------------------------------------------------------
    # Pipeline management
    # ---------------------------------------------------------------------------

    def register_pipeline(self, pipeline: Pipeline) -> None:
        """Register a Pipeline. Raises ValueError on duplicate name."""
        if pipeline.name in self._pipelines:
            raise ValueError(
                f"Pipeline '{pipeline.name}' is already registered. "
                "Use replace_pipeline() to overwrite."
            )
        self._pipelines[pipeline.name] = pipeline
        if self._config.circuit_breaker_on:
            self._circuit_breakers[pipeline.name] = CircuitBreaker(
                name=pipeline.name,
                failure_threshold=self._config.cb_failure_threshold,
                recovery_timeout_s=self._config.cb_recovery_s,
            )
        logger.info("Pipeline registered", extra={"pipeline": pipeline.name})

    def replace_pipeline(self, pipeline: Pipeline) -> None:
        """Register or replace a pipeline (idempotent)."""
        self._pipelines[pipeline.name] = pipeline
        logger.info("Pipeline replaced", extra={"pipeline": pipeline.name})

    def unregister_pipeline(self, name: str) -> None:
        """Remove a pipeline from the registry."""
        self._pipelines.pop(name, None)
        self._circuit_breakers.pop(name, None)

    # ---------------------------------------------------------------------------
    # Event bus
    # ---------------------------------------------------------------------------

    def subscribe(self, fn: Callable[[ExecutionEvent], Awaitable[None]]) -> None:
        """
        Register an async subscriber to receive ExecutionEvents after each run.
        Useful for audit logging, alerting, or stream forwarding.
        """
        self._event_subscribers.append(fn)

    async def _emit(self, event: ExecutionEvent) -> None:
        """Fan-out event to all subscribers concurrently."""
        if not self._event_subscribers:
            return
        tasks = [asyncio.create_task(fn(event)) for fn in self._event_subscribers]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                logger.exception("Event subscriber error", exc_info=r)

    # ---------------------------------------------------------------------------
    # Main execution entry point
    # ---------------------------------------------------------------------------

    async def run(
        self,
        pipeline_name: str,
        payload: Any,
        *,
        tenant_id: Optional[str] = None,
        user_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        ctx: Optional[ExecutionContext] = None,
    ) -> PipelineResult:
        """
        Execute a registered pipeline with full observability.

        Parameters
        ----------
        pipeline_name   : Registered pipeline identifier.
        payload         : Input data for the first stage.
        tenant_id       : Tenant scope for multi-tenant isolation.
        user_id         : Authenticated user initiating the request.
        correlation_id  : Upstream correlation handle.
        ctx             : Pre-built ExecutionContext (optional override).

        Returns
        -------
        PipelineResult
            Always returned — circuit-open or missing-pipeline cases also
            return a failed PipelineResult rather than raising.
        """
        if pipeline_name not in self._pipelines:
            logger.error("Pipeline not found", extra={"pipeline": pipeline_name})
            return PipelineResult(
                success=False,
                output=None,
                pipeline_name=pipeline_name,
                total_elapsed_ms=0,
            )

        cb = self._circuit_breakers.get(pipeline_name)
        if cb and cb.is_open():
            logger.warning(
                "Circuit breaker is OPEN — request rejected",
                extra={"pipeline": pipeline_name},
            )
            return PipelineResult(
                success=False,
                output=None,
                pipeline_name=pipeline_name,
                total_elapsed_ms=0,
            )

        # Build or reuse execution context
        exec_ctx = ctx or ExecutionContext.create(
            tenant_id=tenant_id,
            user_id=user_id,
            correlation_id=correlation_id,
        )

        async with exec_ctx.scope():
            async with self._semaphore:
                return await self._run_pipeline(
                    pipeline_name=pipeline_name,
                    payload=payload,
                    exec_ctx=exec_ctx,
                    cb=cb,
                )

    async def _run_pipeline(
        self,
        *,
        pipeline_name: str,
        payload: Any,
        exec_ctx: ExecutionContext,
        cb: Optional[CircuitBreaker],
    ) -> PipelineResult:
        import uuid as _uuid

        pipeline = self._pipelines[pipeline_name]
        start_ns = time.perf_counter_ns()

        result = await pipeline.execute(payload)

        elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000

        # Update baseline metrics
        await self._baseline.record(f"{pipeline_name}.latency_ms", elapsed_ms)
        await self._baseline.record(
            f"{pipeline_name}.success_rate",
            1.0 if result.success else 0.0,
        )

        # Circuit breaker feedback
        if cb:
            if result.success:
                cb.record_success()
            else:
                cb.record_failure()

        # Emit audit event
        event = ExecutionEvent(
            event_id=_uuid.uuid4().hex,
            pipeline_name=pipeline_name,
            tenant_id=exec_ctx.tenant_id,
            user_id=exec_ctx.user_id,
            request_id=exec_ctx.request_id,
            trace_id=exec_ctx.trace_id,
            success=result.success,
            elapsed_ms=elapsed_ms,
            occurred_at=datetime.now(timezone.utc).isoformat(),
            error=(
                "; ".join(s.error for s in result.failed_stages if s.error)
                or None
            ),
        )
        await self._emit(event)

        return result

    # ---------------------------------------------------------------------------
    # Observability
    # ---------------------------------------------------------------------------

    async def health(self) -> Dict[str, Any]:
        """Return a structured health snapshot suitable for /healthz endpoints."""
        baselines = await self._baseline.compute_all_baselines()
        cb_statuses = {
            name: cb.state.value for name, cb in self._circuit_breakers.items()
        }
        return {
            "status": "ok",
            "pipelines": list(self._pipelines.keys()),
            "circuit_breakers": cb_statuses,
            "baselines": baselines,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

    async def get_pipeline_baseline(self, pipeline_name: str) -> Dict[str, Any]:
        """Return baseline snapshots specific to a pipeline."""
        metrics = await self._baseline.list_metrics()
        relevant = [m for m in metrics if m.startswith(f"{pipeline_name}.")]
        return {
            m: await self._baseline.get_snapshot(m) for m in relevant
        }