"""
scripts/run_pipeline.py
========================
Enterprise pipeline runner for Hollow Purple / Mahoraga.

Responsibilities
----------------
- Bootstrap the application context
- Accept events from stdin (JSON lines), CLI args, or file input
- Route events through the configured ingest → analyze → project pipeline
- Emit structured results to stdout or a configured sink
- Report pipeline metrics and anomalies on completion
- Support batch and streaming (continuous) modes
- Graceful shutdown on SIGTERM / SIGINT with in-flight drain

Usage
-----
::

    # Single event via CLI
    python scripts/run_pipeline.py --event '{"identity":"alice","event_type":"login","resource":"server1"}'

    # Batch from JSON-lines file
    python scripts/run_pipeline.py --file events.jsonl

    # Read from stdin (streaming / pipe)
    cat events.jsonl | python scripts/run_pipeline.py --stdin

    # With verbose risk and exposure output
    python scripts/run_pipeline.py --file events.jsonl --report
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import signal
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("run_pipeline")


# ---------------------------------------------------------------------------
# Pipeline handler definitions
# ---------------------------------------------------------------------------


async def _stage_validate(event: Dict[str, Any]) -> Dict[str, Any]:
    """Validate required fields and normalize the event structure."""
    required = {"event_type"}
    missing = required - event.keys()
    if missing:
        raise ValueError(f"Event missing required fields: {missing}")

    # Normalize timestamp
    if "timestamp" not in event:
        event["timestamp"] = datetime.now(timezone.utc).isoformat()

    # Normalize identity field
    event.setdefault("identity", event.get("user_id") or event.get("principal") or "unknown")
    event.setdefault("resource", "unknown")

    return event


async def _stage_enrich(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich the event with derived fields.
    In production this would call a threat-intel API or asset inventory.
    """
    event["_enriched"] = True
    event["_source"] = "run_pipeline"

    # Classify action risk level
    high_risk_actions = {
        "privilege_escalation", "lateral_movement", "data_exfiltration",
        "admin_login", "secret_access", "iam_modify", "root_exec",
    }
    event["_risk_hint"] = "high" if event.get("event_type") in high_risk_actions else "normal"
    return event


async def _build_ingest_pipeline():
    """Construct and return the ingestion pipeline."""
    from engine.pipeline import Pipeline, PipelineMode

    pipeline = Pipeline(name="ingest", mode=PipelineMode.FAIL_FAST)
    pipeline.add_stage("validate", _stage_validate, timeout_s=5.0)
    pipeline.add_stage("enrich",   _stage_enrich,   timeout_s=5.0)
    return pipeline


# ---------------------------------------------------------------------------
# Result printer
# ---------------------------------------------------------------------------


def _print_result(result, *, verbose: bool = False) -> None:
    """Print pipeline result as structured JSON."""
    out = result.to_dict()
    print(json.dumps(out, indent=2 if verbose else None, default=str))


def _print_report(
    *,
    identity_projection,
    exposure_projection=None,
    risk_report=None,
) -> None:
    """Print a full security intelligence report to stdout."""
    summary = identity_projection.summary()
    print("\n" + "=" * 60)
    print("  HOLLOW PURPLE — PIPELINE RUN REPORT")
    print("=" * 60)
    print(f"  Total identities   : {summary['total_identities']}")
    print(f"  Anomalous          : {summary['anomalous_identities']}")
    print(f"  Anomaly rate       : {summary['anomaly_rate']:.1%}")
    print(f"  Total events       : {summary['total_events']}")

    if risk_report:
        print(f"\n  Risk Distribution:")
        for tier, count in risk_report.by_tier.items():
            if count:
                print(f"    {tier.upper():10} : {count}")
        print(f"\n  Mean risk score    : {risk_report.mean_score:.1f}")
        print(f"  Critical entities  : {risk_report.critical_count}")

        if risk_report.top_risks:
            print(f"\n  Top 5 Risks:")
            for s in risk_report.top_risks[:5]:
                print(
                    f"    [{s.tier.value.upper():8}] {s.entity_id[:32]:<32} "
                    f"score={s.total_score:.1f}"
                )

    if exposure_projection:
        records = exposure_projection.all_records()
        critical_exp = [r for r in records if r.severity.value == "critical"]
        print(f"\n  Exposure Surface:")
        print(f"    Total exposed    : {len(records)}")
        print(f"    Critical nodes   : {len(critical_exp)}")
        if critical_exp:
            print(f"    Critical nodes   :")
            for r in critical_exp[:5]:
                print(f"      - {r.node_id} ({r.node_type})")

    print("=" * 60 + "\n")


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------


async def run(
    events: List[Dict[str, Any]],
    *,
    report: bool = False,
    verbose: bool = False,
) -> Dict[str, Any]:
    """
    Run the full Hollow Purple pipeline over a list of events.

    Returns a summary dict with counts and timing.
    """
    from scripts.bootstrap_env import bootstrap
    from projections.identity_projection import IdentityProjection
    from projections.graph_projection import GraphProjection
    from projections.exposure_projection import ExposureProjection
    from projections.risk_projection import RiskProjection

    ctx = await bootstrap()

    # Register ingest pipeline
    pipeline = await _build_ingest_pipeline()
    ctx.orchestrator.register_pipeline(pipeline)

    # Start scheduler
    await ctx.scheduler.start()

    identity_proj = IdentityProjection()
    graph_proj    = GraphProjection()
    exposure_proj = ExposureProjection()
    risk_engine   = RiskProjection()

    start_ns = time.perf_counter_ns()
    succeeded = 0
    failed = 0
    anomalies = 0

    logger.info("Pipeline run starting", extra={"event_count": len(events)})

    for raw_event in events:
        try:
            result = await ctx.orchestrator.run(
                "ingest",
                raw_event,
                tenant_id=raw_event.get("tenant_id"),
                user_id=raw_event.get("identity"),
            )

            if result.success:
                processed_event = result.output

                # Append to EventStore
                await ctx.event_store.append(
                    payload=processed_event,
                    source="run_pipeline",
                    event_type=processed_event.get("event_type", "unknown"),
                    tenant_id=processed_event.get("tenant_id"),
                )

                # Record baseline metric
                await ctx.baseline_engine.record(
                    f"pipeline.ingest.latency_ms",
                    result.total_elapsed_ms,
                )

                # Update identity projection
                identity_proj.ingest_event(processed_event)

                succeeded += 1
                if verbose:
                    _print_result(result, verbose=True)
            else:
                failed += 1
                logger.warning(
                    "Event pipeline failed",
                    extra={"event": raw_event, "stages": result.to_dict()},
                )

        except Exception as exc:
            failed += 1
            logger.exception("Unhandled error processing event", extra={"error": str(exc)})

    # Run anomaly detection
    identity_proj.refresh_anomalies()
    anomalies = len(identity_proj.anomalous_identities())

    # Build graph and exposure projections
    await graph_proj.build(ctx.graph_store)
    exposure_proj.compute(graph_proj)

    # Generate risk report
    risk_report = risk_engine.generate_report(
        identity_projection=identity_proj,
        exposure_projection=exposure_proj,
        graph_projection=graph_proj,
    )

    elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000

    if report:
        _print_report(
            identity_projection=identity_proj,
            exposure_projection=exposure_proj,
            risk_report=risk_report,
        )

    summary = {
        "total_events": len(events),
        "succeeded": succeeded,
        "failed": failed,
        "anomalous_identities": anomalies,
        "elapsed_ms": round(elapsed_ms, 2),
        "throughput_eps": round(len(events) / (elapsed_ms / 1000), 1) if elapsed_ms > 0 else 0,
    }

    logger.info("Pipeline run complete", extra=summary)

    await ctx.scheduler.stop(graceful=True)
    return summary


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Hollow Purple pipeline runner")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--event", type=str, help="Single JSON event string")
    source.add_argument("--file",  type=str, help="Path to JSON-lines event file")
    source.add_argument("--stdin", action="store_true", help="Read JSON-lines from stdin")
    parser.add_argument("--report",  action="store_true", help="Print security report on completion")
    parser.add_argument("--verbose", action="store_true", help="Print each pipeline result")
    return parser.parse_args()


def _load_events(args: argparse.Namespace) -> List[Dict[str, Any]]:
    if args.event:
        return [json.loads(args.event)]
    if args.file:
        with open(args.file) as f:
            return [json.loads(line) for line in f if line.strip()]
    if args.stdin:
        return [json.loads(line) for line in sys.stdin if line.strip()]

    # Default demo event
    return [
        {
            "identity": "user123",
            "event_type": "login",
            "resource": "server1",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    ]


if __name__ == "__main__":
    args = _parse_args()
    events = _load_events(args)

    # Graceful shutdown on SIGTERM/SIGINT
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    def _handle_shutdown(sig, frame):
        logger.info("Shutdown signal received", extra={"signal": sig})
        loop.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _handle_shutdown)
    signal.signal(signal.SIGINT, _handle_shutdown)

    summary = loop.run_until_complete(
        run(events, report=args.report, verbose=args.verbose)
    )
    print(json.dumps(summary, indent=2))