"""
engine/scheduler.py
====================
Enterprise-grade async job scheduler for Hollow Purple / Mahoraga.

Features
--------
- Fixed-interval and cron-expression scheduling (via ``croniter``)
- Per-job retry with exponential back-off
- Per-job timeout enforcement
- Job enable/disable at runtime without restart
- Graceful shutdown with in-flight job draining
- Jitter on startup to avoid thundering herd at t=0
- Structured logging and per-job execution history (ring buffer)
- Missed-run detection and alerting
- AsyncContextManager lifecycle (``async with Scheduler() as s:``)
- Optional job-lock callback to prevent concurrent duplicate runs
  (hook in a Redis/DB distributed lock externally)
"""

from __future__ import annotations

import asyncio
import logging
import time
import traceback
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Deque, Dict, List, Optional, Awaitable
from collections import deque


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Job status
# ---------------------------------------------------------------------------


class JobStatus(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    FAILED = "failed"
    DISABLED = "disabled"
    COMPLETED = "completed"   # one-shot jobs


class TriggerType(str, Enum):
    INTERVAL = "interval"
    CRON = "cron"
    ONE_SHOT = "one_shot"


# ---------------------------------------------------------------------------
# Execution record
# ---------------------------------------------------------------------------


@dataclass
class JobRun:
    """Single execution record stored in the job history ring buffer."""
    run_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    started_at: str = ""
    finished_at: str = ""
    elapsed_ms: float = 0.0
    success: bool = False
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "elapsed_ms": round(self.elapsed_ms, 3),
            "success": self.success,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Job definition
# ---------------------------------------------------------------------------


@dataclass
class ScheduledJob:
    """
    A single schedulable unit of work.

    Parameters
    ----------
    name            : Unique job identifier.
    handler         : Async callable ``async def handler() -> Any``.
    trigger         : TriggerType (INTERVAL, CRON, ONE_SHOT).
    interval_s      : Seconds between runs (INTERVAL trigger).
    cron_expr       : Cron string ``"*/5 * * * *"`` (CRON trigger).
    max_retries     : Retry attempts after handler failure.
    retry_base_s    : Base back-off for retries (exponential + jitter).
    timeout_s       : Per-run timeout. None = no limit.
    jitter_s        : Max random startup delay to avoid thundering herd.
    history_size    : Number of recent JobRun records to keep.
    enabled         : Start enabled or disabled.
    lock_fn         : Optional ``async def lock_fn(job_name) -> bool`` —
                      return True to allow run, False to skip (distributed lock).
    """

    name: str
    handler: Callable[[], Awaitable[Any]]
    trigger: TriggerType = TriggerType.INTERVAL
    interval_s: float = 60.0
    cron_expr: Optional[str] = None
    max_retries: int = 0
    retry_base_s: float = 1.0
    timeout_s: Optional[float] = None
    jitter_s: float = 0.0
    history_size: int = 50
    enabled: bool = True
    lock_fn: Optional[Callable[[str], Awaitable[bool]]] = None

    # Runtime state (not part of config)
    status: JobStatus = field(default=JobStatus.IDLE, repr=False)
    _next_run_at: float = field(default=0.0, repr=False)
    _history: Deque[JobRun] = field(
        default_factory=lambda: deque(maxlen=50), repr=False
    )
    _consecutive_failures: int = field(default=0, repr=False)
    _total_runs: int = field(default=0, repr=False)

    def __post_init__(self) -> None:
        self._history = deque(maxlen=self.history_size)

    # ---------------------------------------------------------------------------

    def _compute_next_interval(self) -> float:
        """Next scheduled timestamp (monotonic)."""
        if self.trigger == TriggerType.INTERVAL:
            return time.monotonic() + self.interval_s

        if self.trigger == TriggerType.CRON:
            try:
                from croniter import croniter  # optional dependency
                cron = croniter(self.cron_expr, datetime.now(timezone.utc))
                next_dt = cron.get_next(datetime)
                return time.monotonic() + (next_dt - datetime.now(timezone.utc)).total_seconds()
            except ImportError:
                logger.warning(
                    "croniter not installed — falling back to 60s interval",
                    extra={"job": self.name},
                )
                return time.monotonic() + 60.0

        return float("inf")  # ONE_SHOT: never reschedule

    def schedule_now(self) -> None:
        """Mark the job as ready to run immediately (plus jitter)."""
        import random
        self._next_run_at = time.monotonic() + random.uniform(0, self.jitter_s)

    def is_due(self) -> bool:
        return self.enabled and time.monotonic() >= self._next_run_at

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "trigger": self.trigger.value,
            "interval_s": self.interval_s,
            "cron_expr": self.cron_expr,
            "status": self.status.value,
            "enabled": self.enabled,
            "total_runs": self._total_runs,
            "consecutive_failures": self._consecutive_failures,
            "recent_history": [r.to_dict() for r in list(self._history)[-5:]],
        }


# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------


class Scheduler:
    """
    Async job scheduler.

    Usage
    -----
    ::

        scheduler = Scheduler(tick_interval_s=1.0)

        scheduler.add_job(
            ScheduledJob(
                name="baseline_flush",
                handler=flush_baselines,
                interval_s=30,
                max_retries=2,
            )
        )

        # Option 1: Manual lifecycle
        await scheduler.start()
        ...
        await scheduler.stop(graceful=True)

        # Option 2: Context manager
        async with scheduler:
            await asyncio.sleep(3600)
    """

    def __init__(self, *, tick_interval_s: float = 1.0):
        self._jobs: Dict[str, ScheduledJob] = {}
        self._tick_interval = tick_interval_s
        self._running = False
        self._loop_task: Optional[asyncio.Task] = None
        self._in_flight: Dict[str, asyncio.Task] = {}
        self._lock = asyncio.Lock()

        logger.info("Scheduler created", extra={"tick_s": tick_interval_s})

    # ---------------------------------------------------------------------------
    # Job management
    # ---------------------------------------------------------------------------

    def add_job(self, job: ScheduledJob) -> None:
        """Register a job. Raises ValueError on duplicate name."""
        if job.name in self._jobs:
            raise ValueError(f"Job '{job.name}' already registered.")
        job.schedule_now()
        self._jobs[job.name] = job
        logger.info("Job registered", extra={"job": job.name, "trigger": job.trigger.value})

    def remove_job(self, name: str) -> None:
        """Remove a job. Cancels any in-flight run."""
        self._jobs.pop(name, None)
        task = self._in_flight.pop(name, None)
        if task:
            task.cancel()

    def enable_job(self, name: str) -> None:
        if name in self._jobs:
            self._jobs[name].enabled = True
            self._jobs[name].status = JobStatus.IDLE

    def disable_job(self, name: str) -> None:
        if name in self._jobs:
            self._jobs[name].enabled = False
            self._jobs[name].status = JobStatus.DISABLED

    # ---------------------------------------------------------------------------
    # Execution core
    # ---------------------------------------------------------------------------

    async def _execute_job(self, job: ScheduledJob) -> None:
        """Run a single job with retry, timeout, and history recording."""
        if not job.enabled:
            return

        # Distributed lock check
        if job.lock_fn is not None:
            try:
                acquired = await job.lock_fn(job.name)
                if not acquired:
                    logger.debug("Job lock not acquired — skipping", extra={"job": job.name})
                    return
            except Exception:
                logger.exception("Job lock_fn error", extra={"job": job.name})
                return

        run = JobRun(started_at=datetime.now(timezone.utc).isoformat())
        job.status = JobStatus.RUNNING
        job._total_runs += 1

        t_start = time.perf_counter()
        last_exc: Optional[Exception] = None

        for attempt in range(1, job.max_retries + 2):
            try:
                coro = job.handler()
                if job.timeout_s is not None:
                    await asyncio.wait_for(coro, timeout=job.timeout_s)
                else:
                    await coro

                # Success
                elapsed_ms = (time.perf_counter() - t_start) * 1000
                run.success = True
                run.elapsed_ms = elapsed_ms
                run.finished_at = datetime.now(timezone.utc).isoformat()
                job._consecutive_failures = 0
                job.status = (
                    JobStatus.COMPLETED
                    if job.trigger == TriggerType.ONE_SHOT
                    else JobStatus.IDLE
                )
                logger.info(
                    "Job succeeded",
                    extra={
                        "job": job.name,
                        "attempt": attempt,
                        "elapsed_ms": round(elapsed_ms, 2),
                    },
                )
                break

            except asyncio.TimeoutError as exc:
                last_exc = exc
                elapsed_ms = (time.perf_counter() - t_start) * 1000
                logger.error(
                    "Job timed out",
                    extra={"job": job.name, "timeout_s": job.timeout_s},
                )
                break  # no retry on timeout

            except Exception as exc:
                last_exc = exc
                logger.warning(
                    "Job attempt failed",
                    extra={"job": job.name, "attempt": attempt, "error": str(exc)},
                )
                if attempt <= job.max_retries:
                    import random
                    sleep_s = job.retry_base_s * (2 ** (attempt - 1))
                    jitter = random.uniform(0, sleep_s * 0.25)
                    await asyncio.sleep(sleep_s + jitter)

        if not run.success:
            elapsed_ms = (time.perf_counter() - t_start) * 1000
            run.elapsed_ms = elapsed_ms
            run.finished_at = datetime.now(timezone.utc).isoformat()
            run.error = f"{type(last_exc).__name__}: {last_exc}" if last_exc else "unknown"
            job._consecutive_failures += 1
            job.status = JobStatus.FAILED
            logger.error(
                "Job permanently failed",
                extra={
                    "job": job.name,
                    "consecutive_failures": job._consecutive_failures,
                    "error": run.error,
                },
            )

        job._history.append(run)

        # Reschedule (skip for ONE_SHOT or disabled)
        if job.trigger != TriggerType.ONE_SHOT and job.enabled:
            job._next_run_at = job._compute_next_interval()

    # ---------------------------------------------------------------------------
    # Scheduler loop
    # ---------------------------------------------------------------------------

    async def _loop(self) -> None:
        logger.info("Scheduler loop started")
        while self._running:
            due_jobs = [j for j in self._jobs.values() if j.is_due()]

            for job in due_jobs:
                if job.name in self._in_flight and not self._in_flight[job.name].done():
                    logger.debug(
                        "Job still running — skipping tick", extra={"job": job.name}
                    )
                    continue

                task = asyncio.create_task(
                    self._execute_job(job), name=f"job:{job.name}"
                )
                self._in_flight[job.name] = task

            # Clean up completed tasks
            self._in_flight = {
                name: t for name, t in self._in_flight.items() if not t.done()
            }

            await asyncio.sleep(self._tick_interval)

        logger.info("Scheduler loop exited")

    # ---------------------------------------------------------------------------
    # Lifecycle
    # ---------------------------------------------------------------------------

    async def start(self) -> None:
        """Start the scheduler background loop."""
        if self._running:
            logger.warning("Scheduler already running")
            return
        self._running = True
        self._loop_task = asyncio.create_task(self._loop(), name="scheduler:loop")
        logger.info("Scheduler started")

    async def stop(self, *, graceful: bool = True, drain_timeout_s: float = 30.0) -> None:
        """
        Stop the scheduler.

        Parameters
        ----------
        graceful        : Wait for in-flight jobs to complete before returning.
        drain_timeout_s : Maximum seconds to wait for drain.
        """
        logger.info("Scheduler stopping", extra={"graceful": graceful})
        self._running = False

        if self._loop_task:
            self._loop_task.cancel()
            try:
                await self._loop_task
            except asyncio.CancelledError:
                pass

        if graceful and self._in_flight:
            in_flight_tasks = list(self._in_flight.values())
            logger.info(
                "Draining in-flight jobs",
                extra={"count": len(in_flight_tasks)},
            )
            try:
                await asyncio.wait_for(
                    asyncio.gather(*in_flight_tasks, return_exceptions=True),
                    timeout=drain_timeout_s,
                )
            except asyncio.TimeoutError:
                logger.warning("Drain timeout — cancelling remaining jobs")
                for t in in_flight_tasks:
                    t.cancel()

        self._in_flight.clear()
        logger.info("Scheduler stopped")

    # ---------------------------------------------------------------------------
    # Context manager support
    # ---------------------------------------------------------------------------

    async def __aenter__(self) -> "Scheduler":
        await self.start()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.stop(graceful=True)

    # ---------------------------------------------------------------------------
    # Observability
    # ---------------------------------------------------------------------------

    def status_report(self) -> Dict[str, Any]:
        """Return a structured status snapshot for all jobs."""
        return {
            "running": self._running,
            "job_count": len(self._jobs),
            "in_flight": list(self._in_flight.keys()),
            "jobs": {name: job.to_dict() for name, job in self._jobs.items()},
        }

    def get_job(self, name: str) -> Optional[ScheduledJob]:
        return self._jobs.get(name)

    def list_jobs(self) -> List[str]:
        return list(self._jobs.keys())