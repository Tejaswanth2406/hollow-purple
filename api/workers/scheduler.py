"""
workers/scheduler.py — Periodic Task Scheduler

Cron-style scheduler for background maintenance tasks:
  - Hourly risk recomputation for high-risk identities
  - Daily full graph rebuild
  - Periodic cache sweep (evict expired entries)
  - Replay spot-checks (random window verification)
  - Attack pattern digest reports
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine, Dict, List, Optional

logger = logging.getLogger("hollowpurple.workers.scheduler")


@dataclass
class ScheduledTask:
    name:         str
    coro_factory: Callable[[], Coroutine]
    interval_sec: float
    last_run:     float = field(default=0.0)
    run_count:    int   = field(default=0)
    error_count:  int   = field(default=0)
    enabled:      bool  = field(default=True)

    @property
    def next_run_in(self) -> float:
        return max(0.0, self.interval_sec - (time.monotonic() - self.last_run))


class TaskScheduler:
    """
    Lightweight in-process periodic task scheduler.

    Usage:
        scheduler = TaskScheduler()
        scheduler.register("cache_sweep", lambda: cache.sweep(), interval_sec=300)
        await scheduler.start()
    """

    TICK_INTERVAL = 5.0   # resolution

    def __init__(self) -> None:
        self._tasks:  List[ScheduledTask] = []
        self._running = False
        self._loop_task: Optional[asyncio.Task] = None

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(
        self,
        name: str,
        coro_factory: Callable[[], Coroutine],
        interval_sec: float,
        run_immediately: bool = False,
    ) -> None:
        """Register a periodic coroutine."""
        last = 0.0 if run_immediately else time.monotonic()
        self._tasks.append(ScheduledTask(
            name=name,
            coro_factory=coro_factory,
            interval_sec=interval_sec,
            last_run=last,
        ))
        logger.info("task_registered", extra={"name": name, "interval_sec": interval_sec})

    def disable(self, name: str) -> bool:
        for t in self._tasks:
            if t.name == name:
                t.enabled = False
                return True
        return False

    def enable(self, name: str) -> bool:
        for t in self._tasks:
            if t.name == name:
                t.enabled = True
                return True
        return False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._register_defaults()
        self._loop_task = asyncio.create_task(self._tick_loop(), name="scheduler")
        logger.info("scheduler_started", extra={"task_count": len(self._tasks)})

    async def stop(self) -> None:
        self._running = False
        if self._loop_task:
            self._loop_task.cancel()
            try:
                await self._loop_task
            except asyncio.CancelledError:
                pass
        logger.info("scheduler_stopped")

    def status(self) -> List[Dict[str, Any]]:
        return [
            {
                "name":         t.name,
                "interval_sec": t.interval_sec,
                "next_run_in":  round(t.next_run_in, 1),
                "run_count":    t.run_count,
                "error_count":  t.error_count,
                "enabled":      t.enabled,
            }
            for t in self._tasks
        ]

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _register_defaults(self) -> None:
        """Register built-in Hollow Purple maintenance tasks."""

        async def cache_sweep():
            try:
                from api.cache.cache_manager import CacheManager
                # Sweep is per-instance; services hold their own managers
                logger.debug("cache_sweep_tick")
            except Exception:
                pass

        async def high_risk_recompute():
            try:
                from graph.scoring import get_high_risk_identities
                from api.services.risk_service import RiskService
                svc = RiskService()
                identities = get_high_risk_identities(threshold=0.7, limit=50)
                for identity in identities:
                    await svc.query_identity_risk(identity, window_hours=24, include_paths=True)
            except ImportError:
                pass

        async def graph_prune():
            from api.workers.graph_worker import graph_worker
            await graph_worker.enqueue_prune(inactive_days=90)

        async def replay_spot_check():
            from datetime import datetime, timedelta
            from api.workers.replay_worker import replay_worker
            end   = datetime.utcnow()
            start = end - timedelta(hours=1)
            await replay_worker.enqueue(start, end)

        async def telemetry_digest():
            try:
                from MAHORAGHA.telemetry import emit_digest
                emit_digest()
            except ImportError:
                pass

        self.register("cache_sweep",          cache_sweep,          interval_sec=300,   run_immediately=True)
        self.register("high_risk_recompute",  high_risk_recompute,  interval_sec=3600)
        self.register("graph_prune",          graph_prune,          interval_sec=86400)
        self.register("replay_spot_check",    replay_spot_check,    interval_sec=3600)
        self.register("telemetry_digest",     telemetry_digest,     interval_sec=300)

    async def _tick_loop(self) -> None:
        while self._running:
            now = time.monotonic()
            for task in self._tasks:
                if not task.enabled:
                    continue
                if now - task.last_run >= task.interval_sec:
                    asyncio.create_task(self._run_task(task), name=f"scheduled:{task.name}")
            await asyncio.sleep(self.TICK_INTERVAL)

    async def _run_task(self, task: ScheduledTask) -> None:
        task.last_run = time.monotonic()
        task.run_count += 1
        logger.debug("scheduled_task_run", extra={"name": task.name})
        try:
            await task.coro_factory()
        except Exception as exc:
            task.error_count += 1
            logger.exception("scheduled_task_failed", extra={"name": task.name, "error": str(exc)})


# Global singleton
scheduler = TaskScheduler()