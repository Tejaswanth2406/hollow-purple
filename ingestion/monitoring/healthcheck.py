"""
ingestion/monitoring/healthcheck.py — Comprehensive Health Check System

Health checks for all pipeline subsystems:
  - Queue depth and saturation
  - DLQ backlog
  - Circuit breaker states
  - Collector reachability (async probe)
  - Rate limiter saturation
  - Worker liveness
  - Uptime and last-event age

Returns structured health report compatible with Kubernetes liveness/readiness probes.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Awaitable

logger = logging.getLogger("hollow_purple.healthcheck")


class HealthStatus(Enum):
    HEALTHY   = "healthy"
    DEGRADED  = "degraded"
    UNHEALTHY = "unhealthy"


@dataclass
class ComponentHealth:
    name:    str
    status:  HealthStatus
    message: str = ""
    details: dict = field(default_factory=dict)
    checked_at: float = field(default_factory=time.time)


class HealthCheck:
    """
    Aggregates health status across all ingestion pipeline components.

    Usage:
        hc = HealthCheck()
        hc.register("queue",       lambda: check_queue(queue))
        hc.register("dlq",         lambda: check_dlq(dlq))
        hc.register("aws_collector", lambda: probe_aws())

        report = await hc.run()
        print(report["overall"])          # "healthy" | "degraded" | "unhealthy"
        print(report["components"])
    """

    def __init__(self):
        self._checks: dict[str, Callable[[], Awaitable[ComponentHealth]]] = {}
        self._start_time = time.time()
        self._last_event_ts: float | None = None

    def register(self, name: str, check_fn: Callable[[], Awaitable[ComponentHealth]]):
        self._checks[name] = check_fn

    def record_event(self):
        """Call whenever an event is processed — tracks event freshness."""
        self._last_event_ts = time.time()

    async def run(self) -> dict:
        """Execute all registered health checks concurrently."""
        results = await asyncio.gather(
            *[fn() for fn in self._checks.values()],
            return_exceptions=True,
        )

        components: list[ComponentHealth] = []
        for name, result in zip(self._checks.keys(), results):
            if isinstance(result, Exception):
                components.append(ComponentHealth(
                    name=name,
                    status=HealthStatus.UNHEALTHY,
                    message=f"Health check raised: {result}",
                ))
            else:
                components.append(result)

        # Add built-in checks
        components.append(self._check_uptime())
        components.append(self._check_event_freshness())

        # Overall status
        statuses = {c.status for c in components}
        if HealthStatus.UNHEALTHY in statuses:
            overall = HealthStatus.UNHEALTHY
        elif HealthStatus.DEGRADED in statuses:
            overall = HealthStatus.DEGRADED
        else:
            overall = HealthStatus.HEALTHY

        return {
            "overall":    overall.value,
            "checked_at": time.time(),
            "components": [
                {
                    "name":       c.name,
                    "status":     c.status.value,
                    "message":    c.message,
                    "details":    c.details,
                    "checked_at": c.checked_at,
                }
                for c in components
            ],
        }

    # ------------------------------------------------------------------ #
    #  Built-in check factories                                           #
    # ------------------------------------------------------------------ #

    @staticmethod
    def queue_check(queue) -> Callable[[], Awaitable[ComponentHealth]]:
        async def _check():
            size     = queue.size()
            maxsize  = queue._maxsize
            fill_pct = (size / max(1, maxsize)) * 100
            if fill_pct > 95:
                status, msg = HealthStatus.UNHEALTHY, f"Queue critical: {fill_pct:.1f}% full"
            elif fill_pct > 75:
                status, msg = HealthStatus.DEGRADED,  f"Queue high: {fill_pct:.1f}% full"
            else:
                status, msg = HealthStatus.HEALTHY,   f"Queue OK: {fill_pct:.1f}% full"
            return ComponentHealth("queue", status, msg, {"size": size, "fill_pct": fill_pct})
        return _check

    @staticmethod
    def dlq_check(dlq, threshold: int = 100) -> Callable[[], Awaitable[ComponentHealth]]:
        async def _check():
            size = dlq.size()
            if size >= threshold:
                status, msg = HealthStatus.DEGRADED, f"DLQ backlog: {size} events"
            else:
                status, msg = HealthStatus.HEALTHY,  f"DLQ OK: {size} events"
            return ComponentHealth("dlq", status, msg, dlq.stats())
        return _check

    @staticmethod
    def circuit_breaker_check(breaker, name: str) -> Callable[[], Awaitable[ComponentHealth]]:
        async def _check():
            stats = breaker.stats()
            if stats["state"] == "open":
                status = HealthStatus.UNHEALTHY
                msg    = f"Circuit breaker OPEN — {stats['failures']} failures"
            elif stats["state"] == "half_open":
                status = HealthStatus.DEGRADED
                msg    = "Circuit breaker HALF_OPEN — recovery probe in progress"
            else:
                status = HealthStatus.HEALTHY
                msg    = "Circuit breaker closed"
            return ComponentHealth(f"breaker_{name}", status, msg, stats)
        return _check

    # ------------------------------------------------------------------ #
    #  Built-in checks                                                     #
    # ------------------------------------------------------------------ #

    def _check_uptime(self) -> ComponentHealth:
        uptime = time.time() - self._start_time
        return ComponentHealth(
            "uptime",
            HealthStatus.HEALTHY,
            f"Running for {uptime:.0f}s",
            {"uptime_sec": round(uptime, 1)},
        )

    def _check_event_freshness(self) -> ComponentHealth:
        if self._last_event_ts is None:
            return ComponentHealth(
                "event_freshness",
                HealthStatus.DEGRADED,
                "No events processed yet",
            )
        age = time.time() - self._last_event_ts
        if age > 300:
            return ComponentHealth(
                "event_freshness",
                HealthStatus.DEGRADED,
                f"No events in {age:.0f}s — collector may be stalled",
                {"last_event_age_sec": round(age, 1)},
            )
        return ComponentHealth(
            "event_freshness",
            HealthStatus.HEALTHY,
            f"Last event {age:.1f}s ago",
            {"last_event_age_sec": round(age, 1)},
        )

    async def liveness(self) -> dict:
        """Kubernetes liveness probe — just confirm process is alive."""
        return {"status": "alive", "uptime_sec": round(time.time() - self._start_time, 1)}

    async def readiness(self) -> dict:
        """Kubernetes readiness probe — confirm pipeline is ready to accept events."""
        report = await self.run()
        ready  = report["overall"] in ("healthy", "degraded")
        return {"ready": ready, "status": report["overall"]}