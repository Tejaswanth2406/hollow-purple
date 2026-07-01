"""Health startup helpers for Hollow Purple."""

from __future__ import annotations

import asyncio
import logging

from MAHORAGHA.health import HealthMonitor

logger = logging.getLogger("hollowpurple.health.startup")

_health_monitor: HealthMonitor | None = None


def _run_monitor() -> None:
    if _health_monitor is None:
        return
    report = _health_monitor.check()
    logger.info("health_report %s", report.to_dict())


async def start_health_monitor() -> None:
    global _health_monitor
    if _health_monitor is None:
        _health_monitor = HealthMonitor()

    loop = asyncio.get_event_loop()
    while True:
        await loop.run_in_executor(None, _run_monitor)
        await asyncio.sleep(15)
