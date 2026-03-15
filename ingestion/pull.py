"""
ingestion/pull.py — Pull-Based Collector Runner

Manages scheduled polling of pull-based collectors (AWS CloudTrail, Azure Activity Logs, etc.)
with:
  - Configurable poll interval with jitter to avoid thundering herd
  - Per-collector circuit breaker and failure tracking
  - Async generator interface for downstream consumption
  - Graceful shutdown signal
  - Collector health reporting
"""

import asyncio
import logging
import random
import time
from typing import AsyncGenerator

logger = logging.getLogger("hollow_purple.pull_runner")


class PullRunner:
    """
    Async pull runner for a single collector.

    Usage:
        runner = PullRunner(collector=AWSCollector(), interval=30, jitter=5)
        await runner.start()
        async for event in runner.events():
            await orchestrator.ingest(event)
    """

    def __init__(self, collector, interval: float = 30.0, jitter: float = 5.0,
                 max_consecutive_failures: int = 5):
        self.collector                = collector
        self.interval                 = interval
        self.jitter                   = jitter
        self.max_consecutive_failures = max_consecutive_failures

        self._shutdown      = asyncio.Event()
        self._failures      = 0
        self._total_polls   = 0
        self._total_events  = 0
        self._last_poll_ts: float | None = None

    async def start(self):
        logger.info("PullRunner started for %s (interval=%.1fs ±%.1fs)",
                    self.collector.__class__.__name__, self.interval, self.jitter)

    async def stop(self):
        self._shutdown.set()
        logger.info("PullRunner stopping for %s", self.collector.__class__.__name__)

    async def events(self) -> AsyncGenerator[dict, None]:
        """Async generator yielding individual events from the collector."""
        while not self._shutdown.is_set():
            sleep_sec = self.interval + random.uniform(-self.jitter, self.jitter)
            sleep_sec = max(1.0, sleep_sec)

            try:
                batch = await self.collector.collect()
                self._failures    = 0
                self._total_polls += 1
                self._last_poll_ts = time.time()

                if batch:
                    self._total_events += len(batch)
                    logger.debug("%s collected %d events",
                                 self.collector.__class__.__name__, len(batch))
                    for event in batch:
                        yield event

            except Exception as exc:
                self._failures += 1
                logger.error("%s collection failed (%d/%d): %s",
                             self.collector.__class__.__name__,
                             self._failures, self.max_consecutive_failures, exc)

                if self._failures >= self.max_consecutive_failures:
                    logger.critical(
                        "%s exceeded max failures — suspending for 5× interval",
                        self.collector.__class__.__name__,
                    )
                    await asyncio.sleep(self.interval * 5)
                    self._failures = 0
                    continue

            try:
                await asyncio.wait_for(self._shutdown.wait(), timeout=sleep_sec)
            except asyncio.TimeoutError:
                pass

    def health(self) -> dict:
        return {
            "collector":     self.collector.__class__.__name__,
            "total_polls":   self._total_polls,
            "total_events":  self._total_events,
            "failures":      self._failures,
            "last_poll":     self._last_poll_ts,
            "healthy":       self._failures < self.max_consecutive_failures,
        }


class MultiPullRunner:
    """
    Manages multiple PullRunner instances concurrently.

    Usage:
        runner = MultiPullRunner([
            PullRunner(AWSCollector(),   interval=30),
            PullRunner(AzureCollector(), interval=60),
            PullRunner(GCPCollector(),   interval=45),
        ])
        await runner.start_all(orchestrator)
    """

    def __init__(self, runners: list[PullRunner]):
        self.runners = runners
        self._tasks:  list[asyncio.Task] = []

    async def start_all(self, orchestrator):
        for runner in self.runners:
            await runner.start()
            task = asyncio.create_task(
                self._drain(runner, orchestrator),
                name=f"pull_{runner.collector.__class__.__name__}",
            )
            self._tasks.append(task)

    async def stop_all(self):
        for runner in self.runners:
            await runner.stop()
        await asyncio.gather(*self._tasks, return_exceptions=True)

    async def _drain(self, runner: PullRunner, orchestrator):
        async for event in runner.events():
            await orchestrator.ingest(event)

    def health_report(self) -> list[dict]:
        return [r.health() for r in self.runners]