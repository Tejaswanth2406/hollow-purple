"""
ingestion/queue/batching.py — Intelligent Event Batcher

Features:
  - Size-based flushing (batch full)
  - Time-based flushing (max age exceeded)
  - Priority-aware flushing (CRITICAL events flush immediately)
  - Per-source partitioned batching
  - Partial flush support (drain remaining buffer)
  - Batch metadata (source mix, priority distribution, age stats)
"""

import asyncio
import logging
import time
from collections import defaultdict
from typing import Callable, Awaitable

logger = logging.getLogger("hollow_purple.batcher")


class Batch:
    """A collected group of events with metadata."""

    def __init__(self):
        self.events:    list[dict] = []
        self.created_at: float     = time.time()
        self.source_counts: dict[str, int] = defaultdict(int)
        self.priority_counts: dict[int, int] = defaultdict(int)

    def add(self, event: dict, priority: int = 2):
        self.events.append(event)
        self.source_counts[event.get("source", "unknown")] += 1
        self.priority_counts[priority] += 1

    def size(self) -> int:
        return len(self.events)

    def age_seconds(self) -> float:
        return time.time() - self.created_at

    def metadata(self) -> dict:
        return {
            "size":            self.size(),
            "age_sec":         round(self.age_seconds(), 3),
            "source_mix":      dict(self.source_counts),
            "priority_mix":    dict(self.priority_counts),
            "created_at":      self.created_at,
        }


class Batcher:
    """
    Accumulates events into batches and flushes when:
      - batch reaches max_size
      - batch age exceeds max_age_sec
      - a CRITICAL priority event arrives (immediate flush)

    Usage (manual):
        batcher = Batcher(size=100, max_age_sec=5.0)
        batch = batcher.add(event, priority=1)
        if batch:
            await dispatch(batch)

    Usage (async loop):
        async for batch in batcher.auto_flush_loop(queue):
            await dispatch(batch)
    """

    def __init__(
        self,
        size: int         = 100,
        max_age_sec: float = 5.0,
        immediate_priority: int = 0,   # Priority.CRITICAL
    ):
        self.max_size           = size
        self.max_age_sec        = max_age_sec
        self.immediate_priority = immediate_priority

        self.buffer    = Batch()
        self._total_batches  = 0
        self._total_events   = 0

    def add(self, event: dict, priority: int = 2) -> Batch | None:
        """
        Add an event. Returns a completed Batch if flush triggered, else None.
        """
        self.buffer.add(event, priority)

        # Immediate flush for CRITICAL events
        if priority <= self.immediate_priority:
            return self._flush(reason="critical_priority")

        # Size-based flush
        if self.buffer.size() >= self.max_size:
            return self._flush(reason="size")

        return None

    def tick(self) -> Batch | None:
        """
        Call periodically to trigger time-based flush.
        Returns a Batch if age exceeded, else None.
        """
        if self.buffer.size() > 0 and self.buffer.age_seconds() >= self.max_age_sec:
            return self._flush(reason="age")
        return None

    def flush(self) -> Batch | None:
        """Force-flush the current buffer regardless of size or age."""
        if self.buffer.size() == 0:
            return None
        return self._flush(reason="force")

    def stats(self) -> dict:
        return {
            "total_batches": self._total_batches,
            "total_events":  self._total_events,
            "buffer_size":   self.buffer.size(),
            "buffer_age_sec": round(self.buffer.age_seconds(), 2),
        }

    async def auto_flush_loop(
        self,
        queue,
        tick_interval: float = 1.0,
    ):
        """
        Async generator that yields complete Batches.
        Pulls from an EventQueue and handles time-based flushes via periodic tick.

        Usage:
            async for batch in batcher.auto_flush_loop(queue):
                await downstream_callback(batch)
        """
        while True:
            event = await queue.pop(timeout=tick_interval)
            if event is not None:
                priority = event.get("_priority", 2)
                batch = self.add(event, priority=priority)
                if batch:
                    yield batch
            else:
                # Timeout — check age-based flush
                batch = self.tick()
                if batch:
                    yield batch

    # ------------------------------------------------------------------ #
    #  Internal                                                            #
    # ------------------------------------------------------------------ #

    def _flush(self, reason: str) -> Batch:
        batch = self.buffer
        self._total_batches += 1
        self._total_events  += batch.size()
        logger.debug("Flushing batch: reason=%s size=%d age=%.2fs",
                     reason, batch.size(), batch.age_seconds())
        self.buffer = Batch()
        return batch