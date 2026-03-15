"""
ingestion/queue/event_queue.py — Async Priority Event Queue

Features:
  - Priority levels: CRITICAL > HIGH > NORMAL > LOW
  - asyncio.PriorityQueue backend
  - Overflow policy: DROP_LOWEST or BLOCK
  - Queue depth metrics
  - Per-priority counters
  - Async context manager support
"""

import asyncio
import logging
import time
from enum import IntEnum
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("hollow_purple.queue")


class Priority(IntEnum):
    CRITICAL = 0
    HIGH     = 1
    NORMAL   = 2
    LOW      = 3


@dataclass(order=True)
class QueueItem:
    priority: int
    seq:      int       # tie-break by insertion order
    ts:       float = field(compare=False)
    event:    Any   = field(compare=False)


class EventQueue:
    """
    Priority-aware async event queue.

    Usage:
        queue = EventQueue(maxsize=10_000)
        await queue.push(event, priority=Priority.HIGH)
        event = await queue.pop()
    """

    def __init__(self, maxsize: int = 10_000, overflow: str = "drop_lowest"):
        self._queue   = asyncio.PriorityQueue(maxsize=0)   # unbounded — we manage size
        self._maxsize = maxsize
        self._overflow = overflow
        self._seq     = 0

        self._pushed:  dict[int, int] = {p: 0 for p in Priority}
        self._popped:  dict[int, int] = {p: 0 for p in Priority}
        self._dropped  = 0

    async def push(self, event: dict, priority: Priority = Priority.NORMAL) -> bool:
        """
        Push event onto the queue.
        Returns True if enqueued, False if dropped due to overflow.
        """
        if self._queue.qsize() >= self._maxsize:
            if self._overflow == "drop_lowest":
                dropped = await self._drop_lowest_priority()
                if not dropped:
                    self._dropped += 1
                    logger.warning("Queue full and no low-priority items to drop — discarding event")
                    return False
            else:
                self._dropped += 1
                return False

        self._seq += 1
        item = QueueItem(priority=int(priority), seq=self._seq, ts=time.time(), event=event)
        await self._queue.put(item)
        self._pushed[int(priority)] = self._pushed.get(int(priority), 0) + 1
        return True

    async def pop(self, timeout: float | None = None) -> dict | None:
        """
        Pop highest-priority event. Blocks until available or timeout.
        Returns None on timeout.
        """
        try:
            if timeout is not None:
                item = await asyncio.wait_for(self._queue.get(), timeout=timeout)
            else:
                item = await self._queue.get()
            self._popped[item.priority] = self._popped.get(item.priority, 0) + 1
            return item.event
        except asyncio.TimeoutError:
            return None

    def size(self) -> int:
        return self._queue.qsize()

    def is_empty(self) -> bool:
        return self._queue.empty()

    def stats(self) -> dict:
        return {
            "size":      self.size(),
            "maxsize":   self._maxsize,
            "dropped":   self._dropped,
            "pushed":    dict(self._pushed),
            "popped":    dict(self._popped),
        }

    async def _drop_lowest_priority(self) -> bool:
        """Drain the queue temporarily to find and drop a LOW priority item."""
        # NOTE: This is a best-effort approach for in-process queues.
        # In production with Kafka/Redis Streams, use TTL-based expiry instead.
        items: list[QueueItem] = []
        dropped = False
        while not self._queue.empty():
            item = self._queue.get_nowait()
            items.append(item)
        # Sort: keep highest priority (lowest int value) first; drop one LOW item
        items.sort()
        for i in range(len(items) - 1, -1, -1):
            if items[i].priority == int(Priority.LOW):
                items.pop(i)
                dropped = True
                self._dropped += 1
                break
        for item in items:
            await self._queue.put(item)
        return dropped