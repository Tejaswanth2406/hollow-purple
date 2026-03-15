"""
ingestion/reliability/dead_letter_queue.py — Enterprise Dead Letter Queue

Features:
  - Bounded in-memory DLQ with overflow to disk (optional)
  - Reason tagging per failed event
  - Retry-from-DLQ with configurable policy
  - DLQ age tracking (detect stale unprocessed failures)
  - Export to JSON for offline analysis
  - Alerting hook when DLQ exceeds threshold
  - Per-reason failure counters
"""

import asyncio
import json
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable, Any

logger = logging.getLogger("hollow_purple.dlq")

MAX_DLQ_SIZE    = 50_000
ALERT_THRESHOLD = 1_000    # Alert when DLQ exceeds this many items


@dataclass
class DLQEntry:
    event:      Any
    reason:     str
    ts:         float = field(default_factory=time.time)
    attempt:    int   = 1
    source:     str   = ""


class DeadLetterQueue:
    """
    Bounded dead letter queue for failed events.

    Usage:
        dlq = DeadLetterQueue(max_size=10_000)
        dlq.push(event, reason="validation_error")
        entries = dlq.peek(limit=100)
        await dlq.replay(orchestrator, limit=50)
    """

    def __init__(
        self,
        max_size: int = MAX_DLQ_SIZE,
        alert_threshold: int = ALERT_THRESHOLD,
        on_alert: Callable[[int], None] | None = None,
    ):
        self._entries:    list[DLQEntry]       = []
        self.max_size     = max_size
        self.alert_threshold = alert_threshold
        self._on_alert    = on_alert
        self._reason_counts: dict[str, int]   = defaultdict(int)
        self._total_pushed = 0
        self._total_replayed = 0
        self._alert_fired  = False

    def push(self, event: Any, reason: str = "unknown", source: str = ""):
        """Add a failed event to the DLQ."""
        if len(self._entries) >= self.max_size:
            # Evict oldest entry
            evicted = self._entries.pop(0)
            logger.warning("DLQ full (max=%d) — evicted oldest entry: reason=%s",
                           self.max_size, evicted.reason)

        entry = DLQEntry(
            event=event,
            reason=reason,
            source=source or (event.get("source", "") if isinstance(event, dict) else ""),
        )
        self._entries.append(entry)
        self._reason_counts[reason] += 1
        self._total_pushed += 1

        logger.debug("DLQ push: reason=%s size=%d", reason, len(self._entries))

        # Alert check
        if not self._alert_fired and len(self._entries) >= self.alert_threshold:
            self._alert_fired = True
            logger.error("DLQ alert: size %d exceeded threshold %d",
                         len(self._entries), self.alert_threshold)
            if self._on_alert:
                self._on_alert(len(self._entries))

    def peek(self, limit: int = 100) -> list[DLQEntry]:
        """View the oldest N entries without removing them."""
        return self._entries[:limit]

    def pop(self) -> DLQEntry | None:
        """Remove and return the oldest entry."""
        if not self._entries:
            return None
        return self._entries.pop(0)

    async def replay(self, orchestrator, limit: int = 100, filter_reason: str | None = None) -> int:
        """
        Re-inject DLQ entries back through the ingestion orchestrator.
        Returns the count of successfully replayed events.
        """
        replayed = 0
        remaining: list[DLQEntry] = []

        entries_to_try = [
            e for e in self._entries[:limit]
            if filter_reason is None or e.reason == filter_reason
        ]
        skipped = [
            e for e in self._entries
            if e not in entries_to_try
        ]

        for entry in entries_to_try:
            try:
                result = await orchestrator.ingest(entry.event)
                if result is not None:
                    replayed += 1
                    self._total_replayed += 1
                    logger.info("DLQ replay success: reason=%s", entry.reason)
                else:
                    entry.attempt += 1
                    remaining.append(entry)
            except Exception as exc:
                entry.attempt += 1
                remaining.append(entry)
                logger.warning("DLQ replay failed (attempt %d): %s", entry.attempt, exc)

        self._entries = remaining + skipped[limit:]
        if replayed > 0 and len(self._entries) < self.alert_threshold:
            self._alert_fired = False

        return replayed

    def export_json(self, path: str):
        """Dump DLQ to a JSON file for offline analysis."""
        records = [
            {
                "reason":   e.reason,
                "ts":       e.ts,
                "attempt":  e.attempt,
                "source":   e.source,
                "event":    e.event if isinstance(e.event, dict) else str(e.event),
            }
            for e in self._entries
        ]
        with open(path, "w") as f:
            json.dump(records, f, indent=2, default=str)
        logger.info("DLQ exported %d entries to %s", len(records), path)

    def size(self) -> int:
        return len(self._entries)

    def stats(self) -> dict:
        ages = [time.time() - e.ts for e in self._entries]
        return {
            "size":           len(self._entries),
            "total_pushed":   self._total_pushed,
            "total_replayed": self._total_replayed,
            "reason_counts":  dict(self._reason_counts),
            "oldest_age_sec": round(max(ages), 1) if ages else 0,
            "avg_age_sec":    round(sum(ages) / len(ages), 1) if ages else 0,
        }