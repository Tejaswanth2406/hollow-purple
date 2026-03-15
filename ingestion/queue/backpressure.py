"""
ingestion/queue/backpressure.py — Adaptive Backpressure Controller

Implements a multi-threshold backpressure model:
  - GREEN  (< 50% full): full throughput
  - YELLOW (50–80% full): slow down — rate-limit collectors
  - RED    (80–95% full): drop LOW-priority events
  - CRITICAL (> 95% full): drop all but CRITICAL events + alert

Consumers receive a BackpressureSignal they act on.
"""

import logging
import time
from enum import Enum
from typing import Callable

logger = logging.getLogger("hollow_purple.backpressure")


class BackpressureLevel(Enum):
    GREEN    = "green"
    YELLOW   = "yellow"
    RED      = "red"
    CRITICAL = "critical"


class BackpressureController:
    """
    Adaptive backpressure based on queue depth relative to max capacity.

    Usage:
        bp = BackpressureController(max_size=10_000)
        level = bp.level(queue.size())
        if bp.should_throttle(queue.size()):
            await asyncio.sleep(0.1)
        if bp.should_drop(queue.size(), event_priority):
            return   # discard event
    """

    THRESHOLDS = {
        BackpressureLevel.YELLOW:   0.50,
        BackpressureLevel.RED:      0.80,
        BackpressureLevel.CRITICAL: 0.95,
    }

    def __init__(
        self,
        max_size: int,
        on_level_change: Callable[[BackpressureLevel, BackpressureLevel], None] | None = None,
    ):
        self.max_size        = max_size
        self._on_level_change = on_level_change
        self._current_level  = BackpressureLevel.GREEN
        self._level_since    = time.time()
        self._throttle_count = 0
        self._drop_count     = 0

    def level(self, queue_size: int) -> BackpressureLevel:
        fill = queue_size / max(1, self.max_size)
        if fill >= self.THRESHOLDS[BackpressureLevel.CRITICAL]:
            new = BackpressureLevel.CRITICAL
        elif fill >= self.THRESHOLDS[BackpressureLevel.RED]:
            new = BackpressureLevel.RED
        elif fill >= self.THRESHOLDS[BackpressureLevel.YELLOW]:
            new = BackpressureLevel.YELLOW
        else:
            new = BackpressureLevel.GREEN

        if new != self._current_level:
            old = self._current_level
            self._current_level = new
            self._level_since   = time.time()
            logger.warning("Backpressure level: %s → %s (queue=%d/%d)",
                           old.value, new.value, queue_size, self.max_size)
            if self._on_level_change:
                self._on_level_change(old, new)

        return new

    def should_throttle(self, queue_size: int) -> bool:
        lvl = self.level(queue_size)
        if lvl in (BackpressureLevel.YELLOW, BackpressureLevel.RED, BackpressureLevel.CRITICAL):
            self._throttle_count += 1
            return True
        return False

    def should_drop(self, queue_size: int, priority: int = 2) -> bool:
        """
        priority: 0=CRITICAL, 1=HIGH, 2=NORMAL, 3=LOW
        RED   → drop LOW (priority 3)
        CRITICAL → drop everything except CRITICAL (priority > 0)
        """
        lvl = self.level(queue_size)
        if lvl == BackpressureLevel.CRITICAL and priority > 0:
            self._drop_count += 1
            return True
        if lvl == BackpressureLevel.RED and priority >= 3:
            self._drop_count += 1
            return True
        return False

    def throttle_delay_ms(self, queue_size: int) -> float:
        """Suggested sleep duration in milliseconds for the collector."""
        lvl = self.level(queue_size)
        return {
            BackpressureLevel.GREEN:    0,
            BackpressureLevel.YELLOW:  50,
            BackpressureLevel.RED:    200,
            BackpressureLevel.CRITICAL: 1000,
        }[lvl]

    def stats(self) -> dict:
        return {
            "level":           self._current_level.value,
            "level_since":     self._level_since,
            "throttle_count":  self._throttle_count,
            "drop_count":      self._drop_count,
        }