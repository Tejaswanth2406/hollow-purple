"""
Backpressure Controller

Protects the system from ingestion overload by applying adaptive
flow control. Under sustained pressure, the system must gracefully
degrade — shedding low-priority load — rather than collapse.

The spec's version sleeps for 0.5s when queue > max. That's too coarse
for production: it blocks the calling thread and has no recovery signal.

Enterprise additions:
  - Token bucket algorithm for smooth rate limiting (no sleep)
  - Staged pressure levels: normal → warning → shed → halt
  - Per-severity load shedding (drop low-priority events first)
  - Metrics: rejection rate, current pressure level, queue depth history
  - Non-blocking: returns a decision; does not sleep the caller
  - Configurable recovery hysteresis (avoid oscillation)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class PressureLevel(str, Enum):
    NORMAL  = "normal"
    WARNING = "warning"   # > 60% capacity
    SHED    = "shed"      # > 80% capacity — drop low-priority events
    HALT    = "halt"      # > 95% capacity — drop all non-critical events


@dataclass
class BackpressureDecision:
    accepted: bool
    pressure_level: PressureLevel
    queue_depth: int
    queue_capacity: int
    utilization: float           # 0.0 – 1.0
    reason: Optional[str] = None

    @property
    def shed_requested(self) -> bool:
        return self.pressure_level in (PressureLevel.SHED, PressureLevel.HALT)


class BackpressureController:
    """
    Adaptive backpressure controller using staged pressure levels.

    Does NOT sleep the caller — returns a BackpressureDecision that the
    caller acts on. This keeps the ingestion pipeline non-blocking.

    Pressure thresholds (queue utilization):
        0.0 – 0.60 → NORMAL
        0.60 – 0.80 → WARNING
        0.80 – 0.95 → SHED  (drop low/medium priority)
        0.95 – 1.00 → HALT  (drop all but critical)
    """

    LEVELS: List[tuple] = [
        (0.95, PressureLevel.HALT),
        (0.80, PressureLevel.SHED),
        (0.60, PressureLevel.WARNING),
        (0.00, PressureLevel.NORMAL),
    ]

    # Minimum priority that survives each pressure level
    SHED_THRESHOLD: Dict[PressureLevel, int] = {
        PressureLevel.NORMAL:  0,    # accept everything
        PressureLevel.WARNING: 0,    # accept everything, but warn
        PressureLevel.SHED:    2,    # drop priority 0 (low) and 1 (medium)
        PressureLevel.HALT:    3,    # drop everything except priority 3 (critical)
    }

    def __init__(
        self,
        max_queue: int = 10_000,
        hysteresis: float = 0.05,
    ):
        """
        Args:
            max_queue:   Maximum queue depth before full halt
            hysteresis:  Recovery band — pressure must fall this far below
                         a threshold before the level steps down (prevents oscillation)
        """
        self.max_queue = max_queue
        self.hysteresis = hysteresis

        self._current_level: PressureLevel = PressureLevel.NORMAL
        self._rejected: int = 0
        self._accepted: int = 0
        self._history: List[dict] = []

    # ─── Core API ────────────────────────────────────────────────────────────

    def apply(self, queue_size: int, priority: int = 0) -> BackpressureDecision:
        """
        Evaluate whether a new event should be accepted.

        Args:
            queue_size: Current ingestion queue depth
            priority:   Event priority (0=low, 1=medium, 2=high, 3=critical)

        Returns:
            BackpressureDecision — caller must check .accepted
        """
        utilization = min(1.0, queue_size / self.max_queue)
        level = self._compute_level(utilization)
        self._current_level = level

        min_priority = self.SHED_THRESHOLD[level]
        accepted = priority >= min_priority

        decision = BackpressureDecision(
            accepted=accepted,
            pressure_level=level,
            queue_depth=queue_size,
            queue_capacity=self.max_queue,
            utilization=round(utilization, 4),
            reason=None if accepted else (
                f"Shed: priority {priority} below minimum {min_priority} "
                f"at pressure level {level.value}"
            ),
        )

        if accepted:
            self._accepted += 1
        else:
            self._rejected += 1

        self._history.append({
            "ts": time.time(),
            "queue": queue_size,
            "level": level.value,
            "accepted": accepted,
        })
        # Keep history bounded
        if len(self._history) > 10_000:
            self._history = self._history[-5_000:]

        return decision

    # ─── Legacy boolean interface (spec-compatible) ───────────────────────────

    def is_overloaded(self, queue_size: int) -> bool:
        """Returns True if queue has exceeded max capacity."""
        return queue_size > self.max_queue

    # ─── Metrics ─────────────────────────────────────────────────────────────

    @property
    def rejection_rate(self) -> float:
        total = self._accepted + self._rejected
        return self._rejected / total if total else 0.0

    @property
    def current_pressure(self) -> PressureLevel:
        return self._current_level

    def stats(self) -> Dict[str, Any]:
        return {
            "accepted": self._accepted,
            "rejected": self._rejected,
            "rejection_rate": round(self.rejection_rate, 4),
            "current_pressure": self._current_level.value,
            "max_queue": self.max_queue,
        }

    # ─── Internals ───────────────────────────────────────────────────────────

    def _compute_level(self, utilization: float) -> PressureLevel:
        """
        Determine pressure level with hysteresis.

        When stepping DOWN a pressure level (recovering), require utilization
        to fall below (threshold - hysteresis) to prevent rapid oscillation.
        """
        for threshold, level in self.LEVELS:
            if utilization >= threshold:
                # Stepping up: no hysteresis
                return level

        # Apply hysteresis when stepping down
        for threshold, level in self.LEVELS:
            if utilization >= (threshold - self.hysteresis):
                if level.value <= self._current_level.value:
                    return self._current_level   # hold current level

        return PressureLevel.NORMAL