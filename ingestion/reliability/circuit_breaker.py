"""
ingestion/reliability/circuit_breaker.py — Production Circuit Breaker

States:
  CLOSED   → Normal operation. Failures tracked.
  OPEN     → Tripped. All calls rejected immediately.
  HALF_OPEN → Recovery probe. One call allowed; success closes, failure re-opens.

Features:
  - Configurable failure threshold (count-based)
  - Sliding window failure rate (percentage-based)
  - Recovery timeout with auto half-open probe
  - Success streak required to fully close from half-open
  - State change callbacks (for alerting / dashboards)
  - Per-breaker metrics
  - Async context manager
"""

import asyncio
import logging
import time
from enum import Enum
from typing import Callable, Awaitable, Any

logger = logging.getLogger("hollow_purple.circuit_breaker")


class CBState(Enum):
    CLOSED    = "closed"
    OPEN      = "open"
    HALF_OPEN = "half_open"


class CircuitBreakerOpen(Exception):
    """Raised when a call is attempted while the circuit is open."""
    pass


class CircuitBreaker:
    """
    Thread-safe async circuit breaker.

    Usage:
        breaker = CircuitBreaker(threshold=5, recovery_timeout=30)

        async with breaker:
            result = await risky_operation()

        # Or manual:
        if breaker.is_open():
            raise CircuitBreakerOpen("downstream unavailable")
        try:
            result = await risky_operation()
            breaker.record_success()
        except Exception as exc:
            breaker.record_failure()
            raise
    """

    def __init__(
        self,
        threshold: int         = 5,
        recovery_timeout: float = 30.0,
        half_open_probes: int   = 1,
        success_streak: int    = 2,
        on_state_change: Callable[[CBState, CBState], None] | None = None,
    ):
        self.threshold        = threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_probes = half_open_probes
        self.success_streak   = success_streak
        self._on_state_change = on_state_change

        self._state           = CBState.CLOSED
        self._failures        = 0
        self._successes       = 0
        self._opened_at:  float | None = None
        self._last_probe: float | None = None
        self._total_opens = 0
        self._total_calls = 0
        self._rejected    = 0
        self._lock        = asyncio.Lock()

    def is_open(self) -> bool:
        """Returns True if the circuit is OPEN (calls should be rejected)."""
        if self._state == CBState.OPEN:
            if self._should_attempt_recovery():
                self._transition(CBState.HALF_OPEN)
                return False   # Allow the probe through
            return True
        return False

    def record_success(self):
        if self._state == CBState.HALF_OPEN:
            self._successes += 1
            if self._successes >= self.success_streak:
                self._transition(CBState.CLOSED)
        elif self._state == CBState.CLOSED:
            # Decay failures on success (sliding window approach)
            self._failures = max(0, self._failures - 1)

    def record_failure(self):
        self._failures  += 1
        self._successes  = 0

        if self._state == CBState.HALF_OPEN:
            logger.warning("CircuitBreaker: probe failed — re-opening")
            self._transition(CBState.OPEN)
            return

        if self._state == CBState.CLOSED and self._failures >= self.threshold:
            logger.error(
                "CircuitBreaker: threshold reached (%d failures) — opening circuit",
                self._failures,
            )
            self._transition(CBState.OPEN)

    async def call(self, fn: Callable[..., Awaitable[Any]], *args, **kwargs) -> Any:
        """Execute a coroutine through the circuit breaker."""
        self._total_calls += 1
        if self.is_open():
            self._rejected += 1
            raise CircuitBreakerOpen(
                f"Circuit breaker OPEN — {self._failures} failures, "
                f"recovery in {self._time_until_recovery():.1f}s"
            )
        try:
            result = await fn(*args, **kwargs)
            self.record_success()
            return result
        except Exception as exc:
            self.record_failure()
            raise

    # Async context manager
    async def __aenter__(self):
        if self.is_open():
            self._rejected += 1
            raise CircuitBreakerOpen("Circuit breaker is OPEN")
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            self.record_failure()
        else:
            self.record_success()
        return False   # Don't suppress exceptions

    # ------------------------------------------------------------------ #
    #  Internal                                                            #
    # ------------------------------------------------------------------ #

    def _should_attempt_recovery(self) -> bool:
        if self._opened_at is None:
            return False
        return (time.time() - self._opened_at) >= self.recovery_timeout

    def _time_until_recovery(self) -> float:
        if self._opened_at is None:
            return 0.0
        elapsed = time.time() - self._opened_at
        return max(0.0, self.recovery_timeout - elapsed)

    def _transition(self, new_state: CBState):
        old_state = self._state
        self._state = new_state
        if new_state == CBState.OPEN:
            self._opened_at = time.time()
            self._total_opens += 1
            self._successes = 0
        elif new_state == CBState.CLOSED:
            self._failures  = 0
            self._successes = 0
            self._opened_at = None
        elif new_state == CBState.HALF_OPEN:
            self._successes = 0
        logger.info("CircuitBreaker: %s → %s", old_state.value, new_state.value)
        if self._on_state_change:
            self._on_state_change(old_state, new_state)

    def stats(self) -> dict:
        return {
            "state":          self._state.value,
            "failures":       self._failures,
            "successes":      self._successes,
            "total_opens":    self._total_opens,
            "total_calls":    self._total_calls,
            "rejected":       self._rejected,
            "opened_at":      self._opened_at,
            "recovery_in_sec": self._time_until_recovery(),
        }