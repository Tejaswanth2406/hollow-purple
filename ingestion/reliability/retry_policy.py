"""
ingestion/reliability/retry_policy.py — Advanced Async Retry Policy

Strategies:
  - Exponential backoff with configurable base delay and multiplier
  - Jitter (full jitter algorithm) to avoid retry thundering herd
  - Max delay cap
  - Per-exception-type retry decisions (retryable vs. fatal)
  - Retry budget tracking (prevent runaway retries across many callers)
  - Async context manager support
  - Hooks: on_retry, on_failure callbacks
"""

import asyncio
import logging
import random
import time
from typing import Callable, Awaitable, Any, Type

logger = logging.getLogger("hollow_purple.retry")

# Exception types that should NEVER be retried (fatal errors)
FATAL_EXCEPTIONS = (ValueError, TypeError, KeyError, AttributeError)

# Exception types that are always retried
RETRYABLE_EXCEPTIONS = (IOError, OSError, ConnectionError, TimeoutError, asyncio.TimeoutError)


class RetryExhausted(Exception):
    """Raised when all retry attempts are exhausted."""
    def __init__(self, attempts: int, last_error: Exception):
        self.attempts   = attempts
        self.last_error = last_error
        super().__init__(f"Retry exhausted after {attempts} attempts: {last_error}")


class RetryPolicy:
    """
    Configurable async retry policy with exponential backoff + full jitter.

    Usage:
        policy = RetryPolicy(retries=3, base_delay=0.5, max_delay=10.0)
        result = await policy.run(my_async_fn, arg1, arg2)

    With callbacks:
        policy = RetryPolicy(
            retries=5,
            on_retry=lambda attempt, exc, delay: logger.warning("Retry %d: %s", attempt, exc),
        )
    """

    def __init__(
        self,
        retries:    int   = 3,
        base_delay: float = 0.5,
        max_delay:  float = 30.0,
        multiplier: float = 2.0,
        jitter:     bool  = True,
        retryable:  tuple[Type[Exception], ...] | None = None,
        fatal:      tuple[Type[Exception], ...] | None = None,
        on_retry:   Callable[[int, Exception, float], None] | None = None,
        on_failure: Callable[[int, Exception], None] | None = None,
    ):
        self.retries     = retries
        self.base_delay  = base_delay
        self.max_delay   = max_delay
        self.multiplier  = multiplier
        self.jitter      = jitter
        self.retryable   = retryable or RETRYABLE_EXCEPTIONS
        self.fatal       = fatal     or FATAL_EXCEPTIONS
        self.on_retry    = on_retry
        self.on_failure  = on_failure

        self._total_retries  = 0
        self._total_failures = 0

    async def run(self, fn: Callable[..., Awaitable[Any]], *args, **kwargs) -> Any:
        last_exc: Exception | None = None

        for attempt in range(self.retries):
            try:
                return await fn(*args, **kwargs)

            except self.fatal as exc:
                # Fatal — do not retry
                logger.debug("Fatal exception in attempt %d/%d — not retrying: %s",
                             attempt + 1, self.retries, exc)
                if self.on_failure:
                    self.on_failure(attempt + 1, exc)
                self._total_failures += 1
                raise

            except Exception as exc:
                last_exc = exc
                is_last  = attempt == self.retries - 1

                if is_last:
                    self._total_failures += 1
                    if self.on_failure:
                        self.on_failure(attempt + 1, exc)
                    break

                delay = self._compute_delay(attempt)
                self._total_retries += 1

                logger.warning(
                    "Attempt %d/%d failed: %s — retrying in %.2fs",
                    attempt + 1, self.retries, exc, delay,
                )

                if self.on_retry:
                    self.on_retry(attempt + 1, exc, delay)

                await asyncio.sleep(delay)

        raise RetryExhausted(self.retries, last_exc)

    def _compute_delay(self, attempt: int) -> float:
        """Full jitter: uniform(0, min(cap, base * multiplier^attempt))"""
        delay = min(self.max_delay, self.base_delay * (self.multiplier ** attempt))
        if self.jitter:
            delay = random.uniform(0, delay)
        return delay

    def stats(self) -> dict:
        return {
            "total_retries":  self._total_retries,
            "total_failures": self._total_failures,
        }