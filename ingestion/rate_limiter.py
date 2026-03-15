"""
ingestion/rate_limiter.py — Enterprise Token-Bucket Rate Limiter

Features:
  - Per-key rate limiting (per-source, per-collector, per-IP)
  - Token bucket algorithm with configurable burst
  - Async wait mode (blocks caller until token available)
  - Global limiter + per-key limiters in one class
  - Metrics export (allowed / throttled / waited counts)
  - Thread-safe with asyncio.Lock
"""

import asyncio
import time
import logging
from collections import defaultdict

logger = logging.getLogger("hollow_purple.rate_limiter")


class TokenBucket:
    """
    Single token-bucket limiter.

    rate  = tokens replenished per second
    burst = maximum tokens in bucket (allows short bursts above steady rate)
    """

    def __init__(self, rate: float, burst: float | None = None):
        self.rate      = rate
        self.burst     = burst or rate
        self._tokens   = self.burst
        self._last_ts  = time.monotonic()
        self._lock     = asyncio.Lock()

        self.allowed   = 0
        self.throttled = 0
        self.waited    = 0

    def _refill(self):
        now     = time.monotonic()
        elapsed = now - self._last_ts
        self._tokens = min(self.burst, self._tokens + elapsed * self.rate)
        self._last_ts = now

    def allow(self) -> bool:
        """Non-blocking check. Returns True if token available."""
        self._refill()
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            self.allowed += 1
            return True
        self.throttled += 1
        return False

    async def wait(self, timeout: float = 5.0) -> bool:
        """
        Async wait until a token is available or timeout expires.
        Returns True if acquired, False if timed out.
        """
        async with self._lock:
            deadline = time.monotonic() + timeout
            while True:
                self._refill()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    self.allowed += 1
                    self.waited  += 1
                    return True
                wait_sec = (1.0 - self._tokens) / self.rate
                remaining = deadline - time.monotonic()
                if wait_sec > remaining:
                    self.throttled += 1
                    return False
                await asyncio.sleep(min(wait_sec, 0.05))

    def stats(self) -> dict:
        return {
            "rate":      self.rate,
            "burst":     self.burst,
            "tokens":    round(self._tokens, 3),
            "allowed":   self.allowed,
            "throttled": self.throttled,
            "waited":    self.waited,
        }


class RateLimiter:
    """
    Multi-key rate limiter. Each key (collector name, IP, source) gets
    its own token bucket.

    Usage:
        limiter = RateLimiter(default_rate=1000, default_burst=2000)
        limiter.configure("aws_collector", rate=500, burst=800)

        if not limiter.allow("aws_collector"):
            # drop or wait
            pass

        acquired = await limiter.wait("aws_collector", timeout=2.0)
    """

    def __init__(self, default_rate: float = 1000.0, default_burst: float | None = None):
        self.default_rate  = default_rate
        self.default_burst = default_burst or default_rate * 2
        self._buckets: dict[str, TokenBucket] = {}
        self._configs: dict[str, dict]        = {}

    def configure(self, key: str, rate: float, burst: float | None = None):
        """Pre-configure a specific key's rate/burst before first use."""
        self._configs[key] = {"rate": rate, "burst": burst or rate * 2}
        # Recreate bucket if already exists
        if key in self._buckets:
            self._buckets[key] = TokenBucket(**self._configs[key])
        logger.info("RateLimiter configured key='%s' rate=%.0f burst=%.0f",
                    key, rate, burst or rate * 2)

    def _get_bucket(self, key: str) -> TokenBucket:
        if key not in self._buckets:
            cfg = self._configs.get(key, {"rate": self.default_rate, "burst": self.default_burst})
            self._buckets[key] = TokenBucket(**cfg)
        return self._buckets[key]

    def allow(self, key: str = "global") -> bool:
        return self._get_bucket(key).allow()

    async def wait(self, key: str = "global", timeout: float = 5.0) -> bool:
        return await self._get_bucket(key).wait(timeout=timeout)

    def stats(self) -> dict[str, dict]:
        return {key: bucket.stats() for key, bucket in self._buckets.items()}

    def throttled_keys(self) -> list[str]:
        return [k for k, b in self._buckets.items() if b.throttled > 0]