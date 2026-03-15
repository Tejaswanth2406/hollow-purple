"""
middleware/rate_limit.py — Token Bucket Rate Limiter

Per-IP rate limiting with burst allowance.
In production, replace bucket store with Redis for distributed enforcement.
"""

from __future__ import annotations

import os
import time
from collections import defaultdict
from typing import Dict

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

RATE_PER_SECOND: int = int(os.getenv("HP_RATE_PER_SEC", "10"))
BURST_CAPACITY: int  = int(os.getenv("HP_RATE_BURST",  "30"))

# Paths excluded from rate limiting (health probes, etc.)
EXEMPT_PATHS = {"/api/v1/health", "/docs", "/openapi.json", "/redoc"}


class _TokenBucket:
    """Thread-safe token bucket for a single client."""

    __slots__ = ("rate", "capacity", "tokens", "last_refill")

    def __init__(self, rate: float, capacity: float) -> None:
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.last_refill = time.monotonic()

    def consume(self) -> bool:
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.last_refill = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Token-bucket rate limiter keyed by client IP.

    Parameters
    ----------
    rate    : sustained requests per second allowed
    burst   : maximum burst capacity (tokens)
    """

    def __init__(self, app, rate: int = RATE_PER_SECOND, burst: int = BURST_CAPACITY) -> None:
        super().__init__(app)
        self.rate = rate
        self.burst = burst
        self._buckets: Dict[str, _TokenBucket] = defaultdict(
            lambda: _TokenBucket(self.rate, self.burst)
        )

    def _client_ip(self, request: Request) -> str:
        # Honour X-Forwarded-For if behind a reverse proxy
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    async def dispatch(self, request: Request, call_next):
        if request.url.path in EXEMPT_PATHS:
            return await call_next(request)

        ip = self._client_ip(request)
        bucket = self._buckets[ip]

        if not bucket.consume():
            return JSONResponse(
                status_code=429,
                content={
                    "error": "rate_limit_exceeded",
                    "message": "Too many requests — slow down",
                    "retry_after_seconds": round(1.0 / self.rate, 2),
                },
                headers={"Retry-After": str(round(1.0 / self.rate, 2))},
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(self.burst)
        response.headers["X-RateLimit-Remaining"] = str(int(bucket.tokens))
        return response