"""
middleware/attack_detection.py — Heuristic Attack Detection

Detects API abuse patterns in real-time:
  - Endpoint scanning      (many distinct paths from same IP)
  - Brute-force auth       (repeated 401 responses)
  - Burst probing          (extreme short-window request volume)
  - Replay hammering       (repeated /replay/verify in short window)

Blocks detected abusers with 403 and emits a security alert.
In production, integrate with MAHORAGHA.telemetry.emit_alert().
"""

from __future__ import annotations

import time
import logging
from collections import defaultdict, deque
from typing import Deque, Dict, Set

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

logger = logging.getLogger("hollowpurple.security.attack_detection")

# Tuning constants
BURST_WINDOW_SEC   = 10      # rolling window for burst detection
BURST_THRESHOLD    = 60      # requests in window before flagging
SCAN_WINDOW_SEC    = 30      # window for endpoint-scan detection
SCAN_PATH_LIMIT    = 20      # distinct paths before flagging
AUTH_FAIL_WINDOW   = 60      # window for brute-force detection
AUTH_FAIL_LIMIT    = 10      # 401s in window before flagging
REPLAY_WINDOW_SEC  = 30
REPLAY_BURST_LIMIT = 15


class _SlidingWindow:
    """Tracks event timestamps in a rolling time window."""

    def __init__(self, window_sec: float) -> None:
        self._window = window_sec
        self._events: Deque[float] = deque()

    def record(self) -> int:
        now = time.monotonic()
        self._events.append(now)
        cutoff = now - self._window
        while self._events and self._events[0] < cutoff:
            self._events.popleft()
        return len(self._events)

    def count(self) -> int:
        cutoff = time.monotonic() - self._window
        while self._events and self._events[0] < cutoff:
            self._events.popleft()
        return len(self._events)


class _IpState:
    """All per-IP counters."""

    def __init__(self) -> None:
        self.burst        = _SlidingWindow(BURST_WINDOW_SEC)
        self.auth_fails   = _SlidingWindow(AUTH_FAIL_WINDOW)
        self.replay_burst = _SlidingWindow(REPLAY_WINDOW_SEC)
        self.scan_paths:  Set[str]  = set()
        self.scan_reset:  float     = time.monotonic()

    def seen_path(self, path: str) -> int:
        now = time.monotonic()
        if now - self.scan_reset > SCAN_WINDOW_SEC:
            self.scan_paths.clear()
            self.scan_reset = now
        self.scan_paths.add(path)
        return len(self.scan_paths)


class AttackDetectionMiddleware(BaseHTTPMiddleware):
    """
    Stateful heuristic middleware for detecting API abuse.

    Detection logic runs BEFORE the actual route handler so that
    malicious requests never reach the engine.
    """

    def __init__(self, app) -> None:
        super().__init__(app)
        self._state: Dict[str, _IpState] = defaultdict(_IpState)

    def _get_ip(self, request: Request) -> str:
        fwd = request.headers.get("X-Forwarded-For", "")
        if fwd:
            return fwd.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    def _block(self, ip: str, reason: str) -> JSONResponse:
        logger.warning("attack_blocked", extra={"client_ip": ip, "reason": reason})
        # -----------------------------------------------------------------
        # Mahoragha hook:
        # from MAHORAGHA.telemetry import emit_alert
        # emit_alert("api_attack_blocked", {"ip": ip, "reason": reason})
        # -----------------------------------------------------------------
        return JSONResponse(
            status_code=403,
            content={"error": "suspicious_activity", "message": reason},
        )

    async def dispatch(self, request: Request, call_next) -> Response:
        ip = self._get_ip(request)
        state = self._state[ip]
        path  = request.url.path

        # 1. Burst detection
        if state.burst.record() > BURST_THRESHOLD:
            return self._block(ip, "Burst rate exceeded — potential DDoS or scrape")

        # 2. Endpoint scan detection
        if state.seen_path(path) > SCAN_PATH_LIMIT:
            return self._block(ip, "Endpoint scanning detected")

        # 3. Replay hammering
        if "/replay" in path and state.replay_burst.record() > REPLAY_BURST_LIMIT:
            return self._block(ip, "Replay verification abuse detected")

        response: Response = await call_next(request)

        # 4. Brute-force auth (post-response)
        if response.status_code == 401:
            if state.auth_fails.record() > AUTH_FAIL_LIMIT:
                logger.warning(
                    "brute_force_detected",
                    extra={"client_ip": ip, "fail_count": state.auth_fails.count()},
                )

        return response