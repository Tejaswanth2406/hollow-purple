"""
middleware/request_logger.py — Forensic Request Logger

Emits a structured log record for every HTTP request.
Fields are SIEM-compatible and map to common log schemas (ECS / CEF).
"""

from __future__ import annotations

import time
import uuid
import logging
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger("hollowpurple.api.requests")

# Paths to skip logging (noise reduction)
SILENT_PATHS = {"/api/v1/health", "/docs", "/openapi.json", "/redoc", "/favicon.ico"}


class RequestLoggerMiddleware(BaseHTTPMiddleware):
    """
    Logs every API request with:
      - request_id  (UUID injected into response headers)
      - method / path / status
      - latency_ms
      - client IP
      - user-agent
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.url.path in SILENT_PATHS:
            return await call_next(request)

        request_id = str(uuid.uuid4())
        start = time.monotonic()

        # Inject request_id so downstream handlers can correlate logs
        request.state.request_id = request_id

        response: Response = await call_next(request)

        latency_ms = round((time.monotonic() - start) * 1000, 2)
        response.headers["X-Request-ID"] = request_id

        logger.info(
            "api_request",
            extra={
                "request_id":  request_id,
                "method":      request.method,
                "path":        request.url.path,
                "query":       str(request.url.query),
                "status":      response.status_code,
                "latency_ms":  latency_ms,
                "client_ip":   _get_ip(request),
                "user_agent":  request.headers.get("User-Agent", ""),
                "content_type": request.headers.get("Content-Type", ""),
            },
        )

        return response


def _get_ip(request: Request) -> str:
    fwd = request.headers.get("X-Forwarded-For")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"