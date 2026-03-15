"""
middleware/audit_trail.py — Tamper-Evident Audit Trail

Writes a structured audit record for every mutating API call.
Records are designed to feed into the Mahoragha Merkle log
(MAHORAGHA.phase3.merkle_log) for cryptographic tamper-evidence.

Each record contains:
  - ISO timestamp
  - endpoint + HTTP method
  - actor (extracted from JWT claim if present)
  - client IP
  - response status
  - SHA-256 content hash placeholder (populated by Merkle layer)
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Callable, Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

audit_logger = logging.getLogger("hollowpurple.audit")

# Only audit write operations
AUDITED_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Endpoints that must always be audited regardless of method
ALWAYS_AUDIT = {"/api/v1/auth/token"}


def _extract_actor(request: Request) -> str:
    """Best-effort actor extraction before full JWT decode."""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        # Extract sub claim without full verification (middleware runs pre-auth)
        try:
            import base64, json as _json
            parts = auth.split(".")
            if len(parts) == 3:
                padded = parts[1] + "=" * (-len(parts[1]) % 4)
                payload = _json.loads(base64.urlsafe_b64decode(padded))
                return payload.get("sub", "unknown")
        except Exception:
            pass
    api_key = request.headers.get("X-API-Key", "")
    if api_key:
        return f"api_key:{api_key[:8]}***"
    return "unauthenticated"


def _audit_hash(record: dict) -> str:
    """Deterministic SHA-256 over the canonical audit fields."""
    canonical = json.dumps(
        {k: record[k] for k in sorted(record) if k != "content_hash"},
        sort_keys=True,
        default=str,
    ).encode()
    return hashlib.sha256(canonical).hexdigest()


class AuditTrailMiddleware(BaseHTTPMiddleware):
    """
    Emits a tamper-evident audit record for write operations.

    Integration point:
        After logging, call MAHORAGHA.phase3.merkle_log.append(record)
        to anchor the record in the append-only Merkle tree.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        should_audit = (
            request.method in AUDITED_METHODS
            or request.url.path in ALWAYS_AUDIT
        )

        if not should_audit:
            return await call_next(request)

        response: Response = await call_next(request)

        request_id: Optional[str] = getattr(request.state, "request_id", None)

        record = {
            "timestamp":    datetime.now(tz=timezone.utc).isoformat(),
            "request_id":   request_id,
            "endpoint":     request.url.path,
            "method":       request.method,
            "actor":        _extract_actor(request),
            "actor_ip":     request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
                            or (request.client.host if request.client else "unknown"),
            "status":       response.status_code,
            "success":      200 <= response.status_code < 300,
        }
        record["content_hash"] = _audit_hash(record)

        audit_logger.info("api_audit_event", extra=record)

        # -----------------------------------------------------------------
        # Mahoragha hook — uncomment when merkle_log is available:
        # from MAHORAGHA.phase3.merkle_log import merkle_log
        # merkle_log.append(record)
        # -----------------------------------------------------------------

        return response