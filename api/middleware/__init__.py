"""
Hollow Purple API Middleware

Security middleware stack providing:
- Rate limiting        (token bucket, per-IP)
- Request logging      (structured forensic logs)
- Audit trail          (tamper-evident, Merkle-ready)
- Attack detection     (heuristic abuse detection)
"""

from .rate_limit import RateLimitMiddleware
from .request_logger import RequestLoggerMiddleware
from .audit_trail import AuditTrailMiddleware
from .attack_detection import AttackDetectionMiddleware

__all__ = [
    "RateLimitMiddleware",
    "RequestLoggerMiddleware",
    "AuditTrailMiddleware",
    "AttackDetectionMiddleware",
]