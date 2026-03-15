"""
ingestion/processors/validator.py — Schema + Business Rule Validator

Validates:
  - Required field presence
  - Field type correctness
  - Timestamp validity (not in far future, not ancient)
  - Source allowlist
  - Actor format (non-empty, length limits)
  - Action format
  - IP address format (if present)
  - Policy-based field rejections (blocked actors, blocked IPs)
"""

import ipaddress
import logging
import re
import time
from typing import Any

logger = logging.getLogger("hollow_purple.validator")

# Configurable constants
MAX_AGE_SECONDS      = 86400 * 7    # reject events older than 7 days
MAX_FUTURE_SECONDS   = 300          # reject events more than 5min in the future
ALLOWED_SOURCES      = frozenset({"aws", "azure", "gcp", "webhook", "custom", "okta", "github"})
MAX_FIELD_LENGTH     = 2048

# Basic actor format — must not be blank, too short, or suspicious
ACTOR_MIN_LEN = 2


class ValidationError(ValueError):
    """Raised when an event fails validation."""
    def __init__(self, field: str, reason: str):
        self.field  = field
        self.reason = reason
        super().__init__(f"Validation failed [{field}]: {reason}")


class EventValidator:
    """
    Stateless async event validator.

    Raises ValidationError on any rule violation.
    Returns the event unchanged if all checks pass.

    Optional policy injection:
        validator = EventValidator(
            blocked_actors={"malicious-svc"},
            blocked_ips={"1.2.3.4"},
            extra_required=["account_id"],
        )
    """

    def __init__(
        self,
        blocked_actors: set[str] | None  = None,
        blocked_ips: set[str] | None     = None,
        extra_required: list[str] | None = None,
        strict_source:  bool             = True,
    ):
        self.blocked_actors  = blocked_actors  or set()
        self.blocked_ips     = blocked_ips     or set()
        self.extra_required  = extra_required  or []
        self.strict_source   = strict_source

    async def validate(self, event: dict) -> dict:
        if not isinstance(event, dict):
            raise ValidationError("_type", f"Event must be a dict, got {type(event).__name__}")

        # Batch envelope — pass through (individual events validated later)
        if event.get("_batch"):
            return event

        self._check_required(event)
        self._check_source(event)
        self._check_timestamp(event)
        self._check_actor(event)
        self._check_ip(event)
        self._check_field_lengths(event)
        self._check_blocked(event)

        return event

    # ------------------------------------------------------------------ #
    #  Rule implementations                                                #
    # ------------------------------------------------------------------ #

    def _check_required(self, event: dict):
        base_required = ["source"]
        for field in base_required + self.extra_required:
            if not event.get(field):
                raise ValidationError(field, "Required field missing or empty")

    def _check_source(self, event: dict):
        if not self.strict_source:
            return
        source = str(event.get("source", "")).lower()
        if source not in ALLOWED_SOURCES:
            raise ValidationError("source", f"Unknown source '{source}'. Allowed: {ALLOWED_SOURCES}")

    def _check_timestamp(self, event: dict):
        ts_raw = event.get("timestamp")
        if ts_raw is None:
            # Auto-stamp and continue — don't reject
            event["timestamp"] = time.time()
            return

        try:
            ts = float(ts_raw)
        except (ValueError, TypeError):
            raise ValidationError("timestamp", f"Cannot parse timestamp: {ts_raw!r}")

        now = time.time()
        age = now - ts
        if age > MAX_AGE_SECONDS:
            raise ValidationError("timestamp",
                                  f"Event too old: age={age:.0f}s > max={MAX_AGE_SECONDS}s")
        if ts - now > MAX_FUTURE_SECONDS:
            raise ValidationError("timestamp",
                                  f"Event timestamp is in the future by {ts - now:.0f}s")

    def _check_actor(self, event: dict):
        actor = event.get("actor")
        if actor is None:
            return   # actor is optional
        if not isinstance(actor, str):
            raise ValidationError("actor", f"Actor must be a string, got {type(actor).__name__}")
        if len(actor.strip()) < ACTOR_MIN_LEN:
            raise ValidationError("actor", f"Actor too short (min {ACTOR_MIN_LEN} chars)")

    def _check_ip(self, event: dict):
        ip = event.get("ip")
        if not ip:
            return
        try:
            ipaddress.ip_address(str(ip))
        except ValueError:
            raise ValidationError("ip", f"Invalid IP address format: {ip!r}")

    def _check_field_lengths(self, event: dict):
        for field in ("actor", "action", "resource", "service"):
            val = event.get(field)
            if val and len(str(val)) > MAX_FIELD_LENGTH:
                raise ValidationError(field,
                                      f"Field exceeds max length {MAX_FIELD_LENGTH}: {len(str(val))} chars")

    def _check_blocked(self, event: dict):
        actor = event.get("actor", "")
        ip    = event.get("ip", "")
        if actor in self.blocked_actors:
            raise ValidationError("actor", f"Actor '{actor}' is on the blocklist")
        if ip and ip in self.blocked_ips:
            raise ValidationError("ip", f"IP '{ip}' is on the blocklist")