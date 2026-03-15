"""
ingestion/schemas/event_schema.py — Canonical Event Schema + Validator

Defines the full HOLLOW_PURPLE canonical event schema.
Provides both structural validation and type coercion.

Schema version: 2.0
"""

from __future__ import annotations
import time
from dataclasses import dataclass, field, asdict
from typing import Any


# ------------------------------------------------------------------ #
#  Field specifications                                               #
# ------------------------------------------------------------------ #

REQUIRED_FIELDS: list[str] = ["source"]

ALLOWED_SOURCES: frozenset[str] = frozenset({
    "aws", "azure", "gcp", "okta", "github", "webhook",
    "pagerduty", "custom", "internal",
})

ALLOWED_SEVERITIES: frozenset[str] = frozenset({
    "critical", "high", "medium", "low", "info",
})

ALLOWED_ACTOR_TYPES: frozenset[str] = frozenset({
    "user", "service_account", "role", "machine", "unknown",
})

MAX_FIELD_LENGTHS: dict[str, int] = {
    "actor":        512,
    "action":       256,
    "resource":     2048,
    "resource_type": 256,
    "service":      128,
    "region":       64,
    "account_id":   128,
    "event_id":     256,
}


# ------------------------------------------------------------------ #
#  Canonical Event Dataclass                                          #
# ------------------------------------------------------------------ #

@dataclass
class CanonicalEvent:
    """
    The normalized, validated event object that flows through
    HOLLOW_PURPLE's detection and storage pipeline.
    """
    # Identity
    event_id:      str   = field(default_factory=lambda: "")
    source:        str   = ""
    service:       str   = ""

    # Action
    action:        str   = ""
    actor:         str   = ""
    actor_type:    str   = "unknown"
    resource:      str   = ""
    resource_type: str   = ""

    # Network
    ip:            str   = ""
    region:        str   = ""
    account_id:    str   = ""

    # Timing
    timestamp:     float = field(default_factory=time.time)

    # Risk
    severity:      str   = "info"
    tags:          list  = field(default_factory=list)

    # Optional enrichment fields
    geo:           dict  = field(default_factory=dict)
    identity:      dict  = field(default_factory=dict)
    threat_intel:  dict  = field(default_factory=dict)
    resource_meta: dict  = field(default_factory=dict)
    session:       dict  = field(default_factory=dict)

    # Preserve original
    raw:           dict  = field(default_factory=dict)

    # Pipeline metadata
    enriched:      bool  = False
    enriched_at:   float = 0.0
    schema_version: str  = "2.0"

    def to_dict(self) -> dict:
        return asdict(self)


# ------------------------------------------------------------------ #
#  Schema validator                                                   #
# ------------------------------------------------------------------ #

class SchemaValidationError(ValueError):
    def __init__(self, field: str, message: str):
        self.field   = field
        self.message = message
        super().__init__(f"SchemaValidationError [{field}]: {message}")


class EventSchema:
    """
    Validates and coerces a raw dict into a schema-conformant event.

    Usage:
        EventSchema.validate(event_dict)          # raises on failure
        canonical = EventSchema.coerce(event_dict) # returns CanonicalEvent
    """

    @classmethod
    def validate(cls, event: dict) -> None:
        """Validate required fields, types, and allowed values. Raises SchemaValidationError."""
        if not isinstance(event, dict):
            raise SchemaValidationError("_root", f"Event must be dict, got {type(event).__name__}")

        # Required fields
        for f in REQUIRED_FIELDS:
            if not event.get(f):
                raise SchemaValidationError(f, "Required field missing or empty")

        # Source allowlist
        source = str(event.get("source", "")).lower()
        if source and source not in ALLOWED_SOURCES:
            raise SchemaValidationError(
                "source",
                f"'{source}' not in allowed sources: {sorted(ALLOWED_SOURCES)}"
            )

        # Severity allowlist
        severity = str(event.get("severity", "info")).lower()
        if severity not in ALLOWED_SEVERITIES:
            raise SchemaValidationError(
                "severity",
                f"'{severity}' not in allowed severities: {sorted(ALLOWED_SEVERITIES)}"
            )

        # Actor type allowlist
        actor_type = str(event.get("actor_type", "unknown")).lower()
        if actor_type not in ALLOWED_ACTOR_TYPES:
            raise SchemaValidationError(
                "actor_type",
                f"'{actor_type}' not in allowed actor types: {sorted(ALLOWED_ACTOR_TYPES)}"
            )

        # Timestamp must be numeric
        ts = event.get("timestamp")
        if ts is not None:
            try:
                float(ts)
            except (ValueError, TypeError):
                raise SchemaValidationError("timestamp", f"Must be numeric, got {ts!r}")

        # Field length limits
        for fname, max_len in MAX_FIELD_LENGTHS.items():
            val = event.get(fname)
            if val and len(str(val)) > max_len:
                raise SchemaValidationError(
                    fname,
                    f"Exceeds max length {max_len}: actual={len(str(val))}"
                )

    @classmethod
    def coerce(cls, event: dict) -> CanonicalEvent:
        """
        Validate and coerce a dict into a CanonicalEvent.
        Missing optional fields are filled with defaults.
        """
        cls.validate(event)
        return CanonicalEvent(
            event_id      = str(event.get("event_id", "")),
            source        = str(event.get("source", "")).lower(),
            service       = str(event.get("service", "")).lower(),
            action        = str(event.get("action", "")),
            actor         = str(event.get("actor", "")),
            actor_type    = str(event.get("actor_type", "unknown")).lower(),
            resource      = str(event.get("resource", "")),
            resource_type = str(event.get("resource_type", "")),
            ip            = str(event.get("ip", "")),
            region        = str(event.get("region", "")),
            account_id    = str(event.get("account_id", "")),
            timestamp     = float(event.get("timestamp") or time.time()),
            severity      = str(event.get("severity", "info")).lower(),
            tags          = list(event.get("tags", [])),
            geo           = dict(event.get("geo", {})),
            identity      = dict(event.get("identity", {})),
            threat_intel  = dict(event.get("threat_intel", {})),
            resource_meta = dict(event.get("resource_meta", {})),
            session       = dict(event.get("session", {})),
            raw           = dict(event.get("raw", {})),
            enriched      = bool(event.get("enriched", False)),
            enriched_at   = float(event.get("enriched_at", 0.0)),
        )

    @classmethod
    def required_fields(cls) -> list[str]:
        return REQUIRED_FIELDS

    @classmethod
    def schema_info(cls) -> dict:
        return {
            "version":            "2.0",
            "required_fields":    REQUIRED_FIELDS,
            "allowed_sources":    sorted(ALLOWED_SOURCES),
            "allowed_severities": sorted(ALLOWED_SEVERITIES),
            "allowed_actor_types": sorted(ALLOWED_ACTOR_TYPES),
            "max_field_lengths":  MAX_FIELD_LENGTHS,
        }