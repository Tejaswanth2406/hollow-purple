"""
core/constants.py — Hollow Purple Core Layer
=============================================
Central definitions for all enumerations, string constants, and
system-wide configuration primitives.

All other modules in core/ and the wider platform import from here.
Never import from higher-level packages in this file — it must remain
dependency-free within the package tree.

Author: Hollow Purple Infrastructure Team
Version: 1.0.0
"""

from __future__ import annotations

from enum import Enum

# ---------------------------------------------------------------------------
# System identity
# ---------------------------------------------------------------------------

SYSTEM_NAME: str = "HOLLOW_PURPLE"
SYSTEM_VERSION: str = "1.0.0"
CORE_LAYER_VERSION: str = "1.0.0"

# ---------------------------------------------------------------------------
# Cryptographic constants
# ---------------------------------------------------------------------------

HASH_ALGORITHM: str = "sha256"
HASH_ENCODING: str = "utf-8"

#: The genesis sentinel — the previous_hash of the very first event in any log.
GENESIS_HASH: str = "0" * 64

# ---------------------------------------------------------------------------
# Timestamp format
# ---------------------------------------------------------------------------

#: ISO-8601 format with microsecond precision, always UTC.
TIMESTAMP_FORMAT: str = "%Y-%m-%dT%H:%M:%S.%f+00:00"

# ---------------------------------------------------------------------------
# Identity constants
# ---------------------------------------------------------------------------

#: Stable UUID5 namespace for deterministic identity derivation.
IDENTITY_NAMESPACE: str = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"

#: Default prefix applied to generated identity IDs.
IDENTITY_PREFIX: str = "identity"

#: Maximum allowed length for identity_id strings.
MAX_IDENTITY_ID_LENGTH: int = 128

# ---------------------------------------------------------------------------
# Resource constants
# ---------------------------------------------------------------------------

MAX_RESOURCE_ID_LENGTH: int = 256

# ---------------------------------------------------------------------------
# Logging / observability defaults
# ---------------------------------------------------------------------------

LOG_LEVEL_DEFAULT: str = "INFO"
DEFAULT_LOG_DIR: str = "logs"
MAX_LOG_FILE_SIZE_BYTES: int = 50 * 1024 * 1024   # 50 MB
LOG_ROTATION_BACKUP_COUNT: int = 5

# ---------------------------------------------------------------------------
# Event type enumeration
# ---------------------------------------------------------------------------


class EventType(str, Enum):
    """Canonical event types recognised by the Hollow Purple event log."""

    # Resource lifecycle
    RESOURCE_CREATED    = "resource.created"
    RESOURCE_ACTIVATED  = "resource.activated"
    RESOURCE_SUSPENDED  = "resource.suspended"
    RESOURCE_ARCHIVED   = "resource.archived"
    RESOURCE_DELETED    = "resource.deleted"

    # Identity lifecycle
    IDENTITY_CREATED    = "identity.created"
    IDENTITY_UPDATED    = "identity.updated"
    IDENTITY_DELETED    = "identity.deleted"

    # Access events
    ACCESS_GRANTED      = "access.granted"
    ACCESS_REVOKED      = "access.revoked"
    ACCESS_ATTEMPTED    = "access.attempted"
    ACCESS_DENIED       = "access.denied"

    # Security / detection events
    ANOMALY_DETECTED    = "security.anomaly_detected"
    ALERT_RAISED        = "security.alert_raised"
    THREAT_MITIGATED    = "security.threat_mitigated"

    # Audit / system events
    AUDIT_LOG_WRITTEN   = "audit.log_written"
    CONFIG_CHANGED      = "system.config_changed"
    REPLAY_STARTED      = "system.replay_started"
    REPLAY_COMPLETED    = "system.replay_completed"


# ---------------------------------------------------------------------------
# Resource state enumeration
# ---------------------------------------------------------------------------


class ResourceState(str, Enum):
    """Valid states for any managed resource in the Hollow Purple platform."""

    CREATED   = "created"
    ACTIVE    = "active"
    SUSPENDED = "suspended"
    ARCHIVED  = "archived"
    DELETED   = "deleted"


# ---------------------------------------------------------------------------
# Valid state-machine transitions
# ---------------------------------------------------------------------------

#: Maps each ResourceState to the set of states it may transition into.
VALID_TRANSITIONS: dict[str, set[str]] = {
    ResourceState.CREATED:   {ResourceState.ACTIVE, ResourceState.DELETED},
    ResourceState.ACTIVE:    {ResourceState.SUSPENDED, ResourceState.ARCHIVED, ResourceState.DELETED},
    ResourceState.SUSPENDED: {ResourceState.ACTIVE, ResourceState.ARCHIVED, ResourceState.DELETED},
    ResourceState.ARCHIVED:  {ResourceState.DELETED},
    ResourceState.DELETED:   set(),
}

# ---------------------------------------------------------------------------
# Replay mode enumeration
# ---------------------------------------------------------------------------


class ReplayMode(str, Enum):
    """Controls how the event log is replayed during state reconstruction."""

    STRICT      = "strict"      # Abort on any integrity violation
    LENIENT     = "lenient"     # Log violations but continue replay
    DRY_RUN     = "dry_run"     # Replay without applying state changes


# ---------------------------------------------------------------------------
# Verification strictness enumeration
# ---------------------------------------------------------------------------


class VerificationStrictness(str, Enum):
    """Controls the strictness of hash-chain integrity verification."""

    STRICT  = "strict"   # Every hash in the chain must match
    RELAXED = "relaxed"  # Only spot-check a sample of hashes
    OFF     = "off"      # Skip verification entirely (testing only)


# ---------------------------------------------------------------------------
# Public surface
# ---------------------------------------------------------------------------

__all__ = [
    # System identity
    "SYSTEM_NAME",
    "SYSTEM_VERSION",
    "CORE_LAYER_VERSION",
    # Crypto
    "HASH_ALGORITHM",
    "HASH_ENCODING",
    "GENESIS_HASH",
    # Timestamps
    "TIMESTAMP_FORMAT",
    # Identity
    "IDENTITY_NAMESPACE",
    "IDENTITY_PREFIX",
    "MAX_IDENTITY_ID_LENGTH",
    # Resource
    "MAX_RESOURCE_ID_LENGTH",
    # Logging
    "LOG_LEVEL_DEFAULT",
    "DEFAULT_LOG_DIR",
    "MAX_LOG_FILE_SIZE_BYTES",
    "LOG_ROTATION_BACKUP_COUNT",
    # Enums
    "EventType",
    "ResourceState",
    "ReplayMode",
    "VerificationStrictness",
    "VALID_TRANSITIONS",
]
