"""
__init__.py — Hollow Purple Core Layer
========================================
Public surface of the hollow_purple.core package.

Import from here for stable, versioned access to all core types and functions.
Internal submodule structure is not part of the public API.

Author: Hollow Purple Infrastructure Team
Version: 1.0.0
"""

from .constants import (
    SYSTEM_NAME,
    SYSTEM_VERSION,
    CORE_LAYER_VERSION,
    GENESIS_HASH,
    HASH_ALGORITHM,
    EventType,
    ResourceState,
    ReplayMode,
    VerificationStrictness,
    VALID_TRANSITIONS,
)

from .config import ConfigLoader, HollowPurpleConfig

from .models import (
    Event,
    EventMetadata,
    Identity,
    Resource,
    ReplayCheckpoint,
)

from .identity import (
    create_identity,
    derive_deterministic_identity,
    validate_identity,
    identity_fingerprint,
    identity_from_dict,
)

from .resource import (
    create_resource,
    transition_state,
    validate_transition,
    apply_event,
    ResourceRegistry,
    InvalidStateTransitionError,
    ResourceNotFoundError,
)

from .event_log import (
    EventLog,
    IntegrityReport,
    IntegrityViolation,
    ReplayResult,
)

__all__ = [
    # Constants
    "SYSTEM_NAME",
    "SYSTEM_VERSION",
    "CORE_LAYER_VERSION",
    "GENESIS_HASH",
    "HASH_ALGORITHM",
    "EventType",
    "ResourceState",
    "ReplayMode",
    "VerificationStrictness",
    "VALID_TRANSITIONS",
    # Config
    "ConfigLoader",
    "HollowPurpleConfig",
    # Models
    "Event",
    "EventMetadata",
    "Identity",
    "Resource",
    "ReplayCheckpoint",
    # Identity
    "create_identity",
    "derive_deterministic_identity",
    "validate_identity",
    "identity_fingerprint",
    "identity_from_dict",
    # Resource
    "create_resource",
    "transition_state",
    "validate_transition",
    "apply_event",
    "ResourceRegistry",
    "InvalidStateTransitionError",
    "ResourceNotFoundError",
    # Event log
    "EventLog",
    "IntegrityReport",
    "IntegrityViolation",
    "ReplayResult",
]