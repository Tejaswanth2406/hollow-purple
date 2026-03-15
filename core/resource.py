"""
resource.py — Hollow Purple Core Layer
========================================
Resource lifecycle management with a validated, deterministic state machine.

Supported states and transitions:
  CREATED   → ACTIVE | DELETED
  ACTIVE    → SUSPENDED | ARCHIVED | DELETED
  SUSPENDED → ACTIVE | ARCHIVED | DELETED
  ARCHIVED  → DELETED
  DELETED   → (terminal)

Author: Hollow Purple Infrastructure Team
Version: 1.0.0
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from .constants import (
    EventType,
    ResourceState,
    VALID_TRANSITIONS,
    TIMESTAMP_FORMAT,
    MAX_RESOURCE_ID_LENGTH,
)
from .models import Event, EventMetadata, Resource

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _utcnow_iso() -> str:
    """Return current UTC time as ISO-8601 with microsecond precision."""
    return datetime.now(tz=timezone.utc).strftime(TIMESTAMP_FORMAT)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class InvalidStateTransitionError(Exception):
    """
    Raised when an attempted resource state transition is not permitted
    by the state machine.
    """

    def __init__(self, resource_id: str, from_state: str, to_state: str) -> None:
        super().__init__(
            f"Invalid transition for resource '{resource_id}': "
            f"'{from_state}' → '{to_state}' is not allowed."
        )
        self.resource_id = resource_id
        self.from_state = from_state
        self.to_state = to_state


class ResourceNotFoundError(Exception):
    """Raised when an operation targets a resource that does not exist."""

    def __init__(self, resource_id: str) -> None:
        super().__init__(f"Resource '{resource_id}' not found.")
        self.resource_id = resource_id


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_transition(from_state: str, to_state: str, resource_id: str) -> None:
    """
    Assert that a state transition is permitted by the state machine rules.

    Args:
        from_state: Current ResourceState value.
        to_state: Target ResourceState value.
        resource_id: Resource identifier (used in error messages only).

    Raises:
        InvalidStateTransitionError: If the transition is not allowed.
        ValueError: If either state is not a valid ResourceState.
    """
    # Validate enum membership
    try:
        ResourceState(from_state)
        ResourceState(to_state)
    except ValueError as exc:
        raise ValueError(f"Invalid state value: {exc}") from exc

    allowed: set[str] = VALID_TRANSITIONS.get(from_state, set())
    if to_state not in allowed:
        raise InvalidStateTransitionError(resource_id, from_state, to_state)


# ---------------------------------------------------------------------------
# Resource creation
# ---------------------------------------------------------------------------

def create_resource(
    owner_identity: str,
    resource_id: Optional[str] = None,
    attributes: Optional[dict[str, Any]] = None,
    created_at: Optional[str] = None,
) -> Resource:
    """
    Create a new Resource in the CREATED state.

    Args:
        owner_identity: Fingerprint of the identity that owns the resource.
        resource_id: Optional explicit ID. If not supplied, a UUIDv4 is generated.
        attributes: Optional arbitrary key-value data to attach to the resource.
        created_at: Override creation timestamp (default: utcnow).

    Returns:
        A new immutable Resource in the CREATED state.

    Raises:
        ValueError: If owner_identity is empty or resource_id exceeds max length.
    """
    if not owner_identity or not owner_identity.strip():
        raise ValueError("owner_identity must not be empty.")

    rid: str = resource_id or str(uuid.uuid4())
    if len(rid) > MAX_RESOURCE_ID_LENGTH:
        raise ValueError(
            f"resource_id exceeds maximum length of {MAX_RESOURCE_ID_LENGTH} chars."
        )

    now: str = created_at or _utcnow_iso()
    attrs: dict[str, Any] = attributes or {}

    resource = Resource(
        resource_id=rid,
        state=ResourceState.CREATED,
        created_at=now,
        updated_at=now,
        owner_identity=owner_identity.strip(),
        version=0,
        attributes=tuple(sorted(attrs.items())),
    )

    logger.info(
        "Resource created.",
        extra={"resource_id": rid, "owner": owner_identity, "state": ResourceState.CREATED},
    )
    return resource


# ---------------------------------------------------------------------------
# State transitions
# ---------------------------------------------------------------------------

def transition_state(
    resource: Resource,
    to_state: str,
    updated_at: Optional[str] = None,
) -> Resource:
    """
    Transition a resource to a new state, returning an updated immutable copy.

    Args:
        resource: The current Resource snapshot.
        to_state: Target state (must be a valid ResourceState).
        updated_at: Override update timestamp (default: utcnow).

    Returns:
        A new Resource with the updated state and incremented version.

    Raises:
        InvalidStateTransitionError: If the transition is not permitted.
        ValueError: If to_state is not a valid ResourceState.
    """
    validate_transition(resource.state, to_state, resource.resource_id)

    updated = resource.with_state(to_state, updated_at)

    logger.info(
        "Resource state transitioned.",
        extra={
            "resource_id": resource.resource_id,
            "from_state": resource.state,
            "to_state": to_state,
            "version": updated.version,
        },
    )
    return updated


# ---------------------------------------------------------------------------
# Event application
# ---------------------------------------------------------------------------

def apply_event(resource: Resource, event: Event) -> Resource:
    """
    Apply a domain event to a resource, advancing its state accordingly.

    Only events that carry explicit state-change semantics cause transitions.
    Unrecognized event types are logged as warnings and leave state unchanged.

    Args:
        resource: The current Resource snapshot.
        event: The Event to apply.

    Returns:
        Updated (or unchanged) Resource snapshot.

    Raises:
        InvalidStateTransitionError: If the event triggers an illegal transition.
    """
    _EVENT_STATE_MAP: dict[str, str] = {
        EventType.RESOURCE_ACTIVATED:  ResourceState.ACTIVE,
        EventType.RESOURCE_SUSPENDED:  ResourceState.SUSPENDED,
        EventType.RESOURCE_ARCHIVED:   ResourceState.ARCHIVED,
        EventType.RESOURCE_DELETED:    ResourceState.DELETED,
    }

    target_state: Optional[str] = _EVENT_STATE_MAP.get(event.event_type)

    if target_state is None:
        logger.debug(
            "Event type has no state mapping; resource unchanged.",
            extra={"event_type": event.event_type, "resource_id": resource.resource_id},
        )
        return resource

    if target_state == resource.state:
        logger.debug(
            "Resource already in target state; no-op.",
            extra={"resource_id": resource.resource_id, "state": resource.state},
        )
        return resource

    return transition_state(resource, target_state, updated_at=event.timestamp)


# ---------------------------------------------------------------------------
# Resource registry (in-memory, for replay)
# ---------------------------------------------------------------------------

class ResourceRegistry:
    """
    Thread-safe in-memory registry of resource snapshots.

    Intended for use during event replay. This class is NOT a persistent store —
    it holds the reconstructed state derived from replaying the event log.

    Usage:
        registry = ResourceRegistry()
        registry.upsert(resource)
        current = registry.get("resource-id")
    """

    def __init__(self) -> None:
        import threading
        self._store: dict[str, Resource] = {}
        self._lock: threading.RLock = threading.RLock()

    def upsert(self, resource: Resource) -> None:
        """
        Insert or replace a resource snapshot.

        Thread-safe. A newer version always overwrites an older one.

        Args:
            resource: The Resource snapshot to store.
        """
        with self._lock:
            existing = self._store.get(resource.resource_id)
            if existing is not None and existing.version >= resource.version:
                logger.warning(
                    "Skipping upsert: incoming version is not newer.",
                    extra={
                        "resource_id": resource.resource_id,
                        "existing_version": existing.version,
                        "incoming_version": resource.version,
                    },
                )
                return
            self._store[resource.resource_id] = resource

    def get(self, resource_id: str) -> Resource:
        """
        Retrieve a resource by ID.

        Args:
            resource_id: The resource identifier to look up.

        Returns:
            The stored Resource snapshot.

        Raises:
            ResourceNotFoundError: If the resource is not in the registry.
        """
        with self._lock:
            resource = self._store.get(resource_id)
        if resource is None:
            raise ResourceNotFoundError(resource_id)
        return resource

    def all(self) -> list[Resource]:
        """Return all stored resources as a sorted list (by resource_id)."""
        with self._lock:
            return sorted(self._store.values(), key=lambda r: r.resource_id)

    def snapshot(self) -> dict[str, dict]:
        """
        Return a plain-dict snapshot of all resources for checkpointing.

        Returns:
            Mapping of resource_id → resource.to_dict().
        """
        with self._lock:
            return {rid: r.to_dict() for rid, r in self._store.items()}

    def load_snapshot(self, snapshot: dict[str, dict]) -> None:
        """
        Restore registry state from a checkpoint snapshot.

        Args:
            snapshot: Mapping of resource_id → resource dict.
        """
        with self._lock:
            self._store = {
                rid: Resource.from_dict(data) for rid, data in snapshot.items()
            }
        logger.info(
            "ResourceRegistry restored from snapshot.",
            extra={"resource_count": len(self._store)},
        )

    def clear(self) -> None:
        """Clear all resources from the registry (test use)."""
        with self._lock:
            self._store.clear()