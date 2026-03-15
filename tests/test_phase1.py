"""
test_phase1.py
==============
Phase 1 — Core Infrastructure Tests
=====================================
Tests for the fundamental building blocks of the Hollow Purple event-sourced
platform:

  • Identity creation and validation
  • Resource lifecycle transitions
  • Event creation and serialization
  • Event log append operations
  • Hash chain integrity
  • Log tamper detection

These tests mock the core/ layer that wraps the policy_engine primitives,
exercising the contracts that all higher-level phases depend upon.

All tests are fully deterministic: no random state, fixed timestamps.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# Minimal in-process implementations of core/ layer
# (These stand in for the actual core/ package; the contracts they define
#  are identical to what Phase 2–5 tests rely on.)
# ---------------------------------------------------------------------------


# ── constants ────────────────────────────────────────────────────────────────

class ResourceState(str, Enum):
    ACTIVE   = "active"
    INACTIVE = "inactive"
    LOCKED   = "locked"
    DELETED  = "deleted"


VALID_TRANSITIONS: dict[ResourceState, set[ResourceState]] = {
    ResourceState.ACTIVE:   {ResourceState.INACTIVE, ResourceState.LOCKED, ResourceState.DELETED},
    ResourceState.INACTIVE: {ResourceState.ACTIVE, ResourceState.DELETED},
    ResourceState.LOCKED:   {ResourceState.ACTIVE, ResourceState.DELETED},
    ResourceState.DELETED:  set(),
}


# ── identity ─────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Identity:
    identity_id: str
    display_name: str
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    attributes: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.identity_id or not isinstance(self.identity_id, str):
            raise ValueError("identity_id must be a non-empty string.")
        if not self.display_name:
            raise ValueError("display_name must be non-empty.")

    def identity_hash(self) -> str:
        payload = json.dumps(
            {"identity_id": self.identity_id, "display_name": self.display_name},
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode()).hexdigest()


# ── resource ─────────────────────────────────────────────────────────────────

@dataclass
class Resource:
    resource_id: str
    resource_type: str
    owner_id: str
    state: ResourceState = ResourceState.ACTIVE
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    state_history: list[tuple[ResourceState, str]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.resource_id:
            raise ValueError("resource_id must be non-empty.")
        if not self.resource_type:
            raise ValueError("resource_type must be non-empty.")
        if not self.owner_id:
            raise ValueError("owner_id must be non-empty.")

    def transition(self, new_state: ResourceState) -> None:
        allowed = VALID_TRANSITIONS[self.state]
        if new_state not in allowed:
            raise ValueError(
                f"Invalid transition {self.state} → {new_state}. "
                f"Allowed: {allowed}"
            )
        self.state_history.append((self.state, datetime.now(timezone.utc).isoformat()))
        self.state = new_state

    def is_accessible(self) -> bool:
        return self.state in {ResourceState.ACTIVE}


# ── event ─────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Event:
    event_id: str
    identity_id: str
    action: str
    resource_id: str
    timestamp: str                        # ISO-8601
    payload: dict[str, Any] = field(default_factory=dict)
    previous_hash: str = ""               # hash of preceding event

    def __post_init__(self) -> None:
        for attr in ("event_id", "identity_id", "action", "resource_id"):
            if not getattr(self, attr):
                raise ValueError(f"{attr} must be non-empty.")

    def content_hash(self) -> str:
        doc = {
            "event_id":      self.event_id,
            "identity_id":   self.identity_id,
            "action":        self.action,
            "resource_id":   self.resource_id,
            "timestamp":     self.timestamp,
            "payload":       self.payload,
            "previous_hash": self.previous_hash,
        }
        return hashlib.sha256(
            json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id":      self.event_id,
            "identity_id":   self.identity_id,
            "action":        self.action,
            "resource_id":   self.resource_id,
            "timestamp":     self.timestamp,
            "payload":       self.payload,
            "previous_hash": self.previous_hash,
            "content_hash":  self.content_hash(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Event":
        stored_hash = data.pop("content_hash", None)
        evt = cls(
            event_id=data["event_id"],
            identity_id=data["identity_id"],
            action=data["action"],
            resource_id=data["resource_id"],
            timestamp=data["timestamp"],
            payload=data.get("payload", {}),
            previous_hash=data.get("previous_hash", ""),
        )
        if stored_hash and evt.content_hash() != stored_hash:
            raise ValueError(
                f"Event {evt.event_id}: content_hash mismatch — "
                f"stored={stored_hash!r}, computed={evt.content_hash()!r}"
            )
        return evt


# ── event log ────────────────────────────────────────────────────────────────

class TamperingError(Exception):
    """Raised when log integrity verification fails."""


class EventLog:
    """Append-only, hash-chained event log."""

    def __init__(self) -> None:
        self._events: list[Event] = []
        self._hashes: list[str] = []
        self._lock = threading.RLock()

    def append(self, event: Event) -> Event:
        """
        Append an event.  The event's ``previous_hash`` must match the last
        stored hash; if it does not, a ``ValueError`` is raised.
        """
        with self._lock:
            expected_prev = self._hashes[-1] if self._hashes else ""
            if event.previous_hash != expected_prev:
                raise ValueError(
                    f"Chain broken at event {event.event_id}: "
                    f"expected previous_hash={expected_prev!r}, "
                    f"got {event.previous_hash!r}"
                )
            self._events.append(event)
            self._hashes.append(event.content_hash())
        return event

    def verify(self) -> bool:
        """Re-compute every hash and confirm the chain is intact."""
        with self._lock:
            events = list(self._events)
            stored_hashes = list(self._hashes)

        prev = ""
        for i, evt in enumerate(events):
            if evt.previous_hash != prev:
                raise TamperingError(
                    f"Chain break at position {i} (event {evt.event_id}): "
                    f"expected previous_hash={prev!r}, got {evt.previous_hash!r}"
                )
            computed = evt.content_hash()
            if computed != stored_hashes[i]:
                raise TamperingError(
                    f"Hash mismatch at position {i} (event {evt.event_id}): "
                    f"stored={stored_hashes[i]!r}, computed={computed!r}"
                )
            prev = computed
        return True

    def __len__(self) -> int:
        with self._lock:
            return len(self._events)

    def __getitem__(self, idx: int) -> Event:
        with self._lock:
            return self._events[idx]

    def head_hash(self) -> str:
        with self._lock:
            return self._hashes[-1] if self._hashes else ""

    def as_list(self) -> list[Event]:
        with self._lock:
            return list(self._events)


# ── helpers ───────────────────────────────────────────────────────────────────

_EPOCH = datetime(2024, 1, 15, 9, 0, 0, tzinfo=timezone.utc)

def _ts(offset_seconds: int = 0) -> str:
    from datetime import timedelta
    return (_EPOCH + timedelta(seconds=offset_seconds)).isoformat()


def _make_event(
    event_id: str,
    identity_id: str = "alice",
    action: str = "READ",
    resource_id: str = "doc-1",
    offset: int = 0,
    previous_hash: str = "",
    payload: dict | None = None,
) -> Event:
    return Event(
        event_id=event_id,
        identity_id=identity_id,
        action=action,
        resource_id=resource_id,
        timestamp=_ts(offset),
        previous_hash=previous_hash,
        payload=payload or {},
    )


def _build_chain(n: int, identity_id: str = "alice") -> tuple[EventLog, list[Event]]:
    log = EventLog()
    events: list[Event] = []
    prev_hash = ""
    for i in range(n):
        evt = _make_event(
            event_id=f"evt-{i:04d}",
            identity_id=identity_id,
            action="READ" if i % 2 == 0 else "WRITE",
            resource_id=f"res-{i % 3}",
            offset=i * 60,
            previous_hash=prev_hash,
        )
        log.append(evt)
        prev_hash = evt.content_hash()
        events.append(evt)
    return log, events


# ===========================================================================
# FIXTURES
# ===========================================================================

@pytest.fixture
def alice() -> Identity:
    return Identity(identity_id="alice", display_name="Alice Wonderland")


@pytest.fixture
def bob() -> Identity:
    return Identity(identity_id="bob", display_name="Bob Builder")


@pytest.fixture
def active_resource() -> Resource:
    return Resource(
        resource_id="res-001",
        resource_type="document",
        owner_id="alice",
    )


@pytest.fixture
def empty_log() -> EventLog:
    return EventLog()


@pytest.fixture
def populated_log() -> tuple[EventLog, list[Event]]:
    return _build_chain(10)


# ===========================================================================
# IDENTITY TESTS
# ===========================================================================

class TestIdentityCreation:

    def test_valid_identity_creates_successfully(self, alice: Identity) -> None:
        assert alice.identity_id == "alice"
        assert alice.display_name == "Alice Wonderland"

    def test_identity_is_immutable(self, alice: Identity) -> None:
        with pytest.raises((AttributeError, TypeError)):
            alice.identity_id = "hacked"  # type: ignore[misc]

    def test_empty_identity_id_raises(self) -> None:
        with pytest.raises(ValueError, match="identity_id"):
            Identity(identity_id="", display_name="Empty")

    def test_empty_display_name_raises(self) -> None:
        with pytest.raises(ValueError, match="display_name"):
            Identity(identity_id="x", display_name="")

    def test_identity_hash_is_deterministic(self, alice: Identity) -> None:
        h1 = alice.identity_hash()
        h2 = alice.identity_hash()
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex digest

    def test_different_identities_have_different_hashes(
        self, alice: Identity, bob: Identity
    ) -> None:
        assert alice.identity_hash() != bob.identity_hash()

    def test_identity_hash_changes_with_display_name(self) -> None:
        a = Identity(identity_id="uid", display_name="Name A")
        b = Identity(identity_id="uid", display_name="Name B")
        assert a.identity_hash() != b.identity_hash()

    def test_identity_attributes_stored(self) -> None:
        ident = Identity(
            identity_id="svc-1",
            display_name="Service Account",
            attributes={"env": "prod", "team": "platform"},
        )
        assert ident.attributes["env"] == "prod"

    def test_multiple_identities_are_independent(self, alice: Identity, bob: Identity) -> None:
        assert alice.identity_id != bob.identity_id
        assert alice.display_name != bob.display_name


# ===========================================================================
# RESOURCE LIFECYCLE TESTS
# ===========================================================================

class TestResourceLifecycle:

    def test_resource_created_in_active_state(self, active_resource: Resource) -> None:
        assert active_resource.state == ResourceState.ACTIVE

    def test_active_resource_is_accessible(self, active_resource: Resource) -> None:
        assert active_resource.is_accessible() is True

    def test_transition_active_to_inactive(self, active_resource: Resource) -> None:
        active_resource.transition(ResourceState.INACTIVE)
        assert active_resource.state == ResourceState.INACTIVE

    def test_transition_active_to_locked(self, active_resource: Resource) -> None:
        active_resource.transition(ResourceState.LOCKED)
        assert active_resource.state == ResourceState.LOCKED

    def test_transition_active_to_deleted(self, active_resource: Resource) -> None:
        active_resource.transition(ResourceState.DELETED)
        assert active_resource.state == ResourceState.DELETED

    def test_transition_inactive_to_active(self, active_resource: Resource) -> None:
        active_resource.transition(ResourceState.INACTIVE)
        active_resource.transition(ResourceState.ACTIVE)
        assert active_resource.state == ResourceState.ACTIVE

    def test_transition_locked_to_active(self, active_resource: Resource) -> None:
        active_resource.transition(ResourceState.LOCKED)
        active_resource.transition(ResourceState.ACTIVE)
        assert active_resource.state == ResourceState.ACTIVE

    def test_invalid_transition_raises(self, active_resource: Resource) -> None:
        active_resource.transition(ResourceState.DELETED)
        with pytest.raises(ValueError, match="Invalid transition"):
            active_resource.transition(ResourceState.ACTIVE)

    def test_deleted_resource_has_no_valid_transitions(self, active_resource: Resource) -> None:
        active_resource.transition(ResourceState.DELETED)
        for state in ResourceState:
            if state != ResourceState.DELETED:
                with pytest.raises(ValueError):
                    active_resource.transition(state)

    def test_state_history_is_recorded(self, active_resource: Resource) -> None:
        active_resource.transition(ResourceState.INACTIVE)
        active_resource.transition(ResourceState.ACTIVE)
        assert len(active_resource.state_history) == 2
        assert active_resource.state_history[0][0] == ResourceState.ACTIVE
        assert active_resource.state_history[1][0] == ResourceState.INACTIVE

    def test_inactive_resource_not_accessible(self, active_resource: Resource) -> None:
        active_resource.transition(ResourceState.INACTIVE)
        assert active_resource.is_accessible() is False

    def test_locked_resource_not_accessible(self, active_resource: Resource) -> None:
        active_resource.transition(ResourceState.LOCKED)
        assert active_resource.is_accessible() is False

    def test_empty_owner_id_raises(self) -> None:
        with pytest.raises(ValueError, match="owner_id"):
            Resource(resource_id="r1", resource_type="doc", owner_id="")


# ===========================================================================
# EVENT CREATION & SERIALIZATION
# ===========================================================================

class TestEventCreation:

    def test_valid_event_creates_successfully(self) -> None:
        evt = _make_event("e-001")
        assert evt.event_id == "e-001"
        assert evt.action == "READ"

    def test_event_is_immutable(self) -> None:
        evt = _make_event("e-001")
        with pytest.raises((AttributeError, TypeError)):
            evt.action = "WRITE"  # type: ignore[misc]

    def test_empty_event_id_raises(self) -> None:
        with pytest.raises(ValueError, match="event_id"):
            Event(
                event_id="", identity_id="alice",
                action="READ", resource_id="r1",
                timestamp=_ts(),
            )

    def test_content_hash_is_deterministic(self) -> None:
        evt = _make_event("e-001", offset=0)
        assert evt.content_hash() == evt.content_hash()

    def test_content_hash_changes_with_action(self) -> None:
        e1 = _make_event("e-001", action="READ")
        e2 = _make_event("e-001", action="WRITE")
        assert e1.content_hash() != e2.content_hash()

    def test_content_hash_is_hex_64_chars(self) -> None:
        evt = _make_event("e-001")
        h = evt.content_hash()
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_event_serializes_to_dict(self) -> None:
        evt = _make_event("e-001", payload={"level": "info"})
        d = evt.to_dict()
        assert d["event_id"] == "e-001"
        assert d["payload"] == {"level": "info"}
        assert "content_hash" in d

    def test_event_round_trips_via_dict(self) -> None:
        original = _make_event("e-001", action="DELETE", payload={"reason": "expired"})
        d = original.to_dict()
        restored = Event.from_dict(d)
        assert restored.event_id == original.event_id
        assert restored.action == original.action
        assert restored.payload == original.payload
        assert restored.content_hash() == original.content_hash()

    def test_tampered_dict_raises_on_load(self) -> None:
        evt = _make_event("e-001")
        d = evt.to_dict()
        d["action"] = "ADMIN_OVERRIDE"          # tamper
        with pytest.raises(ValueError, match="content_hash mismatch"):
            Event.from_dict(d)

    def test_previous_hash_included_in_content_hash(self) -> None:
        e1 = _make_event("e-001")
        e2 = _make_event("e-001", previous_hash=e1.content_hash())
        assert e1.content_hash() != e2.content_hash()


# ===========================================================================
# EVENT LOG OPERATIONS
# ===========================================================================

class TestEventLogAppend:

    def test_append_single_event(self, empty_log: EventLog) -> None:
        evt = _make_event("e-001", previous_hash="")
        empty_log.append(evt)
        assert len(empty_log) == 1

    def test_append_chain_of_events(self) -> None:
        log, events = _build_chain(5)
        assert len(log) == 5

    def test_head_hash_matches_last_event(self) -> None:
        log, events = _build_chain(5)
        assert log.head_hash() == events[-1].content_hash()

    def test_wrong_previous_hash_raises(self, empty_log: EventLog) -> None:
        evt = _make_event("e-001", previous_hash="bad-hash")
        with pytest.raises(ValueError, match="Chain broken"):
            empty_log.append(evt)

    def test_append_after_non_empty_log_requires_correct_prev_hash(self) -> None:
        log = EventLog()
        e1 = _make_event("e-001", previous_hash="")
        log.append(e1)
        # Correct second event
        e2 = _make_event("e-002", previous_hash=e1.content_hash(), offset=60)
        log.append(e2)
        assert len(log) == 2

    def test_incorrect_chain_link_raises(self) -> None:
        log = EventLog()
        e1 = _make_event("e-001", previous_hash="")
        log.append(e1)
        # e2 links to wrong hash
        e2 = _make_event("e-002", previous_hash="wrong-hash", offset=60)
        with pytest.raises(ValueError, match="Chain broken"):
            log.append(e2)

    def test_as_list_returns_copy(self) -> None:
        log, _ = _build_chain(3)
        copy1 = log.as_list()
        copy2 = log.as_list()
        assert copy1 == copy2
        assert copy1 is not copy2


# ===========================================================================
# HASH CHAIN INTEGRITY
# ===========================================================================

class TestHashChainIntegrity:

    def test_verify_passes_on_intact_chain(self) -> None:
        log, _ = _build_chain(20)
        assert log.verify() is True

    def test_verify_passes_on_empty_log(self, empty_log: EventLog) -> None:
        assert empty_log.verify() is True

    def test_verify_single_event(self) -> None:
        log = EventLog()
        log.append(_make_event("e-001", previous_hash=""))
        assert log.verify() is True

    def test_each_event_references_predecessor(self) -> None:
        log, events = _build_chain(10)
        for i in range(1, len(events)):
            assert events[i].previous_hash == events[i - 1].content_hash()

    def test_chain_hashes_are_all_unique(self) -> None:
        log, events = _build_chain(10)
        hashes = [e.content_hash() for e in events]
        assert len(set(hashes)) == len(hashes)

    def test_first_event_has_empty_previous_hash(self) -> None:
        log, events = _build_chain(5)
        assert events[0].previous_hash == ""

    def test_chain_length_matches_event_count(self) -> None:
        log, events = _build_chain(15)
        assert len(log) == 15

    def test_identical_event_streams_produce_identical_head_hashes(self) -> None:
        log1, _ = _build_chain(10, identity_id="charlie")
        log2, _ = _build_chain(10, identity_id="charlie")
        assert log1.head_hash() == log2.head_hash()


# ===========================================================================
# TAMPER DETECTION
# ===========================================================================

class TestTamperDetection:

    def test_mutating_event_in_place_is_detected(self) -> None:
        """
        Simulate a storage-layer tampering by replacing a stored event with a
        modified copy while keeping the hash list stale.
        """
        log, events = _build_chain(5)

        # Inject a forged event at position 2 that has different action
        original = log._events[2]
        forged = Event(
            event_id=original.event_id,
            identity_id=original.identity_id,
            action="ADMIN_PRIVILEGE_ESCALATION",
            resource_id=original.resource_id,
            timestamp=original.timestamp,
            previous_hash=original.previous_hash,
        )
        # Directly mutate internal list (simulates storage compromise)
        log._events[2] = forged

        with pytest.raises(TamperingError):
            log.verify()

    def test_reordering_events_is_detected(self) -> None:
        log, _ = _build_chain(5)
        # Swap positions 1 and 2
        log._events[1], log._events[2] = log._events[2], log._events[1]
        with pytest.raises(TamperingError):
            log.verify()

    def test_deleting_middle_event_is_detected(self) -> None:
        log, _ = _build_chain(5)
        del log._events[2]
        with pytest.raises(TamperingError):
            log.verify()

    def test_inserting_extra_event_is_detected(self) -> None:
        log, events = _build_chain(5)
        # Insert a rogue event (with wrong previous_hash) in the middle
        rogue = Event(
            event_id="rogue",
            identity_id="attacker",
            action="STEAL",
            resource_id="crown-jewels",
            timestamp=_ts(200),
            previous_hash="fake",
        )
        log._events.insert(2, rogue)
        with pytest.raises(TamperingError):
            log.verify()

    def test_modifying_payload_is_detected(self) -> None:
        log = EventLog()
        e1 = _make_event("e-001", previous_hash="", payload={"amount": 100})
        log.append(e1)
        e2 = _make_event("e-002", previous_hash=e1.content_hash(), offset=60)
        log.append(e2)

        # Directly swap stored event to one with modified payload
        forged = Event(
            event_id=e1.event_id,
            identity_id=e1.identity_id,
            action=e1.action,
            resource_id=e1.resource_id,
            timestamp=e1.timestamp,
            previous_hash=e1.previous_hash,
            payload={"amount": 999_999},  # tampered
        )
        log._events[0] = forged
        with pytest.raises(TamperingError):
            log.verify()


# ===========================================================================
# PERFORMANCE: large-batch append
# ===========================================================================

class TestCorePerformance:

    def test_append_1000_events_completes_quickly(self) -> None:
        start = time.perf_counter()
        log, _ = _build_chain(1000)
        elapsed = time.perf_counter() - start
        assert len(log) == 1000
        assert elapsed < 5.0, f"Append 1000 events took {elapsed:.2f}s (limit 5s)"

    def test_verify_1000_event_chain_completes_quickly(self) -> None:
        log, _ = _build_chain(1000)
        start = time.perf_counter()
        assert log.verify() is True
        elapsed = time.perf_counter() - start
        assert elapsed < 5.0, f"Verify 1000 events took {elapsed:.2f}s (limit 5s)"

    def test_concurrent_appends_are_rejected_gracefully(self) -> None:
        """Two threads trying to append conflicting events: only one should win."""
        log = EventLog()
        first = _make_event("e-001", previous_hash="")
        log.append(first)

        errors: list[Exception] = []
        successes: list[bool] = []

        def try_append(event: Event) -> None:
            try:
                log.append(event)
                successes.append(True)
            except ValueError as exc:
                errors.append(exc)

        e_a = _make_event("e-002a", action="READ",  previous_hash=first.content_hash(), offset=60)
        e_b = _make_event("e-002b", action="WRITE", previous_hash=first.content_hash(), offset=61)

        t1 = threading.Thread(target=try_append, args=(e_a,))
        t2 = threading.Thread(target=try_append, args=(e_b,))
        t1.start(); t2.start()
        t1.join(); t2.join()

        # Exactly one must have succeeded (the second sees a wrong prev hash)
        assert len(successes) + len(errors) == 2
        assert len(successes) == 1