"""
engine/replay_engine.py — Hollow Purple Engine Layer
======================================================
ReplayEngine: deterministic state-reconstruction engine for Hollow Purple.

Given the same event log, ReplayEngine always produces identical state.
It is the verification backbone of the platform — no state is trusted unless
it can be derived from a verified event log.

Reconstruction scope per replay:
  • identity_state_map     — Actor identity records keyed by actor_identity string
  • resource_state_map     — Resource snapshots keyed by resource_id
  • baseline_state_map     — Serialized identity baselines keyed by identity_id

Integrity guarantees:
  • Hash-chain verification before any state-mutating replay begins
  • Replay halts immediately on chain break in STRICT mode
  • Checkpoint state hashes are verified against reconstructed state

Author: Hollow Purple Infrastructure Team
Version: 1.0.0
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterator, Optional

from ..core.constants import (
    GENESIS_HASH,
    HASH_ALGORITHM,
    HASH_ENCODING,
    TIMESTAMP_FORMAT,
    EventType,
    ReplayMode,
    ResourceState,
)
from ..core.event_log import EventLog, IntegrityReport, IntegrityViolation
from ..core.models import Event, ReplayCheckpoint, Resource
from ..core.resource import (
    ResourceRegistry,
    apply_event as resource_apply_event,
    create_resource,
    InvalidStateTransitionError,
)

# Baseline engine type alias (avoid hard import cycle; resolved at runtime)
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .baseline import BaselineRuntimeEngine

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Timestamp helpers
# ---------------------------------------------------------------------------

def _utcnow_iso() -> str:
    return datetime.now(tz=timezone.utc).strftime(TIMESTAMP_FORMAT)


def _hash_state(state: dict[str, Any], algorithm: str = HASH_ALGORITHM) -> str:
    """
    Compute a deterministic hash over an arbitrary state dictionary.

    Args:
        state: Plain-dict representation of system state.
        algorithm: Hash algorithm name.

    Returns:
        64-char hex digest.
    """
    serialized = json.dumps(
        state, sort_keys=True, separators=(",", ":"), default=str
    )
    h = hashlib.new(algorithm)
    h.update(serialized.encode(HASH_ENCODING))
    return h.hexdigest()


# ---------------------------------------------------------------------------
# State containers
# ---------------------------------------------------------------------------

@dataclass
class ReconstructedState:
    """
    Mutable container for system state accumulated during replay.

    This object is deliberately mutable during replay and is frozen into
    a ReplaySnapshot once replay completes.

    Attributes:
        identity_state_map:  actor_identity → dict of identity facts derived
                             from events (e.g., first_seen, event_count, types_seen).
        resource_state_map:  resource_id → Resource snapshot.
        baseline_state_map:  identity_id → serialized baseline dict (populated
                             by BaselineRuntimeEngine if injected).
        last_sequence:       Sequence number of the last applied event.
        last_event_hash:     current_hash of the last applied event.
        event_count:         Total events applied.
    """

    identity_state_map: dict[str, dict[str, Any]] = field(default_factory=dict)
    resource_state_map: dict[str, dict[str, Any]] = field(default_factory=dict)
    baseline_state_map: dict[str, dict[str, Any]] = field(default_factory=dict)
    last_sequence: int = -1
    last_event_hash: str = GENESIS_HASH
    event_count: int = 0

    def state_hash(self, algorithm: str = HASH_ALGORITHM) -> str:
        """
        Compute a deterministic hash over the full reconstructed state.

        Used for checkpoint verification.
        """
        composite = {
            "identity_state_map": self.identity_state_map,
            "resource_state_map": self.resource_state_map,
            "baseline_state_map": self.baseline_state_map,
            "last_sequence": self.last_sequence,
            "last_event_hash": self.last_event_hash,
        }
        return _hash_state(composite, algorithm)

    def to_dict(self) -> dict[str, Any]:
        """Serialize current state to a plain dictionary."""
        return {
            "identity_state_map": self.identity_state_map,
            "resource_state_map": self.resource_state_map,
            "baseline_state_map": self.baseline_state_map,
            "last_sequence": self.last_sequence,
            "last_event_hash": self.last_event_hash,
            "event_count": self.event_count,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ReconstructedState":
        """Restore state from a serialized dictionary (e.g., loaded checkpoint)."""
        obj = cls()
        obj.identity_state_map = dict(data.get("identity_state_map", {}))
        obj.resource_state_map = dict(data.get("resource_state_map", {}))
        obj.baseline_state_map = dict(data.get("baseline_state_map", {}))
        obj.last_sequence = int(data.get("last_sequence", -1))
        obj.last_event_hash = str(data.get("last_event_hash", GENESIS_HASH))
        obj.event_count = int(data.get("event_count", 0))
        return obj


# ---------------------------------------------------------------------------
# Replay result
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ReplaySnapshot:
    """
    Immutable snapshot of state produced by a completed replay run.

    Fields:
        identity_state_map:   Reconstructed identity records.
        resource_state_map:   Reconstructed resource states.
        baseline_state_map:   Reconstructed identity baseline dicts.
        last_sequence:        Sequence of the final applied event.
        last_event_hash:      Hash of the final applied event.
        event_count:          Total events applied.
        state_hash:           Deterministic hash of the full state.
        integrity_report:     Result of the hash-chain verification.
        replayed_at:          ISO-8601 UTC timestamp of completion.
    """

    identity_state_map: dict[str, dict[str, Any]]
    resource_state_map: dict[str, dict[str, Any]]
    baseline_state_map: dict[str, dict[str, Any]]
    last_sequence: int
    last_event_hash: str
    event_count: int
    state_hash: str
    integrity_report: IntegrityReport
    replayed_at: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize snapshot to a plain dictionary."""
        return {
            "identity_state_map": self.identity_state_map,
            "resource_state_map": self.resource_state_map,
            "baseline_state_map": self.baseline_state_map,
            "last_sequence": self.last_sequence,
            "last_event_hash": self.last_event_hash,
            "event_count": self.event_count,
            "state_hash": self.state_hash,
            "replayed_at": self.replayed_at,
        }


# ---------------------------------------------------------------------------
# Engine checkpoint
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EngineCheckpoint:
    """
    Checkpoint capturing the full engine state at a specific event sequence.

    Distinct from core.models.ReplayCheckpoint which captures only resources.
    EngineCheckpoint includes baseline and identity state as well.

    Fields:
        checkpoint_id:   Unique identifier.
        sequence:        Last event sequence included.
        last_event_hash: current_hash of the last event at checkpoint time.
        state_hash:      Deterministic hash of full reconstructed state.
        state_snapshot:  Full serialized state for fast recovery.
        created_at:      ISO-8601 UTC creation timestamp.
        node_id:         Node that created this checkpoint.
    """

    checkpoint_id: str
    sequence: int
    last_event_hash: str
    state_hash: str
    state_snapshot: dict[str, Any]
    created_at: str
    node_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "checkpoint_id": self.checkpoint_id,
            "sequence": self.sequence,
            "last_event_hash": self.last_event_hash,
            "state_hash": self.state_hash,
            "state_snapshot": self.state_snapshot,
            "created_at": self.created_at,
            "node_id": self.node_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EngineCheckpoint":
        return cls(
            checkpoint_id=data["checkpoint_id"],
            sequence=data["sequence"],
            last_event_hash=data["last_event_hash"],
            state_hash=data["state_hash"],
            state_snapshot=dict(data.get("state_snapshot", {})),
            created_at=data["created_at"],
            node_id=data["node_id"],
        )

    def content_hash(self, algorithm: str = HASH_ALGORITHM) -> str:
        """Deterministic hash of this checkpoint's content."""
        return _hash_state(self.to_dict(), algorithm)


# ---------------------------------------------------------------------------
# ReplayEngine
# ---------------------------------------------------------------------------

class ReplayEngine:
    """
    Deterministic state-reconstruction engine for Hollow Purple.

    Replays events from the EventLog and rebuilds identity, resource, and
    baseline state. All replays of the same log produce identical state.

    Design:
      • EventLog is the only source of truth.
      • Events are always applied in ascending sequence order.
      • Integrity is verified before any state-mutating replay.
      • STRICT mode halts immediately on any integrity violation.
      • An optional BaselineRuntimeEngine rebuilds behavioral baselines.

    Args:
        event_log:         The authoritative EventLog to replay from.
        replay_mode:       STRICT (halt on violation) or LENIENT (continue).
        baseline_engine:   Optional engine for rebuilding identity baselines.
        node_id:           Logical node identifier for audit logging.
        algorithm:         Hash algorithm for state hashing.
    """

    def __init__(
        self,
        event_log: EventLog,
        replay_mode: ReplayMode = ReplayMode.STRICT,
        baseline_engine: Optional["BaselineRuntimeEngine"] = None,
        node_id: str = "node-default",
        algorithm: str = HASH_ALGORITHM,
    ) -> None:
        if event_log is None:
            raise ValueError("event_log must not be None.")
        if not node_id or not node_id.strip():
            raise ValueError("node_id must not be empty.")

        self._event_log: EventLog = event_log
        self._replay_mode: ReplayMode = replay_mode
        self._baseline_engine: Optional["BaselineRuntimeEngine"] = baseline_engine
        self._node_id: str = node_id.strip()
        self._algorithm: str = algorithm

        # Mutable replay state — reset at the start of each full replay
        self._state: ReconstructedState = ReconstructedState()

        # In-memory resource registry (parallel to resource_state_map, typed)
        self._resource_registry: ResourceRegistry = ResourceRegistry()

        logger.info(
            "ReplayEngine initialised.",
            extra={
                "node_id": self._node_id,
                "replay_mode": self._replay_mode.value,
                "has_baseline_engine": self._baseline_engine is not None,
            },
        )

    # ------------------------------------------------------------------
    # Primary replay API
    # ------------------------------------------------------------------

    def replay_all_events(self) -> ReplaySnapshot:
        """
        Load all events from the event log and rebuild full system state.

        Integrity is verified before replay begins. In STRICT mode, any
        violation causes an immediate halt and returns an empty snapshot.

        Returns:
            ReplaySnapshot representing the fully reconstructed state.
        """
        logger.info("Starting full event replay.", extra={"node_id": self._node_id})

        integrity_report = self._event_log.verify_log_integrity()

        if not integrity_report.is_clean and self._replay_mode == ReplayMode.STRICT:
            logger.error(
                "Replay halted: integrity violations in STRICT mode.",
                extra={"violations": len(integrity_report.violations)},
            )
            return self._empty_snapshot(integrity_report)

        self._reset_state()

        for event in self._event_log.load_events(start_sequence=0):
            self.apply_event(event)

        if self._baseline_engine is not None:
            self._rebuild_baselines_from_state()

        return self._build_snapshot(integrity_report)

    def replay_until(self, event_id: str) -> ReplaySnapshot:
        """
        Replay events from the beginning up to and including a specific event.

        Useful for forensic reconstruction and historical debugging.

        Args:
            event_id: The event_id at which to stop (inclusive).

        Returns:
            ReplaySnapshot at the point of the specified event.

        Raises:
            ValueError: If event_id is empty.
            LookupError: If event_id is not found in the log.
        """
        if not event_id or not event_id.strip():
            raise ValueError("event_id must not be empty.")

        logger.info(
            "Starting targeted replay.",
            extra={"target_event_id": event_id},
        )

        integrity_report = self._event_log.verify_log_integrity()
        if not integrity_report.is_clean and self._replay_mode == ReplayMode.STRICT:
            return self._empty_snapshot(integrity_report)

        self._reset_state()
        found: bool = False

        for event in self._event_log.load_events(start_sequence=0):
            self.apply_event(event)
            if event.event_id == event_id.strip():
                found = True
                break

        if not found:
            raise LookupError(
                f"Event '{event_id}' was not found in the event log."
            )

        if self._baseline_engine is not None:
            self._rebuild_baselines_from_state()

        return self._build_snapshot(integrity_report)

    def replay_range(
        self,
        start_event_id: str,
        end_event_id: str,
    ) -> ReplaySnapshot:
        """
        Replay a contiguous range of events between two event IDs (inclusive).

        State prior to start_event_id is NOT reconstructed; this method
        produces a partial state delta useful for range inspection.
        Use replay_until(end_event_id) for full state at end_event_id.

        Args:
            start_event_id: event_id of the first event to apply.
            end_event_id:   event_id of the last event to apply (inclusive).

        Returns:
            ReplaySnapshot of events in [start_event_id, end_event_id].

        Raises:
            ValueError: If either ID is empty or start comes after end.
            LookupError: If either event_id is not found in the log.
        """
        if not start_event_id or not start_event_id.strip():
            raise ValueError("start_event_id must not be empty.")
        if not end_event_id or not end_event_id.strip():
            raise ValueError("end_event_id must not be empty.")

        logger.info(
            "Starting range replay.",
            extra={"start": start_event_id, "end": end_event_id},
        )

        integrity_report = self._event_log.verify_log_integrity()
        if not integrity_report.is_clean and self._replay_mode == ReplayMode.STRICT:
            return self._empty_snapshot(integrity_report)

        self._reset_state()

        in_range: bool = False
        found_start: bool = False
        found_end: bool = False

        for event in self._event_log.load_events(start_sequence=0):
            if event.event_id == start_event_id.strip():
                in_range = True
                found_start = True

            if in_range:
                self.apply_event(event)

            if event.event_id == end_event_id.strip():
                found_end = True
                break

        if not found_start:
            raise LookupError(f"start_event_id '{start_event_id}' not found in log.")
        if not found_end:
            raise LookupError(f"end_event_id '{end_event_id}' not found in log.")

        return self._build_snapshot(integrity_report)

    def apply_event(self, event: Event) -> None:
        """
        Apply a single event to the in-progress reconstructed state.

        Updates:
          • identity_state_map
          • resource_state_map (via ResourceRegistry)
          • baseline_state_map (if event triggers a baseline-relevant type)

        Args:
            event: The Event to apply. Must not be None.

        Raises:
            ValueError: If event is None.
        """
        if event is None:
            raise ValueError("event must not be None.")

        # Update identity state
        self._apply_identity_state(event)

        # Update resource state
        self._apply_resource_state(event)

        # Advance sequence tracking
        self._state.last_sequence = event.sequence
        self._state.last_event_hash = event.current_hash
        self._state.event_count += 1

        # Sync resource_state_map from registry
        self._state.resource_state_map = self._resource_registry.snapshot()

        logger.debug(
            "Event applied.",
            extra={
                "event_id": event.event_id,
                "event_type": event.event_type,
                "sequence": event.sequence,
            },
        )

    def rebuild_baselines(self) -> None:
        """
        Recompute all identity baselines deterministically from accumulated events.

        This method is a no-op if no BaselineRuntimeEngine was injected.
        It derives baselines from identity_state_map rather than re-streaming
        the event log, so it is suitable for post-replay baseline refresh.
        """
        if self._baseline_engine is None:
            logger.debug("No baseline engine injected; skipping baseline rebuild.")
            return
        self._rebuild_baselines_from_state()

    def verify_replay_integrity(
        self, snapshot: ReplaySnapshot, checkpoint: EngineCheckpoint
    ) -> bool:
        """
        Verify that a replay snapshot matches a previously persisted checkpoint.

        Args:
            snapshot:    The ReplaySnapshot produced by a replay run.
            checkpoint:  The EngineCheckpoint to compare against.

        Returns:
            True if state hashes match.

        Raises:
            ValueError: If the state hashes do not match.
        """
        if snapshot.state_hash != checkpoint.state_hash:
            raise ValueError(
                f"Replay integrity check failed for checkpoint "
                f"'{checkpoint.checkpoint_id}'.\n"
                f"  Checkpoint state_hash: {checkpoint.state_hash}\n"
                f"  Snapshot   state_hash: {snapshot.state_hash}"
            )
        logger.info(
            "Replay integrity verified.",
            extra={"checkpoint_id": checkpoint.checkpoint_id},
        )
        return True

    # ------------------------------------------------------------------
    # Checkpoint API
    # ------------------------------------------------------------------

    def create_checkpoint(self) -> EngineCheckpoint:
        """
        Capture the current reconstructed state as a checkpoint.

        Returns:
            EngineCheckpoint that can be used for fast recovery.
        """
        snapshot_dict = self._state.to_dict()
        sh = self._state.state_hash(self._algorithm)
        cid = str(
            uuid.uuid5(
                uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8"),
                f"{self._node_id}:{self._state.last_sequence}:{sh}",
            )
        )
        checkpoint = EngineCheckpoint(
            checkpoint_id=cid,
            sequence=self._state.last_sequence,
            last_event_hash=self._state.last_event_hash,
            state_hash=sh,
            state_snapshot=snapshot_dict,
            created_at=_utcnow_iso(),
            node_id=self._node_id,
        )
        logger.info(
            "Engine checkpoint created.",
            extra={
                "checkpoint_id": cid,
                "sequence": self._state.last_sequence,
                "state_hash": sh[:16],
            },
        )
        return checkpoint

    def load_checkpoint(self, checkpoint: EngineCheckpoint) -> None:
        """
        Restore engine state from a previously created checkpoint.

        After loading, incremental replay can continue from
        checkpoint.sequence + 1 without replaying earlier events.

        Args:
            checkpoint: EngineCheckpoint to restore from.

        Raises:
            ValueError: If checkpoint is None.
        """
        if checkpoint is None:
            raise ValueError("checkpoint must not be None.")

        self._state = ReconstructedState.from_dict(checkpoint.state_snapshot)
        self._resource_registry = ResourceRegistry()
        self._resource_registry.load_snapshot(self._state.resource_state_map)

        logger.info(
            "Engine checkpoint loaded.",
            extra={
                "checkpoint_id": checkpoint.checkpoint_id,
                "sequence": checkpoint.sequence,
            },
        )

    def verify_checkpoint(self, checkpoint: EngineCheckpoint) -> bool:
        """
        Verify a checkpoint's state_hash against a full replay from sequence 0.

        This is expensive for large logs — use for audit/forensics only.

        Args:
            checkpoint: The EngineCheckpoint to verify.

        Returns:
            True if the checkpoint is consistent with the event log.

        Raises:
            ValueError: If state hashes do not match.
        """
        logger.info(
            "Verifying engine checkpoint.",
            extra={"checkpoint_id": checkpoint.checkpoint_id},
        )

        # Temporarily save current state so this call is non-destructive
        saved_state = ReconstructedState.from_dict(self._state.to_dict())

        self._reset_state()
        for event in self._event_log.load_events(start_sequence=0):
            if event.sequence > checkpoint.sequence:
                break
            self.apply_event(event)

        actual_hash = self._state.state_hash(self._algorithm)

        # Restore original state
        self._state = saved_state
        self._resource_registry = ResourceRegistry()
        self._resource_registry.load_snapshot(self._state.resource_state_map)

        if actual_hash != checkpoint.state_hash:
            raise ValueError(
                f"Checkpoint '{checkpoint.checkpoint_id}' verification failed.\n"
                f"  Expected: {checkpoint.state_hash}\n"
                f"  Actual:   {actual_hash}"
            )

        logger.info(
            "Checkpoint verified successfully.",
            extra={"checkpoint_id": checkpoint.checkpoint_id},
        )
        return True

    # ------------------------------------------------------------------
    # State accessors
    # ------------------------------------------------------------------

    @property
    def current_state(self) -> ReconstructedState:
        """Return the mutable in-progress reconstructed state (read-only use)."""
        return self._state

    @property
    def resource_registry(self) -> ResourceRegistry:
        """Return the typed resource registry built during replay."""
        return self._resource_registry

    # ------------------------------------------------------------------
    # Internal state-application helpers
    # ------------------------------------------------------------------

    def _apply_identity_state(self, event: Event) -> None:
        """
        Update identity_state_map from an event.

        Tracks: first_seen, last_seen, event_count, event_types_seen,
        resource_ids_seen for each actor identity.
        """
        iid: str = event.actor_identity
        entry: dict[str, Any] = self._state.identity_state_map.get(iid, {})

        if not entry:
            entry = {
                "identity_id": iid,
                "first_seen": event.timestamp,
                "last_seen": event.timestamp,
                "event_count": 0,
                "event_types_seen": [],
                "resource_ids_seen": [],
            }

        entry["last_seen"] = event.timestamp
        entry["event_count"] = entry.get("event_count", 0) + 1

        types_seen: list[str] = entry.get("event_types_seen", [])
        if event.event_type not in types_seen:
            types_seen.append(event.event_type)
            types_seen.sort()
        entry["event_types_seen"] = types_seen

        resources_seen: list[str] = entry.get("resource_ids_seen", [])
        if event.resource_id not in resources_seen:
            resources_seen.append(event.resource_id)
            resources_seen.sort()
        entry["resource_ids_seen"] = resources_seen

        self._state.identity_state_map[iid] = entry

    def _apply_resource_state(self, event: Event) -> None:
        """
        Update the ResourceRegistry from a resource lifecycle event.

        Non-resource events are silently ignored by the registry.
        """
        try:
            if event.event_type == EventType.RESOURCE_CREATED:
                resource = create_resource(
                    owner_identity=event.actor_identity,
                    resource_id=event.resource_id,
                    attributes=event.payload_dict,
                    created_at=event.timestamp,
                )
                self._resource_registry.upsert(resource)

            elif event.event_type in (
                EventType.RESOURCE_ACTIVATED,
                EventType.RESOURCE_SUSPENDED,
                EventType.RESOURCE_ARCHIVED,
                EventType.RESOURCE_DELETED,
            ):
                try:
                    current = self._resource_registry.get(event.resource_id)
                    updated = resource_apply_event(current, event)
                    self._resource_registry.upsert(updated)
                except Exception as exc:
                    logger.warning(
                        "Could not apply resource event: %s",
                        exc,
                        extra={
                            "event_id": event.event_id,
                            "resource_id": event.resource_id,
                        },
                    )
        except Exception as exc:
            logger.error(
                "Unexpected error in resource state application: %s",
                exc,
                extra={"event_id": event.event_id},
            )

    def _rebuild_baselines_from_state(self) -> None:
        """
        Trigger baseline rebuild for every identity seen during replay.

        Requires a BaselineRuntimeEngine to be injected. Rebuilds are
        driven from the identity_state_map, so no additional log scan
        is needed.
        """
        if self._baseline_engine is None:
            return

        identity_ids = sorted(self._state.identity_state_map.keys())
        logger.info(
            "Rebuilding baselines for %d identities.", len(identity_ids)
        )

        for iid in identity_ids:
            baseline = self._baseline_engine.get_identity_baseline(iid)
            if baseline is not None:
                self._state.baseline_state_map[iid] = baseline.to_dict()

    def _reset_state(self) -> None:
        """Reset all mutable state to a clean initial condition."""
        self._state = ReconstructedState()
        self._resource_registry = ResourceRegistry()

    # ------------------------------------------------------------------
    # Snapshot builders
    # ------------------------------------------------------------------

    def _build_snapshot(self, integrity_report: IntegrityReport) -> ReplaySnapshot:
        """Freeze the current mutable state into an immutable ReplaySnapshot."""
        sh = self._state.state_hash(self._algorithm)
        return ReplaySnapshot(
            identity_state_map=dict(self._state.identity_state_map),
            resource_state_map=dict(self._state.resource_state_map),
            baseline_state_map=dict(self._state.baseline_state_map),
            last_sequence=self._state.last_sequence,
            last_event_hash=self._state.last_event_hash,
            event_count=self._state.event_count,
            state_hash=sh,
            integrity_report=integrity_report,
            replayed_at=_utcnow_iso(),
        )

    def _empty_snapshot(self, integrity_report: IntegrityReport) -> ReplaySnapshot:
        """Return a zero-state snapshot (used when replay is halted)."""
        return ReplaySnapshot(
            identity_state_map={},
            resource_state_map={},
            baseline_state_map={},
            last_sequence=-1,
            last_event_hash=GENESIS_HASH,
            event_count=0,
            state_hash=GENESIS_HASH,
            integrity_report=integrity_report,
            replayed_at=_utcnow_iso(),
        )