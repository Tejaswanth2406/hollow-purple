"""
event_log.py — Hollow Purple Core Layer
=========================================
The tamper-evident, append-only event log — the most critical component
of the Hollow Purple platform.

Architecture:
  • Each event is hashed with its content + previous event's hash (chain).
  • The log is stored as a .jsonl file (one JSON object per line).
  • Integrity verification walks the entire chain and flags any break.
  • Replay is fully deterministic: identical inputs always produce identical state.
  • Checkpoints allow replay to skip already-processed events.

Thread Safety:
  • All write operations are guarded by a reentrant lock.
  • Reads are safe to perform concurrently (append-only file).

Author: Hollow Purple Infrastructure Team
Version: 1.0.0
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Generator, Iterator, Optional

from .constants import (
    GENESIS_HASH,
    HASH_ALGORITHM,
    HASH_ENCODING,
    EventType,
    ResourceState,
    ReplayMode,
    TIMESTAMP_FORMAT,
)
from .models import Event, EventMetadata, ReplayCheckpoint, Resource
from .resource import (
    ResourceRegistry,
    apply_event,
    create_resource,
    transition_state,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Integrity result types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class IntegrityViolation:
    """
    Describes a single integrity failure detected during log verification.

    Fields:
        sequence: The event sequence number where the violation occurred.
        event_id: The event identifier (if known).
        reason: Human-readable description of the failure.
    """

    sequence: int
    event_id: str
    reason: str

    def __str__(self) -> str:
        return (
            f"[seq={self.sequence}] event_id={self.event_id} — {self.reason}"
        )


@dataclass(frozen=True)
class IntegrityReport:
    """
    Summary of a log integrity verification run.

    Fields:
        total_events: Number of events checked.
        violations: List of all detected violations (empty = clean).
        verified_at: ISO-8601 UTC timestamp of the check.
    """

    total_events: int
    violations: tuple[IntegrityViolation, ...]
    verified_at: str

    @property
    def is_clean(self) -> bool:
        """True if no violations were found."""
        return len(self.violations) == 0

    def summary(self) -> str:
        """Return a one-line summary string."""
        if self.is_clean:
            return (
                f"Integrity OK — {self.total_events} events verified at {self.verified_at}."
            )
        return (
            f"Integrity FAILED — {len(self.violations)} violation(s) "
            f"in {self.total_events} events at {self.verified_at}."
        )


# ---------------------------------------------------------------------------
# Replay result
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ReplayResult:
    """
    Outcome of a replay operation.

    Fields:
        events_replayed: Count of events applied during replay.
        final_sequence: Sequence number of the last replayed event.
        registry_snapshot: Plain-dict of resource states after replay.
        integrity_report: The integrity report generated during replay.
        started_from_sequence: Sequence at which replay began (0 = full).
    """

    events_replayed: int
    final_sequence: int
    registry_snapshot: dict[str, dict]
    integrity_report: IntegrityReport
    started_from_sequence: int


# ---------------------------------------------------------------------------
# Internal utilities
# ---------------------------------------------------------------------------

def _utcnow_iso() -> str:
    return datetime.now(tz=timezone.utc).strftime(TIMESTAMP_FORMAT)


def _compute_event_hash(
    event_id: str,
    timestamp: str,
    event_type: str,
    actor_identity: str,
    resource_id: str,
    payload: dict[str, Any],
    previous_hash: str,
    sequence: int,
    algorithm: str = HASH_ALGORITHM,
) -> str:
    """
    Compute the deterministic current_hash for an event.

    The hash input is: canonical JSON of content fields + previous_hash.

    Args:
        (see Event field names)
        algorithm: Hash algorithm to use.

    Returns:
        64-char hex SHA-256 digest.
    """
    content: dict[str, Any] = {
        "event_id": event_id,
        "timestamp": timestamp,
        "event_type": event_type,
        "actor_identity": actor_identity,
        "resource_id": resource_id,
        "payload": payload,
        "previous_hash": previous_hash,
        "sequence": sequence,
    }
    serialized: str = json.dumps(
        content, sort_keys=True, separators=(",", ":"), default=str
    )
    combined: str = serialized + previous_hash
    h = hashlib.new(algorithm)
    h.update(combined.encode(HASH_ENCODING))
    return h.hexdigest()


def _compute_state_hash(
    registry: ResourceRegistry,
    algorithm: str = HASH_ALGORITHM,
) -> str:
    """
    Compute a deterministic hash over the full resource registry state.

    Args:
        registry: The current ResourceRegistry.
        algorithm: Hash algorithm to use.

    Returns:
        64-char hex digest.
    """
    snapshot: dict[str, dict] = registry.snapshot()
    serialized: str = json.dumps(
        snapshot, sort_keys=True, separators=(",", ":"), default=str
    )
    h = hashlib.new(algorithm)
    h.update(serialized.encode(HASH_ENCODING))
    return h.hexdigest()


# ---------------------------------------------------------------------------
# EventLog
# ---------------------------------------------------------------------------

class EventLog:
    """
    Tamper-evident, append-only event log for the Hollow Purple platform.

    The log is persisted as a newline-delimited JSON file (.jsonl).
    Each event is hash-chained to the one before it, making any tampering
    detectable via verify_log_integrity().

    Usage:
        log = EventLog(log_path="./events.jsonl", checkpoint_path="./ckpt.json")
        event = log.append_event(
            event_type=EventType.RESOURCE_CREATED,
            actor_identity="hp-...",
            resource_id="...",
            payload={"name": "my-resource"},
            node_id="node-1",
        )
        report = log.verify_log_integrity()
        result = log.replay_events()
    """

    def __init__(
        self,
        log_path: str,
        checkpoint_path: str,
        algorithm: str = HASH_ALGORITHM,
        replay_mode: ReplayMode = ReplayMode.STRICT,
    ) -> None:
        """
        Initialise the EventLog.

        Args:
            log_path: Filesystem path to the .jsonl event log file.
            checkpoint_path: Filesystem path to the checkpoint JSON file.
            algorithm: Hash algorithm for chaining (default: sha256).
            replay_mode: How to handle integrity failures during replay.
        """
        self._log_path: str = log_path
        self._checkpoint_path: str = checkpoint_path
        self._algorithm: str = algorithm
        self._replay_mode: ReplayMode = replay_mode
        self._lock: threading.RLock = threading.RLock()

        # Runtime state
        self._last_hash: str = GENESIS_HASH
        self._sequence: int = -1

        # Ensure log directory exists
        os.makedirs(os.path.dirname(os.path.abspath(log_path)), exist_ok=True)

        # Recover tail state from existing log
        self._recover_tail()

        logger.info(
            "EventLog initialised.",
            extra={
                "log_path": self._log_path,
                "tail_sequence": self._sequence,
                "last_hash": self._last_hash[:16] + "…",
                "algorithm": self._algorithm,
            },
        )

    # ------------------------------------------------------------------
    # Recovery
    # ------------------------------------------------------------------

    def _recover_tail(self) -> None:
        """
        Scan to the tail of an existing log file to recover
        `_last_hash` and `_sequence` without loading all events into memory.
        """
        if not os.path.exists(self._log_path):
            return

        last_event: Optional[dict] = None
        with open(self._log_path, "r", encoding=HASH_ENCODING) as fh:
            for raw_line in fh:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    last_event = json.loads(line)
                except json.JSONDecodeError as exc:
                    logger.warning("Skipping malformed log line during tail recovery: %s", exc)

        if last_event:
            self._last_hash = last_event.get("current_hash", GENESIS_HASH)
            self._sequence = last_event.get("sequence", -1)
            logger.debug(
                "Tail recovered.",
                extra={"sequence": self._sequence, "last_hash": self._last_hash[:16]},
            )

    # ------------------------------------------------------------------
    # Append
    # ------------------------------------------------------------------

    def append_event(
        self,
        event_type: str,
        actor_identity: str,
        resource_id: str,
        payload: Optional[dict[str, Any]] = None,
        node_id: str = "node-default",
        event_id: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> Event:
        """
        Append a new event to the log.

        This method is thread-safe. The event is hash-chained to the previous
        event and immediately flushed to disk.

        Args:
            event_type: One of the EventType enum values.
            actor_identity: Fingerprint of the acting identity.
            resource_id: Target resource identifier.
            payload: Optional structured data (must be JSON-serializable).
            node_id: The node producing this event.
            event_id: Override event ID (default: UUIDv4).
            timestamp: Override timestamp (default: utcnow).

        Returns:
            The newly appended, immutable Event object.

        Raises:
            ValueError: If required fields are empty.
            IOError: If the log file cannot be written.
        """
        if not actor_identity:
            raise ValueError("actor_identity must not be empty.")
        if not resource_id:
            raise ValueError("resource_id must not be empty.")
        if not event_type:
            raise ValueError("event_type must not be empty.")

        payload = payload or {}

        with self._lock:
            eid: str = event_id or str(uuid.uuid4())
            ts: str = timestamp or _utcnow_iso()
            seq: int = self._sequence + 1
            prev_hash: str = self._last_hash

            current_hash: str = _compute_event_hash(
                event_id=eid,
                timestamp=ts,
                event_type=event_type,
                actor_identity=actor_identity,
                resource_id=resource_id,
                payload=payload,
                previous_hash=prev_hash,
                sequence=seq,
                algorithm=self._algorithm,
            )

            metadata = EventMetadata(node_id=node_id)

            event = Event(
                event_id=eid,
                timestamp=ts,
                event_type=event_type,
                actor_identity=actor_identity,
                resource_id=resource_id,
                payload=tuple(sorted(payload.items())),
                metadata=metadata,
                previous_hash=prev_hash,
                current_hash=current_hash,
                sequence=seq,
            )

            self._write_event(event)
            self._last_hash = current_hash
            self._sequence = seq

        logger.debug(
            "Event appended.",
            extra={
                "event_id": eid,
                "event_type": event_type,
                "sequence": seq,
                "resource_id": resource_id,
            },
        )
        return event

    def _write_event(self, event: Event) -> None:
        """Write a single event to the log file as a JSON line."""
        line: str = json.dumps(event.to_dict(), sort_keys=True, separators=(",", ":"), default=str)
        with open(self._log_path, "a", encoding=HASH_ENCODING) as fh:
            fh.write(line + "\n")
            fh.flush()

    # ------------------------------------------------------------------
    # Load
    # ------------------------------------------------------------------

    def load_events(
        self,
        start_sequence: int = 0,
    ) -> Generator[Event, None, None]:
        """
        Stream events from the log file starting at a given sequence number.

        This is a generator: events are yielded one at a time without loading
        the entire log into memory. Safe for logs containing millions of events.

        Args:
            start_sequence: First sequence number to yield (inclusive).

        Yields:
            Event objects in log order.

        Raises:
            FileNotFoundError: If the log file does not exist.
            ValueError: If a log line cannot be parsed.
        """
        if not os.path.exists(self._log_path):
            logger.warning("Log file not found; yielding no events.", extra={"path": self._log_path})
            return

        with open(self._log_path, "r", encoding=HASH_ENCODING) as fh:
            for line_number, raw_line in enumerate(fh, start=1):
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    event = Event.from_dict(data)
                except (json.JSONDecodeError, KeyError, ValueError) as exc:
                    logger.error(
                        "Failed to parse event at line %d: %s", line_number, exc
                    )
                    raise ValueError(
                        f"Corrupt log at line {line_number}: {exc}"
                    ) from exc

                if event.sequence >= start_sequence:
                    yield event

    # ------------------------------------------------------------------
    # Integrity verification
    # ------------------------------------------------------------------

    def verify_log_integrity(self) -> IntegrityReport:
        """
        Walk the entire event log and verify the hash chain.

        Checks:
          1. Each event's current_hash matches the recomputed hash.
          2. Each event's previous_hash matches the current_hash of the prior event.
          3. The first event's previous_hash is the GENESIS_HASH.

        Returns:
            IntegrityReport describing all violations (if any).
        """
        violations: list[IntegrityViolation] = []
        expected_previous: str = GENESIS_HASH
        total: int = 0

        logger.info("Starting log integrity verification.")

        for event in self.load_events():
            total += 1

            # Check hash chain continuity
            if event.previous_hash != expected_previous:
                violations.append(
                    IntegrityViolation(
                        sequence=event.sequence,
                        event_id=event.event_id,
                        reason=(
                            f"Hash chain broken: expected previous_hash "
                            f"'{expected_previous[:16]}…' but got "
                            f"'{event.previous_hash[:16]}…'."
                        ),
                    )
                )

            # Check event self-consistency
            if not event.is_hash_valid(self._algorithm):
                expected = event.compute_expected_hash(self._algorithm)
                violations.append(
                    IntegrityViolation(
                        sequence=event.sequence,
                        event_id=event.event_id,
                        reason=(
                            f"Tampered event: stored current_hash "
                            f"'{event.current_hash[:16]}…' ≠ "
                            f"expected '{expected[:16]}…'."
                        ),
                    )
                )

            expected_previous = event.current_hash

        report = IntegrityReport(
            total_events=total,
            violations=tuple(violations),
            verified_at=_utcnow_iso(),
        )

        if report.is_clean:
            logger.info("Log integrity verified: clean.", extra={"total_events": total})
        else:
            logger.error(
                "Log integrity FAILED.",
                extra={"violations": len(violations), "total_events": total},
            )
            for v in violations:
                logger.error("  Violation: %s", str(v))

        return report

    # ------------------------------------------------------------------
    # Replay
    # ------------------------------------------------------------------

    def replay_events(
        self,
        start_sequence: int = 0,
        registry: Optional[ResourceRegistry] = None,
    ) -> ReplayResult:
        """
        Replay events from the log, rebuilding resource state deterministically.

        Two calls with the same log always produce identical state.

        Args:
            start_sequence: Sequence to resume from (0 = full replay).
            registry: Optional existing ResourceRegistry to continue from.
                      If None, a fresh registry is created.

        Returns:
            ReplayResult containing the final state and integrity report.
        """
        reg: ResourceRegistry = registry or ResourceRegistry()
        violations: list[IntegrityViolation] = []
        expected_previous_hash: Optional[str] = None if start_sequence == 0 else None
        last_event: Optional[Event] = None
        count: int = 0

        # Re-verify the portion we're replaying
        integrity_report = self.verify_log_integrity()

        if not integrity_report.is_clean and self._replay_mode == ReplayMode.STRICT:
            logger.error(
                "Replay aborted: integrity violations detected in STRICT mode."
            )
            return ReplayResult(
                events_replayed=0,
                final_sequence=-1,
                registry_snapshot={},
                integrity_report=integrity_report,
                started_from_sequence=start_sequence,
            )

        logger.info(
            "Starting event replay.",
            extra={"start_sequence": start_sequence, "mode": self._replay_mode.value},
        )

        for event in self.load_events(start_sequence=start_sequence):
            count += 1
            last_event = event
            reg = self._apply_event_to_registry(event, reg)

        final_sequence = last_event.sequence if last_event else start_sequence - 1

        logger.info(
            "Replay complete.",
            extra={"events_replayed": count, "final_sequence": final_sequence},
        )

        return ReplayResult(
            events_replayed=count,
            final_sequence=final_sequence,
            registry_snapshot=reg.snapshot(),
            integrity_report=integrity_report,
            started_from_sequence=start_sequence,
        )

    def rebuild_state(self) -> ResourceRegistry:
        """
        Convenience method: full replay returning the ResourceRegistry.

        Runs a complete replay from sequence 0. Verifies integrity first.

        Returns:
            Fully populated ResourceRegistry.

        Raises:
            RuntimeError: If integrity check fails in STRICT mode.
        """
        result = self.replay_events(start_sequence=0)
        if not result.integrity_report.is_clean and self._replay_mode == ReplayMode.STRICT:
            raise RuntimeError(
                "Cannot rebuild state: log integrity violations detected. "
                "Run verify_log_integrity() for details."
            )
        reg = ResourceRegistry()
        reg.load_snapshot(result.registry_snapshot)
        return reg

    def _apply_event_to_registry(
        self, event: Event, registry: ResourceRegistry
    ) -> ResourceRegistry:
        """
        Apply a single event to the registry, creating or updating resources.

        For resource-creation events the resource is inserted.
        For all other resource events, the existing resource state is updated.

        Args:
            event: The Event to apply.
            registry: The current ResourceRegistry.

        Returns:
            The updated ResourceRegistry (same object, mutated).
        """
        try:
            if event.event_type == EventType.RESOURCE_CREATED:
                payload: dict = dict(event.payload)
                resource = create_resource(
                    owner_identity=event.actor_identity,
                    resource_id=event.resource_id,
                    attributes=payload,
                    created_at=event.timestamp,
                )
                registry.upsert(resource)

            elif event.event_type in (
                EventType.RESOURCE_ACTIVATED,
                EventType.RESOURCE_SUSPENDED,
                EventType.RESOURCE_ARCHIVED,
                EventType.RESOURCE_DELETED,
            ):
                try:
                    current = registry.get(event.resource_id)
                    updated = apply_event(current, event)
                    registry.upsert(updated)
                except Exception as exc:  # ResourceNotFoundError or transition error
                    logger.warning(
                        "Could not apply event to resource: %s",
                        exc,
                        extra={"event_id": event.event_id, "resource_id": event.resource_id},
                    )
        except Exception as exc:
            logger.error(
                "Unexpected error applying event to registry: %s",
                exc,
                extra={"event_id": event.event_id},
            )

        return registry

    # ------------------------------------------------------------------
    # Checkpointing
    # ------------------------------------------------------------------

    def create_checkpoint(
        self,
        registry: ResourceRegistry,
        node_id: str = "node-default",
    ) -> ReplayCheckpoint:
        """
        Persist the current registry state as a checkpoint.

        The checkpoint records the event sequence and last event hash so that
        future replays can resume from this point rather than replaying
        the entire log from the beginning.

        Args:
            registry: The current ResourceRegistry to snapshot.
            node_id: The node creating the checkpoint.

        Returns:
            The serialized ReplayCheckpoint (also written to disk).
        """
        with self._lock:
            seq = self._sequence
            last_hash = self._last_hash

        state_hash = _compute_state_hash(registry, self._algorithm)
        checkpoint_id = str(uuid.uuid4())
        now = _utcnow_iso()

        resources_snapshot = registry.snapshot()

        checkpoint = ReplayCheckpoint(
            checkpoint_id=checkpoint_id,
            sequence=seq,
            last_event_hash=last_hash,
            state_hash=state_hash,
            created_at=now,
            node_id=node_id,
            resources=tuple(sorted(
                (rid, data) for rid, data in resources_snapshot.items()
            )),
        )

        self._write_checkpoint(checkpoint)

        logger.info(
            "Checkpoint created.",
            extra={
                "checkpoint_id": checkpoint_id,
                "sequence": seq,
                "resource_count": len(resources_snapshot),
            },
        )
        return checkpoint

    def _write_checkpoint(self, checkpoint: ReplayCheckpoint) -> None:
        """Atomically write checkpoint to disk via a temp file + rename."""
        data = json.dumps(
            checkpoint.to_dict(), sort_keys=True, indent=2, default=str
        )
        tmp_path = self._checkpoint_path + ".tmp"
        with open(tmp_path, "w", encoding=HASH_ENCODING) as fh:
            fh.write(data)
            fh.flush()
        os.replace(tmp_path, self._checkpoint_path)

    def load_checkpoint(self) -> Optional[ReplayCheckpoint]:
        """
        Load the most recent checkpoint from disk, if one exists.

        Returns:
            A ReplayCheckpoint, or None if no checkpoint file exists.

        Raises:
            ValueError: If the checkpoint file is corrupt.
        """
        if not os.path.exists(self._checkpoint_path):
            logger.debug("No checkpoint file found at %s.", self._checkpoint_path)
            return None

        try:
            with open(self._checkpoint_path, "r", encoding=HASH_ENCODING) as fh:
                data = json.load(fh)
            checkpoint = ReplayCheckpoint.from_dict(data)
            logger.info(
                "Checkpoint loaded.",
                extra={
                    "checkpoint_id": checkpoint.checkpoint_id,
                    "sequence": checkpoint.sequence,
                },
            )
            return checkpoint
        except (json.JSONDecodeError, KeyError, ValueError) as exc:
            raise ValueError(f"Corrupt checkpoint file: {exc}") from exc

    def verify_checkpoint(self, checkpoint: ReplayCheckpoint) -> bool:
        """
        Verify that a checkpoint's state_hash matches the current registry
        reconstructed from the log up to checkpoint.sequence.

        This is an expensive operation: it replays from 0 → checkpoint.sequence.

        Args:
            checkpoint: The ReplayCheckpoint to verify.

        Returns:
            True if the checkpoint is valid.

        Raises:
            ValueError: If the reconstructed state hash does not match.
        """
        logger.info(
            "Verifying checkpoint integrity.",
            extra={"checkpoint_id": checkpoint.checkpoint_id, "sequence": checkpoint.sequence},
        )

        # Replay up to and including checkpoint sequence
        reg = ResourceRegistry()
        for event in self.load_events(start_sequence=0):
            if event.sequence > checkpoint.sequence:
                break
            self._apply_event_to_registry(event, reg)

        actual_hash = _compute_state_hash(reg, self._algorithm)

        if actual_hash != checkpoint.state_hash:
            raise ValueError(
                f"Checkpoint verification failed for '{checkpoint.checkpoint_id}': "
                f"state_hash mismatch.\n"
                f"  Expected: {checkpoint.state_hash}\n"
                f"  Actual:   {actual_hash}"
            )

        logger.info(
            "Checkpoint verified successfully.",
            extra={"checkpoint_id": checkpoint.checkpoint_id},
        )
        return True

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def current_sequence(self) -> int:
        """Return the current tail sequence number (-1 if log is empty)."""
        with self._lock:
            return self._sequence

    @property
    def current_hash(self) -> str:
        """Return the tail hash of the log."""
        with self._lock:
            return self._last_hash

    @property
    def log_path(self) -> str:
        """Return the filesystem path of the event log."""
        return self._log_path

    @property
    def checkpoint_path(self) -> str:
        """Return the filesystem path of the checkpoint file."""
        return self._checkpoint_path