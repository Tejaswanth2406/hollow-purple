"""
phase4/deterministic_replay.py
================================
Enterprise deterministic event-replay engine.

Core guarantee
--------------
Given the same ordered event sequence, the replay engine ALWAYS produces
byte-identical state output regardless of the machine, time, or process
running it. This is the foundation of forensic reproducibility.

Design principles
-----------------
- Pure functional state transitions: apply_event(state, event) → new_state
- No I/O, no randomness, no wall-clock dependency inside transitions
- Logical clock (Lamport) enforcement: rejects or reorders out-of-sequence events
- Pluggable StateMachine interface — define your own domain transitions
- Pre-built DefaultStateMachine for Hollow Purple's security event model
- Snapshot checkpointing during replay for fast mid-sequence access
- Configurable replay modes: FULL, INCREMENTAL, WINDOWED
- Structured per-event transition log for debugging
- Async-compatible: replay coroutines for large ledgers without blocking
- Replay fingerprinting: hash of (event_seq, state_hash) chain per step
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple, TYPE_CHECKING


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Replay mode
# ---------------------------------------------------------------------------


class ReplayMode(str, Enum):
    FULL        = "full"         # Replay entire ledger from genesis
    INCREMENTAL = "incremental"  # Resume from a known state + new events
    WINDOWED    = "windowed"     # Replay only a time/sequence window


# ---------------------------------------------------------------------------
# State machine interface
# ---------------------------------------------------------------------------


class StateMachine(ABC):
    """
    Abstract state machine defining how events transform state.

    Implementing this interface makes a domain model fully replayable.

    Contract
    --------
    - ``initial_state()`` must be deterministic (same output every call)
    - ``apply_event(state, event)`` must be a pure function:
        no I/O, no randomness, no mutation of ``state`` in place
    - Return a NEW state dict, never mutate the input
    """

    @abstractmethod
    def initial_state(self) -> Dict[str, Any]:
        """Return the canonical empty initial state."""
        ...

    @abstractmethod
    def apply_event(
        self, state: Dict[str, Any], event: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Apply a single event to the current state and return the new state.

        Must be a pure function. The returned dict will be deep-compared
        and hashed for replay verification.
        """
        ...

    def event_sequence(self, event: Dict[str, Any]) -> int:
        """
        Extract the logical sequence number from an event.
        Override to use your event model's sequence field.
        """
        return event.get("sequence", event.get("seq", -1))


# ---------------------------------------------------------------------------
# Default state machine for Hollow Purple security model
# ---------------------------------------------------------------------------


class HollowPurpleStateMachine(StateMachine):
    """
    Built-in state machine for Hollow Purple's security event model.

    State schema
    ------------
    {
        "identities": {
            identity_id: {
                "event_count": int,
                "resources": [str, ...],
                "actions": [str, ...],
                "last_event_type": str,
                "last_seen": str,
                "risk_flags": [str, ...]
            }
        },
        "graph": {
            "nodes": {node_id: {type, label}},
            "edges": [(src, dst, relation), ...]
        },
        "anomalies": [
            {"identity": str, "flag": str, "detected_at": str}
        ],
        "metrics": {
            metric_name: {"count": int, "total": float, "last": float}
        },
        "sequence_clock": int,
        "event_count": int
    }
    """

    # High-risk action classifier
    HIGH_RISK_ACTIONS: frozenset = frozenset({
        "privilege_escalation", "lateral_movement", "data_exfiltration",
        "assume_role", "admin_login", "secret_access", "iam_modify",
        "bulk_data_read", "disable_logging", "install_backdoor",
        "root_exec", "port_scan", "ssh_brute_force", "export_data",
    })

    def initial_state(self) -> Dict[str, Any]:
        return {
            "identities": {},
            "graph": {"nodes": {}, "edges": []},
            "anomalies": [],
            "metrics": {},
            "sequence_clock": -1,
            "event_count": 0,
        }

    def apply_event(
        self, state: Dict[str, Any], event: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Pure transition function.
        Returns a fully independent copy — never mutates ``state``.
        """
        import copy
        new_state = copy.deepcopy(state)

        identity = (
            event.get("identity")
            or event.get("user_id")
            or event.get("principal")
            or "unknown"
        )
        event_type = event.get("event_type", "unknown")
        resource   = event.get("resource", "unknown")
        timestamp  = event.get("timestamp", "")
        seq        = event.get("sequence", new_state["event_count"])

        # --- Update sequence clock ---
        new_state["sequence_clock"] = max(new_state["sequence_clock"], seq)
        new_state["event_count"] += 1

        # --- Identity state ---
        if identity not in new_state["identities"]:
            new_state["identities"][identity] = {
                "event_count": 0,
                "resources": [],
                "actions": [],
                "last_event_type": None,
                "last_seen": None,
                "risk_flags": [],
            }
        id_state = new_state["identities"][identity]
        id_state["event_count"] += 1
        if resource not in id_state["resources"]:
            id_state["resources"].append(resource)
        if event_type not in id_state["actions"]:
            id_state["actions"].append(event_type)
        id_state["last_event_type"] = event_type
        id_state["last_seen"] = timestamp

        # --- Anomaly detection (inline, deterministic) ---
        if event_type in self.HIGH_RISK_ACTIONS:
            flag = f"HIGH_RISK:{event_type}"
            if flag not in id_state["risk_flags"]:
                id_state["risk_flags"].append(flag)
            new_state["anomalies"].append({
                "identity": identity,
                "flag": event_type,
                "resource": resource,
                "detected_at": timestamp,
                "sequence": seq,
            })

        # --- Graph state ---
        node_id = resource
        if node_id not in new_state["graph"]["nodes"]:
            new_state["graph"]["nodes"][node_id] = {
                "type": event.get("resource_type", "generic"),
                "label": node_id,
            }
        # Add identity→resource edge
        edge = (identity, resource, event_type)
        if edge not in new_state["graph"]["edges"]:
            new_state["graph"]["edges"].append(edge)

        # --- Metrics ---
        metric_key = f"events.{event_type}"
        if metric_key not in new_state["metrics"]:
            new_state["metrics"][metric_key] = {"count": 0, "total": 0.0, "last": 0.0}
        new_state["metrics"][metric_key]["count"] += 1

        return new_state


# ---------------------------------------------------------------------------
# Transition record
# ---------------------------------------------------------------------------


@dataclass
class TransitionRecord:
    """Per-step transition telemetry logged during replay."""
    sequence: int
    event_type: str
    identity: str
    resource: str
    state_hash: str
    elapsed_ns: int
    anomaly_detected: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sequence": self.sequence,
            "event_type": self.event_type,
            "identity": self.identity,
            "resource": self.resource,
            "state_hash": self.state_hash[:16] + "…",
            "elapsed_ns": self.elapsed_ns,
            "anomaly_detected": self.anomaly_detected,
        }


# ---------------------------------------------------------------------------
# Replay result
# ---------------------------------------------------------------------------


@dataclass
class ReplayResult:
    """
    Complete output of a deterministic replay run.

    Fields
    ------
    final_state         : Reconstructed state after all events applied.
    state_hash          : SHA-256 of the canonical final state.
    events_applied      : Total events replayed.
    events_skipped      : Events skipped (out-of-order, filtered).
    transitions         : Per-event transition telemetry.
    replay_chain_hash   : Rolling hash of (seq, state_hash) pairs —
                          can be used to prove replay was not tampered with.
    mode                : Replay mode used.
    from_sequence       : Start sequence.
    to_sequence         : Final sequence reached.
    elapsed_ms          : Total wall-clock time for replay.
    replayed_at         : UTC ISO-8601 timestamp.
    """

    final_state: Dict[str, Any]
    state_hash: str
    events_applied: int
    events_skipped: int
    transitions: List[TransitionRecord]
    replay_chain_hash: str
    mode: ReplayMode
    from_sequence: int
    to_sequence: int
    elapsed_ms: float
    replayed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self, include_state: bool = False) -> Dict[str, Any]:
        d = {
            "state_hash": self.state_hash,
            "events_applied": self.events_applied,
            "events_skipped": self.events_skipped,
            "replay_chain_hash": self.replay_chain_hash,
            "mode": self.mode.value,
            "from_sequence": self.from_sequence,
            "to_sequence": self.to_sequence,
            "elapsed_ms": round(self.elapsed_ms, 3),
            "replayed_at": self.replayed_at,
            "anomalies_detected": sum(
                1 for t in self.transitions if t.anomaly_detected
            ),
        }
        if include_state:
            d["final_state"] = self.final_state
        return d


# ---------------------------------------------------------------------------
# DeterministicReplay
# ---------------------------------------------------------------------------


class DeterministicReplay:
    """
    Deterministic event-replay engine.

    Replays an ordered event sequence through a StateMachine producing
    a provably correct final state. Every intermediate state is hashed
    and chained to form a replay proof that can be independently verified.

    Usage
    -----
    ::

        sm = HollowPurpleStateMachine()
        replay = DeterministicReplay(sm)

        result = await replay.run(events)
        print(f"Final state hash: {result.state_hash}")
        print(f"Events applied:   {result.events_applied}")

        # Verify a specific point in the replay
        mid_result = await replay.run(events, to_sequence=500)
    """

    def __init__(
        self,
        state_machine: StateMachine,
        *,
        checkpoint_interval: int = 100,
        log_transitions: bool = True,
    ) -> None:
        self._sm = state_machine
        self._checkpoint_interval = checkpoint_interval
        self._log_transitions = log_transitions

        # In-process checkpoint cache: seq → (state, state_hash)
        self._checkpoints: Dict[int, Tuple[Dict[str, Any], str]] = {}

        logger.info(
            "DeterministicReplay initialised",
            extra={
                "state_machine": type(state_machine).__name__,
                "checkpoint_interval": checkpoint_interval,
            },
        )

    # ---------------------------------------------------------------------------
    # State hashing
    # ---------------------------------------------------------------------------

    @staticmethod
    def hash_state(state: Dict[str, Any]) -> str:
        """
        Produce a deterministic SHA-256 hash of a state dict.
        Uses canonical JSON (sorted keys, no whitespace) for
        byte-identical output across Python versions.
        """
        canonical = json.dumps(state, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()

    @staticmethod
    def _chain_hash(prev_chain: str, seq: int, state_hash: str) -> str:
        """
        Extend the replay chain hash.
        Chains: SHA256(prev_chain || seq || state_hash)
        This produces a tamper-evident log of the entire replay sequence.
        """
        payload = f"{prev_chain}:{seq}:{state_hash}"
        return hashlib.sha256(payload.encode()).hexdigest()

    # ---------------------------------------------------------------------------
    # Core replay
    # ---------------------------------------------------------------------------

    async def run(
        self,
        events: List[Dict[str, Any]],
        *,
        mode: ReplayMode = ReplayMode.FULL,
        initial_state: Optional[Dict[str, Any]] = None,
        from_sequence: int = 0,
        to_sequence: Optional[int] = None,
    ) -> ReplayResult:
        """
        Execute a deterministic replay over ``events``.

        Parameters
        ----------
        events          : Ordered list of event dicts.
        mode            : Replay mode (FULL / INCREMENTAL / WINDOWED).
        initial_state   : Provide a pre-existing state for INCREMENTAL mode.
                          If None, uses ``state_machine.initial_state()``.
        from_sequence   : Skip events with sequence < this value.
        to_sequence     : Stop after this sequence. None = replay all.

        Returns
        -------
        ReplayResult
            Final state, state hash, transition log, and replay chain proof.
        """
        start_ns = time.perf_counter_ns()

        state = (
            initial_state
            if initial_state is not None
            else self._sm.initial_state()
        )

        transitions: List[TransitionRecord] = []
        chain_hash = "GENESIS"
        applied = 0
        skipped = 0
        last_seq = from_sequence - 1

        # Sort events by sequence for deterministic ordering
        ordered = sorted(
            events,
            key=lambda e: self._sm.event_sequence(e),
        )

        for event in ordered:
            seq = self._sm.event_sequence(event)

            # Sequence range filtering
            if seq < from_sequence:
                skipped += 1
                continue
            if to_sequence is not None and seq > to_sequence:
                break

            # Strict monotonicity check (warn but continue — allow gaps)
            if seq <= last_seq:
                logger.warning(
                    "Out-of-order event detected",
                    extra={"seq": seq, "last_seq": last_seq},
                )
                skipped += 1
                continue

            t_start = time.perf_counter_ns()

            # Apply pure state transition
            new_state = self._sm.apply_event(state, event)
            state_hash = self.hash_state(new_state)

            t_elapsed = time.perf_counter_ns() - t_start

            # Extend chain proof
            chain_hash = self._chain_hash(chain_hash, seq, state_hash)

            # Checkpoint
            if applied % self._checkpoint_interval == 0:
                self._checkpoints[seq] = (new_state, state_hash)

            # Transition log
            if self._log_transitions:
                anomaly = len(new_state.get("anomalies", [])) > len(
                    state.get("anomalies", [])
                )
                transitions.append(
                    TransitionRecord(
                        sequence=seq,
                        event_type=event.get("event_type", "unknown"),
                        identity=event.get("identity", "unknown"),
                        resource=event.get("resource", "unknown"),
                        state_hash=state_hash,
                        elapsed_ns=t_elapsed,
                        anomaly_detected=anomaly,
                    )
                )

            state = new_state
            last_seq = seq
            applied += 1

            # Yield control periodically for large replays
            if applied % 1000 == 0:
                await asyncio.sleep(0)
                logger.debug(
                    "Replay progress",
                    extra={"applied": applied, "seq": seq},
                )

        final_hash = self.hash_state(state)
        elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000

        result = ReplayResult(
            final_state=state,
            state_hash=final_hash,
            events_applied=applied,
            events_skipped=skipped,
            transitions=transitions if self._log_transitions else [],
            replay_chain_hash=chain_hash,
            mode=mode,
            from_sequence=from_sequence,
            to_sequence=last_seq,
            elapsed_ms=round(elapsed_ms, 3),
        )

        logger.info(
            "Replay complete",
            extra={
                "applied": applied,
                "skipped": skipped,
                "state_hash": final_hash[:16],
                "elapsed_ms": round(elapsed_ms, 2),
                "mode": mode.value,
            },
        )
        return result

    # ---------------------------------------------------------------------------
    # Cached checkpoint access
    # ---------------------------------------------------------------------------

    def nearest_checkpoint(self, target_seq: int) -> Optional[Tuple[int, Dict[str, Any], str]]:
        """
        Return (seq, state, state_hash) of the nearest cached checkpoint
        at or before ``target_seq``. Returns None if no checkpoints exist.
        """
        candidates = [(s, st, h) for s, (st, h) in self._checkpoints.items()
                      if s <= target_seq]
        if not candidates:
            return None
        return max(candidates, key=lambda x: x[0])

    def clear_checkpoints(self) -> None:
        self._checkpoints.clear()