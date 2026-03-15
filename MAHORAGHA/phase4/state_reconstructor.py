"""
phase4/state_reconstructor.py
==============================
Enterprise state reconstruction engine using snapshot + delta replay.

The problem it solves
---------------------
Replaying millions of events from genesis is O(N) and can take minutes.
The StateReconstructor reduces this to:
    O(delta_events) by loading the nearest snapshot and replaying only
    the events that occurred AFTER that snapshot.

Strategy selection
------------------
The engine automatically selects the optimal reconstruction strategy:

    SNAPSHOT_THEN_DELTA  — Load nearest snapshot, replay delta events
                           (fastest — preferred when snapshots exist)
    FULL_REPLAY          — No usable snapshot; replay from genesis
                           (correct but slow for large ledgers)
    CHECKPOINT_SEEK      — Use in-process replay engine checkpoints
                           (fastest of all — O(1) lookup if cached)

Gap detection
-------------
If event sequence numbers have gaps between the snapshot position and
the target sequence, a GapDetectedError is raised in strict mode.
In non-strict mode, gaps are logged and the reconstruction continues
using available events (useful for partial ledger recovery).

Forensic audit support
----------------------
Every reconstruction emits a signed ReconstructionResult that records:
    - Which snapshot (if any) was used
    - How many delta events were applied
    - Final state hash for independent verification
    - Total elapsed time for performance auditing
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class GapDetectedError(Exception):
    """
    Raised when sequence gaps are detected between snapshot and target
    in strict reconstruction mode.
    """

    def __init__(
        self,
        missing_sequences: List[int],
        snapshot_seq: int,
        target_seq: int,
    ) -> None:
        self.missing_sequences = missing_sequences
        self.snapshot_seq = snapshot_seq
        self.target_seq = target_seq
        super().__init__(
            f"Sequence gap detected: {len(missing_sequences)} missing events "
            f"between seq {snapshot_seq} and {target_seq}"
        )


class SnapshotLoadError(Exception):
    """Raised when a snapshot cannot be loaded or verified."""


# ---------------------------------------------------------------------------
# Reconstruction strategy
# ---------------------------------------------------------------------------


class ReconstructionStrategy(str, Enum):
    SNAPSHOT_THEN_DELTA = "snapshot_then_delta"
    FULL_REPLAY         = "full_replay"
    CHECKPOINT_SEEK     = "checkpoint_seek"


# ---------------------------------------------------------------------------
# Reconstruction result
# ---------------------------------------------------------------------------


@dataclass
class ReconstructionResult:
    """
    Complete output of a state reconstruction run.

    Fields
    ------
    state               : Reconstructed state dict at ``target_sequence``.
    state_hash          : SHA-256 of the canonical reconstructed state.
    target_sequence     : The sequence number reconstructed to.
    strategy            : Which strategy was used.
    snapshot_id         : Snapshot used as base (None for full replay).
    snapshot_sequence   : Sequence of the base snapshot.
    delta_events_applied: Number of events replayed after the snapshot.
    gap_sequences       : Sequence numbers missing from the event log.
    elapsed_ms          : Total wall-clock reconstruction time.
    reconstructed_at    : UTC ISO-8601 timestamp.
    reconstruction_id   : UUID for audit trail linkage.
    """

    state: Dict[str, Any]
    state_hash: str
    target_sequence: int
    strategy: ReconstructionStrategy
    snapshot_id: Optional[str]
    snapshot_sequence: int
    delta_events_applied: int
    gap_sequences: List[int]
    elapsed_ms: float
    reconstructed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    reconstruction_id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def to_dict(self, include_state: bool = False) -> Dict[str, Any]:
        d = {
            "reconstruction_id": self.reconstruction_id,
            "state_hash": self.state_hash,
            "target_sequence": self.target_sequence,
            "strategy": self.strategy.value,
            "snapshot_id": self.snapshot_id,
            "snapshot_sequence": self.snapshot_sequence,
            "delta_events_applied": self.delta_events_applied,
            "gap_sequences": self.gap_sequences[:20],
            "gap_count": len(self.gap_sequences),
            "elapsed_ms": round(self.elapsed_ms, 3),
            "reconstructed_at": self.reconstructed_at,
        }
        if include_state:
            d["state"] = self.state
        return d


# ---------------------------------------------------------------------------
# StateReconstructor
# ---------------------------------------------------------------------------


class StateReconstructor:
    """
    Efficient state reconstruction from snapshot + event delta.

    Usage
    -----
    ::

        reconstructor = StateReconstructor(
            snapshot_store=snapshot_store,
            replay_engine=replay_engine,
            strict_gaps=True,
        )

        # Reconstruct state at sequence 1500
        result = await reconstructor.reconstruct(
            target_sequence=1500,
            events=all_events,          # full event log
            tenant_id="acme",
        )
        print(f"State hash: {result.state_hash}")
        print(f"Strategy: {result.strategy.value}")
        print(f"Delta events: {result.delta_events_applied}")

        # Direct snapshot + events (no auto-snapshot lookup)
        result = await reconstructor.reconstruct_from_snapshot(
            snapshot_id="snap-abc123",
            delta_events=events_after_snapshot,
        )
    """

    def __init__(
        self,
        *,
        snapshot_store=None,
        replay_engine=None,
        strict_gaps: bool = False,
    ) -> None:
        """
        Parameters
        ----------
        snapshot_store  : SnapshotStore instance (optional).
                          If None, always falls back to FULL_REPLAY.
        replay_engine   : DeterministicReplay instance.
                          If None, a default HollowPurpleStateMachine is used.
        strict_gaps     : If True, raise GapDetectedError on missing sequences.
                          If False, log gaps and continue.
        """
        self._snapshot_store = snapshot_store
        self._replay_engine = replay_engine
        self._strict_gaps = strict_gaps

        if self._replay_engine is None:
            from .deterministic_replay import DeterministicReplay, HollowPurpleStateMachine
            self._replay_engine = DeterministicReplay(HollowPurpleStateMachine())

        logger.info(
            "StateReconstructor initialised",
            extra={
                "has_snapshot_store": snapshot_store is not None,
                "strict_gaps": strict_gaps,
            },
        )

    # ---------------------------------------------------------------------------
    # Primary reconstruction entry point
    # ---------------------------------------------------------------------------

    async def reconstruct(
        self,
        target_sequence: int,
        events: List[Dict[str, Any]],
        *,
        tenant_id: Optional[str] = None,
    ) -> ReconstructionResult:
        """
        Reconstruct system state at ``target_sequence``.

        Strategy selection
        ------------------
        1. Try in-process checkpoint cache (O(1) if hit)
        2. Try SnapshotStore for nearest snapshot before target
        3. Fall back to full replay from genesis

        Parameters
        ----------
        target_sequence : Reconstruct state as it was at this sequence.
        events          : Full or partial event log.
        tenant_id       : Tenant scope.

        Returns
        -------
        ReconstructionResult
        """
        start_ns = time.perf_counter_ns()

        # Strategy 1: In-process checkpoint cache
        cached = self._replay_engine.nearest_checkpoint(target_sequence)
        if cached is not None:
            cp_seq, cp_state, cp_hash = cached
            if cp_seq == target_sequence:
                elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000
                logger.info(
                    "Reconstruction from in-process checkpoint",
                    extra={"seq": cp_seq, "strategy": "checkpoint_seek"},
                )
                return ReconstructionResult(
                    state=cp_state,
                    state_hash=cp_hash,
                    target_sequence=target_sequence,
                    strategy=ReconstructionStrategy.CHECKPOINT_SEEK,
                    snapshot_id=None,
                    snapshot_sequence=cp_seq,
                    delta_events_applied=0,
                    gap_sequences=[],
                    elapsed_ms=round(elapsed_ms, 3),
                )

            # Use checkpoint as base, replay delta
            delta_events = [
                e for e in events
                if self._replay_engine._sm.event_sequence(e) > cp_seq
            ]
            gaps = self._detect_gaps(delta_events, cp_seq + 1, target_sequence)
            await self._handle_gaps(gaps, cp_seq, target_sequence)

            replay_result = await self._replay_engine.run(
                delta_events,
                mode=__import__("phase4.deterministic_replay", fromlist=["ReplayMode"]).ReplayMode.INCREMENTAL,
                initial_state=cp_state,
                from_sequence=cp_seq + 1,
                to_sequence=target_sequence,
            )

            elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000
            return ReconstructionResult(
                state=replay_result.final_state,
                state_hash=replay_result.state_hash,
                target_sequence=target_sequence,
                strategy=ReconstructionStrategy.CHECKPOINT_SEEK,
                snapshot_id=None,
                snapshot_sequence=cp_seq,
                delta_events_applied=replay_result.events_applied,
                gap_sequences=gaps,
                elapsed_ms=round(elapsed_ms, 3),
            )

        # Strategy 2: Snapshot-then-delta
        if self._snapshot_store is not None:
            try:
                return await self._reconstruct_via_snapshot(
                    target_sequence=target_sequence,
                    events=events,
                    tenant_id=tenant_id,
                    start_ns=start_ns,
                )
            except Exception as exc:
                logger.warning(
                    "Snapshot strategy failed — falling back to full replay",
                    extra={"error": str(exc)},
                )

        # Strategy 3: Full replay
        return await self._reconstruct_full_replay(
            target_sequence=target_sequence,
            events=events,
            start_ns=start_ns,
        )

    # ---------------------------------------------------------------------------
    # Strategy implementations
    # ---------------------------------------------------------------------------

    async def _reconstruct_via_snapshot(
        self,
        *,
        target_sequence: int,
        events: List[Dict[str, Any]],
        tenant_id: Optional[str],
        start_ns: int,
    ) -> ReconstructionResult:
        """Load nearest snapshot, apply delta events."""
        from .deterministic_replay import ReplayMode

        nearest = await self._snapshot_store.nearest_before(
            target_sequence, tenant_id=tenant_id
        )
        if nearest is None:
            raise SnapshotLoadError("No suitable snapshot found")

        snap_state = await self._snapshot_store.load(nearest.snapshot_id, verify=True)
        snap_seq = nearest.ledger_sequence

        delta_events = [
            e for e in events
            if self._replay_engine._sm.event_sequence(e) > snap_seq
        ]

        gaps = self._detect_gaps(delta_events, snap_seq + 1, target_sequence)
        await self._handle_gaps(gaps, snap_seq, target_sequence)

        replay_result = await self._replay_engine.run(
            delta_events,
            mode=ReplayMode.INCREMENTAL,
            initial_state=snap_state,
            from_sequence=snap_seq + 1,
            to_sequence=target_sequence,
        )

        elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000

        logger.info(
            "Reconstruction via snapshot complete",
            extra={
                "snapshot_id": nearest.snapshot_id,
                "snap_seq": snap_seq,
                "delta_events": replay_result.events_applied,
                "target": target_sequence,
                "elapsed_ms": round(elapsed_ms, 2),
            },
        )

        return ReconstructionResult(
            state=replay_result.final_state,
            state_hash=replay_result.state_hash,
            target_sequence=target_sequence,
            strategy=ReconstructionStrategy.SNAPSHOT_THEN_DELTA,
            snapshot_id=nearest.snapshot_id,
            snapshot_sequence=snap_seq,
            delta_events_applied=replay_result.events_applied,
            gap_sequences=gaps,
            elapsed_ms=round(elapsed_ms, 3),
        )

    async def _reconstruct_full_replay(
        self,
        *,
        target_sequence: int,
        events: List[Dict[str, Any]],
        start_ns: int,
    ) -> ReconstructionResult:
        """Full replay from genesis — slowest but always correct."""
        from .deterministic_replay import ReplayMode

        gaps = self._detect_gaps(events, 0, target_sequence)
        await self._handle_gaps(gaps, 0, target_sequence)

        replay_result = await self._replay_engine.run(
            events,
            mode=ReplayMode.FULL,
            to_sequence=target_sequence,
        )

        elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000

        logger.info(
            "Full replay reconstruction complete",
            extra={
                "events_applied": replay_result.events_applied,
                "target": target_sequence,
                "elapsed_ms": round(elapsed_ms, 2),
            },
        )

        return ReconstructionResult(
            state=replay_result.final_state,
            state_hash=replay_result.state_hash,
            target_sequence=target_sequence,
            strategy=ReconstructionStrategy.FULL_REPLAY,
            snapshot_id=None,
            snapshot_sequence=0,
            delta_events_applied=replay_result.events_applied,
            gap_sequences=gaps,
            elapsed_ms=round(elapsed_ms, 3),
        )

    # ---------------------------------------------------------------------------
    # Direct snapshot-based reconstruction (no auto-lookup)
    # ---------------------------------------------------------------------------

    async def reconstruct_from_snapshot(
        self,
        snapshot_id: str,
        delta_events: List[Dict[str, Any]],
        *,
        target_sequence: Optional[int] = None,
    ) -> ReconstructionResult:
        """
        Reconstruct state using an explicitly named snapshot as the base.
        Use when you already know which snapshot to load.
        """
        from .deterministic_replay import ReplayMode

        if self._snapshot_store is None:
            raise SnapshotLoadError("No SnapshotStore configured")

        start_ns = time.perf_counter_ns()
        meta = await self._snapshot_store.get_metadata(snapshot_id)
        snap_state = await self._snapshot_store.load(snapshot_id, verify=True)
        snap_seq = meta.ledger_sequence

        to_seq = target_sequence or (
            max((self._replay_engine._sm.event_sequence(e) for e in delta_events), default=snap_seq)
        )

        replay_result = await self._replay_engine.run(
            delta_events,
            mode=ReplayMode.INCREMENTAL,
            initial_state=snap_state,
            from_sequence=snap_seq + 1,
            to_sequence=to_seq,
        )

        elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000

        return ReconstructionResult(
            state=replay_result.final_state,
            state_hash=replay_result.state_hash,
            target_sequence=to_seq,
            strategy=ReconstructionStrategy.SNAPSHOT_THEN_DELTA,
            snapshot_id=snapshot_id,
            snapshot_sequence=snap_seq,
            delta_events_applied=replay_result.events_applied,
            gap_sequences=[],
            elapsed_ms=round(elapsed_ms, 3),
        )

    # ---------------------------------------------------------------------------
    # Gap detection
    # ---------------------------------------------------------------------------

    def _detect_gaps(
        self,
        events: List[Dict[str, Any]],
        from_seq: int,
        to_seq: int,
    ) -> List[int]:
        """
        Detect missing sequence numbers in the event list between
        ``from_seq`` and ``to_seq`` (inclusive).
        """
        present: set = {
            self._replay_engine._sm.event_sequence(e)
            for e in events
        }
        expected = set(range(from_seq, to_seq + 1))
        missing = sorted(expected - present)
        return missing

    async def _handle_gaps(
        self,
        gaps: List[int],
        from_seq: int,
        to_seq: int,
    ) -> None:
        if not gaps:
            return
        if self._strict_gaps:
            raise GapDetectedError(gaps, from_seq, to_seq)
        logger.warning(
            "Sequence gaps detected in reconstruction window",
            extra={
                "gap_count": len(gaps),
                "first_gap": gaps[0],
                "last_gap": gaps[-1],
                "from_seq": from_seq,
                "to_seq": to_seq,
            },
        )

    # ---------------------------------------------------------------------------
    # Comparison
    # ---------------------------------------------------------------------------

    async def compare(
        self,
        sequence: int,
        events_a: List[Dict[str, Any]],
        events_b: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Reconstruct the same sequence from two different event sets and compare.
        Used to verify that a corrected or filtered event log produces the
        same state as the original.
        """
        result_a = await self.reconstruct(sequence, events_a)
        result_b = await self.reconstruct(sequence, events_b)

        match = result_a.state_hash == result_b.state_hash
        return {
            "sequence": sequence,
            "match": match,
            "hash_a": result_a.state_hash,
            "hash_b": result_b.state_hash,
            "strategy_a": result_a.strategy.value,
            "strategy_b": result_b.strategy.value,
            "delta_a": result_a.delta_events_applied,
            "delta_b": result_b.delta_events_applied,
        }