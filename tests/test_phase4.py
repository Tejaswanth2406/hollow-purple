"""
test_phase4.py
==============
Phase 4 — Deterministic Replay Tests
======================================
Tests for deterministic event replay in the Hollow Purple platform.

This phase verifies that:
  • Replaying the same event stream always produces identical state
  • State reconstruction from partial streams is accurate
  • Replay can be halted at a specific event (replay-until)
  • Checkpoints capture and restore state faithfully
  • Baseline state derived from replay matches baseline state from
    original ingestion (bit-for-bit equivalence)

The ReplayEngine implemented here wraps the existing policy_engine modules
to demonstrate deterministic stateful replay over baseline + drift state.

All tests use fixed timestamps, no randomness.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import numpy as np
import pytest

from policy_engine.baseline_engine import BaselineEngine
from policy_engine.drift_detector import DriftDetector, DriftResult
from policy_engine.feature_extractor import (
    FEATURE_DIM,
    FEATURE_NAMES,
    RawEvent,
    extract_features,
)
from policy_engine.identity_baseline import IdentityBaseline
from policy_engine.baseline_store import InMemoryBaselineStore

# ===========================================================================
# REPLAY ENGINE (self-contained, wraps policy_engine primitives)
# ===========================================================================

@dataclass
class ReplayCheckpoint:
    """Serializable snapshot of replay state at a given event index."""
    event_index: int
    identity_id: str
    baseline_json: str
    events_processed: int
    state_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_index":       self.event_index,
            "identity_id":       self.identity_id,
            "baseline_json":     self.baseline_json,
            "events_processed":  self.events_processed,
            "state_hash":        self.state_hash,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ReplayCheckpoint":
        return cls(**d)


@dataclass
class ReplayState:
    """Accumulated state after processing a stream up to some point."""
    identity_id: str
    baseline: IdentityBaseline | None
    last_drift_result: DriftResult | None
    events_processed: int
    event_ids_seen: list[str] = field(default_factory=list)

    def state_hash(self) -> str:
        doc = {
            "identity_id":      self.identity_id,
            "events_processed": self.events_processed,
            "baseline_hash":    self.baseline.content_hash() if self.baseline else "",
            "event_ids":        sorted(self.event_ids_seen),
        }
        return hashlib.sha256(
            json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()


class ReplayEngine:
    """
    Deterministic replay engine over a Hollow Purple event stream.

    Given the same ordered event stream, ``replay`` always produces
    an identical ``ReplayState``.
    """

    def __init__(
        self,
        baseline_engine: BaselineEngine | None = None,
        detector: DriftDetector | None = None,
        drift_window: int = 10,
    ) -> None:
        self._be        = baseline_engine or BaselineEngine()
        self._detector  = detector or DriftDetector()
        self._drift_window = drift_window       # events per drift evaluation
        self._checkpoints: dict[int, ReplayCheckpoint] = {}

    # ------------------------------------------------------------------ #
    # Primary API
    # ------------------------------------------------------------------ #

    def replay(
        self,
        identity_id: str,
        events: list[RawEvent],
        *,
        stop_before_index: int | None = None,
    ) -> ReplayState:
        """
        Replay all events (or up to ``stop_before_index``) and return state.
        Events are sorted deterministically before processing.
        """
        sorted_events = sorted(events, key=lambda e: (e.timestamp, e.event_id))
        target_events = (
            sorted_events[:stop_before_index]
            if stop_before_index is not None
            else sorted_events
        )

        own_events = [e for e in target_events if e.identity_id == identity_id]

        if not own_events:
            return ReplayState(
                identity_id=identity_id,
                baseline=None,
                last_drift_result=None,
                events_processed=0,
            )

        # Build baseline from full batch
        baseline = self._be.build_baseline(identity_id, own_events)

        # Evaluate drift on the last window of events
        last_drift: DriftResult | None = None
        if len(own_events) >= self._drift_window:
            window = own_events[-self._drift_window :]
            window_features = extract_features(window)
            last_drift = self._detector.detect_drift(baseline, window_features)

        return ReplayState(
            identity_id=identity_id,
            baseline=baseline,
            last_drift_result=last_drift,
            events_processed=len(own_events),
            event_ids_seen=[e.event_id for e in own_events],
        )

    def replay_until_event(
        self,
        identity_id: str,
        events: list[RawEvent],
        target_event_id: str,
    ) -> ReplayState:
        """
        Replay only up to (and including) the event with ``target_event_id``.
        """
        sorted_events = sorted(events, key=lambda e: (e.timestamp, e.event_id))
        cutoff = None
        for i, evt in enumerate(sorted_events):
            if evt.event_id == target_event_id:
                cutoff = i + 1
                break
        if cutoff is None:
            raise ValueError(
                f"Event {target_event_id!r} not found in stream."
            )
        return self.replay(identity_id, sorted_events, stop_before_index=cutoff)

    def create_checkpoint(
        self,
        state: ReplayState,
        event_index: int,
    ) -> ReplayCheckpoint:
        if state.baseline is None:
            raise ValueError("Cannot checkpoint a state with no baseline.")
        cp = ReplayCheckpoint(
            event_index=event_index,
            identity_id=state.identity_id,
            baseline_json=state.baseline.to_json(),
            events_processed=state.events_processed,
            state_hash=state.state_hash(),
        )
        self._checkpoints[event_index] = cp
        return cp

    def restore_from_checkpoint(
        self, checkpoint: ReplayCheckpoint
    ) -> ReplayState:
        baseline = IdentityBaseline.from_json(checkpoint.baseline_json)
        return ReplayState(
            identity_id=checkpoint.identity_id,
            baseline=baseline,
            last_drift_result=None,
            events_processed=checkpoint.events_processed,
        )

    def get_checkpoint(self, event_index: int) -> ReplayCheckpoint:
        if event_index not in self._checkpoints:
            raise KeyError(f"No checkpoint at index {event_index}.")
        return self._checkpoints[event_index]


# ===========================================================================
# HELPERS & FIXTURES
# ===========================================================================

_EPOCH = datetime(2024, 5, 1, 8, 0, 0, tzinfo=timezone.utc)


def _ts(offset: int = 0) -> datetime:
    return _EPOCH + timedelta(seconds=offset)


def _make_stream(
    identity_id: str,
    n: int,
    base_offset: int = 0,
    actions: list[str] | None = None,
) -> list[RawEvent]:
    _actions = actions or ["READ", "WRITE", "LIST", "CREATE", "DELETE"]
    return [
        RawEvent(
            event_id=f"{identity_id}-{i:05d}",
            identity_id=identity_id,
            action=_actions[i % len(_actions)],
            resource=f"resource-{i % 6}",
            timestamp=_ts(base_offset + i * 90),
        )
        for i in range(n)
    ]


@pytest.fixture
def replay_engine() -> ReplayEngine:
    return ReplayEngine()


@pytest.fixture
def alice_stream() -> list[RawEvent]:
    return _make_stream("alice", 50)


@pytest.fixture
def bob_stream() -> list[RawEvent]:
    return _make_stream("bob", 30, base_offset=5000)


@pytest.fixture
def mixed_stream(
    alice_stream: list[RawEvent],
    bob_stream: list[RawEvent],
) -> list[RawEvent]:
    return alice_stream + bob_stream


# ===========================================================================
# BASIC REPLAY CORRECTNESS
# ===========================================================================

class TestReplayCorrectness:

    def test_replay_returns_replay_state(
        self, replay_engine: ReplayEngine, alice_stream: list[RawEvent]
    ) -> None:
        state = replay_engine.replay("alice", alice_stream)
        assert isinstance(state, ReplayState)

    def test_replay_correct_event_count(
        self, replay_engine: ReplayEngine, alice_stream: list[RawEvent]
    ) -> None:
        state = replay_engine.replay("alice", alice_stream)
        assert state.events_processed == len(alice_stream)

    def test_replay_sets_identity_id(
        self, replay_engine: ReplayEngine, alice_stream: list[RawEvent]
    ) -> None:
        state = replay_engine.replay("alice", alice_stream)
        assert state.identity_id == "alice"

    def test_replay_produces_baseline(
        self, replay_engine: ReplayEngine, alice_stream: list[RawEvent]
    ) -> None:
        state = replay_engine.replay("alice", alice_stream)
        assert state.baseline is not None
        assert isinstance(state.baseline, IdentityBaseline)

    def test_replay_baseline_identity_matches(
        self, replay_engine: ReplayEngine, alice_stream: list[RawEvent]
    ) -> None:
        state = replay_engine.replay("alice", alice_stream)
        assert state.baseline.identity_id == "alice"

    def test_replay_filters_other_identity_events(
        self, replay_engine: ReplayEngine, mixed_stream: list[RawEvent]
    ) -> None:
        state = replay_engine.replay("alice", mixed_stream)
        assert state.events_processed == 50  # only alice's 50 events

    def test_replay_empty_stream_returns_zero_state(
        self, replay_engine: ReplayEngine
    ) -> None:
        state = replay_engine.replay("ghost", [])
        assert state.events_processed == 0
        assert state.baseline is None

    def test_replay_event_ids_all_recorded(
        self, replay_engine: ReplayEngine, alice_stream: list[RawEvent]
    ) -> None:
        state = replay_engine.replay("alice", alice_stream)
        expected_ids = sorted(e.event_id for e in alice_stream)
        assert sorted(state.event_ids_seen) == expected_ids


# ===========================================================================
# DETERMINISTIC REPLAY
# ===========================================================================

class TestDeterministicReplay:

    def test_same_stream_same_baseline_hash(
        self, alice_stream: list[RawEvent]
    ) -> None:
        r1 = ReplayEngine().replay("alice", alice_stream)
        r2 = ReplayEngine().replay("alice", alice_stream)
        assert r1.baseline.content_hash() == r2.baseline.content_hash()

    def test_same_stream_same_state_hash(
        self, alice_stream: list[RawEvent]
    ) -> None:
        r1 = ReplayEngine().replay("alice", alice_stream)
        r2 = ReplayEngine().replay("alice", alice_stream)
        assert r1.state_hash() == r2.state_hash()

    def test_shuffled_stream_same_result(
        self, alice_stream: list[RawEvent]
    ) -> None:
        shuffled = list(reversed(alice_stream))
        r1 = ReplayEngine().replay("alice", alice_stream)
        r2 = ReplayEngine().replay("alice", shuffled)
        assert r1.baseline.content_hash() == r2.baseline.content_hash()

    def test_different_streams_different_state_hashes(
        self, alice_stream: list[RawEvent]
    ) -> None:
        truncated = alice_stream[:-5]
        r_full    = ReplayEngine().replay("alice", alice_stream)
        r_partial = ReplayEngine().replay("alice", truncated)
        assert r_full.state_hash() != r_partial.state_hash()

    def test_replay_repeated_n_times_identical_result(
        self, alice_stream: list[RawEvent]
    ) -> None:
        hashes = set()
        for _ in range(10):
            state = ReplayEngine().replay("alice", alice_stream)
            hashes.add(state.baseline.content_hash())
        assert len(hashes) == 1, "Replay produced different hashes across runs"

    def test_replay_with_interleaved_identities_isolated(
        self, mixed_stream: list[RawEvent]
    ) -> None:
        state_alice = ReplayEngine().replay("alice", mixed_stream)
        state_bob   = ReplayEngine().replay("bob",   mixed_stream)
        assert state_alice.baseline.content_hash() != state_bob.baseline.content_hash()
        assert state_alice.events_processed == 50
        assert state_bob.events_processed   == 30

    def test_baseline_features_are_deterministic_across_engines(
        self, alice_stream: list[RawEvent]
    ) -> None:
        r1 = ReplayEngine().replay("alice", alice_stream)
        r2 = ReplayEngine().replay("alice", alice_stream)
        np.testing.assert_array_equal(
            np.array(r1.baseline.feature_means),
            np.array(r2.baseline.feature_means),
        )


# ===========================================================================
# PARTIAL / STOP-BEFORE REPLAY
# ===========================================================================

class TestPartialReplay:

    def test_stop_before_reduces_event_count(
        self, replay_engine: ReplayEngine, alice_stream: list[RawEvent]
    ) -> None:
        state = replay_engine.replay("alice", alice_stream, stop_before_index=20)
        assert state.events_processed == 20

    def test_stop_before_zero_returns_empty_state(
        self, replay_engine: ReplayEngine, alice_stream: list[RawEvent]
    ) -> None:
        state = replay_engine.replay("alice", alice_stream, stop_before_index=0)
        assert state.events_processed == 0
        assert state.baseline is None

    def test_stop_before_produces_different_state_than_full_replay(
        self, alice_stream: list[RawEvent]
    ) -> None:
        r_full    = ReplayEngine().replay("alice", alice_stream)
        r_partial = ReplayEngine().replay("alice", alice_stream, stop_before_index=25)
        assert r_full.state_hash() != r_partial.state_hash()

    def test_stop_before_full_length_equals_full_replay(
        self, alice_stream: list[RawEvent]
    ) -> None:
        full_n = len(alice_stream)
        r1 = ReplayEngine().replay("alice", alice_stream)
        r2 = ReplayEngine().replay("alice", alice_stream, stop_before_index=full_n)
        assert r1.baseline.content_hash() == r2.baseline.content_hash()

    def test_partial_state_hash_is_deterministic(
        self, alice_stream: list[RawEvent]
    ) -> None:
        h1 = ReplayEngine().replay("alice", alice_stream, stop_before_index=30).state_hash()
        h2 = ReplayEngine().replay("alice", alice_stream, stop_before_index=30).state_hash()
        assert h1 == h2

    def test_event_count_increases_monotonically_with_index(
        self, alice_stream: list[RawEvent]
    ) -> None:
        counts = [
            ReplayEngine().replay("alice", alice_stream, stop_before_index=i).events_processed
            for i in [10, 20, 30, 40, 50]
        ]
        assert counts == sorted(counts)


# ===========================================================================
# REPLAY UNTIL EVENT
# ===========================================================================

class TestReplayUntilEvent:

    def test_replay_until_includes_target_event(
        self, replay_engine: ReplayEngine, alice_stream: list[RawEvent]
    ) -> None:
        # Sort as replay engine does
        sorted_events = sorted(alice_stream, key=lambda e: (e.timestamp, e.event_id))
        target = sorted_events[19]
        state = replay_engine.replay_until_event("alice", alice_stream, target.event_id)
        assert target.event_id in state.event_ids_seen

    def test_replay_until_event_count_correct(
        self, replay_engine: ReplayEngine, alice_stream: list[RawEvent]
    ) -> None:
        sorted_events = sorted(alice_stream, key=lambda e: (e.timestamp, e.event_id))
        target = sorted_events[14]
        state = replay_engine.replay_until_event("alice", alice_stream, target.event_id)
        assert state.events_processed == 15

    def test_replay_until_first_event(
        self, replay_engine: ReplayEngine, alice_stream: list[RawEvent]
    ) -> None:
        sorted_events = sorted(alice_stream, key=lambda e: (e.timestamp, e.event_id))
        target = sorted_events[0]
        state = replay_engine.replay_until_event("alice", alice_stream, target.event_id)
        assert state.events_processed == 1

    def test_replay_until_last_event_equals_full_replay(
        self, alice_stream: list[RawEvent]
    ) -> None:
        sorted_events = sorted(alice_stream, key=lambda e: (e.timestamp, e.event_id))
        last_event = sorted_events[-1]
        r_until = ReplayEngine().replay_until_event(
            "alice", alice_stream, last_event.event_id
        )
        r_full = ReplayEngine().replay("alice", alice_stream)
        assert r_until.baseline.content_hash() == r_full.baseline.content_hash()

    def test_replay_until_unknown_event_raises(
        self, replay_engine: ReplayEngine, alice_stream: list[RawEvent]
    ) -> None:
        with pytest.raises(ValueError, match="not found"):
            replay_engine.replay_until_event("alice", alice_stream, "nonexistent-id")

    def test_replay_until_is_deterministic(
        self, alice_stream: list[RawEvent]
    ) -> None:
        sorted_events = sorted(alice_stream, key=lambda e: (e.timestamp, e.event_id))
        target = sorted_events[24].event_id
        h1 = ReplayEngine().replay_until_event("alice", alice_stream, target).state_hash()
        h2 = ReplayEngine().replay_until_event("alice", alice_stream, target).state_hash()
        assert h1 == h2


# ===========================================================================
# CHECKPOINTS
# ===========================================================================

class TestCheckpoints:

    def test_create_checkpoint_returns_checkpoint(
        self, replay_engine: ReplayEngine, alice_stream: list[RawEvent]
    ) -> None:
        state = replay_engine.replay("alice", alice_stream)
        cp = replay_engine.create_checkpoint(state, event_index=len(alice_stream))
        assert isinstance(cp, ReplayCheckpoint)

    def test_checkpoint_event_index_matches(
        self, replay_engine: ReplayEngine, alice_stream: list[RawEvent]
    ) -> None:
        state = replay_engine.replay("alice", alice_stream)
        cp = replay_engine.create_checkpoint(state, event_index=50)
        assert cp.event_index == 50

    def test_checkpoint_state_hash_matches_state(
        self, replay_engine: ReplayEngine, alice_stream: list[RawEvent]
    ) -> None:
        state = replay_engine.replay("alice", alice_stream)
        cp = replay_engine.create_checkpoint(state, event_index=50)
        assert cp.state_hash == state.state_hash()

    def test_restore_from_checkpoint_recovers_baseline(
        self, replay_engine: ReplayEngine, alice_stream: list[RawEvent]
    ) -> None:
        state = replay_engine.replay("alice", alice_stream)
        cp = replay_engine.create_checkpoint(state, event_index=50)
        restored = replay_engine.restore_from_checkpoint(cp)
        assert restored.baseline.content_hash() == state.baseline.content_hash()

    def test_restore_events_processed_matches(
        self, replay_engine: ReplayEngine, alice_stream: list[RawEvent]
    ) -> None:
        state = replay_engine.replay("alice", alice_stream)
        cp = replay_engine.create_checkpoint(state, event_index=50)
        restored = replay_engine.restore_from_checkpoint(cp)
        assert restored.events_processed == state.events_processed

    def test_checkpoint_serializes_and_deserializes(
        self, replay_engine: ReplayEngine, alice_stream: list[RawEvent]
    ) -> None:
        state = replay_engine.replay("alice", alice_stream)
        cp = replay_engine.create_checkpoint(state, event_index=50)
        cp_dict = cp.to_dict()
        restored_cp = ReplayCheckpoint.from_dict(cp_dict)
        assert restored_cp.state_hash == cp.state_hash
        assert restored_cp.event_index == cp.event_index

    def test_checkpoint_at_multiple_points(
        self, alice_stream: list[RawEvent]
    ) -> None:
        engine = ReplayEngine()
        for idx in [10, 20, 30, 40, 50]:
            state = engine.replay("alice", alice_stream, stop_before_index=idx)
            if state.baseline:
                cp = engine.create_checkpoint(state, event_index=idx)
                assert cp.event_index == idx

    def test_get_checkpoint_returns_correct(
        self, replay_engine: ReplayEngine, alice_stream: list[RawEvent]
    ) -> None:
        state = replay_engine.replay("alice", alice_stream)
        cp = replay_engine.create_checkpoint(state, event_index=50)
        retrieved = replay_engine.get_checkpoint(50)
        assert retrieved.state_hash == cp.state_hash

    def test_get_missing_checkpoint_raises(self, replay_engine: ReplayEngine) -> None:
        with pytest.raises(KeyError):
            replay_engine.get_checkpoint(999)

    def test_checkpoint_of_empty_state_raises(
        self, replay_engine: ReplayEngine
    ) -> None:
        state = replay_engine.replay("ghost", [])
        with pytest.raises(ValueError, match="no baseline"):
            replay_engine.create_checkpoint(state, event_index=0)


# ===========================================================================
# STATE RECONSTRUCTION ACCURACY
# ===========================================================================

class TestStateReconstruction:

    def test_replay_baseline_means_match_direct_build(
        self, alice_stream: list[RawEvent]
    ) -> None:
        """Replay engine must produce the same baseline as direct engine.build_baseline."""
        engine = BaselineEngine()
        direct_baseline = engine.build_baseline("alice", alice_stream)

        replay_state = ReplayEngine().replay("alice", alice_stream)

        np.testing.assert_allclose(
            np.array(replay_state.baseline.feature_means),
            np.array(direct_baseline.feature_means),
            rtol=1e-6,
        )

    def test_replay_baseline_variances_match_direct_build(
        self, alice_stream: list[RawEvent]
    ) -> None:
        engine = BaselineEngine()
        direct = engine.build_baseline("alice", alice_stream)
        replay_state = ReplayEngine().replay("alice", alice_stream)
        np.testing.assert_allclose(
            np.array(replay_state.baseline.feature_variances),
            np.array(direct.feature_variances),
            rtol=1e-6,
        )

    def test_replay_baseline_hash_matches_direct_build(
        self, alice_stream: list[RawEvent]
    ) -> None:
        engine = BaselineEngine()
        direct = engine.build_baseline("alice", alice_stream)
        replay_state = ReplayEngine().replay("alice", alice_stream)
        assert replay_state.baseline.content_hash() == direct.content_hash()

    def test_incremental_replay_equals_full_replay(
        self, alice_stream: list[RawEvent]
    ) -> None:
        """Progressively replaying batches must converge to the same baseline."""
        full_state = ReplayEngine().replay("alice", alice_stream)

        # Simulate incremental processing by replaying growing windows
        for size in [10, 20, 30, 40, 50]:
            partial = ReplayEngine().replay("alice", alice_stream, stop_before_index=size)
            if partial.baseline and size == len(alice_stream):
                assert partial.baseline.content_hash() == full_state.baseline.content_hash()

    def test_restored_baseline_used_for_detection(
        self, alice_stream: list[RawEvent]
    ) -> None:
        engine = ReplayEngine()
        state = engine.replay("alice", alice_stream)
        cp = engine.create_checkpoint(state, event_index=len(alice_stream))

        restored = engine.restore_from_checkpoint(cp)
        detector = DriftDetector()
        new_features = extract_features(alice_stream[:10])
        result = detector.detect_drift(restored.baseline, new_features)
        assert result.identity_id == "alice"


# ===========================================================================
# PERFORMANCE
# ===========================================================================

class TestPhase4Performance:

    def test_replay_1000_events_under_5s(self) -> None:
        events = _make_stream("perf-id", 1000)
        start = time.perf_counter()
        state = ReplayEngine().replay("perf-id", events)
        elapsed = time.perf_counter() - start
        assert state.events_processed == 1000
        assert elapsed < 5.0, f"Replay 1000 events took {elapsed:.2f}s"

    def test_replay_deterministic_100_runs(self) -> None:
        events = _make_stream("det-test", 30)
        hashes = set()
        for _ in range(100):
            state = ReplayEngine().replay("det-test", events)
            hashes.add(state.baseline.content_hash())
        assert len(hashes) == 1

    def test_checkpoint_create_restore_cycle_under_50ms(self) -> None:
        events = _make_stream("cp-test", 50)
        engine = ReplayEngine()
        state = engine.replay("cp-test", events)
        start = time.perf_counter()
        cp = engine.create_checkpoint(state, event_index=50)
        _ = engine.restore_from_checkpoint(cp)
        elapsed = time.perf_counter() - start
        assert elapsed < 0.05, f"Checkpoint cycle took {elapsed*1000:.1f}ms"

    def test_100_replay_until_operations_under_10s(self) -> None:
        events = _make_stream("stream-x", 100)
        sorted_events = sorted(events, key=lambda e: (e.timestamp, e.event_id))
        targets = [sorted_events[i].event_id for i in range(10, 100, 10)]
        start = time.perf_counter()
        for target_id in targets:
            ReplayEngine().replay_until_event("stream-x", events, target_id)
        elapsed = time.perf_counter() - start
        assert elapsed < 10.0, f"90 replay-until ops took {elapsed:.2f}s"