"""
test_phase2.py
==============
Phase 2 — Policy Engine Baseline Tests
========================================
Tests for:
  • feature_extractor  – deterministic feature vectors from raw events
  • identity_baseline  – immutable baseline model, hashing, serialization
  • baseline_engine    – build / update / merge baselines via Welford
  • baseline_store     – InMemoryBaselineStore & FileBaselineStore

All tests are fully deterministic: fixed timestamps, no random state.
"""

from __future__ import annotations

import json
import math
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pytest

from policy_engine.feature_extractor import (
    FEATURE_DIM,
    FEATURE_NAMES,
    RawEvent,
    aggregate_features,
    extract_features,
    normalize_features,
    validate_feature_vector,
)
from policy_engine.identity_baseline import BASELINE_SCHEMA_VERSION, IdentityBaseline
from policy_engine.baseline_engine import BaselineEngine
from policy_engine.baseline_store import (
    BaselineStore,
    FileBaselineStore,
    InMemoryBaselineStore,
)

# ===========================================================================
# SHARED FIXTURES & HELPERS
# ===========================================================================

_EPOCH = datetime(2024, 3, 1, 9, 0, 0, tzinfo=timezone.utc)


def _ts(offset_seconds: int = 0) -> datetime:
    return _EPOCH + timedelta(seconds=offset_seconds)


def _evt(
    event_id: str,
    identity_id: str = "alice",
    action: str = "READ",
    resource: str = "doc-1",
    offset: int = 0,
) -> RawEvent:
    return RawEvent(
        event_id=event_id,
        identity_id=identity_id,
        action=action,
        resource=resource,
        timestamp=_ts(offset),
    )


def _make_event_stream(
    identity_id: str,
    n: int,
    *,
    base_offset: int = 0,
    actions: list[str] | None = None,
    resources: list[str] | None = None,
) -> list[RawEvent]:
    _actions  = actions  or ["READ", "WRITE", "DELETE", "CREATE", "LIST"]
    _resources = resources or [f"res-{i % 4}" for i in range(n)]
    return [
        RawEvent(
            event_id=f"{identity_id}-evt-{i:04d}",
            identity_id=identity_id,
            action=_actions[i % len(_actions)],
            resource=_resources[i % len(_resources)],
            timestamp=_ts(base_offset + i * 60),
        )
        for i in range(n)
    ]


@pytest.fixture
def alice_events() -> list[RawEvent]:
    return _make_event_stream("alice", 30)


@pytest.fixture
def bob_events() -> list[RawEvent]:
    return _make_event_stream("bob", 20, base_offset=1800)


@pytest.fixture
def engine() -> BaselineEngine:
    return BaselineEngine()


@pytest.fixture
def mem_store() -> InMemoryBaselineStore:
    return InMemoryBaselineStore()


@pytest.fixture
def file_store(tmp_path: Path) -> FileBaselineStore:
    return FileBaselineStore(tmp_path / "baselines")


# ===========================================================================
# FEATURE EXTRACTOR TESTS
# ===========================================================================

class TestFeatureExtractor:

    def test_empty_events_returns_zero_vector(self) -> None:
        vec = extract_features([])
        assert vec.shape == (FEATURE_DIM,)
        assert np.all(vec == 0.0)

    def test_output_shape_matches_feature_dim(self, alice_events: list[RawEvent]) -> None:
        vec = extract_features(alice_events)
        assert vec.shape == (FEATURE_DIM,)

    def test_output_dtype_is_float64(self, alice_events: list[RawEvent]) -> None:
        vec = extract_features(alice_events)
        assert vec.dtype == np.float64

    def test_all_values_are_finite(self, alice_events: list[RawEvent]) -> None:
        vec = extract_features(alice_events)
        assert np.isfinite(vec).all()

    def test_extraction_is_deterministic_same_input(self, alice_events: list[RawEvent]) -> None:
        v1 = extract_features(alice_events)
        v2 = extract_features(alice_events)
        np.testing.assert_array_equal(v1, v2)

    def test_extraction_is_order_invariant(self, alice_events: list[RawEvent]) -> None:
        shuffled = list(reversed(alice_events))
        v1 = extract_features(alice_events)
        v2 = extract_features(shuffled)
        np.testing.assert_array_equal(v1, v2)

    def test_event_frequency_is_positive(self, alice_events: list[RawEvent]) -> None:
        vec = extract_features(alice_events)
        freq_idx = FEATURE_NAMES.index("event_frequency")
        assert vec[freq_idx] > 0.0

    def test_unique_resource_ratio_between_zero_and_one(self) -> None:
        events = _make_event_stream("alice", 20)
        vec = extract_features(events)
        ratio_idx = FEATURE_NAMES.index("unique_resource_ratio")
        assert 0.0 <= vec[ratio_idx] <= 1.0

    def test_action_entropy_non_negative(self, alice_events: list[RawEvent]) -> None:
        vec = extract_features(alice_events)
        ent_idx = FEATURE_NAMES.index("action_entropy")
        assert vec[ent_idx] >= 0.0

    def test_single_action_type_yields_zero_entropy(self) -> None:
        events = [_evt(f"e-{i}", action="READ", offset=i * 100) for i in range(10)]
        vec = extract_features(events)
        ent_idx = FEATURE_NAMES.index("action_entropy")
        assert vec[ent_idx] == 0.0

    def test_max_entropy_for_uniform_actions(self) -> None:
        # Two equally frequent actions → entropy = 1.0 (1 bit)
        events = [
            _evt("e-0", action="READ",  offset=0),
            _evt("e-1", action="WRITE", offset=100),
            _evt("e-2", action="READ",  offset=200),
            _evt("e-3", action="WRITE", offset=300),
        ]
        vec = extract_features(events)
        ent_idx = FEATURE_NAMES.index("action_entropy")
        assert abs(vec[ent_idx] - 1.0) < 1e-6

    def test_tod_buckets_sum_to_one(self) -> None:
        events = _make_event_stream("alice", 20)
        vec = extract_features(events)
        bucket_indices = [FEATURE_NAMES.index(f"tod_bucket_{i}") for i in range(6)]
        total = sum(vec[i] for i in bucket_indices)
        assert abs(total - 1.0) < 1e-9

    def test_burst_ratio_between_zero_and_one(self) -> None:
        events = _make_event_stream("alice", 20)
        vec = extract_features(events)
        burst_idx = FEATURE_NAMES.index("burst_ratio")
        assert 0.0 <= vec[burst_idx] <= 1.0

    def test_high_burst_ratio_for_rapid_events(self) -> None:
        # All events within 60 s of each other → burst_ratio should be 1.0
        events = [_evt(f"e-{i}", offset=i * 5) for i in range(10)]
        vec = extract_features(events)
        burst_idx = FEATURE_NAMES.index("burst_ratio")
        assert vec[burst_idx] == 1.0

    def test_feature_names_length_matches_dim(self) -> None:
        assert len(FEATURE_NAMES) == FEATURE_DIM

    def test_single_event_returns_finite_vector(self) -> None:
        events = [_evt("e-0")]
        vec = extract_features(events)
        assert np.isfinite(vec).all()

    def test_different_identities_produce_different_vectors(
        self, alice_events: list[RawEvent], bob_events: list[RawEvent]
    ) -> None:
        v_alice = extract_features(alice_events)
        v_bob   = extract_features(bob_events)
        assert not np.allclose(v_alice, v_bob)

    def test_aggregate_features_shape(
        self, alice_events: list[RawEvent], bob_events: list[RawEvent]
    ) -> None:
        mixed = alice_events + bob_events
        vec = aggregate_features(mixed)
        assert vec.shape == (FEATURE_DIM,)

    def test_aggregate_features_empty_returns_zeros(self) -> None:
        vec = aggregate_features([])
        assert np.all(vec == 0.0)

    def test_normalize_features_zero_std_dims_become_zero(self) -> None:
        features = np.ones(FEATURE_DIM, dtype=np.float64)
        means    = np.ones(FEATURE_DIM, dtype=np.float64)
        stds     = np.zeros(FEATURE_DIM, dtype=np.float64)
        norm = normalize_features(features, means, stds)
        assert np.all(norm == 0.0)

    def test_normalize_features_known_values(self) -> None:
        features = np.array([10.0] + [0.0] * (FEATURE_DIM - 1))
        means    = np.array([5.0]  + [0.0] * (FEATURE_DIM - 1))
        stds     = np.array([2.5]  + [1.0] * (FEATURE_DIM - 1))
        norm = normalize_features(features, means, stds)
        assert abs(norm[0] - 2.0) < 1e-9

    def test_validate_feature_vector_correct_shape_passes(self) -> None:
        vec = np.zeros(FEATURE_DIM)
        validate_feature_vector(vec)   # should not raise

    def test_validate_feature_vector_wrong_dim_raises(self) -> None:
        with pytest.raises(ValueError, match="Expected"):
            validate_feature_vector(np.zeros(FEATURE_DIM + 1))

    def test_validate_feature_vector_nan_raises(self) -> None:
        vec = np.zeros(FEATURE_DIM)
        vec[0] = float("nan")
        with pytest.raises(ValueError, match="Non-finite"):
            validate_feature_vector(vec)

    def test_validate_feature_vector_inf_raises(self) -> None:
        vec = np.zeros(FEATURE_DIM)
        vec[3] = float("inf")
        with pytest.raises(ValueError, match="Non-finite"):
            validate_feature_vector(vec)


# ===========================================================================
# IDENTITY BASELINE MODEL TESTS
# ===========================================================================

class TestIdentityBaseline:

    def _make_baseline(
        self,
        identity_id: str = "alice",
        dim: int = FEATURE_DIM,
        n: int = 50,
    ) -> IdentityBaseline:
        fv = tuple(float(i) * 0.1 for i in range(dim))
        return IdentityBaseline(
            identity_id=identity_id,
            feature_vector=fv,
            feature_means=fv,
            feature_variances=tuple(0.01 for _ in range(dim)),
            feature_names=FEATURE_NAMES,
            event_count=n,
        )

    def test_baseline_is_immutable(self) -> None:
        b = self._make_baseline()
        with pytest.raises((AttributeError, TypeError)):
            b.identity_id = "hacked"  # type: ignore[misc]

    def test_content_hash_is_deterministic(self) -> None:
        b = self._make_baseline()
        assert b.content_hash() == b.content_hash()

    def test_different_identity_different_hash(self) -> None:
        b1 = self._make_baseline("alice")
        b2 = self._make_baseline("bob")
        assert b1.content_hash() != b2.content_hash()

    def test_is_equivalent_to_itself(self) -> None:
        b = self._make_baseline()
        assert b.is_equivalent_to(b)

    def test_is_not_equivalent_to_different_baseline(self) -> None:
        b1 = self._make_baseline("alice")
        b2 = self._make_baseline("bob")
        assert not b1.is_equivalent_to(b2)

    def test_feature_dim_property(self) -> None:
        b = self._make_baseline(dim=FEATURE_DIM)
        assert b.feature_dim == FEATURE_DIM

    def test_feature_stds_computed_from_variances(self) -> None:
        fv = tuple(0.1 for _ in range(FEATURE_DIM))
        b = IdentityBaseline(
            identity_id="x",
            feature_vector=fv,
            feature_means=fv,
            feature_variances=tuple(4.0 for _ in range(FEATURE_DIM)),
            event_count=10,
        )
        for std in b.feature_stds:
            assert abs(std - 2.0) < 1e-9

    def test_empty_baseline_via_factory(self) -> None:
        b = IdentityBaseline.empty("alice")
        assert b.is_empty() is True
        assert b.event_count == 0

    def test_negative_event_count_raises(self) -> None:
        with pytest.raises(ValueError, match="event_count"):
            IdentityBaseline(identity_id="x", event_count=-1)

    def test_mismatched_feature_dims_raises(self) -> None:
        with pytest.raises(ValueError):
            IdentityBaseline(
                identity_id="x",
                feature_vector=(1.0, 2.0),
                feature_means=(1.0,),
                feature_variances=(0.0,),
                event_count=1,
            )

    def test_negative_variance_raises(self) -> None:
        with pytest.raises(ValueError, match="variance"):
            IdentityBaseline(
                identity_id="x",
                feature_vector=(1.0,),
                feature_means=(1.0,),
                feature_variances=(-0.1,),
                event_count=1,
            )

    def test_serialization_round_trip(self) -> None:
        b = self._make_baseline()
        d = b.to_dict()
        restored = IdentityBaseline.from_dict(d)
        assert restored.is_equivalent_to(b)

    def test_json_round_trip(self) -> None:
        b = self._make_baseline()
        j = b.to_json()
        restored = IdentityBaseline.from_json(j)
        assert restored.is_equivalent_to(b)

    def test_tampered_json_raises_on_load(self) -> None:
        b = self._make_baseline()
        d = b.to_dict()
        d["event_count"] = 9999          # tamper
        with pytest.raises(ValueError, match="Integrity check"):
            IdentityBaseline.from_dict(d)

    def test_feature_distance_to_itself_is_zero(self) -> None:
        b = self._make_baseline()
        assert b.feature_distance(b) == 0.0

    def test_feature_distance_incompatible_dims_returns_minus_one(self) -> None:
        b1 = IdentityBaseline(
            identity_id="x",
            feature_vector=(1.0, 2.0),
            feature_means=(1.0, 2.0),
            feature_variances=(0.0, 0.0),
            event_count=1,
        )
        b2 = IdentityBaseline(
            identity_id="y",
            feature_vector=(1.0,),
            feature_means=(1.0,),
            feature_variances=(0.0,),
            event_count=1,
        )
        assert b1.feature_distance(b2) == -1.0

    def test_schema_version_present_in_serialization(self) -> None:
        b = self._make_baseline()
        d = b.to_dict()
        assert d["schema_version"] == BASELINE_SCHEMA_VERSION


# ===========================================================================
# BASELINE ENGINE TESTS
# ===========================================================================

class TestBaselineEngine:

    def test_build_baseline_returns_identity_baseline(
        self, engine: BaselineEngine, alice_events: list[RawEvent]
    ) -> None:
        b = engine.build_baseline("alice", alice_events)
        assert isinstance(b, IdentityBaseline)
        assert b.identity_id == "alice"

    def test_build_baseline_event_count_correct(
        self, engine: BaselineEngine, alice_events: list[RawEvent]
    ) -> None:
        b = engine.build_baseline("alice", alice_events)
        assert b.event_count == len(alice_events)

    def test_build_baseline_is_deterministic(
        self, alice_events: list[RawEvent]
    ) -> None:
        e1 = BaselineEngine()
        e2 = BaselineEngine()
        b1 = e1.build_baseline("alice", alice_events)
        b2 = e2.build_baseline("alice", alice_events)
        assert b1.is_equivalent_to(b2)

    def test_build_baseline_shuffled_events_same_result(
        self, alice_events: list[RawEvent]
    ) -> None:
        shuffled = list(reversed(alice_events))
        e1 = BaselineEngine()
        e2 = BaselineEngine()
        b1 = e1.build_baseline("alice", alice_events)
        b2 = e2.build_baseline("alice", shuffled)
        assert b1.is_equivalent_to(b2)

    def test_build_baseline_skips_other_identity_events(
        self, engine: BaselineEngine,
        alice_events: list[RawEvent],
        bob_events: list[RawEvent],
    ) -> None:
        mixed = alice_events + bob_events
        b = engine.build_baseline("alice", mixed)
        assert b.event_count == len(alice_events)

    def test_build_baseline_no_events_returns_empty(
        self, engine: BaselineEngine
    ) -> None:
        b = engine.build_baseline("ghost", [])
        assert b.is_empty()

    def test_update_baseline_increases_event_count(
        self, engine: BaselineEngine, alice_events: list[RawEvent]
    ) -> None:
        first_half  = alice_events[:15]
        second_half = alice_events[15:]
        b1 = engine.build_baseline("alice", first_half)
        b2 = engine.update_baseline(b1, second_half)
        assert b2.event_count == len(alice_events)

    def test_update_baseline_with_no_new_events_returns_same(
        self, engine: BaselineEngine, alice_events: list[RawEvent]
    ) -> None:
        b1 = engine.build_baseline("alice", alice_events)
        b2 = engine.update_baseline(b1, [])
        assert b2.is_equivalent_to(b1)

    def test_incremental_build_equals_full_build(
        self, alice_events: list[RawEvent]
    ) -> None:
        # Full build in one pass
        e_full = BaselineEngine()
        b_full = e_full.build_baseline("alice", alice_events)

        # Incremental build in 3 batches
        e_inc = BaselineEngine()
        b_inc = e_inc.build_baseline("alice", alice_events[:10])
        b_inc = e_inc.update_baseline(b_inc, alice_events[10:20])
        b_inc = e_inc.update_baseline(b_inc, alice_events[20:])

        # Means should be numerically close (Welford ordering differs)
        np.testing.assert_allclose(
            np.array(b_full.feature_means),
            np.array(b_inc.feature_means),
            rtol=1e-6,
        )

    def test_merge_baselines_same_identity(
        self, engine: BaselineEngine, alice_events: list[RawEvent]
    ) -> None:
        b1 = engine.build_baseline("alice", alice_events[:15])
        b2 = engine.build_baseline("alice", alice_events[15:])
        merged = engine.merge_baselines([b1, b2])
        assert merged.identity_id == "alice"
        assert merged.event_count == b1.event_count + b2.event_count

    def test_merge_baselines_different_identities_raises(
        self, engine: BaselineEngine,
        alice_events: list[RawEvent],
        bob_events: list[RawEvent],
    ) -> None:
        b_alice = engine.build_baseline("alice", alice_events)
        b_bob   = engine.build_baseline("bob",   bob_events)
        with pytest.raises(ValueError, match="same identity"):
            engine.merge_baselines([b_alice, b_bob])

    def test_merge_empty_list_raises(self, engine: BaselineEngine) -> None:
        with pytest.raises(ValueError):
            engine.merge_baselines([])

    def test_known_identities_reflects_built_baselines(
        self, engine: BaselineEngine,
        alice_events: list[RawEvent],
        bob_events: list[RawEvent],
    ) -> None:
        engine.build_baseline("alice", alice_events)
        engine.build_baseline("bob",   bob_events)
        assert "alice" in engine.known_identities()
        assert "bob"   in engine.known_identities()

    def test_reset_removes_identity_state(
        self, engine: BaselineEngine, alice_events: list[RawEvent]
    ) -> None:
        engine.build_baseline("alice", alice_events)
        assert "alice" in engine.known_identities()
        engine.reset("alice")
        assert "alice" not in engine.known_identities()

    def test_feature_means_are_stable_floats(
        self, engine: BaselineEngine, alice_events: list[RawEvent]
    ) -> None:
        b = engine.build_baseline("alice", alice_events)
        for mean in b.feature_means:
            assert math.isfinite(mean)

    def test_feature_variances_are_non_negative(
        self, engine: BaselineEngine, alice_events: list[RawEvent]
    ) -> None:
        b = engine.build_baseline("alice", alice_events)
        for var in b.feature_variances:
            assert var >= 0.0


# ===========================================================================
# BASELINE STORE TESTS (in-memory)
# ===========================================================================

class TestInMemoryBaselineStore:

    def _sample_baseline(self, identity_id: str = "alice") -> IdentityBaseline:
        fv = tuple(float(i) * 0.05 for i in range(FEATURE_DIM))
        return IdentityBaseline(
            identity_id=identity_id,
            feature_vector=fv,
            feature_means=fv,
            feature_variances=tuple(0.01 for _ in range(FEATURE_DIM)),
            feature_names=FEATURE_NAMES,
            event_count=20,
        )

    def test_save_and_load_roundtrip(self, mem_store: InMemoryBaselineStore) -> None:
        b = self._sample_baseline("alice")
        mem_store.save_baseline(b)
        loaded = mem_store.load_baseline("alice")
        assert loaded.is_equivalent_to(b)

    def test_load_missing_raises_key_error(self, mem_store: InMemoryBaselineStore) -> None:
        with pytest.raises(KeyError):
            mem_store.load_baseline("ghost")

    def test_list_baselines_sorted(self, mem_store: InMemoryBaselineStore) -> None:
        for iid in ["charlie", "alice", "bob"]:
            mem_store.save_baseline(self._sample_baseline(iid))
        assert mem_store.list_baselines() == ["alice", "bob", "charlie"]

    def test_delete_baseline(self, mem_store: InMemoryBaselineStore) -> None:
        mem_store.save_baseline(self._sample_baseline("alice"))
        mem_store.delete_baseline("alice")
        assert "alice" not in mem_store

    def test_delete_missing_raises(self, mem_store: InMemoryBaselineStore) -> None:
        with pytest.raises(KeyError):
            mem_store.delete_baseline("nobody")

    def test_overwrite_existing_baseline(self, mem_store: InMemoryBaselineStore) -> None:
        b1 = self._sample_baseline("alice")
        mem_store.save_baseline(b1)
        b2 = IdentityBaseline(
            identity_id="alice",
            feature_vector=tuple(1.0 for _ in range(FEATURE_DIM)),
            feature_means=tuple(1.0 for _ in range(FEATURE_DIM)),
            feature_variances=tuple(0.0 for _ in range(FEATURE_DIM)),
            feature_names=FEATURE_NAMES,
            event_count=100,
        )
        mem_store.save_baseline(b2)
        loaded = mem_store.load_baseline("alice")
        assert loaded.event_count == 100

    def test_len_reflects_stored_count(self, mem_store: InMemoryBaselineStore) -> None:
        for iid in ["a", "b", "c"]:
            mem_store.save_baseline(self._sample_baseline(iid))
        assert len(mem_store) == 3

    def test_contains_operator(self, mem_store: InMemoryBaselineStore) -> None:
        mem_store.save_baseline(self._sample_baseline("alice"))
        assert "alice" in mem_store
        assert "nobody" not in mem_store

    def test_save_all_and_load_all(self, mem_store: InMemoryBaselineStore) -> None:
        baselines = [self._sample_baseline(iid) for iid in ["a", "b", "c"]]
        mem_store.save_all(baselines)
        loaded = mem_store.load_all()
        assert len(loaded) == 3

    def test_clear_empties_store(self, mem_store: InMemoryBaselineStore) -> None:
        mem_store.save_baseline(self._sample_baseline("alice"))
        mem_store.clear()
        assert len(mem_store) == 0

    def test_thread_safe_concurrent_saves(self, mem_store: InMemoryBaselineStore) -> None:
        errors: list[Exception] = []

        def save(iid: str) -> None:
            try:
                mem_store.save_baseline(self._sample_baseline(iid))
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=save, args=(f"id-{i}",)) for i in range(20)]
        for t in threads: t.start()
        for t in threads: t.join()

        assert errors == []
        assert len(mem_store) == 20

    def test_save_non_baseline_raises(self, mem_store: InMemoryBaselineStore) -> None:
        with pytest.raises(TypeError):
            mem_store.save_baseline("not-a-baseline")  # type: ignore[arg-type]


# ===========================================================================
# BASELINE STORE TESTS (file-based)
# ===========================================================================

class TestFileBaselineStore:

    def _sample_baseline(self, identity_id: str = "alice") -> IdentityBaseline:
        fv = tuple(float(i) * 0.1 for i in range(FEATURE_DIM))
        return IdentityBaseline(
            identity_id=identity_id,
            feature_vector=fv,
            feature_means=fv,
            feature_variances=tuple(0.02 for _ in range(FEATURE_DIM)),
            feature_names=FEATURE_NAMES,
            event_count=30,
        )

    def test_save_creates_json_file(self, file_store: FileBaselineStore) -> None:
        b = self._sample_baseline("alice")
        file_store.save_baseline(b)
        files = list(file_store.storage_path().glob("*.json"))
        assert len(files) == 1

    def test_load_round_trip(self, file_store: FileBaselineStore) -> None:
        b = self._sample_baseline("alice")
        file_store.save_baseline(b)
        loaded = file_store.load_baseline("alice")
        assert loaded.is_equivalent_to(b)

    def test_load_missing_raises_key_error(self, file_store: FileBaselineStore) -> None:
        with pytest.raises(KeyError):
            file_store.load_baseline("ghost")

    def test_delete_removes_file(self, file_store: FileBaselineStore) -> None:
        file_store.save_baseline(self._sample_baseline("alice"))
        file_store.delete_baseline("alice")
        assert not (file_store.storage_path() / "alice.json").exists()

    def test_list_baselines_sorted(self, file_store: FileBaselineStore) -> None:
        for iid in ["charlie", "alice", "bob"]:
            file_store.save_baseline(self._sample_baseline(iid))
        assert file_store.list_baselines() == ["alice", "bob", "charlie"]

    def test_corrupt_file_raises_on_load(self, file_store: FileBaselineStore) -> None:
        b = self._sample_baseline("alice")
        file_store.save_baseline(b)
        # Corrupt the file
        path = file_store.storage_path() / "alice.json"
        data = json.loads(path.read_text())
        data["event_count"] = 9999
        path.write_text(json.dumps(data))
        with pytest.raises(ValueError, match="corrupt"):
            file_store.load_baseline("alice")

    def test_purge_all_removes_all_files(self, file_store: FileBaselineStore) -> None:
        for iid in ["a", "b", "c"]:
            file_store.save_baseline(self._sample_baseline(iid))
        removed = file_store.purge_all()
        assert removed == 3
        assert len(file_store) == 0

    def test_save_is_atomic_existing_file_not_corrupted_on_crash(
        self, file_store: FileBaselineStore
    ) -> None:
        b = self._sample_baseline("alice")
        file_store.save_baseline(b)
        loaded = file_store.load_baseline("alice")
        assert loaded.is_equivalent_to(b)

    def test_directory_created_automatically(self, tmp_path: Path) -> None:
        deep_path = tmp_path / "a" / "b" / "c" / "baselines"
        store = FileBaselineStore(deep_path)
        assert deep_path.exists()

    def test_concurrent_writes_are_safe(self, file_store: FileBaselineStore) -> None:
        errors: list[Exception] = []

        def save(iid: str) -> None:
            try:
                file_store.save_baseline(self._sample_baseline(iid))
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=save, args=(f"id-{i:03d}",)) for i in range(10)]
        for t in threads: t.start()
        for t in threads: t.join()

        assert errors == []
        assert len(file_store) == 10


# ===========================================================================
# PERFORMANCE
# ===========================================================================

class TestPhase2Performance:

    def test_extract_features_1000_events_under_2s(self) -> None:
        events = _make_event_stream("perf-id", 1000)
        start = time.perf_counter()
        vec = extract_features(events)
        elapsed = time.perf_counter() - start
        assert vec.shape == (FEATURE_DIM,)
        assert elapsed < 2.0, f"Feature extraction took {elapsed:.2f}s"

    def test_build_baseline_500_events_under_3s(self) -> None:
        events = _make_event_stream("perf-id", 500)
        engine = BaselineEngine()
        start = time.perf_counter()
        b = engine.build_baseline("perf-id", events)
        elapsed = time.perf_counter() - start
        assert b.event_count == 500
        assert elapsed < 3.0, f"build_baseline 500 events took {elapsed:.2f}s"

    def test_incremental_updates_500_batches_under_5s(self) -> None:
        engine = BaselineEngine()
        initial = _make_event_stream("stream-id", 10)
        b = engine.build_baseline("stream-id", initial)

        start = time.perf_counter()
        for batch_no in range(50):
            new_events = _make_event_stream(
                "stream-id", 10,
                base_offset=(batch_no + 1) * 600,
            )
            b = engine.update_baseline(b, new_events)
        elapsed = time.perf_counter() - start

        assert b.event_count == 10 + 50 * 10
        assert elapsed < 5.0, f"50 incremental updates took {elapsed:.2f}s"

    def test_store_save_load_1000_baselines_under_10s(self, tmp_path: Path) -> None:
        store = FileBaselineStore(tmp_path / "perf")
        engine = BaselineEngine()

        start = time.perf_counter()
        for i in range(100):
            events = _make_event_stream(f"id-{i:04d}", 10, base_offset=i * 600)
            b = engine.build_baseline(f"id-{i:04d}", events)
            store.save_baseline(b)
        for iid in store.list_baselines():
            store.load_baseline(iid)
        elapsed = time.perf_counter() - start
        assert len(store) == 100
        assert elapsed < 10.0, f"100 save+load cycles took {elapsed:.2f}s"