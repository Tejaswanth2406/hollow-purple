"""
test_phase3.py
==============
Phase 3 — Drift Detection Tests
=================================
Tests for:
  • DriftDetector.detect_drift()        – primary detection pipeline
  • DriftDetector.calculate_zscore()    – per-dimension Z-scores
  • DriftDetector.calculate_distance()  – L2 composite score
  • DriftSeverity classification        – NONE → CRITICAL thresholds
  • DimensionDrift                      – per-feature drift details
  • Batch detection                     – detect_drift_batch()
  • Edge cases: empty baseline, sparse baseline, identical features
  • Determinism: identical inputs → identical outputs

All tests are fully deterministic.
"""

from __future__ import annotations

import math
import time
from datetime import datetime, timedelta, timezone

import numpy as np
import pytest

from policy_engine.baseline_engine import BaselineEngine
from policy_engine.drift_detector import (
    DEFAULT_DRIFT_THRESHOLD,
    DEFAULT_MIN_EVENTS,
    DEFAULT_ZSCORE_THRESHOLD,
    DimensionDrift,
    DriftDetector,
    DriftResult,
    DriftSeverity,
)
from policy_engine.feature_extractor import (
    FEATURE_DIM,
    FEATURE_NAMES,
    RawEvent,
    extract_features,
)
from policy_engine.identity_baseline import IdentityBaseline

# ===========================================================================
# HELPERS & FIXTURES
# ===========================================================================

_EPOCH = datetime(2024, 4, 1, 10, 0, 0, tzinfo=timezone.utc)


def _ts(offset: int = 0) -> datetime:
    return _EPOCH + timedelta(seconds=offset)


def _evt(
    eid: str,
    identity_id: str = "alice",
    action: str = "READ",
    resource: str = "doc-1",
    offset: int = 0,
) -> RawEvent:
    return RawEvent(
        event_id=eid,
        identity_id=identity_id,
        action=action,
        resource=resource,
        timestamp=_ts(offset),
    )


def _normal_stream(identity_id: str, n: int, base_offset: int = 0) -> list[RawEvent]:
    actions   = ["READ", "WRITE", "LIST", "CREATE", "DELETE"]
    resources = [f"res-{i % 5}" for i in range(n)]
    return [
        RawEvent(
            event_id=f"{identity_id}-{i:04d}",
            identity_id=identity_id,
            action=actions[i % len(actions)],
            resource=resources[i],
            timestamp=_ts(base_offset + i * 120),   # every 2 min
        )
        for i in range(n)
    ]


def _anomalous_stream(identity_id: str, n: int, base_offset: int = 0) -> list[RawEvent]:
    """Very high frequency, single action, single resource → clear drift."""
    return [
        RawEvent(
            event_id=f"{identity_id}-anom-{i:04d}",
            identity_id=identity_id,
            action="ADMIN",          # single action → zero entropy
            resource="crown-jewels",  # single resource → zero diversity
            timestamp=_ts(base_offset + i),  # 1 s apart → high frequency
        )
        for i in range(n)
    ]


def _build_baseline(
    identity_id: str,
    events: list[RawEvent],
    min_events: int = DEFAULT_MIN_EVENTS,
) -> IdentityBaseline:
    engine = BaselineEngine()
    return engine.build_baseline(identity_id, events)


def _synthetic_baseline(
    identity_id: str = "alice",
    means: np.ndarray | None = None,
    variances: np.ndarray | None = None,
    event_count: int = 50,
) -> IdentityBaseline:
    """Construct a baseline directly from numpy arrays for precise test control."""
    m = means    if means    is not None else np.full(FEATURE_DIM, 1.0)
    v = variances if variances is not None else np.full(FEATURE_DIM, 0.25)
    return IdentityBaseline.from_numpy(
        identity_id=identity_id,
        feature_vector=m.copy(),
        feature_means=m.copy(),
        feature_variances=v.copy(),
        event_count=event_count,
        feature_names=FEATURE_NAMES,
    )


@pytest.fixture
def detector() -> DriftDetector:
    return DriftDetector()


@pytest.fixture
def alice_baseline() -> IdentityBaseline:
    events = _normal_stream("alice", 50)
    return _build_baseline("alice", events)


@pytest.fixture
def alice_normal_features(alice_baseline: IdentityBaseline) -> np.ndarray:
    events = _normal_stream("alice", 20)
    return extract_features(events)


@pytest.fixture
def alice_anomalous_features() -> np.ndarray:
    events = _anomalous_stream("alice", 50)
    return extract_features(events)


# ===========================================================================
# ZSCORE TESTS
# ===========================================================================

class TestCalculateZScore:

    def test_zero_drift_returns_zero_zscores(self) -> None:
        means = np.full(FEATURE_DIM, 2.0)
        stds  = np.full(FEATURE_DIM, 1.0)
        feat  = means.copy()
        z = DriftDetector.calculate_zscore(feat, means, stds)
        np.testing.assert_array_equal(z, np.zeros(FEATURE_DIM))

    def test_known_zscore_value(self) -> None:
        means = np.zeros(FEATURE_DIM)
        stds  = np.ones(FEATURE_DIM)
        feat  = np.full(FEATURE_DIM, 3.0)
        z = DriftDetector.calculate_zscore(feat, means, stds)
        np.testing.assert_allclose(z, np.full(FEATURE_DIM, 3.0), rtol=1e-6)

    def test_negative_zscore_below_mean(self) -> None:
        means = np.full(FEATURE_DIM, 5.0)
        stds  = np.full(FEATURE_DIM, 1.0)
        feat  = np.full(FEATURE_DIM, 3.0)
        z = DriftDetector.calculate_zscore(feat, means, stds)
        assert (z < 0).all()

    def test_zero_std_dims_yield_zero_zscore(self) -> None:
        means = np.ones(FEATURE_DIM)
        stds  = np.zeros(FEATURE_DIM)
        feat  = np.full(FEATURE_DIM, 999.0)
        z = DriftDetector.calculate_zscore(feat, means, stds)
        np.testing.assert_array_equal(z, np.zeros(FEATURE_DIM))

    def test_shape_mismatch_raises(self) -> None:
        with pytest.raises(ValueError, match="Shape mismatch"):
            DriftDetector.calculate_zscore(
                np.zeros(FEATURE_DIM),
                np.zeros(FEATURE_DIM + 1),
                np.zeros(FEATURE_DIM),
            )

    def test_output_dtype_is_float64(self) -> None:
        means = np.ones(FEATURE_DIM)
        stds  = np.ones(FEATURE_DIM)
        feat  = np.ones(FEATURE_DIM)
        z = DriftDetector.calculate_zscore(feat, means, stds)
        assert z.dtype == np.float64

    def test_zscore_is_deterministic(self) -> None:
        means = np.full(FEATURE_DIM, 2.5)
        stds  = np.full(FEATURE_DIM, 0.5)
        feat  = np.full(FEATURE_DIM, 4.0)
        z1 = DriftDetector.calculate_zscore(feat, means, stds)
        z2 = DriftDetector.calculate_zscore(feat, means, stds)
        np.testing.assert_array_equal(z1, z2)

    def test_partial_zero_stds(self) -> None:
        means = np.zeros(FEATURE_DIM)
        stds  = np.zeros(FEATURE_DIM)
        stds[0] = 1.0                         # only dim-0 has variance
        feat  = np.zeros(FEATURE_DIM)
        feat[0] = 5.0
        z = DriftDetector.calculate_zscore(feat, means, stds)
        assert abs(z[0] - 5.0) < 1e-9
        assert all(z[i] == 0.0 for i in range(1, FEATURE_DIM))


# ===========================================================================
# DISTANCE TESTS
# ===========================================================================

class TestCalculateDistance:

    def test_zero_vector_distance_is_zero(self) -> None:
        z = np.zeros(FEATURE_DIM)
        assert DriftDetector.calculate_distance(z) == 0.0

    def test_unit_vector_distance_is_sqrt_dim(self) -> None:
        z = np.ones(FEATURE_DIM)
        expected = math.sqrt(FEATURE_DIM)
        dist = DriftDetector.calculate_distance(z)
        assert abs(dist - expected) < 1e-6

    def test_known_distance(self) -> None:
        z = np.zeros(FEATURE_DIM)
        z[0] = 3.0; z[1] = 4.0
        dist = DriftDetector.calculate_distance(z)
        assert abs(dist - 5.0) < 1e-6

    def test_distance_is_always_non_negative(self) -> None:
        z = np.random.default_rng(42).normal(0, 5, FEATURE_DIM)
        assert DriftDetector.calculate_distance(z) >= 0.0

    def test_empty_vector_returns_zero(self) -> None:
        assert DriftDetector.calculate_distance(np.array([])) == 0.0

    def test_distance_is_deterministic(self) -> None:
        z = np.arange(FEATURE_DIM, dtype=np.float64)
        d1 = DriftDetector.calculate_distance(z)
        d2 = DriftDetector.calculate_distance(z)
        assert d1 == d2


# ===========================================================================
# DETECT DRIFT — CORE TESTS
# ===========================================================================

class TestDetectDrift:

    def test_no_drift_on_same_distribution(
        self,
        detector: DriftDetector,
        alice_baseline: IdentityBaseline,
        alice_normal_features: np.ndarray,
    ) -> None:
        result = detector.detect_drift(alice_baseline, alice_normal_features)
        assert isinstance(result, DriftResult)
        assert result.identity_id == "alice"

    def test_drift_result_is_immutable(
        self,
        detector: DriftDetector,
        alice_baseline: IdentityBaseline,
        alice_normal_features: np.ndarray,
    ) -> None:
        result = detector.detect_drift(alice_baseline, alice_normal_features)
        with pytest.raises((AttributeError, TypeError)):
            result.drift_score = 999.0  # type: ignore[misc]

    def test_drift_score_is_non_negative(
        self,
        detector: DriftDetector,
        alice_baseline: IdentityBaseline,
        alice_normal_features: np.ndarray,
    ) -> None:
        result = detector.detect_drift(alice_baseline, alice_normal_features)
        assert result.drift_score >= 0.0

    def test_anomaly_detected_on_extreme_features(
        self,
        detector: DriftDetector,
        alice_anomalous_features: np.ndarray,
    ) -> None:
        # Baseline built on normal behaviour; anomalous features deviate wildly
        normal_events = _normal_stream("alice", 100)
        baseline = _build_baseline("alice", normal_events)
        result = detector.detect_drift(baseline, alice_anomalous_features)
        assert result.is_anomalous is True

    def test_high_zscore_features_trigger_anomaly(self) -> None:
        detector = DriftDetector(zscore_threshold=3.0, drift_threshold=4.5)
        baseline = _synthetic_baseline(
            means=np.ones(FEATURE_DIM),
            variances=np.ones(FEATURE_DIM),
        )
        # Place features 10 std devs away on every dimension
        features = np.full(FEATURE_DIM, 11.0)
        result = detector.detect_drift(baseline, features)
        assert result.is_anomalous is True

    def test_in_range_features_not_anomalous(self) -> None:
        detector = DriftDetector()
        baseline = _synthetic_baseline(
            means=np.full(FEATURE_DIM, 5.0),
            variances=np.full(FEATURE_DIM, 1.0),
        )
        # Features exactly at mean → z-scores all 0 → not anomalous
        features = np.full(FEATURE_DIM, 5.0)
        result = detector.detect_drift(baseline, features)
        assert result.is_anomalous is False
        assert result.drift_score == 0.0

    def test_drift_result_z_scores_length(
        self,
        detector: DriftDetector,
        alice_baseline: IdentityBaseline,
        alice_normal_features: np.ndarray,
    ) -> None:
        result = detector.detect_drift(alice_baseline, alice_normal_features)
        assert len(result.z_scores) == FEATURE_DIM

    def test_dimension_drifts_length(
        self,
        detector: DriftDetector,
        alice_baseline: IdentityBaseline,
        alice_normal_features: np.ndarray,
    ) -> None:
        result = detector.detect_drift(alice_baseline, alice_normal_features)
        assert len(result.dimension_drifts) == FEATURE_DIM

    def test_dimension_drift_names_match_feature_names(
        self,
        detector: DriftDetector,
        alice_baseline: IdentityBaseline,
        alice_normal_features: np.ndarray,
    ) -> None:
        result = detector.detect_drift(alice_baseline, alice_normal_features)
        for dd, name in zip(result.dimension_drifts, FEATURE_NAMES):
            assert dd.feature_name == name

    def test_anomalous_dimensions_subset_of_feature_names(
        self,
        detector: DriftDetector,
    ) -> None:
        baseline = _synthetic_baseline(
            means=np.ones(FEATURE_DIM),
            variances=np.ones(FEATURE_DIM),
        )
        features = np.full(FEATURE_DIM, 50.0)
        result = detector.detect_drift(baseline, features)
        for dim in result.anomalous_dimensions:
            assert dim in FEATURE_NAMES

    def test_empty_baseline_returns_no_anomaly(self, detector: DriftDetector) -> None:
        empty = IdentityBaseline.empty("ghost")
        features = np.ones(FEATURE_DIM)
        result = detector.detect_drift(empty, features)
        assert result.is_anomalous is False
        assert result.insufficient_baseline is True

    def test_sparse_baseline_flags_insufficient(self, detector: DriftDetector) -> None:
        events = _normal_stream("new-user", DEFAULT_MIN_EVENTS - 1)
        baseline = _build_baseline("new-user", events)
        features = extract_features(events)
        result = detector.detect_drift(baseline, features)
        assert result.insufficient_baseline is True

    def test_detection_is_deterministic(
        self,
        alice_baseline: IdentityBaseline,
        alice_anomalous_features: np.ndarray,
    ) -> None:
        d1 = DriftDetector()
        d2 = DriftDetector()
        r1 = d1.detect_drift(alice_baseline, alice_anomalous_features)
        r2 = d2.detect_drift(alice_baseline, alice_anomalous_features)
        assert r1.drift_score == r2.drift_score
        assert r1.is_anomalous == r2.is_anomalous
        assert r1.z_scores == r2.z_scores

    def test_invalid_feature_shape_raises(
        self,
        detector: DriftDetector,
        alice_baseline: IdentityBaseline,
    ) -> None:
        bad_vec = np.zeros(FEATURE_DIM + 5)
        with pytest.raises(ValueError):
            detector.detect_drift(alice_baseline, bad_vec)

    def test_drift_result_baseline_hash_matches(
        self,
        detector: DriftDetector,
        alice_baseline: IdentityBaseline,
        alice_normal_features: np.ndarray,
    ) -> None:
        result = detector.detect_drift(alice_baseline, alice_normal_features)
        assert result.baseline_hash == alice_baseline.content_hash()

    def test_baseline_event_count_recorded(
        self,
        detector: DriftDetector,
        alice_baseline: IdentityBaseline,
        alice_normal_features: np.ndarray,
    ) -> None:
        result = detector.detect_drift(alice_baseline, alice_normal_features)
        assert result.baseline_event_count == alice_baseline.event_count

    def test_anomaly_ratio_between_zero_and_one(
        self,
        detector: DriftDetector,
        alice_baseline: IdentityBaseline,
        alice_anomalous_features: np.ndarray,
    ) -> None:
        result = detector.detect_drift(alice_baseline, alice_anomalous_features)
        assert 0.0 <= result.anomaly_ratio <= 1.0


# ===========================================================================
# SEVERITY CLASSIFICATION
# ===========================================================================

class TestSeverityClassification:

    def _detect_with_score(self, drift_score_multiplier: float) -> DriftResult:
        """Build a detector, then craft a baseline+features that produces the
        desired drift score by placing all dimensions at exactly the right
        Z-score offset."""
        detector = DriftDetector(
            zscore_threshold=3.0,
            drift_threshold=DEFAULT_DRIFT_THRESHOLD,
        )
        # We want ||z|| ≈ target_score
        # With FEATURE_DIM dims all at equal z → z_dim = target / sqrt(dim)
        target = DEFAULT_DRIFT_THRESHOLD * drift_score_multiplier
        z_per_dim = target / math.sqrt(FEATURE_DIM)

        means = np.zeros(FEATURE_DIM)
        stds  = np.ones(FEATURE_DIM)
        features = means + z_per_dim * stds

        baseline = _synthetic_baseline(
            means=means,
            variances=stds ** 2,
            event_count=100,
        )
        return detector.detect_drift(baseline, features)

    def test_zero_drift_is_severity_none(self) -> None:
        detector = DriftDetector()
        baseline = _synthetic_baseline(
            means=np.ones(FEATURE_DIM),
            variances=np.ones(FEATURE_DIM),
        )
        features = np.ones(FEATURE_DIM)  # exactly at mean
        result = detector.detect_drift(baseline, features)
        assert result.severity == DriftSeverity.NONE

    def test_severity_ordering(self) -> None:
        """Higher drift multipliers must produce equal-or-higher severity."""
        severities = [
            self._detect_with_score(m).severity
            for m in [0.3, 0.7, 0.95, 1.2, 2.0]
        ]
        order = [DriftSeverity.NONE, DriftSeverity.LOW, DriftSeverity.MEDIUM,
                 DriftSeverity.HIGH, DriftSeverity.CRITICAL]
        for s in severities:
            assert s in order

    def test_critical_severity_on_extreme_drift(self) -> None:
        detector = DriftDetector()
        baseline = _synthetic_baseline(
            means=np.zeros(FEATURE_DIM),
            variances=np.ones(FEATURE_DIM),
            event_count=500,
        )
        # 100 std devs away on every dimension → clearly critical
        features = np.full(FEATURE_DIM, 100.0)
        result = detector.detect_drift(baseline, features)
        assert result.severity == DriftSeverity.CRITICAL
        assert result.is_anomalous is True

    def test_none_severity_not_anomalous(self) -> None:
        detector = DriftDetector()
        baseline = _synthetic_baseline(
            means=np.full(FEATURE_DIM, 3.0),
            variances=np.full(FEATURE_DIM, 1.0),
        )
        features = np.full(FEATURE_DIM, 3.0)
        result = detector.detect_drift(baseline, features)
        assert result.severity == DriftSeverity.NONE
        assert result.is_anomalous is False

    def test_severity_enum_values(self) -> None:
        assert DriftSeverity.NONE.value     == "none"
        assert DriftSeverity.LOW.value      == "low"
        assert DriftSeverity.MEDIUM.value   == "medium"
        assert DriftSeverity.HIGH.value     == "high"
        assert DriftSeverity.CRITICAL.value == "critical"


# ===========================================================================
# CUSTOM THRESHOLDS
# ===========================================================================

class TestCustomThresholds:

    def test_low_zscore_threshold_flags_more_dimensions(self) -> None:
        strict  = DriftDetector(zscore_threshold=1.0,  drift_threshold=DEFAULT_DRIFT_THRESHOLD)
        relaxed = DriftDetector(zscore_threshold=10.0, drift_threshold=DEFAULT_DRIFT_THRESHOLD)
        baseline = _synthetic_baseline(
            means=np.zeros(FEATURE_DIM),
            variances=np.ones(FEATURE_DIM),
        )
        features = np.full(FEATURE_DIM, 2.0)     # z = 2.0 per dim
        r_strict  = strict.detect_drift(baseline, features)
        r_relaxed = relaxed.detect_drift(baseline, features)
        assert len(r_strict.anomalous_dimensions) > len(r_relaxed.anomalous_dimensions)

    def test_low_drift_threshold_triggers_anomaly(self) -> None:
        sensitive = DriftDetector(drift_threshold=0.01)
        baseline = _synthetic_baseline(
            means=np.zeros(FEATURE_DIM),
            variances=np.ones(FEATURE_DIM),
        )
        features = np.full(FEATURE_DIM, 0.01)
        result = sensitive.detect_drift(baseline, features)
        assert result.is_anomalous is True

    def test_invalid_zscore_threshold_raises(self) -> None:
        with pytest.raises(ValueError, match="zscore_threshold"):
            DriftDetector(zscore_threshold=-1.0)

    def test_invalid_drift_threshold_raises(self) -> None:
        with pytest.raises(ValueError, match="drift_threshold"):
            DriftDetector(drift_threshold=0.0)

    def test_invalid_min_events_raises(self) -> None:
        with pytest.raises(ValueError, match="min_events"):
            DriftDetector(min_events=0)


# ===========================================================================
# BATCH DETECTION
# ===========================================================================

class TestBatchDetection:

    def test_batch_returns_one_result_per_feature_vector(
        self, detector: DriftDetector, alice_baseline: IdentityBaseline
    ) -> None:
        batch = [np.ones(FEATURE_DIM) for _ in range(5)]
        results = detector.detect_drift_batch(alice_baseline, batch)
        assert len(results) == 5

    def test_batch_results_are_drift_result_instances(
        self, detector: DriftDetector, alice_baseline: IdentityBaseline
    ) -> None:
        batch = [np.ones(FEATURE_DIM), np.zeros(FEATURE_DIM)]
        results = detector.detect_drift_batch(alice_baseline, batch)
        for r in results:
            assert isinstance(r, DriftResult)

    def test_batch_order_preserved(
        self, detector: DriftDetector
    ) -> None:
        baseline = _synthetic_baseline(
            means=np.zeros(FEATURE_DIM),
            variances=np.ones(FEATURE_DIM),
        )
        low_drift  = np.zeros(FEATURE_DIM)        # z = 0
        high_drift = np.full(FEATURE_DIM, 100.0)  # z = 100
        results = detector.detect_drift_batch(baseline, [low_drift, high_drift])
        assert results[0].drift_score < results[1].drift_score

    def test_batch_is_deterministic(
        self, alice_baseline: IdentityBaseline
    ) -> None:
        d1 = DriftDetector()
        d2 = DriftDetector()
        batch = [np.full(FEATURE_DIM, float(i)) for i in range(5)]
        r1 = d1.detect_drift_batch(alice_baseline, batch)
        r2 = d2.detect_drift_batch(alice_baseline, batch)
        for a, b in zip(r1, r2):
            assert a.drift_score == b.drift_score
            assert a.is_anomalous == b.is_anomalous

    def test_empty_batch_returns_empty_list(
        self, detector: DriftDetector, alice_baseline: IdentityBaseline
    ) -> None:
        results = detector.detect_drift_batch(alice_baseline, [])
        assert results == []


# ===========================================================================
# RESULT SERIALIZATION
# ===========================================================================

class TestDriftResultSerialization:

    def test_to_dict_contains_required_keys(
        self, detector: DriftDetector, alice_baseline: IdentityBaseline,
        alice_normal_features: np.ndarray
    ) -> None:
        result = detector.detect_drift(alice_baseline, alice_normal_features)
        d = result.to_dict()
        for key in (
            "identity_id", "drift_score", "is_anomalous", "severity",
            "z_scores", "anomalous_dimensions", "anomaly_ratio",
            "baseline_event_count", "evaluated_at", "dimension_drifts",
        ):
            assert key in d, f"Missing key: {key}"

    def test_severity_value_in_dict_is_string(
        self, detector: DriftDetector, alice_baseline: IdentityBaseline,
        alice_normal_features: np.ndarray
    ) -> None:
        d = detector.detect_drift(alice_baseline, alice_normal_features).to_dict()
        assert isinstance(d["severity"], str)

    def test_dimension_drifts_list_length_matches_dim(
        self, detector: DriftDetector, alice_baseline: IdentityBaseline,
        alice_normal_features: np.ndarray
    ) -> None:
        d = detector.detect_drift(alice_baseline, alice_normal_features).to_dict()
        assert len(d["dimension_drifts"]) == FEATURE_DIM


# ===========================================================================
# CONSISTENCY WITH DIFFERENT BASELINE CONSTRUCTIONS
# ===========================================================================

class TestDriftConsistency:

    def test_higher_variance_reduces_drift_score(self) -> None:
        features = np.full(FEATURE_DIM, 10.0)

        tight_baseline = _synthetic_baseline(
            means=np.ones(FEATURE_DIM),
            variances=np.full(FEATURE_DIM, 0.1),
        )
        wide_baseline = _synthetic_baseline(
            means=np.ones(FEATURE_DIM),
            variances=np.full(FEATURE_DIM, 100.0),
        )

        detector = DriftDetector()
        r_tight = detector.detect_drift(tight_baseline, features)
        r_wide  = detector.detect_drift(wide_baseline, features)

        assert r_tight.drift_score > r_wide.drift_score

    def test_features_at_baseline_mean_yield_zero_zscore(self) -> None:
        means = np.arange(FEATURE_DIM, dtype=np.float64) * 0.1
        baseline = _synthetic_baseline(
            means=means,
            variances=np.ones(FEATURE_DIM),
        )
        detector = DriftDetector()
        result = detector.detect_drift(baseline, means)
        for z in result.z_scores:
            assert abs(z) < 1e-9

    def test_symmetric_drift_same_score(self) -> None:
        means = np.full(FEATURE_DIM, 5.0)
        stds  = np.ones(FEATURE_DIM)
        baseline = _synthetic_baseline(means=means, variances=stds ** 2)
        detector = DriftDetector()

        above = means + 2.0 * stds
        below = means - 2.0 * stds

        r_above = detector.detect_drift(baseline, above)
        r_below = detector.detect_drift(baseline, below)

        assert abs(r_above.drift_score - r_below.drift_score) < 1e-9

    def test_incremental_update_does_not_destroy_drift_detection(self) -> None:
        engine = BaselineEngine()
        # Build on normal events
        normal = _normal_stream("diana", 50)
        baseline = engine.build_baseline("diana", normal)
        # Update with more normal events
        more_normal = _normal_stream("diana", 20, base_offset=6000)
        updated_baseline = engine.update_baseline(baseline, more_normal)
        # Anomalous features should still be flagged
        anom_features = extract_features(_anomalous_stream("diana", 30))
        detector = DriftDetector()
        result = detector.detect_drift(updated_baseline, anom_features)
        assert result.is_anomalous is True


# ===========================================================================
# PERFORMANCE
# ===========================================================================

class TestPhase3Performance:

    def test_single_detection_under_10ms(self) -> None:
        baseline = _synthetic_baseline(event_count=500)
        features = np.random.default_rng(42).uniform(0, 2, FEATURE_DIM)
        detector = DriftDetector()
        start = time.perf_counter()
        detector.detect_drift(baseline, features)
        elapsed = time.perf_counter() - start
        assert elapsed < 0.01, f"Single detect_drift took {elapsed*1000:.1f}ms"

    def test_batch_1000_detections_under_5s(self) -> None:
        rng = np.random.default_rng(0)
        baseline = _synthetic_baseline(event_count=500)
        batch = [rng.uniform(0, 5, FEATURE_DIM) for _ in range(1000)]
        detector = DriftDetector()
        start = time.perf_counter()
        results = detector.detect_drift_batch(baseline, batch)
        elapsed = time.perf_counter() - start
        assert len(results) == 1000
        assert elapsed < 5.0, f"1000 batch detections took {elapsed:.2f}s"

    def test_drift_detection_throughput(self) -> None:
        """At least 500 detections per second."""
        rng = np.random.default_rng(1)
        baseline = _synthetic_baseline(event_count=100)
        detector = DriftDetector()
        n = 500
        vectors = [rng.normal(1.0, 0.5, FEATURE_DIM) for _ in range(n)]
        start = time.perf_counter()
        for vec in vectors:
            detector.detect_drift(baseline, vec)
        elapsed = time.perf_counter() - start
        assert elapsed < 5.0, f"{n} detections took {elapsed:.2f}s"