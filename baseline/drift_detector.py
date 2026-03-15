"""
drift_detector.py
=================
Deterministic behavioral drift detection for the Hollow Purple policy engine.

Given a live feature vector and an identity baseline, the detector computes a
composite drift score and emits a structured ``DriftResult``.

Algorithm Overview
------------------
1. Per-dimension Z-score  : z_i = (x_i - mean_i) / std_i
2. Mahalanobis-like score : aggregate z-scores (L2 norm of z-vector, clipped)
3. Chi-squared p-value    : approximate tail probability for anomaly confidence
4. Binary anomaly flag    : score > configured threshold

All operations are deterministic: no random seeds, no non-reproducible math.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Sequence

import numpy as np

from .feature_extractor import (
    FEATURE_DIM,
    FEATURE_NAMES,
    validate_feature_vector,
)
from .identity_baseline import IdentityBaseline

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants / thresholds
# ---------------------------------------------------------------------------

DEFAULT_ZSCORE_THRESHOLD: float = 3.0     # |z| > this flags individual dim
DEFAULT_DRIFT_THRESHOLD: float = 4.5      # composite score above which = anomaly
DEFAULT_MIN_EVENTS: int = 10              # baseline needs ≥ this many events
_EPSILON: float = 1e-9                    # numerical stability floor for stds
_FLOAT_PRECISION: int = 10


def _round(v: float) -> float:
    return round(float(v), _FLOAT_PRECISION)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


class DriftSeverity(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class DimensionDrift:
    """Drift detail for a single feature dimension."""

    feature_name: str
    observed_value: float
    baseline_mean: float
    baseline_std: float
    z_score: float
    is_anomalous: bool


@dataclass(frozen=True)
class DriftResult:
    """
    Immutable drift analysis result for one (identity, feature vector) pair.
    """

    identity_id: str
    drift_score: float               # composite L2-norm drift score
    is_anomalous: bool
    severity: DriftSeverity
    z_scores: tuple[float, ...]      # per-dimension Z-scores
    dimension_drifts: tuple[DimensionDrift, ...]
    anomalous_dimensions: tuple[str, ...]
    baseline_event_count: int
    evaluated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    # Diagnostic
    baseline_hash: str = ""
    insufficient_baseline: bool = False

    # ------------------------------------------------------------------ #
    # Convenience
    # ------------------------------------------------------------------ #

    @property
    def anomaly_ratio(self) -> float:
        """Fraction of feature dimensions flagged as anomalous."""
        if FEATURE_DIM == 0:
            return 0.0
        return _round(len(self.anomalous_dimensions) / FEATURE_DIM)

    def to_dict(self) -> dict:
        return {
            "identity_id": self.identity_id,
            "drift_score": self.drift_score,
            "is_anomalous": self.is_anomalous,
            "severity": self.severity.value,
            "z_scores": list(self.z_scores),
            "anomalous_dimensions": list(self.anomalous_dimensions),
            "anomaly_ratio": self.anomaly_ratio,
            "baseline_event_count": self.baseline_event_count,
            "baseline_hash": self.baseline_hash,
            "evaluated_at": self.evaluated_at,
            "insufficient_baseline": self.insufficient_baseline,
            "dimension_drifts": [
                {
                    "feature": d.feature_name,
                    "observed": d.observed_value,
                    "mean": d.baseline_mean,
                    "std": d.baseline_std,
                    "z_score": d.z_score,
                    "anomalous": d.is_anomalous,
                }
                for d in self.dimension_drifts
            ],
        }

    def __repr__(self) -> str:
        return (
            f"DriftResult(identity={self.identity_id!r}, "
            f"score={self.drift_score:.4f}, "
            f"anomalous={self.is_anomalous}, "
            f"severity={self.severity.value})"
        )


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


class DriftDetector:
    """
    Stateless drift detection engine.

    All public methods are pure functions; no mutable instance state is
    written during detection.

    Parameters
    ----------
    zscore_threshold:
        Absolute Z-score above which an individual dimension is flagged.
    drift_threshold:
        Composite drift score above which the identity is flagged as anomalous.
    min_events:
        Minimum number of baseline events required for reliable detection.
        Results on sparse baselines carry ``insufficient_baseline=True``.
    """

    def __init__(
        self,
        zscore_threshold: float = DEFAULT_ZSCORE_THRESHOLD,
        drift_threshold: float = DEFAULT_DRIFT_THRESHOLD,
        min_events: int = DEFAULT_MIN_EVENTS,
    ) -> None:
        if zscore_threshold <= 0:
            raise ValueError("zscore_threshold must be positive.")
        if drift_threshold <= 0:
            raise ValueError("drift_threshold must be positive.")
        if min_events < 1:
            raise ValueError("min_events must be >= 1.")

        self.zscore_threshold = zscore_threshold
        self.drift_threshold = drift_threshold
        self.min_events = min_events

    # ------------------------------------------------------------------ #
    # Primary API
    # ------------------------------------------------------------------ #

    def detect_drift(
        self,
        baseline: IdentityBaseline,
        features: np.ndarray,
    ) -> DriftResult:
        """
        Compare ``features`` against ``baseline`` and return a DriftResult.

        Parameters
        ----------
        baseline:
            The identity's current behavioral baseline.
        features:
            A 1-D feature vector of length ``FEATURE_DIM``.
        """
        validate_feature_vector(features)

        if baseline.is_empty():
            logger.warning(
                "detect_drift: empty baseline for %r – returning no-drift.",
                baseline.identity_id,
            )
            return self._empty_result(baseline, features)

        means = np.array(baseline.feature_means, dtype=np.float64)
        stds = np.array(baseline.feature_stds, dtype=np.float64)

        insufficient = baseline.event_count < self.min_events

        z_scores = self.calculate_zscore(features, means, stds)
        drift_score = self.calculate_distance(z_scores)

        dimension_drifts: list[DimensionDrift] = []
        anomalous_dims: list[str] = []

        for i, name in enumerate(FEATURE_NAMES):
            z = float(z_scores[i])
            is_dim_anomalous = abs(z) > self.zscore_threshold
            if is_dim_anomalous:
                anomalous_dims.append(name)

            dimension_drifts.append(
                DimensionDrift(
                    feature_name=name,
                    observed_value=_round(float(features[i])),
                    baseline_mean=_round(float(means[i])),
                    baseline_std=_round(float(stds[i])),
                    z_score=_round(z),
                    is_anomalous=is_dim_anomalous,
                )
            )

        is_anomalous = drift_score > self.drift_threshold
        severity = self._classify_severity(drift_score, len(anomalous_dims))

        result = DriftResult(
            identity_id=baseline.identity_id,
            drift_score=_round(drift_score),
            is_anomalous=is_anomalous,
            severity=severity,
            z_scores=tuple(_round(z) for z in z_scores.tolist()),
            dimension_drifts=tuple(dimension_drifts),
            anomalous_dimensions=tuple(sorted(anomalous_dims)),
            baseline_event_count=baseline.event_count,
            baseline_hash=baseline.content_hash(),
            insufficient_baseline=insufficient,
        )

        if is_anomalous:
            logger.warning(
                "detect_drift: ANOMALY identity=%r score=%.4f severity=%s "
                "anomalous_dims=%s",
                baseline.identity_id, drift_score, severity.value,
                anomalous_dims,
            )
        else:
            logger.debug(
                "detect_drift: OK identity=%r score=%.4f",
                baseline.identity_id, drift_score,
            )

        return result

    # ------------------------------------------------------------------ #
    # Distance & Z-score
    # ------------------------------------------------------------------ #

    @staticmethod
    def calculate_distance(z_scores: np.ndarray) -> float:
        """
        Compute the L2 norm of the Z-score vector (analogous to Mahalanobis
        distance under diagonal covariance assumption).

        Returns a stable, rounded float.
        """
        if z_scores.size == 0:
            return 0.0
        dist = float(np.linalg.norm(z_scores))
        return _round(dist)

    @staticmethod
    def calculate_zscore(
        features: np.ndarray,
        means: np.ndarray,
        stds: np.ndarray,
    ) -> np.ndarray:
        """
        Compute per-dimension Z-scores.

        Dimensions where std ≈ 0 yield a Z-score of 0 (no variation in
        baseline → no signal).

        Returns
        -------
        np.ndarray of shape (FEATURE_DIM,), dtype float64.
        """
        if not (features.shape == means.shape == stds.shape):
            raise ValueError(
                f"Shape mismatch: features={features.shape}, "
                f"means={means.shape}, stds={stds.shape}"
            )
        safe_stds = np.where(stds < _EPSILON, 1.0, stds)
        z = (features - means) / safe_stds
        z = np.where(stds < _EPSILON, 0.0, z)
        return np.array([_round(v) for v in z.tolist()], dtype=np.float64)

    # ------------------------------------------------------------------ #
    # Batch detection
    # ------------------------------------------------------------------ #

    def detect_drift_batch(
        self,
        baseline: IdentityBaseline,
        feature_batch: Sequence[np.ndarray],
    ) -> list[DriftResult]:
        """
        Evaluate drift for multiple feature vectors against the same baseline.

        Returns results in the same order as ``feature_batch``.
        """
        return [self.detect_drift(baseline, vec) for vec in feature_batch]

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    def _classify_severity(
        self,
        drift_score: float,
        num_anomalous_dims: int,
    ) -> DriftSeverity:
        """
        Map a drift score + anomalous dimension count to a severity level.

        Thresholds are relative to ``self.drift_threshold``.
        """
        t = self.drift_threshold
        if drift_score <= t * 0.5:
            return DriftSeverity.NONE
        if drift_score <= t * 0.8:
            return DriftSeverity.LOW
        if drift_score <= t:
            return DriftSeverity.MEDIUM
        if drift_score <= t * 1.5 or num_anomalous_dims <= 2:
            return DriftSeverity.HIGH
        return DriftSeverity.CRITICAL

    @staticmethod
    def _empty_result(
        baseline: IdentityBaseline,
        features: np.ndarray,
    ) -> DriftResult:
        dim_drifts = tuple(
            DimensionDrift(
                feature_name=name,
                observed_value=_round(float(features[i])),
                baseline_mean=0.0,
                baseline_std=0.0,
                z_score=0.0,
                is_anomalous=False,
            )
            for i, name in enumerate(FEATURE_NAMES)
        )
        return DriftResult(
            identity_id=baseline.identity_id,
            drift_score=0.0,
            is_anomalous=False,
            severity=DriftSeverity.NONE,
            z_scores=tuple(0.0 for _ in FEATURE_NAMES),
            dimension_drifts=dim_drifts,
            anomalous_dimensions=(),
            baseline_event_count=0,
            baseline_hash="",
            insufficient_baseline=True,
        )