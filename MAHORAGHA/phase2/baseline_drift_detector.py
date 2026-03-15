"""
Baseline Drift Detector

Detects when an identity's behavioral vector deviates from its
established baseline. Attackers rarely go loud immediately — they
drift gradually. This module is designed to catch slow-burn deviations.

Drift is computed as the L2 (Euclidean) norm of the difference vector,
but the module also supports cosine distance for high-dimensional feature
spaces where magnitude matters less than direction.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class DriftResult:
    identity_id: str
    baseline: List[float]
    current: List[float]
    distance: float
    threshold: float
    is_drift: bool
    z_scores: List[float] = field(default_factory=list)
    dimensions_breached: List[int] = field(default_factory=list)

    @property
    def severity(self) -> str:
        ratio = self.distance / self.threshold if self.threshold else float("inf")
        if ratio > 3.0:
            return "critical"
        if ratio > 2.0:
            return "high"
        if ratio > 1.0:
            return "medium"
        return "low"


class BaselineDriftDetector:
    """
    Detects behavioral drift from established baseline vectors.

    Supports:
      - L2 (Euclidean) distance — default
      - Cosine distance — for high-dimensional feature spaces
      - Per-dimension Z-score analysis — pinpoints *which* features drifted
      - Rolling baseline updates — baselines age and adapt over time
      - Per-identity threshold overrides

    Baseline vector dimensions (example):
        [login_frequency, resource_diversity, geo_variance,
         session_duration_avg, off_hours_ratio, failed_auth_rate]
    """

    def __init__(
        self,
        threshold: float = 0.35,
        distance_metric: str = "l2",
        adaptive: bool = False,
        adaptation_rate: float = 0.05,
    ):
        """
        Args:
            threshold:        Default drift threshold (L2 or cosine distance)
            distance_metric:  "l2" | "cosine"
            adaptive:         If True, baselines drift slowly toward observed behavior
            adaptation_rate:  How quickly the baseline adapts (0.0–1.0)
        """
        if distance_metric not in ("l2", "cosine"):
            raise ValueError(f"Unsupported distance metric: {distance_metric!r}")

        self.threshold = threshold
        self.distance_metric = distance_metric
        self.adaptive = adaptive
        self.adaptation_rate = adaptation_rate

        # Per-identity stored baselines  {id: [float, ...]}
        self._baselines: Dict[str, List[float]] = {}
        # Per-identity threshold overrides
        self._threshold_overrides: Dict[str, float] = {}
        # Baseline standard deviations for Z-score analysis
        self._baseline_stds: Dict[str, List[float]] = {}

    # ─── Public API ──────────────────────────────────────────────────────────

    def set_baseline(
        self,
        identity_id: str,
        vector: List[float],
        stds: Optional[List[float]] = None,
    ):
        """
        Store a baseline vector for an identity.

        Args:
            identity_id: The identity this baseline belongs to
            vector:      Feature vector representing normal behavior
            stds:        Per-dimension standard deviations (for Z-score analysis)
        """
        self._baselines[identity_id] = list(vector)
        if stds:
            if len(stds) != len(vector):
                raise ValueError("stds must match vector length")
            self._baseline_stds[identity_id] = list(stds)

    def set_threshold(self, identity_id: str, threshold: float):
        """Override the drift threshold for a specific identity."""
        self._threshold_overrides[identity_id] = threshold

    def evaluate(
        self,
        identity_id: str,
        current_vector: List[float],
        baseline_override: Optional[List[float]] = None,
    ) -> DriftResult:
        """
        Evaluate drift for an identity against its stored (or provided) baseline.

        Args:
            identity_id:       The identity to evaluate
            current_vector:    Current behavioral feature vector
            baseline_override: Use this baseline instead of the stored one

        Returns:
            DriftResult with distance, threshold, drift flag, and Z-scores
        """
        baseline = baseline_override or self._baselines.get(identity_id)
        if baseline is None:
            raise KeyError(f"No baseline registered for identity: {identity_id!r}")

        threshold = self._threshold_overrides.get(identity_id, self.threshold)
        distance = self._compute_distance(baseline, current_vector)
        z_scores, dims_breached = self._z_score_analysis(identity_id, baseline, current_vector)

        result = DriftResult(
            identity_id=identity_id,
            baseline=list(baseline),
            current=list(current_vector),
            distance=round(distance, 6),
            threshold=threshold,
            is_drift=distance > threshold,
            z_scores=z_scores,
            dimensions_breached=dims_breached,
        )

        # Adaptive baseline update — only shift baseline toward observed if NOT drifting
        if self.adaptive and not result.is_drift:
            self._adapt_baseline(identity_id, current_vector)

        return result

    def compute_drift(
        self,
        baseline_vector: List[float],
        current_vector: List[float],
    ) -> float:
        """
        Stateless drift distance computation (no identity tracking).

        Raises ValueError on size mismatch.
        """
        if len(baseline_vector) != len(current_vector):
            raise ValueError(
                f"Vector size mismatch: baseline={len(baseline_vector)}, "
                f"current={len(current_vector)}"
            )
        return self._compute_distance(baseline_vector, current_vector)

    def is_drift(
        self,
        baseline_vector: List[float],
        current_vector: List[float],
        threshold: Optional[float] = None,
    ) -> bool:
        """Stateless boolean drift check."""
        distance = self.compute_drift(baseline_vector, current_vector)
        return distance > (threshold if threshold is not None else self.threshold)

    def batch_evaluate(
        self,
        observations: Dict[str, List[float]],
    ) -> Dict[str, DriftResult]:
        """
        Evaluate drift for multiple identities in one call.

        Args:
            observations: {identity_id: current_vector}

        Returns:
            {identity_id: DriftResult}
        """
        results = {}
        for identity_id, current_vector in observations.items():
            try:
                results[identity_id] = self.evaluate(identity_id, current_vector)
            except KeyError:
                pass  # No baseline registered — skip silently
        return results

    # ─── Internals ───────────────────────────────────────────────────────────

    def _compute_distance(self, a: List[float], b: List[float]) -> float:
        if len(a) != len(b):
            raise ValueError("Vector length mismatch")

        if self.distance_metric == "cosine":
            return self._cosine_distance(a, b)
        return self._l2_distance(a, b)

    @staticmethod
    def _l2_distance(a: List[float], b: List[float]) -> float:
        return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))

    @staticmethod
    def _cosine_distance(a: List[float], b: List[float]) -> float:
        dot = sum(x * y for x, y in zip(a, b))
        mag_a = math.sqrt(sum(x ** 2 for x in a))
        mag_b = math.sqrt(sum(y ** 2 for y in b))
        if mag_a == 0 or mag_b == 0:
            return 1.0  # Treat zero-vector as maximally distant
        similarity = dot / (mag_a * mag_b)
        return 1.0 - max(-1.0, min(1.0, similarity))

    def _z_score_analysis(
        self,
        identity_id: str,
        baseline: List[float],
        current: List[float],
        breach_threshold: float = 2.5,
    ) -> Tuple[List[float], List[int]]:
        """
        Compute per-dimension Z-scores to identify which features drifted most.
        Requires standard deviations to be set via set_baseline(stds=...).
        """
        stds = self._baseline_stds.get(identity_id)
        if not stds:
            return [], []

        z_scores = []
        dims_breached = []

        for i, (b, c, s) in enumerate(zip(baseline, current, stds)):
            if s == 0:
                z = 0.0
            else:
                z = abs(c - b) / s
            z_scores.append(round(z, 4))
            if z > breach_threshold:
                dims_breached.append(i)

        return z_scores, dims_breached

    def _adapt_baseline(self, identity_id: str, current_vector: List[float]):
        """
        Exponential moving average update: baseline = (1-α)*baseline + α*current
        """
        α = self.adaptation_rate
        old = self._baselines[identity_id]
        self._baselines[identity_id] = [
            round((1 - α) * b + α * c, 6)
            for b, c in zip(old, current_vector)
        ]