"""
Risk Calibrator

Combines multiple behavioral intelligence signals into a single, normalized
risk score and classification. Acts as the final aggregation step in Phase 2
before handing off to Graph Intelligence and Mahoragha.

Design principles:
  - Weighted linear combination (default, transparent, auditable)
  - Configurable signal weights
  - Bayesian posterior update support (for iterative scoring)
  - Temporal decay: older signals contribute less
  - Explainability: which signals drove the score?
  - Signal normalization: all inputs expected in [0, 1]
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# Default signal weights — must sum to 1.0
_DEFAULT_WEIGHTS: Dict[str, float] = {
    "drift":       0.30,
    "entropy":     0.25,
    "privilege":   0.25,
    "graph_risk":  0.20,
}

_RISK_LEVELS = [
    (0.80, "critical"),
    (0.60, "high"),
    (0.30, "medium"),
    (0.00, "low"),
]


@dataclass
class RiskResult:
    identity_id: str
    score: float
    classification: str
    signal_contributions: Dict[str, float]   # weighted contribution per signal
    dominant_signal: str                      # which signal drove the score most
    confidence: float                         # how many signals were provided (0–1)
    timestamp: float = field(default_factory=time.time)

    def __repr__(self) -> str:
        return (
            f"RiskResult(id={self.identity_id!r}, score={self.score:.3f}, "
            f"level={self.classification!r}, dominant={self.dominant_signal!r})"
        )


class RiskCalibrator:
    """
    Combines Phase 2 behavioral signals into a calibrated risk score.

    Signals:
        drift       — how much behavior deviates from baseline (0–1)
        entropy     — behavior unpredictability score (0–1)
        privilege   — privilege escalation signal (0–1)
        graph_risk  — attack-path proximity from graph intelligence (0–1)

    Custom signals can be added via add_signal_weight().
    """

    def __init__(
        self,
        weights: Optional[Dict[str, float]] = None,
        decay_halflife: Optional[float] = None,
    ):
        """
        Args:
            weights:          Signal weights dict (must sum to ~1.0)
            decay_halflife:   If set (seconds), apply exponential time decay
                              to older risk results when computing running scores
        """
        self.weights = dict(weights or _DEFAULT_WEIGHTS)
        self._validate_weights()
        self.decay_halflife = decay_halflife

        # Per-identity historical scores for trend analysis
        self._history: Dict[str, List[RiskResult]] = {}

    # ─── Core scoring ────────────────────────────────────────────────────────

    def compute_risk(
        self,
        signals: Dict[str, float],
        identity_id: str = "unknown",
    ) -> RiskResult:
        """
        Compute a calibrated risk score from a signal dict.

        Args:
            signals:     {signal_name: normalized_value (0–1)}
            identity_id: Identity this score belongs to

        Returns:
            RiskResult with score, classification, and explainability breakdown
        """
        # Clamp all inputs to [0, 1]
        clamped = {k: max(0.0, min(1.0, v)) for k, v in signals.items()}

        score = 0.0
        contributions: Dict[str, float] = {}
        total_weight_used = 0.0

        for signal, weight in self.weights.items():
            if signal in clamped:
                contribution = clamped[signal] * weight
                contributions[signal] = round(contribution, 4)
                score += contribution
                total_weight_used += weight

        # Normalize score by the weight actually used
        # (prevents underscoring when signals are missing)
        if 0 < total_weight_used < 1.0:
            score = score / total_weight_used

        score = round(min(1.0, score), 4)

        # Confidence = fraction of expected signals that were provided
        confidence = round(total_weight_used, 4)

        dominant = max(contributions, key=contributions.get) if contributions else "none"

        result = RiskResult(
            identity_id=identity_id,
            score=score,
            classification=self.classify(score),
            signal_contributions=contributions,
            dominant_signal=dominant,
            confidence=confidence,
        )

        self._history.setdefault(identity_id, []).append(result)
        return result

    def classify(self, risk_score: float) -> str:
        """Map a numeric score to a severity classification."""
        for threshold, level in _RISK_LEVELS:
            if risk_score >= threshold:
                return level
        return "low"

    # ─── Trend and history ───────────────────────────────────────────────────

    def trend(self, identity_id: str, last_n: int = 10) -> Dict:
        """
        Return trend analysis for an identity's recent risk scores.

        Returns avg, max, direction ('rising' | 'falling' | 'stable'), and
        the last N results.
        """
        history = self._history.get(identity_id, [])[-last_n:]
        if not history:
            return {"error": "No history available"}

        scores = [r.score for r in history]
        avg = sum(scores) / len(scores)
        peak = max(scores)

        if len(scores) >= 3:
            recent_avg = sum(scores[-3:]) / 3
            early_avg = sum(scores[:3]) / 3
            if recent_avg > early_avg + 0.05:
                direction = "rising"
            elif recent_avg < early_avg - 0.05:
                direction = "falling"
            else:
                direction = "stable"
        else:
            direction = "stable"

        return {
            "identity_id": identity_id,
            "avg_score": round(avg, 4),
            "peak_score": round(peak, 4),
            "direction": direction,
            "sample_size": len(scores),
            "latest": history[-1],
        }

    def running_risk(
        self,
        identity_id: str,
        decay: bool = True,
    ) -> Optional[float]:
        """
        Compute a time-decayed running risk score from all historical results.

        Useful for persistent threat scoring where recent activity matters more.
        """
        history = self._history.get(identity_id)
        if not history:
            return None

        now = time.time()
        total_weight = 0.0
        weighted_score = 0.0

        for result in history:
            age = now - result.timestamp
            if decay and self.decay_halflife:
                w = math.exp(-math.log(2) * age / self.decay_halflife)
            else:
                w = 1.0
            weighted_score += result.score * w
            total_weight += w

        return round(weighted_score / total_weight, 4) if total_weight else None

    # ─── Configuration ───────────────────────────────────────────────────────

    def add_signal_weight(self, signal: str, weight: float, renormalize: bool = True):
        """
        Register a new signal type with a given weight.

        Args:
            signal:      Signal identifier
            weight:      Contribution weight (will be renormalized if flag set)
            renormalize: If True, rescale all weights to sum to 1.0 after adding
        """
        self.weights[signal] = weight
        if renormalize:
            total = sum(self.weights.values())
            self.weights = {k: round(v / total, 6) for k, v in self.weights.items()}

    def get_weights(self) -> Dict[str, float]:
        return dict(self.weights)

    def explain(self, result: RiskResult) -> str:
        """
        Return a human-readable explanation of a RiskResult.
        """
        lines = [
            f"Risk Score: {result.score:.3f} ({result.classification.upper()})",
            f"Identity:   {result.identity_id}",
            f"Confidence: {result.confidence * 100:.0f}% of signals provided",
            f"Dominant:   {result.dominant_signal}",
            "",
            "Signal Contributions:",
        ]
        sorted_contribs = sorted(
            result.signal_contributions.items(),
            key=lambda x: x[1],
            reverse=True,
        )
        for signal, contrib in sorted_contribs:
            bar = "█" * int(contrib * 40)
            lines.append(f"  {signal:<14} {contrib:.4f}  {bar}")
        return "\n".join(lines)

    # ─── Internals ───────────────────────────────────────────────────────────

    def _validate_weights(self):
        total = sum(self.weights.values())
        if not (0.99 <= total <= 1.01):
            raise ValueError(
                f"Signal weights must sum to 1.0, got {total:.4f}. "
                f"Weights: {self.weights}"
            )