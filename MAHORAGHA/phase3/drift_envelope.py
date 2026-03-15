"""
Drift Envelope

Defines acceptable behavioral boundaries and detects when the system or
an identity has left the safe operating region.

Unlike Phase 2's BaselineDriftDetector (which compares individual identity
vectors), the DriftEnvelope operates at the system level — it defines a
multi-dimensional operating envelope and flags any observation that falls
outside it.

Think of it as the system's equivalent of an aircraft flight envelope:
  - normal flight = inside the envelope
  - stall or structural limit = outside the envelope

Enterprise additions over the spec:
  - Multi-dimensional envelope (per-axis thresholds, not just a scalar)
  - Soft vs hard limits: soft triggers a warning; hard triggers a halt
  - Violation history with timestamps
  - Adaptive envelope: expands slightly on consistent in-bounds readings
  - Per-dimension weighting for composite boundary scoring
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union


@dataclass
class EnvelopeViolation:
    dimension: str
    value: float
    soft_limit: float
    hard_limit: Optional[float]
    is_hard: bool
    timestamp: float = field(default_factory=time.time)

    @property
    def severity(self) -> str:
        return "critical" if self.is_hard else "warning"


@dataclass
class EnvelopeResult:
    in_bounds: bool
    soft_violations: List[EnvelopeViolation]
    hard_violations: List[EnvelopeViolation]
    composite_score: float       # 0 = fully in bounds, 1 = maximally out of bounds

    @property
    def any_hard(self) -> bool:
        return len(self.hard_violations) > 0

    @property
    def any_soft(self) -> bool:
        return len(self.soft_violations) > 0


@dataclass
class _DimensionConfig:
    soft_limit: float
    hard_limit: Optional[float]
    weight: float
    adaptive: bool
    _observation_sum: float = 0.0
    _observation_count: int = 0


class DriftEnvelope:
    """
    Defines and enforces multi-dimensional behavioral operating envelopes.

    Usage:
        envelope = DriftEnvelope(default_soft=0.5, default_hard=0.9)
        envelope.add_dimension("login_freq", soft=0.4, hard=0.8)
        envelope.add_dimension("resource_diversity", soft=0.6)

        result = envelope.validate({
            "login_freq": 0.75,
            "resource_diversity": 0.3,
        })
    """

    def __init__(
        self,
        default_soft: float = 0.5,
        default_hard: Optional[float] = None,
        adaptive: bool = False,
        adaptation_rate: float = 0.02,
    ):
        """
        Args:
            default_soft:     Default soft violation threshold for unknown dimensions
            default_hard:     Default hard violation threshold (None = no hard limit)
            adaptive:         Expand soft limits slightly on consistent in-bounds data
            adaptation_rate:  Rate of envelope expansion per in-bounds observation
        """
        self.default_soft = default_soft
        self.default_hard = default_hard
        self.adaptive = adaptive
        self.adaptation_rate = adaptation_rate

        self._dimensions: Dict[str, _DimensionConfig] = {}
        self._violation_history: List[EnvelopeViolation] = []

    # ─── Configuration ───────────────────────────────────────────────────────

    def add_dimension(
        self,
        name: str,
        soft: Optional[float] = None,
        hard: Optional[float] = None,
        weight: float = 1.0,
        adaptive: Optional[bool] = None,
    ):
        """
        Register a named dimension with its soft and hard limits.

        Args:
            name:     Dimension identifier (e.g. "login_freq")
            soft:     Soft limit — violations trigger a warning
            hard:     Hard limit — violations trigger a halt (must be >= soft)
            weight:   Contribution to composite score
            adaptive: Override global adaptive setting for this dimension
        """
        s = soft if soft is not None else self.default_soft
        h = hard if hard is not None else self.default_hard

        if h is not None and h < s:
            raise ValueError(f"Hard limit ({h}) must be >= soft limit ({s}) for '{name}'")

        self._dimensions[name] = _DimensionConfig(
            soft_limit=s,
            hard_limit=h,
            weight=weight,
            adaptive=adaptive if adaptive is not None else self.adaptive,
        )

    # ─── Validation ──────────────────────────────────────────────────────────

    def validate(self, observation: Union[Dict[str, float], float]) -> EnvelopeResult:
        """
        Validate an observation against the envelope.

        Args:
            observation: Either a dict of {dimension: value} or a scalar
                         (scalar uses the default thresholds)

        Returns:
            EnvelopeResult
        """
        if isinstance(observation, (int, float)):
            return self._validate_scalar(float(observation))

        return self._validate_dict(observation)

    def validate_scalar(self, drift_score: float) -> bool:
        """Simple boolean check (backward compatible with spec interface)."""
        return drift_score <= self.default_soft

    # ─── History ─────────────────────────────────────────────────────────────

    def get_violations(
        self,
        hard_only: bool = False,
        dimension: Optional[str] = None,
    ) -> List[EnvelopeViolation]:
        vios = self._violation_history
        if hard_only:
            vios = [v for v in vios if v.is_hard]
        if dimension:
            vios = [v for v in vios if v.dimension == dimension]
        return vios

    # ─── Internals ───────────────────────────────────────────────────────────

    def _validate_scalar(self, value: float) -> EnvelopeResult:
        soft_vios, hard_vios = [], []
        is_hard = self.default_hard is not None and value > self.default_hard
        is_soft = value > self.default_soft

        if is_hard:
            v = EnvelopeViolation("default", value, self.default_soft, self.default_hard, True)
            hard_vios.append(v)
            self._violation_history.append(v)
        elif is_soft:
            v = EnvelopeViolation("default", value, self.default_soft, self.default_hard, False)
            soft_vios.append(v)
            self._violation_history.append(v)

        composite = min(1.0, value / self.default_soft) if self.default_soft > 0 else 0.0

        return EnvelopeResult(
            in_bounds=not (soft_vios or hard_vios),
            soft_violations=soft_vios,
            hard_violations=hard_vios,
            composite_score=round(composite, 4),
        )

    def _validate_dict(self, obs: Dict[str, float]) -> EnvelopeResult:
        soft_vios, hard_vios = [], []
        total_weight = 0.0
        weighted_excess = 0.0

        for dim, value in obs.items():
            cfg = self._dimensions.get(dim)
            if cfg is None:
                # Use defaults for undeclared dimensions
                cfg = _DimensionConfig(
                    soft_limit=self.default_soft,
                    hard_limit=self.default_hard,
                    weight=1.0,
                    adaptive=False,
                )

            total_weight += cfg.weight

            if cfg.hard_limit is not None and value > cfg.hard_limit:
                v = EnvelopeViolation(dim, value, cfg.soft_limit, cfg.hard_limit, True)
                hard_vios.append(v)
                self._violation_history.append(v)
                excess = (value - cfg.soft_limit) / max(cfg.soft_limit, 1e-9)
                weighted_excess += cfg.weight * min(1.0, excess)

            elif value > cfg.soft_limit:
                v = EnvelopeViolation(dim, value, cfg.soft_limit, cfg.hard_limit, False)
                soft_vios.append(v)
                self._violation_history.append(v)
                excess = (value - cfg.soft_limit) / max(cfg.soft_limit, 1e-9)
                weighted_excess += cfg.weight * min(1.0, excess)

            else:
                # In bounds: optionally adapt envelope
                if cfg.adaptive:
                    cfg.soft_limit = min(
                        cfg.soft_limit * (1 + self.adaptation_rate),
                        cfg.hard_limit or float("inf"),
                    )

        composite = round(weighted_excess / total_weight, 4) if total_weight else 0.0

        return EnvelopeResult(
            in_bounds=not (soft_vios or hard_vios),
            soft_violations=soft_vios,
            hard_violations=hard_vios,
            composite_score=composite,
        )