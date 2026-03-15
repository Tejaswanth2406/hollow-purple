"""
projections/risk_projection.py
================================
Enterprise multi-factor risk scoring engine.

Scoring model
-------------
Risk is computed across four orthogonal dimensions:

    1. Identity Risk       — behavioral anomalies, privilege footprint,
                             action entropy, peer-group deviation

    2. Exposure Risk       — attack surface score, blast radius,
                             sensitive data exposure, hop distance

    3. Velocity Risk       — event rate spikes, temporal clustering,
                             high-frequency resource access

    4. Graph Position Risk — centrality, path criticality, node type weight

Final risk score is a weighted composite normalized to [0, 100].

Risk tiers
----------
    CRITICAL   ≥ 80
    HIGH       ≥ 60
    MEDIUM     ≥ 35
    LOW        ≥ 15
    MINIMAL    <  15

Design
------
- Fully deterministic: same inputs → same outputs
- Weights are configurable at construction for tuning per deployment
- All scoring functions are pure (no side effects)
- Emits structured RiskScore and RiskReport objects for SIEM/SOAR
- Supports identity, asset, and composite (entity-level) scoring
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Risk tier
# ---------------------------------------------------------------------------


class RiskTier(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    MINIMAL  = "minimal"

    @classmethod
    def from_score(cls, score: float) -> "RiskTier":
        if score >= 80:
            return cls.CRITICAL
        if score >= 60:
            return cls.HIGH
        if score >= 35:
            return cls.MEDIUM
        if score >= 15:
            return cls.LOW
        return cls.MINIMAL

    @property
    def numeric(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "minimal": 0}[self.value]


# ---------------------------------------------------------------------------
# Risk score record
# ---------------------------------------------------------------------------


@dataclass
class RiskScore:
    """
    Comprehensive risk assessment for a single entity (identity or asset).

    Fields
    ------
    entity_id           : Identifier of the scored entity.
    entity_type         : ``"identity"`` | ``"asset"`` | ``"composite"``
    total_score         : Normalized composite score [0, 100].
    tier                : RiskTier derived from total_score.
    identity_score      : Contribution from identity dimension.
    exposure_score      : Contribution from exposure dimension.
    velocity_score      : Contribution from velocity dimension.
    graph_score         : Contribution from graph position dimension.
    contributing_factors: Ordered list of scored factors with weights.
    anomaly_count       : Number of anomaly flags detected.
    scored_at           : UTC ISO-8601 timestamp.
    """

    entity_id: str
    entity_type: str
    total_score: float
    tier: RiskTier
    identity_score: float = 0.0
    exposure_score: float = 0.0
    velocity_score: float = 0.0
    graph_score: float = 0.0
    contributing_factors: List[Dict[str, Any]] = field(default_factory=list)
    anomaly_count: int = 0
    scored_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "total_score": round(self.total_score, 2),
            "tier": self.tier.value,
            "dimensions": {
                "identity": round(self.identity_score, 2),
                "exposure": round(self.exposure_score, 2),
                "velocity": round(self.velocity_score, 2),
                "graph_position": round(self.graph_score, 2),
            },
            "anomaly_count": self.anomaly_count,
            "contributing_factors": self.contributing_factors[:10],
            "scored_at": self.scored_at,
        }


# ---------------------------------------------------------------------------
# Risk report
# ---------------------------------------------------------------------------


@dataclass
class RiskReport:
    """
    Aggregated risk intelligence report across all scored entities.

    Fields
    ------
    scores              : All computed RiskScore objects.
    by_tier             : {tier: count} distribution.
    mean_score          : Average total score across all entities.
    top_risks           : Top-N highest risk entities.
    critical_count      : Number of CRITICAL-tier entities.
    attack_surface_score: Aggregated exposure surface score (from ExposureProjection).
    generated_at        : UTC ISO-8601 timestamp.
    """

    scores: List[RiskScore]
    by_tier: Dict[str, int]
    mean_score: float
    top_risks: List[RiskScore]
    critical_count: int
    attack_surface_score: float = 0.0
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_entities": len(self.scores),
            "by_tier": self.by_tier,
            "mean_score": round(self.mean_score, 2),
            "critical_count": self.critical_count,
            "attack_surface_score": round(self.attack_surface_score, 2),
            "top_risks": [r.to_dict() for r in self.top_risks[:20]],
            "generated_at": self.generated_at,
        }


# ---------------------------------------------------------------------------
# Dimension weights (configurable)
# ---------------------------------------------------------------------------


@dataclass
class RiskWeights:
    """
    Tunable dimension weights. Must sum to 1.0.
    Adjust per deployment profile (e.g., insider-threat-focused
    deployments weight identity higher; perimeter-focused weight exposure).
    """

    identity: float = 0.35
    exposure: float = 0.30
    velocity: float = 0.20
    graph_position: float = 0.15

    # Node type risk multipliers
    node_type_weights: Dict[str, float] = field(default_factory=lambda: {
        "database":         2.0,
        "secrets_manager":  2.5,
        "key_vault":        2.5,
        "k8s_control_plane": 2.0,
        "domain_controller": 2.5,
        "authentication":   2.0,
        "storage_bucket":   1.5,
        "api_gateway":      1.5,
        "load_balancer":    1.2,
        "host":             1.0,
        "service":          1.0,
        "user":             1.0,
        "generic":          0.8,
    })

    def validate(self) -> None:
        total = self.identity + self.exposure + self.velocity + self.graph_position
        if not math.isclose(total, 1.0, rel_tol=1e-3):
            raise ValueError(f"RiskWeights must sum to 1.0, got {total}")


# ---------------------------------------------------------------------------
# RiskProjection
# ---------------------------------------------------------------------------


class RiskProjection:
    """
    Multi-factor risk scoring engine for Hollow Purple.

    Scores identities, assets, and composite entities using a weighted
    four-dimension model. Produces structured RiskScore and RiskReport
    objects suitable for Mahoraga decision-engine consumption.

    Usage
    -----
    ::

        risk = RiskProjection()

        # Score all identities from IdentityProjection
        scores = risk.score_all_identities(identity_projection)

        # Score assets from ExposureProjection + GraphProjection
        asset_scores = risk.score_all_assets(exposure_projection, graph_projection)

        # Full consolidated report
        report = risk.generate_report(
            identity_projection=ip,
            exposure_projection=ep,
            graph_projection=gp,
        )
    """

    def __init__(self, *, weights: Optional[RiskWeights] = None) -> None:
        self._weights = weights or RiskWeights()
        self._weights.validate()
        self._scores: Dict[str, RiskScore] = {}

        logger.info(
            "RiskProjection initialised",
            extra={
                "weights": {
                    "identity": self._weights.identity,
                    "exposure": self._weights.exposure,
                    "velocity": self._weights.velocity,
                    "graph": self._weights.graph_position,
                }
            },
        )

    # ---------------------------------------------------------------------------
    # Internal scoring helpers
    # ---------------------------------------------------------------------------

    def _normalize(self, raw: float, *, cap: float = 100.0) -> float:
        """Clamp and normalize a raw score to [0, 100]."""
        return round(min(max(raw, 0.0), cap), 4)

    def _factor(
        self, name: str, value: float, weight: float, explanation: str = ""
    ) -> Tuple[float, Dict[str, Any]]:
        """Compute a single contributing factor and return (contribution, record)."""
        contribution = value * weight
        record = {
            "factor": name,
            "raw_value": round(value, 4),
            "weight": weight,
            "contribution": round(contribution, 4),
            "explanation": explanation,
        }
        return contribution, record

    # ---------------------------------------------------------------------------
    # Identity dimension
    # ---------------------------------------------------------------------------

    def _score_identity_dimension(self, profile) -> Tuple[float, List[Dict]]:
        """
        Score an IdentityProfile on the identity risk dimension.

        Factors
        -------
        - Anomaly flag count (weighted by flag severity)
        - Privilege footprint
        - Activity entropy
        - Peer deviation z-score
        """
        factors: List[Dict[str, Any]] = []
        total = 0.0

        # Anomaly flags
        flag_score = len(profile.anomaly_flags) * 12.0
        flag_score = self._normalize(flag_score, cap=60.0)
        val, rec = self._factor(
            "anomaly_flags", flag_score, 1.0,
            f"{len(profile.anomaly_flags)} anomaly flags detected"
        )
        total += val
        factors.append(rec)

        # Privilege footprint
        pf = self._normalize(profile.privilege_footprint() * 8.0, cap=30.0)
        val, rec = self._factor(
            "privilege_footprint", pf, 1.0,
            "Breadth of resource × action access"
        )
        total += val
        factors.append(rec)

        # Activity entropy
        entropy_score = self._normalize(profile.activity_entropy() * 5.0, cap=20.0)
        val, rec = self._factor(
            "activity_entropy", entropy_score, 1.0,
            "Shannon entropy of resource access distribution"
        )
        total += val
        factors.append(rec)

        # Event volume relative signal (log-scaled)
        volume_score = self._normalize(math.log1p(profile.event_count) * 2.5, cap=15.0)
        val, rec = self._factor(
            "event_volume", volume_score, 1.0,
            "Log-scaled total event count"
        )
        total += val
        factors.append(rec)

        return self._normalize(total), factors

    # ---------------------------------------------------------------------------
    # Exposure dimension
    # ---------------------------------------------------------------------------

    def _score_exposure_dimension(
        self, node_id: str, exposure_projection
    ) -> Tuple[float, List[Dict]]:
        """Score an entity on the exposure risk dimension."""
        factors: List[Dict[str, Any]] = []
        total = 0.0

        record = exposure_projection.get_record(node_id) if exposure_projection else None
        if record is None:
            return 0.0, []

        # Severity score
        sev_score = self._normalize(float(record.severity.score), cap=100.0)
        val, rec = self._factor(
            "exposure_severity", sev_score, 0.5,
            f"Exposure severity: {record.severity.value}"
        )
        total += val
        factors.append(rec)

        # Hop distance (closer = worse)
        hop_score = self._normalize((4 - min(record.hop_distance, 4)) * 15.0, cap=60.0)
        val, rec = self._factor(
            "hop_distance", hop_score, 0.3,
            f"{record.hop_distance} hops from internet entry point"
        )
        total += val
        factors.append(rec)

        # Sensitive data
        sensitive_score = 30.0 if record.sensitive_data_tags else 0.0
        val, rec = self._factor(
            "sensitive_data", sensitive_score, 0.2,
            f"Sensitive tags: {record.sensitive_data_tags}"
        )
        total += val
        factors.append(rec)

        return self._normalize(total), factors

    # ---------------------------------------------------------------------------
    # Velocity dimension
    # ---------------------------------------------------------------------------

    def _score_velocity_dimension(self, profile) -> Tuple[float, List[Dict]]:
        """Score an identity on event rate / velocity risk dimension."""
        factors: List[Dict[str, Any]] = []
        total = 0.0

        peak = profile.peak_velocity()
        vel_score = self._normalize(math.log1p(peak) * 10.0, cap=60.0)
        val, rec = self._factor(
            "peak_velocity", vel_score, 1.0,
            f"Peak events/hour: {peak}"
        )
        total += val
        factors.append(rec)

        return self._normalize(total), factors

    # ---------------------------------------------------------------------------
    # Graph position dimension
    # ---------------------------------------------------------------------------

    def _score_graph_dimension(
        self, node_id: str, graph_projection
    ) -> Tuple[float, List[Dict]]:
        """Score an entity on its structural position in the attack graph."""
        factors: List[Dict[str, Any]] = []
        total = 0.0

        if graph_projection is None:
            return 0.0, []

        degree = graph_projection.degree(node_id)
        out_d = degree.get("out", 0)
        in_d = degree.get("in", 0)

        # Out-degree: pivot potential (can reach many nodes)
        pivot_score = self._normalize(math.log1p(out_d) * 12.0, cap=50.0)
        val, rec = self._factor(
            "pivot_potential", pivot_score, 0.6,
            f"Out-degree: {out_d} (attack pivot potential)"
        )
        total += val
        factors.append(rec)

        # In-degree: target attractiveness (many things depend on this node)
        target_score = self._normalize(math.log1p(in_d) * 8.0, cap=40.0)
        val, rec = self._factor(
            "target_attractiveness", target_score, 0.4,
            f"In-degree: {in_d} (target value)"
        )
        total += val
        factors.append(rec)

        # Node type multiplier
        node_meta = graph_projection.get_node(node_id)
        node_type = node_meta.get("node_type", "generic") if node_meta else "generic"
        multiplier = self._weights.node_type_weights.get(node_type, 1.0)
        total *= multiplier
        factors.append({
            "factor": "node_type_multiplier",
            "node_type": node_type,
            "multiplier": multiplier,
        })

        return self._normalize(total), factors

    # ---------------------------------------------------------------------------
    # Composite scoring
    # ---------------------------------------------------------------------------

    def _composite_score(
        self,
        identity_dim: float,
        exposure_dim: float,
        velocity_dim: float,
        graph_dim: float,
    ) -> float:
        w = self._weights
        raw = (
            identity_dim * w.identity
            + exposure_dim * w.exposure
            + velocity_dim * w.velocity
            + graph_dim * w.graph_position
        )
        return self._normalize(raw)

    # ---------------------------------------------------------------------------
    # Public scoring APIs
    # ---------------------------------------------------------------------------

    def score_identity(
        self,
        profile,
        *,
        exposure_projection=None,
        graph_projection=None,
    ) -> RiskScore:
        """
        Compute a full RiskScore for an IdentityProfile.

        Parameters
        ----------
        profile             : IdentityProfile from IdentityProjection.
        exposure_projection : Optional ExposureProjection for exposure dimension.
        graph_projection    : Optional GraphProjection for graph dimension.
        """
        identity_score, id_factors = self._score_identity_dimension(profile)
        velocity_score, vel_factors = self._score_velocity_dimension(profile)
        exposure_score, exp_factors = self._score_exposure_dimension(
            profile.identity, exposure_projection
        )
        graph_score, graph_factors = self._score_graph_dimension(
            profile.identity, graph_projection
        )

        total = self._composite_score(
            identity_score, exposure_score, velocity_score, graph_score
        )
        tier = RiskTier.from_score(total)
        all_factors = id_factors + exp_factors + vel_factors + graph_factors
        all_factors.sort(key=lambda f: f.get("contribution", 0), reverse=True)

        score = RiskScore(
            entity_id=profile.identity,
            entity_type="identity",
            total_score=total,
            tier=tier,
            identity_score=identity_score,
            exposure_score=exposure_score,
            velocity_score=velocity_score,
            graph_score=graph_score,
            contributing_factors=all_factors,
            anomaly_count=len(profile.anomaly_flags),
        )
        self._scores[profile.identity] = score
        return score

    def score_all_identities(
        self,
        identity_projection,
        *,
        exposure_projection=None,
        graph_projection=None,
    ) -> List[RiskScore]:
        """Score every identity in an IdentityProjection."""
        scores = []
        for profile in identity_projection.all_profiles().values():
            s = self.score_identity(
                profile,
                exposure_projection=exposure_projection,
                graph_projection=graph_projection,
            )
            scores.append(s)

        scores.sort(key=lambda s: s.total_score, reverse=True)
        logger.info(
            "Identity risk scoring complete",
            extra={
                "total": len(scores),
                "critical": sum(1 for s in scores if s.tier == RiskTier.CRITICAL),
                "high": sum(1 for s in scores if s.tier == RiskTier.HIGH),
            },
        )
        return scores

    def score_asset(
        self,
        node_id: str,
        *,
        exposure_projection=None,
        graph_projection=None,
    ) -> RiskScore:
        """Score a graph asset node."""
        exposure_score, exp_factors = self._score_exposure_dimension(
            node_id, exposure_projection
        )
        graph_score, graph_factors = self._score_graph_dimension(
            node_id, graph_projection
        )
        total = self._composite_score(0.0, exposure_score, 0.0, graph_score)
        tier = RiskTier.from_score(total)

        all_factors = exp_factors + graph_factors
        all_factors.sort(key=lambda f: f.get("contribution", 0), reverse=True)

        score = RiskScore(
            entity_id=node_id,
            entity_type="asset",
            total_score=total,
            tier=tier,
            exposure_score=exposure_score,
            graph_score=graph_score,
            contributing_factors=all_factors,
        )
        self._scores[node_id] = score
        return score

    # ---------------------------------------------------------------------------
    # Report generation
    # ---------------------------------------------------------------------------

    def generate_report(
        self,
        *,
        identity_projection=None,
        exposure_projection=None,
        graph_projection=None,
    ) -> RiskReport:
        """
        Generate a consolidated risk intelligence report.
        Scores all available identities and surfaces.
        """
        all_scores: List[RiskScore] = []

        if identity_projection:
            all_scores.extend(
                self.score_all_identities(
                    identity_projection,
                    exposure_projection=exposure_projection,
                    graph_projection=graph_projection,
                )
            )

        by_tier: Dict[str, int] = {t.value: 0 for t in RiskTier}
        for s in all_scores:
            by_tier[s.tier.value] += 1

        mean_score = (
            sum(s.total_score for s in all_scores) / len(all_scores)
            if all_scores
            else 0.0
        )

        surface_score = 0.0
        if exposure_projection:
            surface = exposure_projection._build_surface() if hasattr(exposure_projection, '_build_surface') else None
            # Access cached surface score
            all_records = exposure_projection.all_records()
            surface_score = sum(r.severity.score for r in all_records)

        top = sorted(all_scores, key=lambda s: s.total_score, reverse=True)

        report = RiskReport(
            scores=all_scores,
            by_tier=by_tier,
            mean_score=round(mean_score, 2),
            top_risks=top[:20],
            critical_count=by_tier.get("critical", 0),
            attack_surface_score=surface_score,
        )

        logger.info(
            "Risk report generated",
            extra={
                "entities": len(all_scores),
                "critical": report.critical_count,
                "mean_score": report.mean_score,
            },
        )
        return report

    # ---------------------------------------------------------------------------
    # Query API
    # ---------------------------------------------------------------------------

    def get_score(self, entity_id: str) -> Optional[RiskScore]:
        return self._scores.get(entity_id)

    def top_risks(self, n: int = 10) -> List[RiskScore]:
        return sorted(self._scores.values(), key=lambda s: s.total_score, reverse=True)[:n]

    def by_tier(self, tier: RiskTier) -> List[RiskScore]:
        return [s for s in self._scores.values() if s.tier == tier]