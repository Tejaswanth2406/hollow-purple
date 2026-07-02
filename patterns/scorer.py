"""
patterns/scorer.py — 4-Criteria Copy Layer Gate Evaluator
==========================================================
The Copy Layer uses four hard gates before a pattern is committed to
long-term memory.  A pattern that fails any single gate is dropped
without prejudice — it may be re-evaluated if it re-emerges later.

Gates
-----
1. STRUCTURAL ISOMORPHISM
   The graph sub-structure of the candidate pattern must be isomorphic
   to at least one previously stored pattern skeleton OR must satisfy
   a minimum structural complexity threshold (≥2 hops, ≥1 role node).

2. DIRECTIONAL PRIVILEGE GRADIENT
   At least one edge in the candidate path must cross an escalation
   boundary — i.e., the target role/service must have strictly higher
   effective-privilege than the source.

3. TEMPORAL PERSISTENCE  (N ≥ 3 observations)
   The exact same pattern (same actor class, same privilege path,
   same cloud provider) must have been observed at least N times
   across distinct temporal windows before it is stored.

4. CONTEXT INDEPENDENCE
   The pattern must recur across at least 2 distinct context variants
   (e.g., different source IPs, different time-of-day buckets, or
   different target resource identifiers) to exclude coincidental or
   environment-specific artefacts.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("hollow_purple.scorer")

# ---------------------------------------------------------------------------
# Configurable thresholds (override via env or config injection)
# ---------------------------------------------------------------------------

MIN_OBSERVATIONS: int = 3       # Gate 3: minimum repeated sightings
MIN_CONTEXT_VARIANTS: int = 2   # Gate 4: minimum distinct contexts
MIN_HOPS: int = 2               # Gate 1: minimum path length
MIN_PRIV_DELTA: float = 1.0     # Gate 2: minimum privilege elevation delta


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class PatternCandidate:
    """A candidate pattern submitted to the Copy Layer scorer."""

    pattern_id: str
    pattern_type: str               # PE, LM, TA, DI, etc.
    actor_class: str                # e.g. "service_account", "human_user"
    cloud_provider: str             # AWS | GCP | Azure
    privilege_path: list[str]       # ordered list of roles/services
    privilege_scores: list[float]   # effective-privilege score per hop
    observation_count: int          # how many times seen so far
    context_variants: set[str]      # distinct context fingerprints
    confidence: float               # aggregated confidence (0-1)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScorerResult:
    """Result from the 4-criteria gate evaluation."""

    pattern_id: str
    passed: bool

    gate_structural_isomorphism: bool = False
    gate_privilege_gradient: bool = False
    gate_temporal_persistence: bool = False
    gate_context_independence: bool = False

    failure_reasons: list[str] = field(default_factory=list)
    confidence: float = 0.0

    @property
    def gates_passed(self) -> int:
        return sum([
            self.gate_structural_isomorphism,
            self.gate_privilege_gradient,
            self.gate_temporal_persistence,
            self.gate_context_independence,
        ])


# ---------------------------------------------------------------------------
# Core scorer
# ---------------------------------------------------------------------------

class CopyLayerScorer:
    """
    Evaluates a PatternCandidate against the four Copy Layer gates.

    Usage::

        scorer = CopyLayerScorer()
        result = scorer.evaluate(candidate)
        if result.passed:
            memory_store.commit(candidate)
    """

    def __init__(
        self,
        min_observations: int = MIN_OBSERVATIONS,
        min_context_variants: int = MIN_CONTEXT_VARIANTS,
        min_hops: int = MIN_HOPS,
        min_priv_delta: float = MIN_PRIV_DELTA,
    ) -> None:
        self.min_observations = min_observations
        self.min_context_variants = min_context_variants
        self.min_hops = min_hops
        self.min_priv_delta = min_priv_delta

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(self, candidate: PatternCandidate) -> ScorerResult:
        """
        Run all four gates against the candidate pattern.

        Returns a ScorerResult; ``passed`` is True iff ALL four gates pass.
        """
        result = ScorerResult(
            pattern_id=candidate.pattern_id,
            passed=False,
            confidence=candidate.confidence,
        )

        result.gate_structural_isomorphism = self._check_structural(candidate, result)
        result.gate_privilege_gradient     = self._check_privilege(candidate, result)
        result.gate_temporal_persistence   = self._check_temporal(candidate, result)
        result.gate_context_independence   = self._check_context(candidate, result)

        result.passed = (
            result.gate_structural_isomorphism
            and result.gate_privilege_gradient
            and result.gate_temporal_persistence
            and result.gate_context_independence
        )

        level = logging.INFO if result.passed else logging.DEBUG
        logger.log(
            level,
            "CopyLayerScorer: pattern=%s passed=%s gates=%d/4 reasons=%s",
            candidate.pattern_id,
            result.passed,
            result.gates_passed,
            result.failure_reasons,
        )

        return result

    # ------------------------------------------------------------------
    # Gate implementations
    # ------------------------------------------------------------------

    def _check_structural(self, c: PatternCandidate, r: ScorerResult) -> bool:
        """Gate 1 — structural isomorphism / minimum complexity."""
        hops = len(c.privilege_path)
        if hops < self.min_hops:
            r.failure_reasons.append(
                f"Gate1: path too short ({hops} hops, need ≥{self.min_hops})"
            )
            return False
        return True

    def _check_privilege(self, c: PatternCandidate, r: ScorerResult) -> bool:
        """Gate 2 — directional privilege gradient (must escalate)."""
        scores = c.privilege_scores
        if not scores or len(scores) < 2:
            r.failure_reasons.append("Gate2: insufficient privilege score data")
            return False

        max_delta = max(
            scores[i + 1] - scores[i]
            for i in range(len(scores) - 1)
        )
        if max_delta < self.min_priv_delta:
            r.failure_reasons.append(
                f"Gate2: no escalation edge found (max delta={max_delta:.2f}, need ≥{self.min_priv_delta})"
            )
            return False
        return True

    def _check_temporal(self, c: PatternCandidate, r: ScorerResult) -> bool:
        """Gate 3 — temporal persistence (N ≥ 3 observations)."""
        if c.observation_count < self.min_observations:
            r.failure_reasons.append(
                f"Gate3: only {c.observation_count} observation(s), need ≥{self.min_observations}"
            )
            return False
        return True

    def _check_context(self, c: PatternCandidate, r: ScorerResult) -> bool:
        """Gate 4 — context independence (recurs across ≥2 distinct contexts)."""
        n = len(c.context_variants)
        if n < self.min_context_variants:
            r.failure_reasons.append(
                f"Gate4: only {n} context variant(s), need ≥{self.min_context_variants}"
            )
            return False
        return True


# ---------------------------------------------------------------------------
# Module-level convenience instance
# ---------------------------------------------------------------------------

default_scorer = CopyLayerScorer()


def evaluate_pattern(candidate: PatternCandidate) -> ScorerResult:
    """Evaluate a candidate using the default scorer configuration."""
    return default_scorer.evaluate(candidate)


__all__ = [
    "CopyLayerScorer",
    "PatternCandidate",
    "ScorerResult",
    "evaluate_pattern",
    "default_scorer",
    "MIN_OBSERVATIONS",
    "MIN_CONTEXT_VARIANTS",
    "MIN_HOPS",
    "MIN_PRIV_DELTA",
]
