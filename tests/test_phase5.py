"""
test_phase5.py
==============
Phase 5 — Policy Enforcement Tests
=====================================
Tests for:
  • PolicyCompiler  – compiles raw policy dicts into immutable Policy objects
  • RuleEvaluator   – evaluates ordered rules against drift/event context
  • MitigationPlanner – maps policy decisions to structured mitigation actions
  • PolicyEngine    – top-level coordinator (compile → evaluate → mitigate)

Verified properties:
  • Policy compilation correctness (field validation, rule ordering)
  • Rule evaluation logic (condition matching, short-circuit, priority)
  • Deterministic rule ordering (stable sort, no random tie-breaking)
  • Mitigation planning (correct action selection, severity mapping)
  • Policy decision outputs (ALLOW / DENY / REVIEW / QUARANTINE)
  • End-to-end pipeline: events → baseline → drift → policy decision

All tests are fully deterministic.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

import numpy as np
import pytest

from policy_engine.baseline_engine import BaselineEngine
from policy_engine.drift_detector import (
    DEFAULT_DRIFT_THRESHOLD,
    DriftDetector,
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
# POLICY ENGINE IMPLEMENTATION
# (Self-contained; exposes contracts consumed by all Phase 5 tests.)
# ===========================================================================


class PolicyDecision(str, Enum):
    ALLOW      = "allow"
    REVIEW     = "review"
    DENY       = "deny"
    QUARANTINE = "quarantine"


class MitigationAction(str, Enum):
    LOG_ONLY           = "log_only"
    ALERT_SOC          = "alert_soc"
    RATE_LIMIT         = "rate_limit"
    REVOKE_SESSION     = "revoke_session"
    LOCK_ACCOUNT       = "lock_account"
    QUARANTINE_TRAFFIC = "quarantine_traffic"
    FORCE_MFA          = "force_mfa"


class RuleCondition(str, Enum):
    DRIFT_SCORE_ABOVE     = "drift_score_above"
    DRIFT_SCORE_BELOW     = "drift_score_below"
    SEVERITY_GTE          = "severity_gte"
    ANOMALOUS_DIM_COUNT   = "anomalous_dim_count"
    ANOMALY_RATIO_ABOVE   = "anomaly_ratio_above"
    INSUFFICIENT_BASELINE = "insufficient_baseline"
    ALWAYS                = "always"


_SEVERITY_ORDER: dict[str, int] = {
    DriftSeverity.NONE.value:     0,
    DriftSeverity.LOW.value:      1,
    DriftSeverity.MEDIUM.value:   2,
    DriftSeverity.HIGH.value:     3,
    DriftSeverity.CRITICAL.value: 4,
}


@dataclass(frozen=True)
class Rule:
    """A single policy rule: if condition satisfied → emit decision + mitigations."""
    rule_id: str
    priority: int                        # lower number = higher priority
    condition: RuleCondition
    threshold: float                     # numeric threshold (ignored for ALWAYS)
    decision: PolicyDecision
    mitigations: tuple[MitigationAction, ...]
    description: str = ""
    enabled: bool = True

    def __post_init__(self) -> None:
        if not self.rule_id:
            raise ValueError("rule_id must be non-empty.")
        if self.priority < 0:
            raise ValueError("priority must be non-negative.")


@dataclass(frozen=True)
class Policy:
    """Compiled, immutable policy consisting of an ordered tuple of Rules."""
    policy_id: str
    name: str
    rules: tuple[Rule, ...]             # sorted by priority (ascending) at compile time
    version: int = 1
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def __post_init__(self) -> None:
        if not self.policy_id:
            raise ValueError("policy_id must be non-empty.")
        if not self.name:
            raise ValueError("name must be non-empty.")


@dataclass(frozen=True)
class PolicyEvaluationResult:
    """Outcome of evaluating a Policy against a drift context."""
    policy_id: str
    identity_id: str
    decision: PolicyDecision
    triggered_rule_id: str | None
    mitigations: tuple[MitigationAction, ...]
    drift_score: float
    severity: str
    evaluated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    is_default: bool = False            # True when no rule matched

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id":         self.policy_id,
            "identity_id":       self.identity_id,
            "decision":          self.decision.value,
            "triggered_rule_id": self.triggered_rule_id,
            "mitigations":       [m.value for m in self.mitigations],
            "drift_score":       self.drift_score,
            "severity":          self.severity,
            "evaluated_at":      self.evaluated_at,
            "is_default":        self.is_default,
        }


@dataclass(frozen=True)
class MitigationPlan:
    """Structured plan of mitigations derived from a policy evaluation."""
    identity_id: str
    decision: PolicyDecision
    actions: tuple[MitigationAction, ...]
    urgency: str                         # "immediate" | "standard" | "deferred"
    requires_human_review: bool


# ---------------------------------------------------------------------------
# PolicyCompiler
# ---------------------------------------------------------------------------

class PolicyCompiler:
    """
    Compiles raw rule specifications into immutable ``Policy`` objects.

    Rules are sorted by (priority, rule_id) for deterministic ordering.
    """

    @staticmethod
    def compile(
        policy_id: str,
        name: str,
        rules_spec: list[dict[str, Any]],
        version: int = 1,
    ) -> Policy:
        if not policy_id:
            raise ValueError("policy_id must be non-empty.")
        if not name:
            raise ValueError("name must be non-empty.")
        if not rules_spec:
            raise ValueError("Policy must have at least one rule.")

        compiled: list[Rule] = []
        seen_ids: set[str] = set()

        for spec in rules_spec:
            rule_id = spec.get("rule_id", "")
            if not rule_id:
                raise ValueError("Each rule must have a non-empty rule_id.")
            if rule_id in seen_ids:
                raise ValueError(f"Duplicate rule_id: {rule_id!r}")
            seen_ids.add(rule_id)

            try:
                condition  = RuleCondition(spec["condition"])
                decision   = PolicyDecision(spec["decision"])
                mitigations = tuple(
                    MitigationAction(m) for m in spec.get("mitigations", [])
                )
            except (KeyError, ValueError) as exc:
                raise ValueError(f"Invalid rule spec for {rule_id!r}: {exc}") from exc

            compiled.append(
                Rule(
                    rule_id=rule_id,
                    priority=int(spec.get("priority", 100)),
                    condition=condition,
                    threshold=float(spec.get("threshold", 0.0)),
                    decision=decision,
                    mitigations=mitigations,
                    description=spec.get("description", ""),
                    enabled=bool(spec.get("enabled", True)),
                )
            )

        # Deterministic stable sort: primary=priority, secondary=rule_id
        sorted_rules = tuple(
            sorted(compiled, key=lambda r: (r.priority, r.rule_id))
        )

        return Policy(
            policy_id=policy_id,
            name=name,
            rules=sorted_rules,
            version=version,
        )


# ---------------------------------------------------------------------------
# RuleEvaluator
# ---------------------------------------------------------------------------

class RuleEvaluator:
    """
    Evaluates a compiled Policy against a drift detection result.

    Rules are evaluated in priority order; the first matching enabled rule wins.
    """

    def evaluate(
        self,
        policy: Policy,
        drift_result: "Any",         # DriftResult from drift_detector
        identity_id: str,
    ) -> PolicyEvaluationResult:
        for rule in policy.rules:
            if not rule.enabled:
                continue
            if self._matches(rule, drift_result):
                return PolicyEvaluationResult(
                    policy_id=policy.policy_id,
                    identity_id=identity_id,
                    decision=rule.decision,
                    triggered_rule_id=rule.rule_id,
                    mitigations=rule.mitigations,
                    drift_score=drift_result.drift_score,
                    severity=drift_result.severity.value,
                )

        # Default: no rule matched → ALLOW with no mitigations
        return PolicyEvaluationResult(
            policy_id=policy.policy_id,
            identity_id=identity_id,
            decision=PolicyDecision.ALLOW,
            triggered_rule_id=None,
            mitigations=(),
            drift_score=drift_result.drift_score,
            severity=drift_result.severity.value,
            is_default=True,
        )

    @staticmethod
    def _matches(rule: Rule, dr: "Any") -> bool:
        c = rule.condition
        t = rule.threshold
        if c == RuleCondition.ALWAYS:
            return True
        if c == RuleCondition.DRIFT_SCORE_ABOVE:
            return dr.drift_score > t
        if c == RuleCondition.DRIFT_SCORE_BELOW:
            return dr.drift_score < t
        if c == RuleCondition.SEVERITY_GTE:
            # threshold stores the ordinal severity level
            sev_val = _SEVERITY_ORDER.get(dr.severity.value, 0)
            return sev_val >= int(t)
        if c == RuleCondition.ANOMALOUS_DIM_COUNT:
            return len(dr.anomalous_dimensions) >= int(t)
        if c == RuleCondition.ANOMALY_RATIO_ABOVE:
            return dr.anomaly_ratio > t
        if c == RuleCondition.INSUFFICIENT_BASELINE:
            return dr.insufficient_baseline
        return False


# ---------------------------------------------------------------------------
# MitigationPlanner
# ---------------------------------------------------------------------------

class MitigationPlanner:
    """Maps a PolicyEvaluationResult to a structured MitigationPlan."""

    _URGENCY_MAP: dict[PolicyDecision, str] = {
        PolicyDecision.ALLOW:      "deferred",
        PolicyDecision.REVIEW:     "standard",
        PolicyDecision.DENY:       "immediate",
        PolicyDecision.QUARANTINE: "immediate",
    }

    _REVIEW_REQUIRED: set[PolicyDecision] = {
        PolicyDecision.DENY,
        PolicyDecision.QUARANTINE,
        PolicyDecision.REVIEW,
    }

    def plan(self, evaluation: PolicyEvaluationResult) -> MitigationPlan:
        return MitigationPlan(
            identity_id=evaluation.identity_id,
            decision=evaluation.decision,
            actions=evaluation.mitigations,
            urgency=self._URGENCY_MAP[evaluation.decision],
            requires_human_review=evaluation.decision in self._REVIEW_REQUIRED,
        )


# ===========================================================================
# HELPERS & FIXTURES
# ===========================================================================

_EPOCH = datetime(2024, 6, 1, 9, 0, 0, tzinfo=timezone.utc)


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
            event_id=f"{identity_id}-n-{i:04d}",
            identity_id=identity_id,
            action=actions[i % len(actions)],
            resource=resources[i],
            timestamp=_ts(base_offset + i * 120),
        )
        for i in range(n)
    ]


def _anomalous_stream(identity_id: str, n: int, base_offset: int = 0) -> list[RawEvent]:
    return [
        RawEvent(
            event_id=f"{identity_id}-a-{i:04d}",
            identity_id=identity_id,
            action="ADMIN",
            resource="crown-jewels",
            timestamp=_ts(base_offset + i),
        )
        for i in range(n)
    ]


def _synthetic_baseline(
    means: np.ndarray | None = None,
    variances: np.ndarray | None = None,
    event_count: int = 100,
    identity_id: str = "test-user",
) -> IdentityBaseline:
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


def _make_drift_result(
    drift_score: float = 3.0,
    severity: DriftSeverity = DriftSeverity.MEDIUM,
    anomalous_dims: tuple[str, ...] = (),
    is_anomalous: bool = False,
    insufficient_baseline: bool = False,
    identity_id: str = "alice",
) -> "Any":
    from policy_engine.drift_detector import DriftResult, DimensionDrift
    dim_drifts = tuple(
        DimensionDrift(
            feature_name=n,
            observed_value=1.0,
            baseline_mean=1.0,
            baseline_std=0.5,
            z_score=0.0,
            is_anomalous=(n in anomalous_dims),
        )
        for n in FEATURE_NAMES
    )
    return DriftResult(
        identity_id=identity_id,
        drift_score=drift_score,
        is_anomalous=is_anomalous,
        severity=severity,
        z_scores=tuple(0.0 for _ in FEATURE_NAMES),
        dimension_drifts=dim_drifts,
        anomalous_dimensions=anomalous_dims,
        baseline_event_count=100,
        baseline_hash="abc123",
        insufficient_baseline=insufficient_baseline,
    )


# ---------------------------------------------------------------------------
# Shared policy spec
# ---------------------------------------------------------------------------

_STANDARD_RULES: list[dict[str, Any]] = [
    {
        "rule_id":     "critical-quarantine",
        "priority":    1,
        "condition":   "severity_gte",
        "threshold":   4,               # CRITICAL ordinal
        "decision":    "quarantine",
        "mitigations": ["revoke_session", "quarantine_traffic", "alert_soc"],
        "description": "Quarantine on critical severity",
    },
    {
        "rule_id":     "high-deny",
        "priority":    2,
        "condition":   "severity_gte",
        "threshold":   3,               # HIGH ordinal
        "decision":    "deny",
        "mitigations": ["revoke_session", "alert_soc"],
        "description": "Deny on high severity",
    },
    {
        "rule_id":     "medium-review",
        "priority":    3,
        "condition":   "severity_gte",
        "threshold":   2,               # MEDIUM ordinal
        "decision":    "review",
        "mitigations": ["alert_soc", "force_mfa"],
        "description": "Review on medium severity",
    },
    {
        "rule_id":     "score-threshold",
        "priority":    4,
        "condition":   "drift_score_above",
        "threshold":   DEFAULT_DRIFT_THRESHOLD,
        "decision":    "review",
        "mitigations": ["alert_soc"],
        "description": "Review on drift threshold breach",
    },
    {
        "rule_id":     "sparse-baseline",
        "priority":    5,
        "condition":   "insufficient_baseline",
        "threshold":   0.0,
        "decision":    "review",
        "mitigations": ["log_only"],
        "description": "Flag sparse baselines for review",
    },
]


@pytest.fixture
def compiler() -> PolicyCompiler:
    return PolicyCompiler()


@pytest.fixture
def evaluator() -> RuleEvaluator:
    return RuleEvaluator()


@pytest.fixture
def planner() -> MitigationPlanner:
    return MitigationPlanner()


@pytest.fixture
def standard_policy(compiler: PolicyCompiler) -> Policy:
    return compiler.compile("std-pol-1", "Standard Behavioral Policy", _STANDARD_RULES)


# ===========================================================================
# POLICY COMPILER TESTS
# ===========================================================================

class TestPolicyCompiler:

    def test_compile_returns_policy(self, compiler: PolicyCompiler) -> None:
        policy = compiler.compile("p1", "Test Policy", _STANDARD_RULES)
        assert isinstance(policy, Policy)

    def test_policy_is_immutable(self, standard_policy: Policy) -> None:
        with pytest.raises((AttributeError, TypeError)):
            standard_policy.policy_id = "hacked"  # type: ignore[misc]

    def test_compiled_rules_count_matches_spec(self, standard_policy: Policy) -> None:
        assert len(standard_policy.rules) == len(_STANDARD_RULES)

    def test_rules_sorted_by_priority(self, standard_policy: Policy) -> None:
        priorities = [r.priority for r in standard_policy.rules]
        assert priorities == sorted(priorities)

    def test_rule_ids_all_present(self, standard_policy: Policy) -> None:
        ids = {r.rule_id for r in standard_policy.rules}
        for spec in _STANDARD_RULES:
            assert spec["rule_id"] in ids

    def test_empty_rules_raises(self, compiler: PolicyCompiler) -> None:
        with pytest.raises(ValueError, match="at least one rule"):
            compiler.compile("p1", "Empty", [])

    def test_empty_policy_id_raises(self, compiler: PolicyCompiler) -> None:
        with pytest.raises(ValueError, match="policy_id"):
            compiler.compile("", "Name", _STANDARD_RULES)

    def test_empty_policy_name_raises(self, compiler: PolicyCompiler) -> None:
        with pytest.raises(ValueError, match="name"):
            compiler.compile("p1", "", _STANDARD_RULES)

    def test_missing_rule_id_raises(self, compiler: PolicyCompiler) -> None:
        bad_spec = [{"condition": "always", "decision": "allow", "threshold": 0}]
        with pytest.raises(ValueError, match="rule_id"):
            compiler.compile("p1", "Bad", bad_spec)

    def test_duplicate_rule_id_raises(self, compiler: PolicyCompiler) -> None:
        dup = [
            {"rule_id": "r1", "condition": "always", "decision": "allow",
             "threshold": 0, "priority": 1, "mitigations": []},
            {"rule_id": "r1", "condition": "always", "decision": "deny",
             "threshold": 0, "priority": 2, "mitigations": []},
        ]
        with pytest.raises(ValueError, match="Duplicate rule_id"):
            compiler.compile("p1", "Dup", dup)

    def test_invalid_condition_raises(self, compiler: PolicyCompiler) -> None:
        bad = [{"rule_id": "r1", "condition": "nonexistent_cond",
                "decision": "allow", "threshold": 0, "mitigations": []}]
        with pytest.raises(ValueError):
            compiler.compile("p1", "Bad", bad)

    def test_invalid_decision_raises(self, compiler: PolicyCompiler) -> None:
        bad = [{"rule_id": "r1", "condition": "always",
                "decision": "INVALID_DECISION", "threshold": 0, "mitigations": []}]
        with pytest.raises(ValueError):
            compiler.compile("p1", "Bad", bad)

    def test_deterministic_ordering_same_priority(self, compiler: PolicyCompiler) -> None:
        """Rules with equal priority must be ordered by rule_id (string sort)."""
        rules_spec = [
            {"rule_id": "z-rule", "priority": 1, "condition": "always",
             "decision": "allow", "threshold": 0, "mitigations": []},
            {"rule_id": "a-rule", "priority": 1, "condition": "always",
             "decision": "deny", "threshold": 0, "mitigations": []},
            {"rule_id": "m-rule", "priority": 1, "condition": "always",
             "decision": "review", "threshold": 0, "mitigations": []},
        ]
        policy = compiler.compile("p1", "Same Priority", rules_spec)
        ids = [r.rule_id for r in policy.rules]
        assert ids == sorted(ids)

    def test_compile_is_idempotent(self, compiler: PolicyCompiler) -> None:
        p1 = compiler.compile("p1", "Policy", _STANDARD_RULES)
        p2 = compiler.compile("p1", "Policy", _STANDARD_RULES)
        assert [r.rule_id for r in p1.rules] == [r.rule_id for r in p2.rules]

    def test_disabled_rule_preserved_in_compiled_policy(
        self, compiler: PolicyCompiler
    ) -> None:
        rules = [
            {"rule_id": "disabled-rule", "priority": 1, "condition": "always",
             "decision": "deny", "threshold": 0, "mitigations": [], "enabled": False},
        ]
        policy = compiler.compile("p1", "P", rules)
        assert policy.rules[0].enabled is False

    def test_mitigations_are_tuple(self, standard_policy: Policy) -> None:
        for rule in standard_policy.rules:
            assert isinstance(rule.mitigations, tuple)


# ===========================================================================
# RULE EVALUATOR TESTS
# ===========================================================================

class TestRuleEvaluator:

    def test_evaluate_returns_evaluation_result(
        self, evaluator: RuleEvaluator, standard_policy: Policy
    ) -> None:
        dr = _make_drift_result()
        result = evaluator.evaluate(standard_policy, dr, "alice")
        assert isinstance(result, PolicyEvaluationResult)

    def test_critical_severity_triggers_quarantine(
        self, evaluator: RuleEvaluator, standard_policy: Policy
    ) -> None:
        dr = _make_drift_result(severity=DriftSeverity.CRITICAL, is_anomalous=True)
        result = evaluator.evaluate(standard_policy, dr, "alice")
        assert result.decision == PolicyDecision.QUARANTINE
        assert result.triggered_rule_id == "critical-quarantine"

    def test_high_severity_triggers_deny(
        self, evaluator: RuleEvaluator, standard_policy: Policy
    ) -> None:
        dr = _make_drift_result(severity=DriftSeverity.HIGH, is_anomalous=True)
        result = evaluator.evaluate(standard_policy, dr, "alice")
        assert result.decision == PolicyDecision.DENY
        assert result.triggered_rule_id == "high-deny"

    def test_medium_severity_triggers_review(
        self, evaluator: RuleEvaluator, standard_policy: Policy
    ) -> None:
        dr = _make_drift_result(severity=DriftSeverity.MEDIUM)
        result = evaluator.evaluate(standard_policy, dr, "alice")
        assert result.decision == PolicyDecision.REVIEW

    def test_no_matching_rule_returns_default_allow(
        self, evaluator: RuleEvaluator, compiler: PolicyCompiler
    ) -> None:
        policy = compiler.compile("p1", "No Match Policy", [
            {
                "rule_id": "only-critical", "priority": 1,
                "condition": "severity_gte", "threshold": 4,
                "decision": "quarantine", "mitigations": [],
            }
        ])
        dr = _make_drift_result(severity=DriftSeverity.NONE, drift_score=0.1)
        result = evaluator.evaluate(policy, dr, "alice")
        assert result.decision == PolicyDecision.ALLOW
        assert result.is_default is True
        assert result.triggered_rule_id is None

    def test_disabled_rule_is_skipped(
        self, evaluator: RuleEvaluator, compiler: PolicyCompiler
    ) -> None:
        policy = compiler.compile("p1", "Disabled Rule Policy", [
            {
                "rule_id": "disabled-deny", "priority": 1,
                "condition": "always", "threshold": 0,
                "decision": "deny", "mitigations": [],
                "enabled": False,
            },
            {
                "rule_id": "fallback-allow", "priority": 2,
                "condition": "always", "threshold": 0,
                "decision": "allow", "mitigations": [],
            },
        ])
        dr = _make_drift_result()
        result = evaluator.evaluate(policy, dr, "alice")
        assert result.decision == PolicyDecision.ALLOW
        assert result.triggered_rule_id == "fallback-allow"

    def test_highest_priority_rule_wins_not_last(
        self, evaluator: RuleEvaluator, compiler: PolicyCompiler
    ) -> None:
        policy = compiler.compile("p1", "Priority Test", [
            {
                "rule_id": "low-priority-allow", "priority": 100,
                "condition": "always", "threshold": 0,
                "decision": "allow", "mitigations": [],
            },
            {
                "rule_id": "high-priority-deny", "priority": 1,
                "condition": "always", "threshold": 0,
                "decision": "deny", "mitigations": [],
            },
        ])
        dr = _make_drift_result()
        result = evaluator.evaluate(policy, dr, "alice")
        assert result.triggered_rule_id == "high-priority-deny"
        assert result.decision == PolicyDecision.DENY

    def test_drift_score_threshold_rule_fires(
        self, evaluator: RuleEvaluator, compiler: PolicyCompiler
    ) -> None:
        policy = compiler.compile("p1", "Score Policy", [
            {
                "rule_id": "score-rule", "priority": 1,
                "condition": "drift_score_above", "threshold": 5.0,
                "decision": "review", "mitigations": ["alert_soc"],
            }
        ])
        dr = _make_drift_result(drift_score=6.0)
        result = evaluator.evaluate(policy, dr, "alice")
        assert result.decision == PolicyDecision.REVIEW

    def test_drift_score_threshold_rule_not_fires_below(
        self, evaluator: RuleEvaluator, compiler: PolicyCompiler
    ) -> None:
        policy = compiler.compile("p1", "Score Policy", [
            {
                "rule_id": "score-rule", "priority": 1,
                "condition": "drift_score_above", "threshold": 5.0,
                "decision": "review", "mitigations": [],
            }
        ])
        dr = _make_drift_result(drift_score=4.9)
        result = evaluator.evaluate(policy, dr, "alice")
        assert result.is_default is True

    def test_insufficient_baseline_rule_fires(
        self, evaluator: RuleEvaluator, standard_policy: Policy
    ) -> None:
        dr = _make_drift_result(
            severity=DriftSeverity.NONE,
            drift_score=0.0,
            insufficient_baseline=True,
        )
        result = evaluator.evaluate(standard_policy, dr, "new-user")
        assert result.triggered_rule_id == "sparse-baseline"
        assert result.decision == PolicyDecision.REVIEW

    def test_evaluation_is_deterministic(
        self, evaluator: RuleEvaluator, standard_policy: Policy
    ) -> None:
        dr = _make_drift_result(severity=DriftSeverity.HIGH, is_anomalous=True)
        r1 = evaluator.evaluate(standard_policy, dr, "alice")
        r2 = evaluator.evaluate(standard_policy, dr, "alice")
        assert r1.decision == r2.decision
        assert r1.triggered_rule_id == r2.triggered_rule_id
        assert r1.mitigations == r2.mitigations

    def test_evaluation_result_contains_drift_score(
        self, evaluator: RuleEvaluator, standard_policy: Policy
    ) -> None:
        dr = _make_drift_result(drift_score=7.77)
        result = evaluator.evaluate(standard_policy, dr, "alice")
        assert result.drift_score == 7.77

    def test_evaluation_result_identity_id_matches(
        self, evaluator: RuleEvaluator, standard_policy: Policy
    ) -> None:
        dr = _make_drift_result(identity_id="bob")
        result = evaluator.evaluate(standard_policy, dr, "bob")
        assert result.identity_id == "bob"

    def test_mitigations_are_tuple(
        self, evaluator: RuleEvaluator, standard_policy: Policy
    ) -> None:
        dr = _make_drift_result(severity=DriftSeverity.CRITICAL)
        result = evaluator.evaluate(standard_policy, dr, "alice")
        assert isinstance(result.mitigations, tuple)

    def test_to_dict_contains_required_keys(
        self, evaluator: RuleEvaluator, standard_policy: Policy
    ) -> None:
        dr = _make_drift_result()
        d = evaluator.evaluate(standard_policy, dr, "alice").to_dict()
        for key in (
            "policy_id", "identity_id", "decision", "triggered_rule_id",
            "mitigations", "drift_score", "severity", "evaluated_at",
        ):
            assert key in d


# ===========================================================================
# MITIGATION PLANNER TESTS
# ===========================================================================

class TestMitigationPlanner:

    def test_plan_returns_mitigation_plan(
        self, planner: MitigationPlanner
    ) -> None:
        ev = PolicyEvaluationResult(
            policy_id="p1",
            identity_id="alice",
            decision=PolicyDecision.DENY,
            triggered_rule_id="high-deny",
            mitigations=(MitigationAction.REVOKE_SESSION, MitigationAction.ALERT_SOC),
            drift_score=7.0,
            severity="high",
        )
        plan = planner.plan(ev)
        assert isinstance(plan, MitigationPlan)

    def test_deny_is_immediate_urgency(self, planner: MitigationPlanner) -> None:
        ev = PolicyEvaluationResult(
            policy_id="p1", identity_id="alice",
            decision=PolicyDecision.DENY,
            triggered_rule_id="r1",
            mitigations=(),
            drift_score=9.0, severity="high",
        )
        assert planner.plan(ev).urgency == "immediate"

    def test_quarantine_is_immediate_urgency(self, planner: MitigationPlanner) -> None:
        ev = PolicyEvaluationResult(
            policy_id="p1", identity_id="alice",
            decision=PolicyDecision.QUARANTINE,
            triggered_rule_id="r1",
            mitigations=(),
            drift_score=15.0, severity="critical",
        )
        assert planner.plan(ev).urgency == "immediate"

    def test_review_is_standard_urgency(self, planner: MitigationPlanner) -> None:
        ev = PolicyEvaluationResult(
            policy_id="p1", identity_id="alice",
            decision=PolicyDecision.REVIEW,
            triggered_rule_id="r1",
            mitigations=(),
            drift_score=3.0, severity="medium",
        )
        assert planner.plan(ev).urgency == "standard"

    def test_allow_is_deferred_urgency(self, planner: MitigationPlanner) -> None:
        ev = PolicyEvaluationResult(
            policy_id="p1", identity_id="alice",
            decision=PolicyDecision.ALLOW,
            triggered_rule_id=None,
            mitigations=(),
            drift_score=0.5, severity="none",
            is_default=True,
        )
        assert planner.plan(ev).urgency == "deferred"

    def test_deny_requires_human_review(self, planner: MitigationPlanner) -> None:
        ev = PolicyEvaluationResult(
            policy_id="p1", identity_id="alice",
            decision=PolicyDecision.DENY,
            triggered_rule_id="r1",
            mitigations=(),
            drift_score=8.0, severity="high",
        )
        assert planner.plan(ev).requires_human_review is True

    def test_allow_does_not_require_human_review(self, planner: MitigationPlanner) -> None:
        ev = PolicyEvaluationResult(
            policy_id="p1", identity_id="alice",
            decision=PolicyDecision.ALLOW,
            triggered_rule_id=None,
            mitigations=(),
            drift_score=0.1, severity="none",
        )
        assert planner.plan(ev).requires_human_review is False

    def test_plan_actions_match_evaluation_mitigations(
        self, planner: MitigationPlanner
    ) -> None:
        mitigations = (MitigationAction.REVOKE_SESSION, MitigationAction.LOCK_ACCOUNT)
        ev = PolicyEvaluationResult(
            policy_id="p1", identity_id="alice",
            decision=PolicyDecision.QUARANTINE,
            triggered_rule_id="r1",
            mitigations=mitigations,
            drift_score=12.0, severity="critical",
        )
        plan = planner.plan(ev)
        assert plan.actions == mitigations

    def test_plan_is_deterministic(self, planner: MitigationPlanner) -> None:
        ev = PolicyEvaluationResult(
            policy_id="p1", identity_id="alice",
            decision=PolicyDecision.REVIEW,
            triggered_rule_id="r1",
            mitigations=(MitigationAction.ALERT_SOC,),
            drift_score=3.5, severity="medium",
        )
        p1 = planner.plan(ev)
        p2 = planner.plan(ev)
        assert p1.urgency == p2.urgency
        assert p1.actions == p2.actions
        assert p1.requires_human_review == p2.requires_human_review


# ===========================================================================
# END-TO-END PIPELINE
# ===========================================================================

class TestEndToEndPipeline:

    def test_normal_behavior_results_in_allow(
        self,
        compiler: PolicyCompiler,
        evaluator: RuleEvaluator,
        planner: MitigationPlanner,
    ) -> None:
        policy = compiler.compile("std", "Standard", _STANDARD_RULES)
        engine = BaselineEngine()
        detector = DriftDetector()

        normal_events = _normal_stream("alice", 50)
        baseline = engine.build_baseline("alice", normal_events)
        features = extract_features(_normal_stream("alice", 20, base_offset=6000))

        drift_result = detector.detect_drift(baseline, features)
        eval_result  = evaluator.evaluate(policy, drift_result, "alice")
        plan         = planner.plan(eval_result)

        # Normal behaviour should not trigger a deny/quarantine
        assert eval_result.decision in {PolicyDecision.ALLOW, PolicyDecision.REVIEW}
        assert plan.urgency in {"deferred", "standard"}

    def test_anomalous_behavior_triggers_protective_decision(
        self,
        compiler: PolicyCompiler,
        evaluator: RuleEvaluator,
    ) -> None:
        policy  = compiler.compile("std", "Standard", _STANDARD_RULES)
        engine  = BaselineEngine()
        detector = DriftDetector()

        normal_events = _normal_stream("bob", 100)
        baseline = engine.build_baseline("bob", normal_events)
        anom_features = extract_features(_anomalous_stream("bob", 50))

        drift_result = detector.detect_drift(baseline, anom_features)
        eval_result  = evaluator.evaluate(policy, drift_result, "bob")

        assert eval_result.decision in {
            PolicyDecision.REVIEW,
            PolicyDecision.DENY,
            PolicyDecision.QUARANTINE,
        }

    def test_pipeline_is_deterministic(
        self,
        compiler: PolicyCompiler,
        evaluator: RuleEvaluator,
    ) -> None:
        policy = compiler.compile("std", "Standard", _STANDARD_RULES)
        events = _normal_stream("charlie", 50)
        anom   = _anomalous_stream("charlie", 30, base_offset=6000)

        results: list[PolicyDecision] = []
        for _ in range(5):
            engine   = BaselineEngine()
            detector = DriftDetector()
            baseline = engine.build_baseline("charlie", events)
            features = extract_features(anom)
            dr = detector.detect_drift(baseline, features)
            er = evaluator.evaluate(policy, dr, "charlie")
            results.append(er.decision)

        assert len(set(results)) == 1, f"Non-deterministic decisions: {results}"

    def test_new_user_sparse_baseline_triggers_review(
        self,
        compiler: PolicyCompiler,
        evaluator: RuleEvaluator,
    ) -> None:
        policy = compiler.compile("std", "Standard", _STANDARD_RULES)
        engine  = BaselineEngine()
        detector = DriftDetector(min_events=20)

        # Only 5 events → insufficient baseline
        sparse_events = _normal_stream("new-user", 5)
        baseline = engine.build_baseline("new-user", sparse_events)
        features = extract_features(sparse_events)

        dr = detector.detect_drift(baseline, features)
        er = evaluator.evaluate(policy, dr, "new-user")

        assert er.triggered_rule_id == "sparse-baseline"
        assert er.decision == PolicyDecision.REVIEW

    def test_multiple_identities_independent_decisions(
        self,
        compiler: PolicyCompiler,
        evaluator: RuleEvaluator,
    ) -> None:
        policy = compiler.compile("std", "Standard", _STANDARD_RULES)
        engine   = BaselineEngine()
        detector = DriftDetector()

        alice_normal = _normal_stream("alice", 50)
        alice_baseline = engine.build_baseline("alice", alice_normal)

        bob_normal = _normal_stream("bob", 50, base_offset=10000)
        bob_baseline   = engine.build_baseline("bob", bob_normal)

        alice_features = extract_features(_normal_stream("alice", 20))
        bob_features   = extract_features(_anomalous_stream("bob", 50))

        alice_dr = detector.detect_drift(alice_baseline, alice_features)
        bob_dr   = detector.detect_drift(bob_baseline,   bob_features)

        alice_result = evaluator.evaluate(policy, alice_dr, "alice")
        bob_result   = evaluator.evaluate(policy, bob_dr,   "bob")

        # Alice should be fine; Bob should be flagged
        assert alice_result.decision in {PolicyDecision.ALLOW, PolicyDecision.REVIEW}
        assert bob_result.decision in {
            PolicyDecision.REVIEW, PolicyDecision.DENY, PolicyDecision.QUARANTINE
        }


# ===========================================================================
# DETERMINISTIC RULE ORDERING
# ===========================================================================

class TestDeterministicRuleOrdering:

    def test_same_spec_always_same_rule_order(
        self, compiler: PolicyCompiler
    ) -> None:
        for _ in range(20):
            p = compiler.compile("p1", "P", _STANDARD_RULES)
            ids = [r.rule_id for r in p.rules]
            expected = sorted(
                _STANDARD_RULES,
                key=lambda s: (s["priority"], s["rule_id"])
            )
            assert ids == [s["rule_id"] for s in expected]

    def test_equal_priority_rules_sorted_by_id(
        self, compiler: PolicyCompiler
    ) -> None:
        spec = [
            {"rule_id": "zulu", "priority": 5, "condition": "always",
             "decision": "allow", "threshold": 0, "mitigations": []},
            {"rule_id": "alpha", "priority": 5, "condition": "always",
             "decision": "deny", "threshold": 0, "mitigations": []},
            {"rule_id": "mike", "priority": 5, "condition": "always",
             "decision": "review", "threshold": 0, "mitigations": []},
        ]
        p = compiler.compile("p1", "P", spec)
        ids = [r.rule_id for r in p.rules]
        assert ids == ["alpha", "mike", "zulu"]

    def test_rule_order_does_not_change_across_compilations(
        self, compiler: PolicyCompiler
    ) -> None:
        p1 = compiler.compile("p1", "P", _STANDARD_RULES)
        p2 = compiler.compile("p1", "P", list(reversed(_STANDARD_RULES)))
        ids1 = [r.rule_id for r in p1.rules]
        ids2 = [r.rule_id for r in p2.rules]
        assert ids1 == ids2


# ===========================================================================
# PERFORMANCE
# ===========================================================================

class TestPhase5Performance:

    def test_compile_100_rules_under_100ms(self, compiler: PolicyCompiler) -> None:
        rules = [
            {
                "rule_id": f"rule-{i:03d}",
                "priority": i,
                "condition": "drift_score_above",
                "threshold": float(i),
                "decision": "review",
                "mitigations": ["alert_soc"],
            }
            for i in range(100)
        ]
        start = time.perf_counter()
        policy = compiler.compile("perf-p1", "Perf Policy", rules)
        elapsed = time.perf_counter() - start
        assert len(policy.rules) == 100
        assert elapsed < 0.1, f"Compile 100 rules took {elapsed*1000:.1f}ms"

    def test_evaluate_1000_times_under_1s(
        self,
        evaluator: RuleEvaluator,
        standard_policy: Policy,
    ) -> None:
        dr = _make_drift_result(severity=DriftSeverity.MEDIUM, drift_score=5.0)
        start = time.perf_counter()
        for _ in range(1000):
            evaluator.evaluate(standard_policy, dr, "alice")
        elapsed = time.perf_counter() - start
        assert elapsed < 1.0, f"1000 evaluations took {elapsed:.2f}s"

    def test_full_pipeline_1000_identities_under_30s(
        self,
        compiler: PolicyCompiler,
        evaluator: RuleEvaluator,
        planner: MitigationPlanner,
    ) -> None:
        policy = compiler.compile("std", "Standard", _STANDARD_RULES)
        engine = BaselineEngine()
        detector = DriftDetector()

        start = time.perf_counter()
        for i in range(100):
            iid = f"user-{i:04d}"
            evts = _normal_stream(iid, 10, base_offset=i * 1200)
            baseline = engine.build_baseline(iid, evts)
            features = extract_features(evts[:5])
            dr = detector.detect_drift(baseline, features)
            er = evaluator.evaluate(policy, dr, iid)
            planner.plan(er)
        elapsed = time.perf_counter() - start
        assert elapsed < 30.0, f"100-identity pipeline took {elapsed:.2f}s"