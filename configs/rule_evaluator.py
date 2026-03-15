"""
policy_engine/rule_evaluator.py — HOLLOW_PURPLE Rule Evaluator

Evaluates a threat context dict against all compiled rules.
Returns a list of Violation objects for each matched rule.

Context fields evaluated:
  - risk_score:     float [0.0–1.0]
  - anomaly_score:  float [0.0–1.0]
  - severity:       str   critical|high|medium|low|info
  - action:         str   e.g. AssumeRole
  - actor:          str
  - actor_type:     str
  - source:         str   aws|gcp|azure
  - resource:       str
  - tags:           list[str]
  - ip:             str
  - region:         str
  - alert_type:     str   (from pattern detectors)
  - [any other event field]

Features:
  - All conditions in a rule are AND-ed (all must pass)
  - Short-circuit evaluation (stops at first failing condition)
  - Per-rule evaluation timing metrics
  - Violation enrichment: which conditions matched, which almost matched
  - Rule execution audit log (last N evaluations)
  - Scope-aware: only evaluates rules matching context's source
  - Exception isolation: one bad rule never fails the whole evaluation
"""

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any

from policy_engine.policy_compiler import Rule, Condition

logger = logging.getLogger("hollow_purple.rule_evaluator")

AUDIT_LOG_MAX = 1000


@dataclass
class ConditionResult:
    condition: Condition
    matched:   bool
    actual:    Any      # The actual value from context


@dataclass
class Violation:
    rule:             Rule
    context:          dict
    matched_conditions: list[ConditionResult]
    evaluated_at:     float = field(default_factory=time.time)
    eval_ms:          float = 0.0

    def to_dict(self) -> dict:
        return {
            "rule_name":    self.rule.name,
            "rule_priority": self.rule.priority,
            "severity":     self._infer_severity(),
            "actions":      self.rule.actions,
            "compliance":   self.rule.compliance,
            "tags":         self.rule.tags,
            "actor":        self.context.get("actor", ""),
            "resource":     self.context.get("resource", ""),
            "risk_score":   self.context.get("risk_score", 0),
            "evaluated_at": self.evaluated_at,
            "eval_ms":      round(self.eval_ms, 3),
            "matched_conditions": [
                {"field": cr.condition.field, "operator": cr.condition.operator,
                 "expected": cr.condition.raw, "actual": cr.actual}
                for cr in self.matched_conditions
            ],
        }

    def _infer_severity(self) -> str:
        score = self.context.get("risk_score", 0)
        ctx_sev = self.context.get("severity", "")
        if ctx_sev in ("critical",):             return "critical"
        if score >= 0.85 or ctx_sev == "high":   return "critical"
        if score >= 0.65:                         return "high"
        if score >= 0.40:                         return "medium"
        return "low"


class RuleEvaluator:
    """
    Evaluates a threat context against all compiled rules.

    Usage:
        evaluator = RuleEvaluator(rules)
        violations = evaluator.evaluate(context)
        violations = evaluator.evaluate(context, scope="aws")
    """

    def __init__(self, rules: list[Rule]):
        self._rules = rules
        self._eval_count   = 0
        self._match_counts: dict[str, int] = {}
        self._audit_log:   list[dict] = []

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def evaluate(
        self,
        context: dict,
        scope: str | None = None,
        max_violations: int = 20,
    ) -> list[Violation]:
        """
        Evaluate context against all enabled rules.

        context: dict with risk_score, severity, actor, resource, etc.
        scope: if provided, only evaluate rules scoped to this provider (+ global)
        max_violations: cap to prevent runaway policy matches

        Returns list of Violation objects sorted by rule priority (ascending = highest priority first).
        """
        violations: list[Violation] = []
        source = context.get("source", "").lower()
        eval_scope = scope or source

        for rule in self._rules:
            if not rule.enabled:
                continue
            # Scope filter
            if rule.scope != "global" and eval_scope and rule.scope != eval_scope:
                continue

            start = time.perf_counter()
            try:
                matched, cond_results = self._evaluate_rule(rule, context)
            except Exception as exc:
                logger.error("Rule '%s' evaluation raised: %s", rule.name, exc)
                continue

            elapsed_ms = (time.perf_counter() - start) * 1000
            self._eval_count += 1

            if matched:
                self._match_counts[rule.name] = self._match_counts.get(rule.name, 0) + 1
                violation = Violation(
                    rule=rule,
                    context=context,
                    matched_conditions=cond_results,
                    eval_ms=elapsed_ms,
                )
                violations.append(violation)
                self._audit_append(rule.name, context, matched=True, ms=elapsed_ms)
                logger.info("Rule MATCHED: '%s' | actor=%s risk=%.2f",
                            rule.name, context.get("actor", ""), context.get("risk_score", 0))

            if len(violations) >= max_violations:
                logger.warning("Max violations (%d) reached — stopping evaluation", max_violations)
                break

        return sorted(violations, key=lambda v: v.rule.priority)

    def evaluate_single(self, rule: Rule, context: dict) -> Violation | None:
        """Evaluate a single named rule against context."""
        matched, cond_results = self._evaluate_rule(rule, context)
        if matched:
            return Violation(rule=rule, context=context, matched_conditions=cond_results)
        return None

    def update_rules(self, rules: list[Rule]):
        """Hot-swap the rule set (used after policy hot-reload)."""
        self._rules = rules
        logger.info("RuleEvaluator: rules updated (%d total)", len(rules))

    def stats(self) -> dict:
        return {
            "total_evaluations": self._eval_count,
            "match_counts":      dict(self._match_counts),
            "top_matched_rules": sorted(
                self._match_counts.items(), key=lambda x: -x[1]
            )[:10],
        }

    def audit_log(self, limit: int = 100) -> list[dict]:
        return self._audit_log[-limit:]

    # ------------------------------------------------------------------ #
    #  Core evaluation logic                                               #
    # ------------------------------------------------------------------ #

    def _evaluate_rule(
        self, rule: Rule, context: dict
    ) -> tuple[bool, list[ConditionResult]]:
        """
        Evaluate all conditions for a rule (AND logic).
        Returns (all_matched, list_of_condition_results).
        Short-circuits on first failing condition.
        """
        results: list[ConditionResult] = []
        for condition in rule.conditions:
            actual = self._extract(context, condition.field)
            matched = self._test(condition, actual)
            results.append(ConditionResult(condition=condition, matched=matched, actual=actual))
            if not matched:
                return False, results   # AND short-circuit
        return True, results

    def _extract(self, context: dict, field: str) -> Any:
        """Extract a value from context, supporting nested dot-path keys."""
        parts = field.split(".")
        val = context
        for part in parts:
            if isinstance(val, dict):
                val = val.get(part)
            else:
                return None
        return val

    def _test(self, cond: Condition, actual: Any) -> bool:
        """Test a single condition against an actual value."""
        op    = cond.operator
        expected = cond.value

        if actual is None:
            return False

        try:
            if op == ">":         return float(actual) >  float(expected)
            if op == "<":         return float(actual) <  float(expected)
            if op == ">=":        return float(actual) >= float(expected)
            if op == "<=":        return float(actual) <= float(expected)
            if op == "==":        return str(actual).lower() == str(expected).lower()
            if op == "!=":        return str(actual).lower() != str(expected).lower()
            if op == "between":
                lo, hi = expected
                return lo <= float(actual) <= hi
            if op == "in":
                if isinstance(expected, list):
                    return str(actual).lower() in [str(e).lower() for e in expected]
                return str(actual).lower() == str(expected).lower()
            if op == "regex":
                return bool(re.search(expected, str(actual), re.IGNORECASE))
            if op == "contains":
                if isinstance(actual, list):
                    return expected in actual
                return expected in str(actual)
        except (TypeError, ValueError, re.error) as exc:
            logger.debug("Condition test failed (%s %s %s): %s", cond.field, op, expected, exc)
            return False

        return False

    def _audit_append(self, rule_name: str, context: dict, matched: bool, ms: float):
        self._audit_log.append({
            "rule":   rule_name,
            "actor":  context.get("actor", ""),
            "score":  context.get("risk_score", 0),
            "matched": matched,
            "ms":     round(ms, 3),
            "ts":     time.time(),
        })
        if len(self._audit_log) > AUDIT_LOG_MAX:
            self._audit_log = self._audit_log[-AUDIT_LOG_MAX:]