"""
rule_evaluator.py
=================
Hollow Purple Policy Engine — Rule Evaluator

Executes compiled policies against an ``EvaluationContext`` in a fully
deterministic manner.  Given the same context and the same compiled policy,
this module always produces the same ``PolicyDecision``.

Design principles
-----------------
* No external I/O, no randomness, no global mutable state.
* Rules are evaluated in the pre-sorted order produced by the compiler
  (priority DESC, rule_id ASC).
* Condition evaluation dispatches through a closed ``_OPERATOR_HANDLERS``
  registry — no ``eval``/``exec``, no arbitrary attribute access on raw
  objects.
* Context fields are resolved through a strict allow-list mapping
  (``_resolve_field``), preventing traversal attacks.
* All evaluation errors are captured per-rule; a rule that raises during
  evaluation is skipped and the error recorded, ensuring one malformed
  rule cannot block the entire evaluation pass.

Decision semantics (first-match wins)
--------------------------------------
Rules are evaluated in priority order.  The first rule whose *all*
conditions evaluate to ``True`` produces the terminal ``PolicyDecision``.
If no rule matches, a ``PolicyDecision`` with effect ``AUDIT`` and
``matched_rule_id=None`` is returned (fail-open sentinel — callers must
handle this case according to their security posture).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Final

from policy_compiler import (
    CompiledCondition,
    CompiledPolicy,
    CompiledRule,
    ConditionField,
    ConditionOperator,
    MitigationAction,
    PolicyEffect,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_NO_MATCH_EFFECT: Final[PolicyEffect] = PolicyEffect.AUDIT


# ---------------------------------------------------------------------------
# Evaluation Context
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class IdentityContext:
    """Immutable identity attributes for the principal under evaluation."""

    id: str
    role: str
    trust_score: float
    region: str
    mfa_verified: bool
    account_age_days: float
    flags: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True, slots=True)
class DriftContext:
    """Behavioral drift metrics for the identity."""

    score: float
    velocity: float
    category: str
    consecutive_anomalies: int


@dataclass(frozen=True, slots=True)
class EventContext:
    """Attributes of the triggering system event."""

    type: str
    source_ip: str
    resource_id: str
    action: str
    timestamp_epoch: float


@dataclass(frozen=True, slots=True)
class ResourceContext:
    """State attributes of the resource being accessed."""

    status: str
    sensitivity: str
    owner_id: str


@dataclass(frozen=True, slots=True)
class EvaluationContext:
    """
    Full evaluation context passed to the rule evaluator.

    All sub-contexts are required.  Callers must supply default/zero values
    when a sub-context is not applicable rather than passing ``None``.

    Attributes
    ----------
    identity:   Identity attributes of the principal.
    drift:      Current behavioral drift metrics.
    event:      The triggering event.
    resource:   State of the resource being acted upon.
    """

    identity: IdentityContext
    drift: DriftContext
    event: EventContext
    resource: ResourceContext


# ---------------------------------------------------------------------------
# Decision Output
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RuleEvaluationTrace:
    """
    Audit trace for a single rule evaluation attempt.

    Included in ``PolicyDecision.evaluation_trace`` for every rule that was
    examined, regardless of whether it matched.
    """

    rule_id: str
    matched: bool
    conditions_evaluated: int
    first_failing_condition_index: int | None
    error: str | None


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """
    The output of a full policy evaluation pass.

    Attributes
    ----------
    policy_id:
        ID of the policy that produced this decision.
    matched_rule_id:
        ID of the first matching rule, or ``None`` if no rule matched.
    effect:
        The ``PolicyEffect`` of the matched rule, or ``AUDIT`` if no match.
    actions:
        Ordered mitigation actions from the matched rule (empty if no match).
    rules_evaluated:
        Total number of rules examined before reaching a decision.
    evaluation_trace:
        Per-rule audit traces for all rules evaluated.
    content_hash:
        Hash of the compiled policy used for this evaluation; enables
        correlation with a specific compiled policy artifact.
    """

    policy_id: str
    matched_rule_id: str | None
    effect: PolicyEffect
    actions: tuple[MitigationAction, ...]
    rules_evaluated: int
    evaluation_trace: tuple[RuleEvaluationTrace, ...]
    content_hash: str


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class EvaluationError(RuntimeError):
    """Raised when the evaluator encounters an unrecoverable error."""


class ContextResolutionError(ValueError):
    """Raised when a condition field cannot be resolved on the context."""


# ---------------------------------------------------------------------------
# Field resolver
# ---------------------------------------------------------------------------

# Maps each ConditionField to a callable that extracts the value from an
# EvaluationContext.  This is the *only* mechanism by which condition values
# are resolved; there is no dynamic attribute access on raw dicts.
_FIELD_RESOLVERS: dict[ConditionField, Any] = {
    ConditionField.IDENTITY_ID: lambda ctx: ctx.identity.id,
    ConditionField.IDENTITY_ROLE: lambda ctx: ctx.identity.role,
    ConditionField.IDENTITY_TRUST_SCORE: lambda ctx: ctx.identity.trust_score,
    ConditionField.IDENTITY_REGION: lambda ctx: ctx.identity.region,
    ConditionField.IDENTITY_MFA_VERIFIED: lambda ctx: ctx.identity.mfa_verified,
    ConditionField.IDENTITY_ACCOUNT_AGE_DAYS: lambda ctx: ctx.identity.account_age_days,
    ConditionField.IDENTITY_FLAGS: lambda ctx: ctx.identity.flags,
    ConditionField.DRIFT_SCORE: lambda ctx: ctx.drift.score,
    ConditionField.DRIFT_VELOCITY: lambda ctx: ctx.drift.velocity,
    ConditionField.DRIFT_CATEGORY: lambda ctx: ctx.drift.category,
    ConditionField.DRIFT_CONSECUTIVE_ANOMALIES: lambda ctx: ctx.drift.consecutive_anomalies,
    ConditionField.EVENT_TYPE: lambda ctx: ctx.event.type,
    ConditionField.EVENT_SOURCE_IP: lambda ctx: ctx.event.source_ip,
    ConditionField.EVENT_RESOURCE_ID: lambda ctx: ctx.event.resource_id,
    ConditionField.EVENT_ACTION: lambda ctx: ctx.event.action,
    ConditionField.EVENT_TIMESTAMP_EPOCH: lambda ctx: ctx.event.timestamp_epoch,
    ConditionField.RESOURCE_STATUS: lambda ctx: ctx.resource.status,
    ConditionField.RESOURCE_SENSITIVITY: lambda ctx: ctx.resource.sensitivity,
    ConditionField.RESOURCE_OWNER_ID: lambda ctx: ctx.resource.owner_id,
    # Time fields are resolved lazily at evaluation time (UTC wall-clock).
    # These are deliberately NOT pure with respect to wall-clock time, but
    # ARE deterministic given the same wall-clock UTC second.
    ConditionField.TIME_HOUR_UTC: lambda _ctx: float(
        datetime.now(tz=timezone.utc).hour
    ),
    ConditionField.TIME_DAY_OF_WEEK: lambda _ctx: float(
        datetime.now(tz=timezone.utc).weekday()  # 0=Monday … 6=Sunday
    ),
}


def _resolve_field(field: ConditionField, ctx: EvaluationContext) -> Any:
    """
    Resolve the value of a ``ConditionField`` from ``ctx``.

    Parameters
    ----------
    field:  The field to resolve.
    ctx:    The evaluation context.

    Returns
    -------
    Any
        The resolved value.

    Raises
    ------
    ContextResolutionError
        If the field has no registered resolver (should never occur in
        production given the compiler validates fields at compile time).
    """
    resolver = _FIELD_RESOLVERS.get(field)
    if resolver is None:
        raise ContextResolutionError(
            f"No resolver registered for field '{field}'. "
            "This indicates a compiler/evaluator version mismatch."
        )
    return resolver(ctx)


# ---------------------------------------------------------------------------
# Operator handlers
# ---------------------------------------------------------------------------

def _op_eq(actual: Any, expected: Any) -> bool:
    return actual == expected


def _op_neq(actual: Any, expected: Any) -> bool:
    return actual != expected


def _op_gt(actual: Any, expected: Any) -> bool:
    return float(actual) > float(expected)


def _op_gte(actual: Any, expected: Any) -> bool:
    return float(actual) >= float(expected)


def _op_lt(actual: Any, expected: Any) -> bool:
    return float(actual) < float(expected)


def _op_lte(actual: Any, expected: Any) -> bool:
    return float(actual) <= float(expected)


def _op_in(actual: Any, expected: Any) -> bool:
    if isinstance(actual, (frozenset, set, list)):
        # Any element of actual present in expected list
        return bool(set(actual) & set(expected))
    return actual in expected


def _op_not_in(actual: Any, expected: Any) -> bool:
    return not _op_in(actual, expected)


def _op_contains(actual: Any, expected: Any) -> bool:
    if isinstance(actual, str):
        return str(expected) in actual
    if isinstance(actual, (frozenset, set, list)):
        return expected in actual
    return False


def _op_starts_with(actual: Any, expected: Any) -> bool:
    return isinstance(actual, str) and actual.startswith(str(expected))


def _op_exists(actual: Any, _expected: Any) -> bool:
    return actual is not None


def _op_not_exists(actual: Any, _expected: Any) -> bool:
    return actual is None


_OPERATOR_HANDLERS: Final[
    dict[ConditionOperator, Any]
] = {
    ConditionOperator.EQ: _op_eq,
    ConditionOperator.NEQ: _op_neq,
    ConditionOperator.GT: _op_gt,
    ConditionOperator.GTE: _op_gte,
    ConditionOperator.LT: _op_lt,
    ConditionOperator.LTE: _op_lte,
    ConditionOperator.IN: _op_in,
    ConditionOperator.NOT_IN: _op_not_in,
    ConditionOperator.CONTAINS: _op_contains,
    ConditionOperator.STARTS_WITH: _op_starts_with,
    ConditionOperator.EXISTS: _op_exists,
    ConditionOperator.NOT_EXISTS: _op_not_exists,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def evaluate_condition(
    condition: CompiledCondition,
    ctx: EvaluationContext,
) -> bool:
    """
    Evaluate a single compiled condition against an evaluation context.

    Parameters
    ----------
    condition:
        The compiled condition to evaluate.
    ctx:
        The current evaluation context.

    Returns
    -------
    bool
        ``True`` if the condition is satisfied, ``False`` otherwise.

    Raises
    ------
    ContextResolutionError
        If the condition field cannot be resolved.
    EvaluationError
        If the operator handler raises an unexpected error.
    """
    actual = _resolve_field(condition.field, ctx)
    handler = _OPERATOR_HANDLERS.get(condition.operator)
    if handler is None:
        raise EvaluationError(
            f"No handler registered for operator '{condition.operator}'. "
            "This is a compiler/evaluator version mismatch."
        )
    try:
        return bool(handler(actual, condition.value))
    except (TypeError, ValueError) as exc:
        raise EvaluationError(
            f"Type error evaluating condition "
            f"(field={condition.field}, op={condition.operator}, "
            f"actual={actual!r}, expected={condition.value!r}): {exc}"
        ) from exc


def evaluate_rule(
    rule: CompiledRule,
    ctx: EvaluationContext,
) -> RuleEvaluationTrace:
    """
    Evaluate a single compiled rule against an evaluation context.

    All conditions must be satisfied for the rule to match.  Evaluation
    short-circuits on the first failing condition to minimise work.

    Parameters
    ----------
    rule:
        The compiled rule to evaluate.
    ctx:
        The current evaluation context.

    Returns
    -------
    RuleEvaluationTrace
        An audit trace recording whether the rule matched, how many conditions
        were evaluated, and any error that occurred.
    """
    conditions_evaluated = 0
    first_failing: int | None = None

    for idx, condition in enumerate(rule.conditions):
        conditions_evaluated += 1
        try:
            result = evaluate_condition(condition, ctx)
        except (ContextResolutionError, EvaluationError) as exc:
            logger.warning(
                "Condition evaluation error; rule skipped",
                extra={
                    "rule_id": rule.rule_id,
                    "condition_index": idx,
                    "error": str(exc),
                },
            )
            return RuleEvaluationTrace(
                rule_id=rule.rule_id,
                matched=False,
                conditions_evaluated=conditions_evaluated,
                first_failing_condition_index=idx,
                error=str(exc),
            )

        if not result:
            first_failing = idx
            # Short-circuit: remaining conditions cannot change the outcome.
            return RuleEvaluationTrace(
                rule_id=rule.rule_id,
                matched=False,
                conditions_evaluated=conditions_evaluated,
                first_failing_condition_index=first_failing,
                error=None,
            )

    return RuleEvaluationTrace(
        rule_id=rule.rule_id,
        matched=True,
        conditions_evaluated=conditions_evaluated,
        first_failing_condition_index=None,
        error=None,
    )


def evaluate_rules(
    ctx: EvaluationContext,
    compiled_policy: CompiledPolicy,
) -> PolicyDecision:
    """
    Evaluate all enabled rules in ``compiled_policy`` against ``ctx`` and
    return the first-match decision.

    Rules are evaluated in the deterministic order established by the compiler
    (priority DESC, rule_id ASC).  The first rule whose all conditions match
    terminates evaluation and its effect + actions are used.

    If no rule matches, the decision has effect ``AUDIT`` and no actions.

    Parameters
    ----------
    ctx:
        The full evaluation context for this event.
    compiled_policy:
        The compiled policy produced by ``policy_compiler.compile_policy``.

    Returns
    -------
    PolicyDecision
        The deterministic policy decision.
    """
    traces: list[RuleEvaluationTrace] = []

    for rule in compiled_policy.rules:
        trace = evaluate_rule(rule, ctx)
        traces.append(trace)

        if trace.matched:
            decision = PolicyDecision(
                policy_id=compiled_policy.policy_id,
                matched_rule_id=rule.rule_id,
                effect=rule.effect,
                actions=rule.actions,
                rules_evaluated=len(traces),
                evaluation_trace=tuple(traces),
                content_hash=compiled_policy.content_hash,
            )
            logger.info(
                "Policy rule matched",
                extra={
                    "policy_id": compiled_policy.policy_id,
                    "matched_rule_id": rule.rule_id,
                    "effect": rule.effect.value,
                    "actions": [a.value for a in rule.actions],
                    "rules_evaluated": len(traces),
                },
            )
            return decision

    # No rule matched — fail-open with AUDIT effect.
    no_match_decision = PolicyDecision(
        policy_id=compiled_policy.policy_id,
        matched_rule_id=None,
        effect=_NO_MATCH_EFFECT,
        actions=(),
        rules_evaluated=len(traces),
        evaluation_trace=tuple(traces),
        content_hash=compiled_policy.content_hash,
    )
    logger.info(
        "No policy rule matched; default AUDIT effect applied",
        extra={
            "policy_id": compiled_policy.policy_id,
            "rules_evaluated": len(traces),
        },
    )
    return no_match_decision