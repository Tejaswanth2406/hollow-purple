"""
mitigation_planner.py
=====================
Hollow Purple Policy Engine — Mitigation Planner

Translates deterministic ``PolicyDecision`` objects into fully auditable
``MitigationPlan`` objects containing ordered ``MitigationStep`` records.

Design principles
-----------------
* Pure transformation — no I/O, no side effects, no global mutable state.
* Every plan is stamped with the ``policy_id``, ``matched_rule_id``,
  ``content_hash``, and a deterministic ``plan_id`` (SHA-256 of the decision
  payload) to ensure full auditability and tamper-evident logging.
* Action ordering within a plan is deterministic: actions from the decision
  retain the order declared in the matched rule, followed by any
  automatically-injected companion actions (e.g. ``LOG_ALERT`` is always
  appended when a ``DENY`` decision carries no explicit log action).
* Validation checks that the plan is internally consistent before it is
  returned to the caller.

Action enrichment
-----------------
Each ``MitigationAction`` is enriched with:
* A human-readable ``description`` for operator dashboards.
* A ``severity`` classification (``LOW`` | ``MEDIUM`` | ``HIGH`` | ``CRITICAL``)
  used by downstream alerting pipelines.
* ``requires_human_review`` flag that instructs the orchestrator to gate
  execution pending a human approval step for destructive actions.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Final

from policy_compiler import MitigationAction, PolicyEffect
from rule_evaluator import PolicyDecision

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class ActionSeverity(str, Enum):
    """Severity classification for a mitigation step."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PlanStatus(str, Enum):
    """Lifecycle status of a mitigation plan."""

    PENDING = "pending"
    APPROVED = "approved"
    EXECUTING = "executing"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


# ---------------------------------------------------------------------------
# Action metadata registry
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class ActionMetadata:
    """
    Static metadata for a ``MitigationAction``.

    Attributes
    ----------
    description:
        Human-readable description suitable for operator dashboards.
    severity:
        Severity classification for alerting pipelines.
    requires_human_review:
        When ``True``, the orchestrator must gate execution on a human
        approval step (used for irreversible or high-impact actions).
    """

    description: str
    severity: ActionSeverity
    requires_human_review: bool


# Registry: maps every MitigationAction to its static metadata.
# Extending the registry here is the *only* safe way to add action metadata.
_ACTION_METADATA: Final[dict[MitigationAction, ActionMetadata]] = {
    MitigationAction.LOG_ALERT: ActionMetadata(
        description="Record a structured security alert in the audit log.",
        severity=ActionSeverity.LOW,
        requires_human_review=False,
    ),
    MitigationAction.FLAG_IDENTITY: ActionMetadata(
        description=(
            "Attach a security flag to the identity record for downstream "
            "risk scoring and review queues."
        ),
        severity=ActionSeverity.MEDIUM,
        requires_human_review=False,
    ),
    MitigationAction.SUSPEND_RESOURCE: ActionMetadata(
        description=(
            "Immediately suspend access to the target resource. "
            "This is a reversible but potentially disruptive action."
        ),
        severity=ActionSeverity.HIGH,
        requires_human_review=True,
    ),
    MitigationAction.REQUIRE_REAUTHENTICATION: ActionMetadata(
        description=(
            "Invalidate the current session and require the identity to "
            "complete a fresh authentication flow (including MFA)."
        ),
        severity=ActionSeverity.MEDIUM,
        requires_human_review=False,
    ),
    MitigationAction.INCREASE_MONITORING: ActionMetadata(
        description=(
            "Elevate telemetry verbosity for this identity/resource pair "
            "and route events to the high-fidelity audit pipeline."
        ),
        severity=ActionSeverity.LOW,
        requires_human_review=False,
    ),
    MitigationAction.DENY_REQUEST: ActionMetadata(
        description=(
            "Reject the triggering request with a policy-enforced denial "
            "response.  A LOG_ALERT companion step is auto-injected."
        ),
        severity=ActionSeverity.HIGH,
        requires_human_review=False,
    ),
    MitigationAction.NOTIFY_SECURITY_TEAM: ActionMetadata(
        description=(
            "Dispatch a real-time notification to the on-call security "
            "team via the configured alerting channel."
        ),
        severity=ActionSeverity.HIGH,
        requires_human_review=False,
    ),
}


# ---------------------------------------------------------------------------
# Step and Plan models
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class MitigationStep:
    """
    A single, auditable mitigation step within a ``MitigationPlan``.

    Attributes
    ----------
    step_index:
        Zero-based position within the plan's ordered action sequence.
    action:
        The mitigation action to execute.
    description:
        Human-readable description of the action.
    severity:
        Severity classification.
    requires_human_review:
        Whether execution must be gated on human approval.
    """

    step_index: int
    action: MitigationAction
    description: str
    severity: ActionSeverity
    requires_human_review: bool


@dataclass(frozen=True, slots=True)
class MitigationPlan:
    """
    A fully validated, auditable mitigation plan derived from a
    ``PolicyDecision``.

    Attributes
    ----------
    plan_id:
        Deterministic SHA-256 identifier derived from the decision payload.
        Equal inputs always produce equal ``plan_id`` values.
    policy_id:
        ID of the policy that generated the source decision.
    matched_rule_id:
        ID of the matched rule, or ``None`` if no rule matched.
    effect:
        ``PolicyEffect`` from the source decision.
    steps:
        Ordered, immutable sequence of mitigation steps.
    status:
        Initial lifecycle status (always ``PENDING``).
    requires_human_review:
        ``True`` if *any* step in the plan requires human approval.
    content_hash:
        Hash of the compiled policy used to generate the source decision.
    highest_severity:
        The highest-severity action across all steps.
    total_steps:
        Total number of steps in the plan.
    """

    plan_id: str
    policy_id: str
    matched_rule_id: str | None
    effect: PolicyEffect
    steps: tuple[MitigationStep, ...]
    status: PlanStatus
    requires_human_review: bool
    content_hash: str
    highest_severity: ActionSeverity
    total_steps: int


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class MitigationPlanError(ValueError):
    """Raised when mitigation plan generation or validation fails."""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_SEVERITY_ORDER: Final[dict[ActionSeverity, int]] = {
    ActionSeverity.LOW: 0,
    ActionSeverity.MEDIUM: 1,
    ActionSeverity.HIGH: 2,
    ActionSeverity.CRITICAL: 3,
}


def _plan_id(decision: PolicyDecision) -> str:
    """
    Derive a deterministic plan ID from the decision payload.

    The same decision always yields the same plan ID, enabling idempotent
    plan creation and deduplication in the event store.
    """
    payload = json.dumps(
        {
            "policy_id": decision.policy_id,
            "matched_rule_id": decision.matched_rule_id,
            "effect": decision.effect.value,
            "actions": [a.value for a in decision.actions],
            "content_hash": decision.content_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _highest_severity(steps: tuple[MitigationStep, ...]) -> ActionSeverity:
    """Return the highest ``ActionSeverity`` across all steps."""
    if not steps:
        return ActionSeverity.LOW
    return max(steps, key=lambda s: _SEVERITY_ORDER[s.severity]).severity


def _inject_companion_actions(
    actions: tuple[MitigationAction, ...],
    effect: PolicyEffect,
) -> tuple[MitigationAction, ...]:
    """
    Inject mandatory companion actions that must accompany certain
    combinations of effect + actions to satisfy audit requirements.

    Rules:
    * ``DENY`` effect with no ``LOG_ALERT`` → append ``LOG_ALERT``.
    * ``SUSPEND_RESOURCE`` without ``LOG_ALERT`` → prepend ``LOG_ALERT``.
    * ``DENY_REQUEST`` without ``LOG_ALERT`` → prepend ``LOG_ALERT``.
    * Deduplicate while preserving order.
    """
    result: list[MitigationAction] = list(actions)
    needs_log = (
        effect == PolicyEffect.DENY
        or MitigationAction.SUSPEND_RESOURCE in result
        or MitigationAction.DENY_REQUEST in result
    )
    if needs_log and MitigationAction.LOG_ALERT not in result:
        result.insert(0, MitigationAction.LOG_ALERT)

    # Deduplicate while preserving insertion order.
    seen: set[MitigationAction] = set()
    deduped: list[MitigationAction] = []
    for a in result:
        if a not in seen:
            seen.add(a)
            deduped.append(a)
    return tuple(deduped)


def _build_steps(actions: tuple[MitigationAction, ...]) -> tuple[MitigationStep, ...]:
    """
    Convert an ordered sequence of ``MitigationAction`` values into
    ``MitigationStep`` objects enriched with metadata from the registry.
    """
    steps: list[MitigationStep] = []
    for idx, action in enumerate(actions):
        metadata = _ACTION_METADATA.get(action)
        if metadata is None:
            raise MitigationPlanError(
                f"No metadata registered for action '{action}'. "
                "This indicates a compiler/planner version mismatch."
            )
        steps.append(
            MitigationStep(
                step_index=idx,
                action=action,
                description=metadata.description,
                severity=metadata.severity,
                requires_human_review=metadata.requires_human_review,
            )
        )
    return tuple(steps)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_actions(decision: PolicyDecision) -> tuple[MitigationAction, ...]:
    """
    Derive the final ordered action sequence for a decision, including any
    automatically-injected companion actions.

    Parameters
    ----------
    decision:
        The ``PolicyDecision`` from which to derive actions.

    Returns
    -------
    tuple[MitigationAction, ...]
        The final, deduplicated, ordered action sequence.
    """
    if not isinstance(decision, PolicyDecision):
        raise MitigationPlanError(
            f"Expected a PolicyDecision; got {type(decision).__name__}."
        )
    return _inject_companion_actions(decision.actions, decision.effect)


def validate_mitigation_plan(plan: MitigationPlan) -> None:
    """
    Validate the internal consistency of a ``MitigationPlan``.

    Checks performed:
    * ``plan_id`` is a non-empty string.
    * ``total_steps`` matches ``len(plan.steps)``.
    * All step indices are contiguous starting from 0.
    * ``requires_human_review`` is consistent with step-level flags.
    * ``highest_severity`` matches the actual maximum severity.
    * Every step action has a registered metadata entry.
    * ``DENY`` effect plans must include at least one of:
      ``DENY_REQUEST`` or ``LOG_ALERT``.

    Parameters
    ----------
    plan:
        The plan to validate.

    Raises
    ------
    MitigationPlanError
        If any validation check fails.
    """
    if not isinstance(plan, MitigationPlan):
        raise MitigationPlanError(
            f"Expected a MitigationPlan; got {type(plan).__name__}."
        )
    if not plan.plan_id:
        raise MitigationPlanError("plan_id must be a non-empty string.")

    if plan.total_steps != len(plan.steps):
        raise MitigationPlanError(
            f"total_steps ({plan.total_steps}) does not match "
            f"len(steps) ({len(plan.steps)})."
        )

    for expected_idx, step in enumerate(plan.steps):
        if step.step_index != expected_idx:
            raise MitigationPlanError(
                f"Step indices are not contiguous: expected {expected_idx}, "
                f"got {step.step_index} for action '{step.action}'."
            )
        if step.action not in _ACTION_METADATA:
            raise MitigationPlanError(
                f"Step at index {expected_idx} references unknown action "
                f"'{step.action}'."
            )

    actual_review = any(s.requires_human_review for s in plan.steps)
    if plan.requires_human_review != actual_review:
        raise MitigationPlanError(
            "Plan-level requires_human_review is inconsistent with "
            "step-level flags."
        )

    actual_highest = _highest_severity(plan.steps) if plan.steps else ActionSeverity.LOW
    if plan.highest_severity != actual_highest:
        raise MitigationPlanError(
            f"highest_severity '{plan.highest_severity}' does not match "
            f"computed value '{actual_highest}'."
        )

    if plan.effect == PolicyEffect.DENY:
        deny_actions = {MitigationAction.DENY_REQUEST, MitigationAction.LOG_ALERT}
        step_actions = {s.action for s in plan.steps}
        if not step_actions & deny_actions:
            raise MitigationPlanError(
                "A DENY-effect plan must include at least one of: "
                "DENY_REQUEST, LOG_ALERT."
            )


def plan_mitigation(decision: PolicyDecision) -> MitigationPlan:
    """
    Translate a ``PolicyDecision`` into a deterministic, auditable
    ``MitigationPlan``.

    This is the primary entry point for downstream orchestrators.  The
    returned plan is fully validated before being returned.

    Parameters
    ----------
    decision:
        The ``PolicyDecision`` to translate.

    Returns
    -------
    MitigationPlan
        A validated, immutable mitigation plan.

    Raises
    ------
    MitigationPlanError
        If action metadata is missing or the plan fails internal validation.
    """
    if not isinstance(decision, PolicyDecision):
        raise MitigationPlanError(
            f"Expected a PolicyDecision; got {type(decision).__name__}."
        )

    final_actions = generate_actions(decision)
    steps = _build_steps(final_actions)
    review_required = any(s.requires_human_review for s in steps)
    highest = _highest_severity(steps) if steps else ActionSeverity.LOW

    plan = MitigationPlan(
        plan_id=_plan_id(decision),
        policy_id=decision.policy_id,
        matched_rule_id=decision.matched_rule_id,
        effect=decision.effect,
        steps=steps,
        status=PlanStatus.PENDING,
        requires_human_review=review_required,
        content_hash=decision.content_hash,
        highest_severity=highest,
        total_steps=len(steps),
    )

    # Validate before returning — belt-and-suspenders for production safety.
    validate_mitigation_plan(plan)

    logger.info(
        "Mitigation plan created",
        extra={
            "plan_id": plan.plan_id,
            "policy_id": plan.policy_id,
            "matched_rule_id": plan.matched_rule_id,
            "effect": plan.effect.value,
            "total_steps": plan.total_steps,
            "highest_severity": plan.highest_severity.value,
            "requires_human_review": plan.requires_human_review,
        },
    )
    return plan