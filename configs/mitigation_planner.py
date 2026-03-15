"""
policy_engine/mitigation_planner.py — HOLLOW_PURPLE Mitigation Planner

Converts policy violations into prioritized, executable action plans.

Features:
  1. Action deduplication — same action on same actor not re-issued within cooldown
  2. Priority ordering — critical actions execute before informational ones
  3. Dry-run mode — log all planned actions without executing them
  4. Action rollback registry — each action can register an undo function
  5. Execution result tracking — success / failure per action
  6. Per-actor cooldown — prevent action flooding on the same identity
  7. Action hooks — pluggable async executors for each action type
  8. Compliance tagging — each plan records which frameworks it satisfies
  9. Plan audit trail — full history of executed plans
  10. Partial execution — if one action fails, others still execute

Action types and their semantics:
  revoke_token             → Add token to revocation registry; notify downstream
  isolate_identity         → Disable identity in state; block all further actions
  block_ip                 → Add IP to network blocklist (WAF / security group)
  rotate_credentials       → Trigger credential rotation workflow
  disable_access_key       → Mark access key as inactive in state
  force_logout             → Terminate all active sessions for actor
  alert_soc                → Send structured alert to SOC dashboard
  page_oncall              → PagerDuty / OpsGenie alert
  create_incident_ticket   → Create JIRA / ServiceNow incident
  quarantine_resource      → Restrict resource access to admin-only
  increase_monitoring      → Elevate logging verbosity for actor
  reduce_token_ttl         → Shorten token TTL for actor (tighten access)
  require_mfa_reauthentication → Revoke session, require fresh MFA
  notify_identity_owner    → Email/Slack the identity's manager
  add_to_watchlist         → Flag actor for elevated monitoring
  enable_step_up_auth      → Require step-up authentication for sensitive actions
  snapshot_state           → Trigger forensic state snapshot
  log_forensic             → Dump full event context to forensic log
"""

import asyncio
import copy
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable, Awaitable

from policy_engine.rule_evaluator import Violation

logger = logging.getLogger("hollow_purple.mitigation_planner")

AUDIT_LOG_MAX    = 5_000
COOLDOWN_DEFAULT = 60.0   # seconds


class ActionPriority(IntEnum):
    CRITICAL    = 0    # Execute immediately (block/revoke)
    HIGH        = 1    # Execute first (isolate/disable)
    MEDIUM      = 2    # Execute after high (alert/notify)
    LOW         = 3    # Execute last (monitoring/logging)


# Priority mapping for each action type
ACTION_PRIORITY_MAP: dict[str, ActionPriority] = {
    "revoke_token":                  ActionPriority.CRITICAL,
    "isolate_identity":              ActionPriority.CRITICAL,
    "block_ip":                      ActionPriority.CRITICAL,
    "force_logout":                  ActionPriority.CRITICAL,
    "quarantine_resource":           ActionPriority.HIGH,
    "disable_access_key":            ActionPriority.HIGH,
    "require_mfa_reauthentication":  ActionPriority.HIGH,
    "rotate_credentials":            ActionPriority.HIGH,
    "reduce_token_ttl":              ActionPriority.HIGH,
    "alert_soc":                     ActionPriority.MEDIUM,
    "page_oncall":                   ActionPriority.MEDIUM,
    "create_incident_ticket":        ActionPriority.MEDIUM,
    "notify_identity_owner":         ActionPriority.MEDIUM,
    "enable_step_up_auth":           ActionPriority.MEDIUM,
    "increase_monitoring":           ActionPriority.LOW,
    "add_to_watchlist":              ActionPriority.LOW,
    "snapshot_state":                ActionPriority.LOW,
    "log_forensic":                  ActionPriority.LOW,
}

# Rollback actions (undo mappings)
ROLLBACK_MAP: dict[str, str] = {
    "isolate_identity":    "restore_identity",
    "block_ip":            "unblock_ip",
    "disable_access_key":  "enable_access_key",
    "quarantine_resource": "unquarantine_resource",
    "reduce_token_ttl":    "restore_token_ttl",
}


@dataclass
class ActionItem:
    name:       str
    priority:   ActionPriority
    context:    dict
    rule_name:  str
    rollback:   str | None = None


@dataclass
class ActionResult:
    action:    str
    success:   bool
    error:     str = ""
    executed_at: float = field(default_factory=time.time)
    duration_ms: float = 0.0


@dataclass
class MitigationPlan:
    plan_id:    str
    actor:      str
    resource:   str
    risk_score: float
    actions:    list[ActionItem]
    violations: list[Violation]
    created_at: float = field(default_factory=time.time)
    compliance: list[str] = field(default_factory=list)
    results:    list[ActionResult] = field(default_factory=list)
    dry_run:    bool = False

    def to_dict(self) -> dict:
        return {
            "plan_id":    self.plan_id,
            "actor":      self.actor,
            "resource":   self.resource,
            "risk_score": self.risk_score,
            "action_count": len(self.actions),
            "actions":    [{"name": a.name, "priority": a.priority.name} for a in self.actions],
            "violations": [v.rule.name for v in self.violations],
            "compliance": self.compliance,
            "created_at": self.created_at,
            "dry_run":    self.dry_run,
            "results":    [{"action": r.action, "success": r.success, "error": r.error}
                           for r in self.results],
        }


class MitigationPlanner:
    """
    Converts policy violations into prioritized, executable action plans.

    Usage:
        planner = MitigationPlanner(dry_run=False)

        # Register action executors
        planner.register_executor("revoke_token", my_token_revoke_fn)
        planner.register_executor("alert_soc",    my_siem_alert_fn)

        # Build and execute a plan
        plan = planner.plan(violations, context)
        results = await planner.execute(plan)
    """

    def __init__(
        self,
        dry_run:             bool  = False,
        cooldown_seconds:    float = COOLDOWN_DEFAULT,
        max_actions_per_plan: int  = 10,
    ):
        self.dry_run              = dry_run
        self.cooldown_seconds     = cooldown_seconds
        self.max_actions_per_plan = max_actions_per_plan

        # Registered async executors: action_name → async fn(context) → bool
        self._executors: dict[str, Callable[..., Awaitable[bool]]] = {}

        # Per-actor per-action cooldown: (actor, action) → last_executed_ts
        self._cooldowns: dict[tuple, float] = {}

        # Plan + execution audit trail
        self._plan_history: list[MitigationPlan] = []

        # Metrics
        self._plans_created   = 0
        self._actions_executed = 0
        self._actions_failed   = 0
        self._actions_skipped  = 0

        # Register default stub executors
        self._register_default_executors()

    # ------------------------------------------------------------------ #
    #  Planning                                                            #
    # ------------------------------------------------------------------ #

    def plan(self, violations: list[Violation], context: dict) -> MitigationPlan:
        """
        Build a prioritized action plan from a list of violations.
        Deduplicates actions, respects cooldowns, and sorts by priority.
        """
        import uuid
        actor     = context.get("actor", "unknown")
        resource  = context.get("resource", "")
        risk      = float(context.get("risk_score", 0))

        # Collect unique actions across all violations
        seen_actions: set[str] = set()
        action_items: list[ActionItem] = []
        compliance_tags: set[str] = set()

        for violation in violations:
            compliance_tags.update(violation.rule.compliance)
            for action_name in violation.rule.actions:
                if action_name in seen_actions:
                    continue
                seen_actions.add(action_name)

                # Cooldown check
                if self._in_cooldown(actor, action_name):
                    self._actions_skipped += 1
                    logger.debug("Cooldown active: actor=%s action=%s", actor, action_name)
                    continue

                priority = ACTION_PRIORITY_MAP.get(action_name, ActionPriority.LOW)
                rollback = ROLLBACK_MAP.get(action_name)
                action_items.append(ActionItem(
                    name=action_name, priority=priority,
                    context=copy.deepcopy(context),
                    rule_name=violation.rule.name,
                    rollback=rollback,
                ))

        # Sort by priority (CRITICAL first)
        action_items.sort(key=lambda a: int(a.priority))

        # Cap to max actions per plan
        if len(action_items) > self.max_actions_per_plan:
            logger.warning("Plan capped at %d actions (had %d)", self.max_actions_per_plan, len(action_items))
            action_items = action_items[:self.max_actions_per_plan]

        plan = MitigationPlan(
            plan_id    = str(uuid.uuid4())[:8],
            actor      = actor,
            resource   = resource,
            risk_score = risk,
            actions    = action_items,
            violations = violations,
            compliance = sorted(compliance_tags),
            dry_run    = self.dry_run,
        )

        self._plans_created += 1
        logger.info("MitigationPlan created: id=%s actor=%s actions=%d risk=%.2f dry_run=%s",
                    plan.plan_id, actor, len(action_items), risk, self.dry_run)
        return plan

    # ------------------------------------------------------------------ #
    #  Execution                                                           #
    # ------------------------------------------------------------------ #

    async def execute(self, plan: MitigationPlan) -> list[ActionResult]:
        """
        Execute all actions in the plan.
        Partial failure: if one action fails, others still run.
        Returns list of ActionResult objects.
        """
        results: list[ActionResult] = []

        for action_item in plan.actions:
            start = time.perf_counter()

            if plan.dry_run:
                logger.info("[DRY-RUN] Would execute: %s for actor=%s",
                            action_item.name, plan.actor)
                result = ActionResult(
                    action=action_item.name, success=True, error="dry_run"
                )
            else:
                result = await self._execute_action(action_item)

            result.duration_ms = (time.perf_counter() - start) * 1000
            results.append(result)
            plan.results.append(result)

            # Record cooldown after successful execution
            if result.success and not plan.dry_run:
                self._set_cooldown(plan.actor, action_item.name)
                self._actions_executed += 1
            elif not result.success:
                self._actions_failed += 1

        # Store plan in history
        self._plan_history.append(plan)
        if len(self._plan_history) > AUDIT_LOG_MAX:
            self._plan_history = self._plan_history[-AUDIT_LOG_MAX:]

        succeeded = sum(1 for r in results if r.success)
        logger.info("Plan %s executed: %d/%d actions succeeded",
                    plan.plan_id, succeeded, len(results))
        return results

    async def rollback(self, plan: MitigationPlan) -> list[ActionResult]:
        """Execute rollback actions for all reversible actions in a plan."""
        rollback_results = []
        for action_item in plan.actions:
            if action_item.rollback:
                rollback_action = ActionItem(
                    name=action_item.rollback,
                    priority=action_item.priority,
                    context=action_item.context,
                    rule_name=f"rollback:{action_item.rule_name}",
                )
                result = await self._execute_action(rollback_action)
                rollback_results.append(result)
                logger.info("Rollback executed: %s → %s (success=%s)",
                            action_item.name, action_item.rollback, result.success)
        return rollback_results

    # ------------------------------------------------------------------ #
    #  Executor registration                                               #
    # ------------------------------------------------------------------ #

    def register_executor(self, action_name: str, fn: Callable[..., Awaitable[bool]]):
        """Register an async callable for a specific action type."""
        self._executors[action_name] = fn
        logger.info("Registered executor for action: '%s'", action_name)

    # ------------------------------------------------------------------ #
    #  Reporting                                                           #
    # ------------------------------------------------------------------ #

    def plan_history(self, limit: int = 50) -> list[dict]:
        return [p.to_dict() for p in self._plan_history[-limit:]]

    def stats(self) -> dict:
        return {
            "plans_created":    self._plans_created,
            "actions_executed": self._actions_executed,
            "actions_failed":   self._actions_failed,
            "actions_skipped":  self._actions_skipped,
            "active_cooldowns": len(self._cooldowns),
            "registered_executors": list(self._executors.keys()),
        }

    # ------------------------------------------------------------------ #
    #  Internal                                                            #
    # ------------------------------------------------------------------ #

    async def _execute_action(self, action_item: ActionItem) -> ActionResult:
        executor = self._executors.get(action_item.name)
        if not executor:
            logger.warning("No executor for action '%s' — using default stub", action_item.name)
            executor = self._default_stub

        try:
            success = await executor(action_item.context)
            return ActionResult(action=action_item.name, success=bool(success))
        except Exception as exc:
            logger.error("Action '%s' executor raised: %s", action_item.name, exc)
            return ActionResult(action=action_item.name, success=False, error=str(exc))

    def _in_cooldown(self, actor: str, action: str) -> bool:
        key  = (actor, action)
        last = self._cooldowns.get(key)
        if last is None:
            return False
        return (time.time() - last) < self.cooldown_seconds

    def _set_cooldown(self, actor: str, action: str):
        self._cooldowns[(actor, action)] = time.time()

    def _register_default_executors(self):
        """Register stub executors for all known actions."""
        async def _stub(context: dict) -> bool:
            return True

        for action in ACTION_PRIORITY_MAP:
            self._executors[action] = _stub

    @staticmethod
    async def _default_stub(context: dict) -> bool:
        return True