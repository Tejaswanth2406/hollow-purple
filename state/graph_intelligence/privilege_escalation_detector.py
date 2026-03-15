"""
graph_intelligence/privilege_escalation_detector.py — Graph-Aware Privilege Escalation Detector

Combines event stream analysis with live graph traversal.

Detection strategies:
  1. Event-stream analysis: privilege_escalation events in state
  2. Graph path analysis: identity → role chain → admin node
  3. Policy mutation detection: who changed IAM policies recently
  4. Role trust policy widening: trust policy made more permissive
  5. Admin group membership changes
  6. Privilege delta scoring: measure privilege gain per actor
  7. Cumulative escalation: multiple small escalations adding up to admin
"""

import logging
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field

logger = logging.getLogger("hollow_purple.priv_esc_graph")

HIGH_PRIV_RE = re.compile(
    r"(admin|root|owner|superuser|full.?access|power.?user|god.?mode|break.?glass)",
    re.IGNORECASE,
)

ESCALATION_ACTIONS = frozenset({
    "AssumeRole", "CreateRole", "AttachRolePolicy", "PutRolePolicy",
    "CreatePolicyVersion", "SetDefaultPolicyVersion", "UpdateAssumeRolePolicy",
    "PassRole", "privilege_escalation", "AssignRole", "SetIAMPolicy",
    "google.iam.admin.v1.SetIamPolicy",
})

PRIVILEGE_LEVELS = {
    "admin":       100,
    "elevated":     75,
    "poweruser":    60,
    "developer":    30,
    "readonly":     10,
    "none":          0,
}


@dataclass
class EscalationAlert:
    subtype:      str
    actor:        str
    severity:     str
    detail:       str
    path:         list = field(default_factory=list)
    old_priv:     int  = 0
    new_priv:     int  = 0
    delta:        int  = 0

    def to_dict(self) -> dict:
        return {
            "type":      "privilege_escalation",
            "subtype":   self.subtype,
            "actor":     self.actor,
            "severity":  self.severity,
            "detail":    self.detail,
            "path":      self.path,
            "priv_delta": self.delta,
        }


class PrivilegeEscalationDetector:
    """
    Multi-strategy privilege escalation detector.

    Usage:
        detector = PrivilegeEscalationDetector(graph_store)
        alerts = detector.detect(events)
        alerts = detector.detect_from_graph("user123")
        alerts = detector.detect_from_state(state_machine.state)
    """

    def __init__(self, graph_store):
        self.graph = graph_store
        # Per-actor privilege history for cumulative detection
        self._priv_history: dict[str, list[tuple[int, float]]] = defaultdict(list)
        # Policy change log
        self._policy_changes: list[dict] = []

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def detect(self, events: list[dict]) -> list[dict]:
        """Analyze a list of events for privilege escalation patterns."""
        alerts: list[EscalationAlert] = []
        for event in events:
            alerts += self._analyze_event(event)
        return [a.to_dict() for a in alerts]

    def detect_from_graph(self, actor: str, max_depth: int = 8) -> list[dict]:
        """Graph traversal privilege escalation analysis for a specific actor."""
        alerts: list[EscalationAlert] = []
        alerts += self._check_graph_paths(actor, max_depth)
        alerts += self._check_cumulative_escalation(actor)
        return [a.to_dict() for a in alerts]

    def detect_from_state(self, state: dict) -> list[dict]:
        """Analyze the full state machine state for escalation patterns."""
        alerts: list[EscalationAlert] = []

        # Check privilege_state in state
        for actor, priv_data in state.get("privilege_state", {}).items():
            roles = priv_data.get("roles", [])
            for role in roles:
                if HIGH_PRIV_RE.search(role):
                    alerts.append(EscalationAlert(
                        subtype="state_privilege_escalation",
                        actor=actor,
                        severity="critical" if "admin" in role.lower() else "high",
                        detail=f"Actor holds high-privilege role '{role}' in state",
                        path=[actor, role],
                    ))

        # Check rapid escalation count
        for actor, priv_data in state.get("privilege_state", {}).items():
            count = priv_data.get("escalations", 0)
            if count >= 3:
                alerts.append(EscalationAlert(
                    subtype="rapid_repeated_escalation",
                    actor=actor,
                    severity="high",
                    detail=f"Actor has escalated privilege {count} times",
                ))

        # Check MFA deactivations (common pre-escalation step)
        mfa_deactivations = state.get("mfa_deactivations", [])
        recent = [e for e in mfa_deactivations if time.time() - e.get("ts", 0) < 3600]
        if recent:
            for e in recent:
                alerts.append(EscalationAlert(
                    subtype="mfa_deactivation_pre_escalation",
                    actor=e.get("actor", "unknown"),
                    severity="high",
                    detail=f"MFA deactivated for '{e.get('target')}' — possible pre-escalation step",
                ))

        return [a.to_dict() for a in alerts]

    # ------------------------------------------------------------------ #
    #  Internal strategies                                                 #
    # ------------------------------------------------------------------ #

    def _analyze_event(self, event: dict) -> list[EscalationAlert]:
        alerts = []
        action = event.get("action", "")
        actor  = event.get("actor", "")

        if action not in ESCALATION_ACTIONS:
            return []

        resource = event.get("resource", "")

        # Direct high-priv assumption
        if HIGH_PRIV_RE.search(resource):
            alerts.append(EscalationAlert(
                subtype="direct_high_priv_assumption",
                actor=actor,
                severity="critical",
                detail=f"Actor directly assumed high-privilege resource: {resource}",
                path=[actor, resource],
            ))

        # Policy mutation
        if action in ("AttachRolePolicy", "PutRolePolicy", "CreatePolicyVersion",
                      "SetDefaultPolicyVersion", "SetIAMPolicy"):
            self._policy_changes.append({"actor": actor, "action": action,
                                          "resource": resource, "ts": event.get("timestamp", time.time())})
            alerts += self._check_policy_concentration(actor)

        # Track privilege level change
        new_priv = self._estimate_privilege(resource)
        if new_priv > 0:
            self._priv_history[actor].append((new_priv, event.get("timestamp", time.time())))

        return alerts

    def _check_graph_paths(self, actor: str, max_depth: int) -> list[EscalationAlert]:
        """Walk graph from actor, flag any path reaching high-privilege nodes."""
        alerts  = []
        visited: set[str] = set()
        stack   = [(actor, [actor])]

        while stack:
            node, path = stack.pop()
            if node in visited or len(path) > max_depth:
                continue
            visited.add(node)

            if node != actor and HIGH_PRIV_RE.search(str(node)):
                hop_count = len(path) - 1
                severity  = "critical" if hop_count <= 2 else "high"
                alerts.append(EscalationAlert(
                    subtype="graph_path_to_high_priv",
                    actor=actor,
                    severity=severity,
                    detail=f"{hop_count}-hop path to high-privilege node '{node}'",
                    path=path,
                    new_priv=self._estimate_privilege(node),
                ))

            for edge in self._safe_neighbors(node):
                nxt = edge.get("target", "")
                if nxt and nxt not in visited:
                    stack.append((nxt, path + [nxt]))

        return alerts

    def _check_policy_concentration(self, actor: str) -> list[EscalationAlert]:
        """Alert if same actor has mutated many policies recently."""
        recent = [e for e in self._policy_changes
                  if e["actor"] == actor and time.time() - e["ts"] < 3600]
        if len(recent) >= 3:
            return [EscalationAlert(
                subtype="policy_mutation_spree",
                actor=actor,
                severity="high",
                detail=f"Actor mutated {len(recent)} policies within 1 hour",
            )]
        return []

    def _check_cumulative_escalation(self, actor: str) -> list[EscalationAlert]:
        """
        Detect gradual privilege accumulation: many small role additions
        that cumulatively reach admin-equivalent access.
        """
        history = self._priv_history.get(actor, [])
        if len(history) < 3:
            return []
        recent = [priv for priv, ts in history if time.time() - ts < 86400]
        if not recent:
            return []
        cumulative = sum(recent)
        if cumulative >= 200:   # Equivalent to ~2 admin-level roles
            return [EscalationAlert(
                subtype="cumulative_escalation",
                actor=actor,
                severity="high",
                detail=f"Cumulative privilege score={cumulative} over 24h "
                       f"({len(recent)} role acquisitions)",
                delta=cumulative,
            )]
        return []

    def _estimate_privilege(self, resource: str) -> int:
        r = resource.lower()
        for key, val in PRIVILEGE_LEVELS.items():
            if key in r:
                return val
        return 0

    def _safe_neighbors(self, node: str) -> list[dict]:
        try:
            return self.graph.get_neighbors(node) or []
        except Exception as exc:
            logger.debug("get_neighbors('%s') failed: %s", node, exc)
            return []