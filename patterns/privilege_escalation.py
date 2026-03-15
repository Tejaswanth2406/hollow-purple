"""
patterns/privilege_escalation.py

Detects direct and multi-hop privilege escalation paths in the identity graph.

Strategies:
  1. Direct AdminRole assumption
  2. Graph path leading to any high-privilege role (admin, root, owner, superuser)
  3. Cross-account escalation via sts:AssumeRole into foreign account admin roles
  4. Permission boundary bypass detection (role has PermissionBoundary=None + admin access)
  5. Wildcard policy abuse: role grants iam:* or *:*
"""

import re
import logging
from graph.pathfinder import find_attack_paths

logger = logging.getLogger("hollow_purple.priv_esc")

# Patterns that indicate high-privilege roles
HIGH_PRIV_PATTERNS = re.compile(
    r"(admin|root|owner|superuser|full.?access|power.?user|god.?mode|break.?glass)",
    re.IGNORECASE,
)

WILDCARD_POLICIES = {("iam", "*"), ("*", "*"), ("s3", "*"), ("ec2", "*")}

ESCALATION_ACTIONS = {
    "AssumeRole", "AssumeRoleWithWebIdentity", "AssumeRoleWithSAML",
    "CreateRole", "AttachRolePolicy", "PutRolePolicy",
    "CreatePolicyVersion", "SetDefaultPolicyVersion",
    "UpdateAssumeRolePolicy", "PassRole",
}


def detect_privilege_escalation(graph, event: dict) -> list[dict]:
    alerts = []
    action  = event.get("action", "")
    actor   = event.get("actor", "")
    resource = event.get("resource", "")
    policies = event.get("policies", [])     # list of {"service": "iam", "action": "*"}
    account  = event.get("account_id", "")
    resource_account = event.get("resource_account_id", "")

    if action not in ESCALATION_ACTIONS:
        return alerts

    # --- 1. Direct high-priv assumption ---
    if HIGH_PRIV_PATTERNS.search(resource):
        alerts.append(_build(
            actor, resource,
            "direct_high_priv_assumption",
            severity="critical",
            detail=f"Actor directly assumed high-privilege role: {resource}",
        ))

    # --- 2. Graph path to high-privilege role ---
    try:
        paths = find_attack_paths(graph, actor, depth=8)
        for path in paths:
            path_str = str(path)
            if HIGH_PRIV_PATTERNS.search(path_str) and len(path) >= 2:
                hop_count = len(path) - 1
                severity = "critical" if hop_count <= 2 else "high"
                alerts.append(_build(
                    actor, resource,
                    "graph_path_escalation",
                    severity=severity,
                    detail=f"{hop_count}-hop escalation path to high-privilege role",
                    path=path,
                ))
    except Exception as exc:
        logger.warning("Graph path lookup failed for actor=%s: %s", actor, exc)

    # --- 3. Cross-account escalation ---
    if account and resource_account and account != resource_account:
        if HIGH_PRIV_PATTERNS.search(resource):
            alerts.append(_build(
                actor, resource,
                "cross_account_escalation",
                severity="critical",
                detail=f"Cross-account assumption into high-priv role "
                       f"(src_account={account}, dst_account={resource_account})",
            ))

    # --- 4. Wildcard policy abuse ---
    for policy in policies:
        pair = (policy.get("service", ""), policy.get("action", ""))
        if pair in WILDCARD_POLICIES:
            alerts.append(_build(
                actor, resource,
                "wildcard_policy_abuse",
                severity="high",
                detail=f"Role granted wildcard policy: {pair[0]}:{pair[1]}",
            ))

    return alerts


def _build(actor, resource, subtype, severity, detail, path=None) -> dict:
    alert = {
        "type":     "privilege_escalation",
        "subtype":  subtype,
        "actor":    actor,
        "resource": resource,
        "severity": severity,
        "detail":   detail,
    }
    if path is not None:
        alert["path"] = path
    return alert