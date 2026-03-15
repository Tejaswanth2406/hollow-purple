"""
policy_engine/policy_compiler.py — HOLLOW_PURPLE Policy Compiler

Loads policy definitions (YAML / JSON) and compiles them into
typed Rule objects the evaluator can execute efficiently.

Policy file schema:

    name:        string        (required, unique)
    version:     string        (optional, default "1.0")
    enabled:     bool          (optional, default true)
    priority:    int           (optional, lower = higher priority, default 100)
    description: string        (optional)
    tags:        list[string]  (optional, for filtering)
    compliance:  list[string]  (optional NIST / ISO framework tags)
    scope:       string        "global" | "aws" | "gcp" | "azure"  (default "global")

    condition:                 (required — AND of all sub-conditions)
      risk_score:    ">0.8"   | "<0.3"  | "==0.5"  | "between:0.6:0.9"
      severity:      "critical" | "high" | ...  (exact match or list)
      action:        "AssumeRole"               (exact or list)
      actor_type:    "service_account"
      source:        "aws"
      actor:         "svc-deploy"               (exact or regex:pattern)
      resource:      regex:.*admin.*            (regex match)
      anomaly_score: ">0.75"
      tags:          contains:sensitive_resource
      custom:        "actor.startswith('svc-')" (Python expression — disabled in safe mode)

    actions:                   (required — list of mitigation action names)
      - revoke_token
      - isolate_identity
      - block_ip
      - rotate_credentials
      - alert_soc
      - page_oncall
      - quarantine_resource
      - increase_monitoring
      - require_mfa_reauthentication
      - disable_access_key

    metadata:
      author:      string
      created_at:  ISO8601 date
      review_date: ISO8601 date
"""

import copy
import glob
import hashlib
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("hollow_purple.policy_compiler")

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

# All known mitigation actions (used for validation)
KNOWN_ACTIONS = frozenset({
    "revoke_token", "isolate_identity", "block_ip", "rotate_credentials",
    "alert_soc", "page_oncall", "quarantine_resource", "increase_monitoring",
    "require_mfa_reauthentication", "disable_access_key", "force_logout",
    "notify_identity_owner", "create_incident_ticket", "add_to_watchlist",
    "reduce_token_ttl", "enable_step_up_auth", "snapshot_state", "log_forensic",
})

KNOWN_SCOPES    = frozenset({"global", "aws", "gcp", "azure"})
KNOWN_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})


@dataclass
class Condition:
    """Compiled, executable condition from a policy definition."""
    field:    str           # e.g. "risk_score", "severity", "actor"
    operator: str           # ">", "<", "==", "!=", "in", "contains", "regex", "between"
    value:    Any           # parsed target value
    raw:      str = ""      # original string for audit trail


@dataclass
class Rule:
    """A compiled, executable security policy rule."""
    name:        str
    version:     str           = "1.0"
    enabled:     bool          = True
    priority:    int           = 100
    description: str           = ""
    tags:        list          = field(default_factory=list)
    compliance:  list          = field(default_factory=list)
    scope:       str           = "global"
    conditions:  list[Condition] = field(default_factory=list)
    actions:     list[str]     = field(default_factory=list)
    metadata:    dict          = field(default_factory=dict)
    source_file: str           = ""
    checksum:    str           = ""


class PolicyCompiler:
    """
    Loads policy YAML/JSON files, validates them, and compiles them
    into executable Rule objects.

    Usage:
        compiler = PolicyCompiler()
        compiler.load_directory("policies/")
        compiler.load_file("policies/high_risk_identity.yaml")
        rules = compiler.get_rules()
        rules = compiler.get_rules(scope="aws", tags=["privilege_escalation"])
    """

    def __init__(self, safe_mode: bool = True):
        self._rules:    dict[str, Rule] = {}    # name → Rule
        self.safe_mode  = safe_mode             # Disables custom Python expressions
        self._load_errors: list[dict] = []

    # ------------------------------------------------------------------ #
    #  Loading                                                             #
    # ------------------------------------------------------------------ #

    def load_directory(self, directory: str, recursive: bool = True) -> int:
        """Load all .yaml/.json policy files from a directory. Returns count loaded."""
        pattern = "**/*.yaml" if recursive else "*.yaml"
        paths   = list(Path(directory).glob(pattern))
        paths  += list(Path(directory).glob("**/*.json" if recursive else "*.json"))
        loaded  = 0
        for path in paths:
            try:
                self.load_file(str(path))
                loaded += 1
            except Exception as exc:
                logger.error("Failed to load policy '%s': %s", path, exc)
                self._load_errors.append({"file": str(path), "error": str(exc)})
        logger.info("PolicyCompiler: loaded %d rules from %s (%d errors)",
                    loaded, directory, len(self._load_errors))
        return loaded

    def load_file(self, path: str) -> list[Rule]:
        """Load a single policy file. Returns list of compiled Rule objects."""
        content = Path(path).read_text(encoding="utf-8")
        checksum = hashlib.sha256(content.encode()).hexdigest()[:12]

        if path.endswith(".yaml") or path.endswith(".yml"):
            if not YAML_AVAILABLE:
                raise ImportError("PyYAML required: pip install pyyaml")
            raw = yaml.safe_load(content)
        elif path.endswith(".json"):
            raw = json.loads(content)
        else:
            raise ValueError(f"Unsupported policy file format: {path}")

        # Support both single policy dict and list of policies
        policies = raw if isinstance(raw, list) else [raw]
        rules    = []
        for policy in policies:
            rule = self._compile(policy, source_file=path, checksum=checksum)
            self._rules[rule.name] = rule
            rules.append(rule)
        return rules

    def load_inline(self, policy: dict) -> Rule:
        """Compile and register a single policy dict at runtime."""
        rule = self._compile(policy, source_file="inline")
        self._rules[rule.name] = rule
        return rule

    def unload(self, name: str):
        self._rules.pop(name, None)

    # ------------------------------------------------------------------ #
    #  Query                                                               #
    # ------------------------------------------------------------------ #

    def get_rules(
        self,
        scope:     str | None       = None,
        tags:      list[str] | None = None,
        enabled:   bool             = True,
    ) -> list[Rule]:
        """Return compiled rules, optionally filtered by scope / tags / enabled status."""
        rules = [r for r in self._rules.values() if r.enabled == enabled or not enabled]
        if scope:
            rules = [r for r in rules if r.scope in ("global", scope)]
        if tags:
            rules = [r for r in rules if any(t in r.tags for t in tags)]
        return sorted(rules, key=lambda r: r.priority)

    def get_rule(self, name: str) -> Rule | None:
        return self._rules.get(name)

    def rule_names(self) -> list[str]:
        return list(self._rules.keys())

    def stats(self) -> dict:
        return {
            "total_rules":   len(self._rules),
            "enabled_rules": sum(1 for r in self._rules.values() if r.enabled),
            "load_errors":   len(self._load_errors),
            "scopes":        list({r.scope for r in self._rules.values()}),
        }

    # ------------------------------------------------------------------ #
    #  Compilation                                                         #
    # ------------------------------------------------------------------ #

    def _compile(self, policy: dict, source_file: str = "", checksum: str = "") -> Rule:
        """Compile a raw policy dict into a Rule object."""
        name = policy.get("name")
        if not name:
            raise ValueError("Policy missing required field 'name'")

        scope = policy.get("scope", "global").lower()
        if scope not in KNOWN_SCOPES:
            raise ValueError(f"Unknown scope '{scope}' in policy '{name}'")

        raw_conditions = policy.get("condition") or policy.get("conditions") or {}
        if isinstance(raw_conditions, list):
            raw_conditions = {k: v for d in raw_conditions for k, v in d.items()}

        conditions = [self._compile_condition(k, v) for k, v in raw_conditions.items()]

        actions = policy.get("action") or policy.get("actions") or []
        if isinstance(actions, str):
            actions = [actions]
        for action in actions:
            if action not in KNOWN_ACTIONS:
                logger.warning("Policy '%s': unknown action '%s'", name, action)

        return Rule(
            name        = name,
            version     = str(policy.get("version", "1.0")),
            enabled     = bool(policy.get("enabled", True)),
            priority    = int(policy.get("priority", 100)),
            description = str(policy.get("description", "")),
            tags        = list(policy.get("tags", [])),
            compliance  = list(policy.get("compliance", [])),
            scope       = scope,
            conditions  = conditions,
            actions     = actions,
            metadata    = dict(policy.get("metadata", {})),
            source_file = source_file,
            checksum    = checksum,
        )

    def _compile_condition(self, field: str, raw_value: Any) -> Condition:
        """Parse a condition field+value into a typed Condition."""
        raw_str = str(raw_value)

        # Numeric comparison: ">0.8", "<0.3", "==0.5", "!=0.5"
        for op in (">", "<", ">=", "<=", "==", "!="):
            if raw_str.startswith(op):
                return Condition(
                    field=field, operator=op,
                    value=float(raw_str[len(op):]), raw=raw_str,
                )

        # Range: "between:0.4:0.8"
        if raw_str.startswith("between:"):
            parts = raw_str.split(":")
            return Condition(
                field=field, operator="between",
                value=(float(parts[1]), float(parts[2])), raw=raw_str,
            )

        # Regex: "regex:.*admin.*"
        if raw_str.startswith("regex:"):
            pattern = raw_str[6:]
            re.compile(pattern)  # Validate regex at compile time
            return Condition(field=field, operator="regex", value=pattern, raw=raw_str)

        # List membership: list values or comma-separated
        if isinstance(raw_value, list):
            return Condition(field=field, operator="in", value=raw_value, raw=raw_str)

        # Contains tag: "contains:sensitive_resource"
        if raw_str.startswith("contains:"):
            return Condition(field=field, operator="contains", value=raw_str[9:], raw=raw_str)

        # Default: exact string match
        return Condition(field=field, operator="==", value=raw_value, raw=raw_str)