"""
state/reducers.py — HOLLOW_PURPLE Event Reducer Registry

Reducers are **pure functions**: (current_state, event) → new_state
They are the ONLY mechanism by which state is modified.

Built-in reducers:
  - login / logout                    → identity session tracking
  - AssumeRole / CreateRole           → role graph state
  - CreateUser / DeleteUser           → identity lifecycle
  - CreateAccessKey / DeleteAccessKey → credential inventory
  - resource_access                   → access audit trail
  - privilege_escalation              → privilege state ledger
  - GuardDutyFinding                  → active threat registry
  - SecurityHubFinding                → compliance finding state
  - MFAAuth / DeactivateMFADevice     → MFA posture state
  - token_revocation                  → revoked token registry

All reducers are registered by event_type / action string.
Custom reducers can be injected at runtime.
"""

import copy
import logging
import time

logger = logging.getLogger("hollow_purple.reducers")

# Max items to keep in access log before rolling
ACCESS_LOG_MAX = 10_000


class ReducerRegistry:
    """
    Central registry of event → reducer mappings.

    Reducers must be pure functions with signature:
        def reducer(state: dict, event: dict) -> dict

    Register custom reducers:
        registry.register("MyCustomEvent", my_reducer_fn)

    Alias multiple event types to the same reducer:
        registry.alias("SignIn", "login")
    """

    def __init__(self):
        self._reducers: dict[str, callable] = {}
        self._aliases:  dict[str, str]      = {}
        self._call_counts: dict[str, int]   = {}
        self._register_builtins()

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def register(self, event_type: str, reducer):
        self._reducers[event_type] = reducer
        self._call_counts[event_type] = 0

    def alias(self, event_type: str, target_event_type: str):
        """Map event_type to an existing reducer."""
        self._aliases[event_type] = target_event_type

    def get(self, event_type: str | None):
        if not event_type:
            return None
        # Resolve alias chain
        resolved = self._aliases.get(event_type, event_type)
        fn = self._reducers.get(resolved)
        if fn:
            self._call_counts[resolved] = self._call_counts.get(resolved, 0) + 1
        return fn

    def call_counts(self) -> dict:
        return dict(self._call_counts)

    # ------------------------------------------------------------------ #
    #  Built-in reducer registration                                       #
    # ------------------------------------------------------------------ #

    def _register_builtins(self):
        # Identity lifecycle
        self.register("login",              self._r_login)
        self.register("logout",             self._r_logout)
        self.register("ConsoleLogin",       self._r_login)
        self.register("CreateUser",         self._r_create_user)
        self.register("DeleteUser",         self._r_delete_user)
        self.register("UpdateLoginProfile", self._r_update_login_profile)

        # Role / privilege
        self.register("AssumeRole",         self._r_assume_role)
        self.register("CreateRole",         self._r_create_role)
        self.register("DeleteRole",         self._r_delete_role)
        self.register("AttachRolePolicy",   self._r_attach_policy)
        self.register("DetachRolePolicy",   self._r_detach_policy)
        self.register("PutRolePolicy",      self._r_put_policy)
        self.register("privilege_escalation", self._r_privilege_escalation)
        self.register("AssignRole",         self._r_assume_role)

        # Credentials
        self.register("CreateAccessKey",    self._r_create_access_key)
        self.register("DeleteAccessKey",    self._r_delete_access_key)
        self.register("UpdateAccessKey",    self._r_update_access_key)
        self.register("token_revocation",   self._r_token_revocation)

        # MFA
        self.register("MFAAuth",                    self._r_mfa_auth)
        self.register("DeactivateMFADevice",         self._r_deactivate_mfa)
        self.register("EnableMFADevice",             self._r_enable_mfa)

        # Resource access
        self.register("resource_access",    self._r_resource_access)
        self.register("GetSecret",          self._r_resource_access)
        self.register("GetObject",          self._r_resource_access)
        self.register("SecretGet",          self._r_resource_access)

        # Findings / alerts
        self.register("GuardDutyFinding",   self._r_guardduty_finding)
        self.register("SecurityHubFinding", self._r_securityhub_finding)
        self.register("SCCFinding",         self._r_securityhub_finding)
        self.register("DefenderAlert",      self._r_guardduty_finding)

        # External access
        self.register("ExternalAccess",     self._r_external_access)

        # Service accounts (GCP)
        self.register("CreateServiceAccountKey", self._r_create_access_key)
        self.register("DeleteServiceAccountKey", self._r_delete_access_key)

    # ------------------------------------------------------------------ #
    #  Reducers — Identity                                                 #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _r_login(state: dict, event: dict) -> dict:
        actor = event.get("actor", "unknown")
        state.setdefault("identities", {})
        ident = state["identities"].setdefault(actor, {
            "logins": 0, "active": False, "mfa": False,
            "regions": [], "ips": [], "first_seen": event.get("timestamp"),
        })
        ident["logins"]     += 1
        ident["active"]      = True
        ident["last_login"]  = event.get("timestamp", time.time())
        ident["last_action"] = event.get("action", "login")
        ip = event.get("ip")
        if ip and ip not in ident["ips"]:
            ident["ips"].append(ip)
            if len(ident["ips"]) > 50:
                ident["ips"] = ident["ips"][-50:]
        region = event.get("region")
        if region and region not in ident["regions"]:
            ident["regions"].append(region)
        return state

    @staticmethod
    def _r_logout(state: dict, event: dict) -> dict:
        actor = event.get("actor", "unknown")
        state.setdefault("identities", {})
        ident = state["identities"].setdefault(actor, {})
        ident["active"]     = False
        ident["last_logout"] = event.get("timestamp", time.time())
        return state

    @staticmethod
    def _r_create_user(state: dict, event: dict) -> dict:
        actor    = event.get("actor", "unknown")
        resource = event.get("resource", "")
        state.setdefault("identities", {})
        state["identities"][resource] = {
            "created_by": actor,
            "created_at": event.get("timestamp", time.time()),
            "logins": 0, "active": False, "disabled": False,
            "mfa": False, "roles": [], "access_keys": [],
        }
        state.setdefault("identity_events", []).append({
            "type": "created", "actor": actor, "target": resource,
            "ts": event.get("timestamp", time.time()),
        })
        return state

    @staticmethod
    def _r_delete_user(state: dict, event: dict) -> dict:
        actor    = event.get("actor", "unknown")
        resource = event.get("resource", "")
        state.setdefault("identities", {})
        if resource in state["identities"]:
            state["identities"][resource]["deleted"]    = True
            state["identities"][resource]["deleted_by"] = actor
            state["identities"][resource]["deleted_at"] = event.get("timestamp", time.time())
        state.setdefault("identity_events", []).append({
            "type": "deleted", "actor": actor, "target": resource,
            "ts": event.get("timestamp", time.time()),
        })
        return state

    @staticmethod
    def _r_update_login_profile(state: dict, event: dict) -> dict:
        actor    = event.get("actor", "unknown")
        resource = event.get("resource", "unknown")
        state.setdefault("password_changes", []).append({
            "actor": actor, "target": resource,
            "ts": event.get("timestamp", time.time()),
        })
        return state

    # ------------------------------------------------------------------ #
    #  Reducers — Roles & Privilege                                        #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _r_assume_role(state: dict, event: dict) -> dict:
        actor    = event.get("actor", "unknown")
        role     = event.get("resource", "")
        ts       = event.get("timestamp", time.time())
        state.setdefault("role_assumptions", {})
        entry = state["role_assumptions"].setdefault(actor, {
            "roles": [], "count": 0, "last_ts": None,
        })
        entry["count"] += 1
        entry["last_ts"] = ts
        if role not in entry["roles"]:
            entry["roles"].append(role)
        state.setdefault("role_assumption_log", []).append({
            "actor": actor, "role": role, "ts": ts,
            "ip": event.get("ip"), "region": event.get("region"),
        })
        if len(state["role_assumption_log"]) > ACCESS_LOG_MAX:
            state["role_assumption_log"] = state["role_assumption_log"][-ACCESS_LOG_MAX:]
        return state

    @staticmethod
    def _r_create_role(state: dict, event: dict) -> dict:
        actor    = event.get("actor", "unknown")
        role     = event.get("resource", "")
        state.setdefault("roles", {})
        state["roles"][role] = {
            "created_by": actor,
            "created_at": event.get("timestamp", time.time()),
            "policies": [], "trust_policy": None,
        }
        return state

    @staticmethod
    def _r_delete_role(state: dict, event: dict) -> dict:
        role = event.get("resource", "")
        state.setdefault("roles", {})
        if role in state["roles"]:
            state["roles"][role]["deleted"]    = True
            state["roles"][role]["deleted_by"] = event.get("actor")
            state["roles"][role]["deleted_at"] = event.get("timestamp", time.time())
        return state

    @staticmethod
    def _r_attach_policy(state: dict, event: dict) -> dict:
        role   = event.get("resource", "")
        policy = event.get("policy_arn", event.get("resource", ""))
        state.setdefault("roles", {}).setdefault(role, {"policies": []})
        if policy not in state["roles"][role].get("policies", []):
            state["roles"][role].setdefault("policies", []).append(policy)
        return state

    @staticmethod
    def _r_detach_policy(state: dict, event: dict) -> dict:
        role   = event.get("resource", "")
        policy = event.get("policy_arn", "")
        state.setdefault("roles", {}).setdefault(role, {"policies": []})
        state["roles"][role]["policies"] = [
            p for p in state["roles"][role].get("policies", []) if p != policy
        ]
        return state

    @staticmethod
    def _r_put_policy(state: dict, event: dict) -> dict:
        role   = event.get("resource", "")
        policy = event.get("policy_document", {})
        state.setdefault("inline_policies", {})
        state["inline_policies"].setdefault(role, []).append({
            "policy":    policy,
            "set_by":    event.get("actor"),
            "set_at":    event.get("timestamp", time.time()),
        })
        return state

    @staticmethod
    def _r_privilege_escalation(state: dict, event: dict) -> dict:
        actor    = event.get("actor") or event.get("identity", "unknown")
        new_role = event.get("new_role") or event.get("resource", "")
        state.setdefault("privilege_state", {})
        entry = state["privilege_state"].setdefault(actor, {
            "roles": [], "escalations": 0, "first_escalation": None,
        })
        if new_role not in entry["roles"]:
            entry["roles"].append(new_role)
        entry["escalations"]    += 1
        entry["last_escalation"] = event.get("timestamp", time.time())
        if entry["first_escalation"] is None:
            entry["first_escalation"] = entry["last_escalation"]
        return state

    # ------------------------------------------------------------------ #
    #  Reducers — Credentials                                              #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _r_create_access_key(state: dict, event: dict) -> dict:
        actor     = event.get("actor", "unknown")
        resource  = event.get("resource", "")
        key_id    = event.get("access_key_id", resource)
        state.setdefault("access_keys", {})
        state["access_keys"][key_id] = {
            "created_by": actor,
            "created_at": event.get("timestamp", time.time()),
            "active":     True, "revoked": False,
            "target":     resource,
        }
        return state

    @staticmethod
    def _r_delete_access_key(state: dict, event: dict) -> dict:
        key_id = event.get("access_key_id") or event.get("resource", "")
        state.setdefault("access_keys", {})
        if key_id in state["access_keys"]:
            state["access_keys"][key_id]["active"]  = False
            state["access_keys"][key_id]["deleted"] = True
        return state

    @staticmethod
    def _r_update_access_key(state: dict, event: dict) -> dict:
        key_id = event.get("access_key_id") or event.get("resource", "")
        status = event.get("status", "Active")
        state.setdefault("access_keys", {}).setdefault(key_id, {})
        state["access_keys"][key_id]["active"] = (status == "Active")
        state["access_keys"][key_id]["status"] = status
        return state

    @staticmethod
    def _r_token_revocation(state: dict, event: dict) -> dict:
        token = event.get("token", "")
        state.setdefault("revoked_tokens", set())
        state["revoked_tokens"].add(token)
        return state

    # ------------------------------------------------------------------ #
    #  Reducers — MFA                                                      #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _r_mfa_auth(state: dict, event: dict) -> dict:
        actor = event.get("actor", "unknown")
        state.setdefault("identities", {}).setdefault(actor, {})
        state["identities"][actor]["mfa"]          = True
        state["identities"][actor]["last_mfa_ts"]  = event.get("timestamp", time.time())
        return state

    @staticmethod
    def _r_deactivate_mfa(state: dict, event: dict) -> dict:
        resource = event.get("resource", event.get("actor", "unknown"))
        state.setdefault("identities", {}).setdefault(resource, {})
        state["identities"][resource]["mfa"] = False
        state.setdefault("mfa_deactivations", []).append({
            "actor": event.get("actor"), "target": resource,
            "ts": event.get("timestamp", time.time()),
        })
        return state

    @staticmethod
    def _r_enable_mfa(state: dict, event: dict) -> dict:
        resource = event.get("resource", event.get("actor", "unknown"))
        state.setdefault("identities", {}).setdefault(resource, {})
        state["identities"][resource]["mfa"] = True
        return state

    # ------------------------------------------------------------------ #
    #  Reducers — Resource Access                                          #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _r_resource_access(state: dict, event: dict) -> dict:
        actor    = event.get("actor", "unknown")
        resource = event.get("resource", "")
        action   = event.get("action", "access")
        ts       = event.get("timestamp", time.time())
        state.setdefault("access_log", []).append({
            "actor": actor, "resource": resource,
            "action": action, "ts": ts,
            "ip": event.get("ip"), "region": event.get("region"),
        })
        if len(state["access_log"]) > ACCESS_LOG_MAX:
            state["access_log"] = state["access_log"][-ACCESS_LOG_MAX:]
        state.setdefault("resource_access_counts", {})
        state["resource_access_counts"][resource] = \
            state["resource_access_counts"].get(resource, 0) + 1
        return state

    # ------------------------------------------------------------------ #
    #  Reducers — Security Findings                                        #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _r_guardduty_finding(state: dict, event: dict) -> dict:
        finding_id = event.get("event_id", f"finding-{time.time()}")
        state.setdefault("active_findings", {})
        state["active_findings"][finding_id] = {
            "source":   event.get("service", "guardduty"),
            "type":     event.get("type") or event.get("alert_type", ""),
            "severity": event.get("severity", "medium"),
            "actor":    event.get("actor", ""),
            "resource": event.get("resource", ""),
            "ts":       event.get("timestamp", time.time()),
            "resolved": False,
        }
        return state

    @staticmethod
    def _r_securityhub_finding(state: dict, event: dict) -> dict:
        finding_id = event.get("event_id", f"sh-{time.time()}")
        state.setdefault("compliance_findings", {})
        state["compliance_findings"][finding_id] = {
            "source":     event.get("service", "securityhub"),
            "severity":   event.get("severity", "medium"),
            "compliance": event.get("compliance", ""),
            "resource":   event.get("resource", ""),
            "ts":         event.get("timestamp", time.time()),
            "resolved":   False,
        }
        return state

    @staticmethod
    def _r_external_access(state: dict, event: dict) -> dict:
        resource  = event.get("resource", "")
        principal = event.get("principal", "unknown")
        state.setdefault("external_access", {})
        state["external_access"].setdefault(resource, []).append({
            "principal": principal,
            "ts": event.get("timestamp", time.time()),
        })
        return state