"""
ingestion/processors/normalizer.py — Canonical Event Normalizer

Converts source-specific events into a single canonical schema:

    {
        "event_id":       str,     # globally unique
        "source":         str,     # aws | azure | gcp | okta | ...
        "service":        str,     # cloudtrail | activity_log | ...
        "action":         str,     # canonical verb (AssumeRole, SignIn, ...)
        "actor":          str,     # identity performing the action
        "actor_type":     str,     # user | service_account | role | machine
        "resource":       str,     # target ARN / resource ID
        "resource_type":  str,     # IAMRole | StorageBucket | ...
        "ip":             str,
        "region":         str,
        "account_id":     str,
        "timestamp":      float,   # Unix epoch
        "severity":       str,     # info | low | medium | high | critical
        "tags":           list,    # freeform enrichment tags
        "raw":            dict,    # original event preserved
    }
"""

import logging
import time
import uuid
from typing import Any

logger = logging.getLogger("hollow_purple.normalizer")

# Action aliases: map source-specific verbs to canonical verbs
ACTION_MAP: dict[str, str] = {
    # Azure → canonical
    "Microsoft.Authorization/roleAssignments/write": "AssignRole",
    "Microsoft.Authorization/roleDefinitions/write": "CreateRoleDefinition",
    "Microsoft.KeyVault/vaults/secrets/read":        "GetSecret",
    "Microsoft.Directory/users/password/update":     "UpdatePassword",
    # GCP → canonical
    "google.iam.admin.v1.CreateServiceAccountKey":   "CreateAccessKey",
    "google.iam.admin.v1.SetIamPolicy":              "SetIAMPolicy",
    "google.admin.AdminService.createUser":          "CreateUser",
    # Okta
    "user.session.start":   "ConsoleLogin",
    "user.authentication.auth_via_mfa": "MFAAuth",
    "system.org.rate_limit.warning":    "RateLimitWarning",
}

# Actor type inference heuristics
SERVICE_ACCOUNT_SIGNALS = (
    "svc-", "sa-", "service-", "bot-", ".iam.gserviceaccount.com",
    "automation-", "ci-", "@developer.gserviceaccount.com",
)
ROLE_SIGNALS = ("assumed-role/", ":role/", "arn:aws:sts")


class EventNormalizer:
    """
    Converts any source event into the canonical HOLLOW_PURPLE event schema.
    Non-destructive: original event preserved in 'raw' field.
    """

    async def normalize(self, event: dict) -> dict:
        # Batch passthrough
        if event.get("_batch"):
            return event

        raw_copy  = dict(event)
        action    = self._canonical_action(event)
        actor     = self._extract_actor(event)
        actor_type = self._infer_actor_type(actor)
        severity  = self._infer_severity(event, action)

        normalized = {
            "event_id":      event.get("event_id") or str(uuid.uuid4()),
            "source":        str(event.get("source", "unknown")).lower(),
            "service":       str(event.get("service", "unknown")).lower(),
            "action":        action,
            "actor":         actor,
            "actor_type":    actor_type,
            "resource":      self._clean(event.get("resource")),
            "resource_type": self._clean(event.get("resource_type")),
            "ip":            self._clean(event.get("ip")),
            "region":        self._clean(event.get("region")),
            "account_id":    self._clean(event.get("account_id")
                                          or event.get("subscription")
                                          or event.get("project")),
            "timestamp":     self._parse_ts(event.get("timestamp")),
            "severity":      severity,
            "tags":          self._extract_tags(event),
            "raw":           raw_copy,
        }

        # Preserve extra fields that pattern detectors may use
        for extra in ("token", "user_agent", "geo_lat", "geo_lon", "asn",
                      "allowed_cidr", "mfa_used", "risk_level", "policies",
                      "resource_account_id"):
            if extra in event:
                normalized[extra] = event[extra]

        return normalized

    # ------------------------------------------------------------------ #
    #  Field extractors                                                    #
    # ------------------------------------------------------------------ #

    def _canonical_action(self, event: dict) -> str:
        raw_action = str(event.get("action") or event.get("event_type") or "Unknown")
        return ACTION_MAP.get(raw_action, raw_action)

    def _extract_actor(self, event: dict) -> str:
        for field in ("actor", "principal", "caller", "user", "username", "principalEmail"):
            val = event.get(field)
            if val and isinstance(val, str) and len(val.strip()) >= 2:
                return val.strip()
        return "unknown"

    def _infer_actor_type(self, actor: str) -> str:
        if any(sig in actor for sig in SERVICE_ACCOUNT_SIGNALS):
            return "service_account"
        if any(sig in actor for sig in ROLE_SIGNALS):
            return "role"
        if "@" in actor:
            return "user"
        return "machine"

    def _infer_severity(self, event: dict, action: str) -> str:
        # Use explicit severity if present
        sev = str(event.get("severity", "")).lower()
        if sev in ("critical", "high", "medium", "low", "info"):
            return sev

        # High-impact actions → high
        HIGH_IMPACT = {
            "AssumeRole", "CreateAccessKey", "CreateUser", "DeleteUser",
            "AssignRole", "SetIAMPolicy", "GetSecret", "UpdatePassword",
        }
        if action in HIGH_IMPACT:
            return "high"

        return "info"

    def _extract_tags(self, event: dict) -> list[str]:
        tags = []
        if event.get("mfa_used") is False:
            tags.append("no_mfa")
        if event.get("risk_level") in ("high", "critical"):
            tags.append("high_risk_login")
        if event.get("service") in ("guardduty", "defender", "scc"):
            tags.append("security_finding")
        return tags

    def _parse_ts(self, ts: Any) -> float:
        if ts is None:
            return time.time()
        try:
            return float(ts)
        except (ValueError, TypeError):
            return time.time()

    def _clean(self, val: Any) -> str:
        if val is None:
            return ""
        return str(val).strip()