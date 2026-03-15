"""
ingestion/collectors/azure_collector.py — Azure Multi-Service Event Collector

Collects from:
  - Azure Activity Log (ARM operations)
  - Microsoft Entra ID (Azure AD) Sign-in logs
  - Microsoft Defender for Cloud alerts
  - Azure Monitor / Diagnostic Logs
  - Azure Key Vault audit logs
"""

import asyncio
import logging
import time

logger = logging.getLogger("hollow_purple.collector.azure")

AZURE_HIGH_VALUE_OPERATIONS = frozenset({
    "Microsoft.Authorization/roleAssignments/write",
    "Microsoft.Authorization/roleDefinitions/write",
    "Microsoft.Authorization/policyAssignments/write",
    "Microsoft.KeyVault/vaults/secrets/read",
    "Microsoft.KeyVault/vaults/keys/read",
    "Microsoft.Compute/virtualMachines/runCommand/action",
    "Microsoft.Storage/storageAccounts/listKeys/action",
    "Microsoft.Directory/users/password/update",
    "Microsoft.Directory/servicePrincipals/credentials/update",
    "Microsoft.AAD/register",
})

SERVICES = ("activity_log", "entra_id", "defender", "keyvault")


class AzureCollector:
    """
    Async Azure multi-service collector.
    Production: wraps azure-mgmt-monitor + azure-identity SDK.
    """

    def __init__(
        self,
        subscription_id: str = "",
        tenant_id: str = "",
        services: tuple = SERVICES,
    ):
        self.subscription_id = subscription_id
        self.tenant_id       = tenant_id
        self.services        = services
        logger.info("AzureCollector ready (subscription=%s, tenant=%s)",
                    subscription_id, tenant_id)

    async def collect(self) -> list[dict]:
        tasks = []
        if "activity_log" in self.services: tasks.append(self._collect_activity_log())
        if "entra_id"     in self.services: tasks.append(self._collect_entra_id())
        if "defender"     in self.services: tasks.append(self._collect_defender())
        if "keyvault"     in self.services: tasks.append(self._collect_keyvault())

        results = await asyncio.gather(*tasks, return_exceptions=True)

        events: list[dict] = []
        for svc, result in zip(self.services, results):
            if isinstance(result, Exception):
                logger.error("Azure sub-collector '%s' failed: %s", svc, result)
            else:
                events.extend(result)

        logger.debug("AzureCollector collected %d events", len(events))
        return events

    async def _collect_activity_log(self) -> list[dict]:
        """Azure ARM Activity Log — filter to high-value operations."""
        raw = [
            {
                "id":            "/subscriptions/xxx/resourceGroups/rg-prod/providers/...",
                "operationName": {"value": "Microsoft.Authorization/roleAssignments/write"},
                "caller":        "user@corp.com",
                "resourceId":    "/subscriptions/xxx/resourceGroups/rg-prod",
                "status":        {"value": "Succeeded"},
                "eventTimestamp": time.time(),
                "properties": {"clientIpAddress": "198.51.100.22"},
            }
        ]
        normalized = []
        for e in raw:
            op = e.get("operationName", {}).get("value", "")
            if op not in AZURE_HIGH_VALUE_OPERATIONS:
                continue
            normalized.append({
                "source":       "azure",
                "service":      "activity_log",
                "event_id":     e.get("id", ""),
                "action":       op,
                "actor":        e.get("caller", ""),
                "resource":     e.get("resourceId", ""),
                "status":       e.get("status", {}).get("value"),
                "ip":           e.get("properties", {}).get("clientIpAddress"),
                "subscription": self.subscription_id,
                "tenant":       self.tenant_id,
                "timestamp":    e.get("eventTimestamp", time.time()),
            })
        return normalized

    async def _collect_entra_id(self) -> list[dict]:
        """Microsoft Entra ID sign-in and audit logs."""
        return [
            {
                "source":    "azure",
                "service":   "entra_id",
                "event_id":  "entra-001",
                "action":    "SignIn",
                "actor":     "user@corp.com",
                "ip":        "198.51.100.22",
                "risk_level": "high",
                "mfa_used":  False,
                "tenant":    self.tenant_id,
                "timestamp": time.time(),
            }
        ]

    async def _collect_defender(self) -> list[dict]:
        """Microsoft Defender for Cloud security alerts."""
        return [
            {
                "source":      "azure",
                "service":     "defender",
                "event_id":    "mdc-alert-001",
                "action":      "DefenderAlert",
                "alert_type":  "VM_SuspiciousActivity",
                "severity":    "high",
                "resource":    "/subscriptions/xxx/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-prod",
                "tenant":      self.tenant_id,
                "timestamp":   time.time(),
            }
        ]

    async def _collect_keyvault(self) -> list[dict]:
        """Azure Key Vault audit logs — secret and key access."""
        return [
            {
                "source":    "azure",
                "service":   "keyvault",
                "event_id":  "kv-001",
                "action":    "SecretGet",
                "actor":     "svc-principal-prod",
                "resource":  "/subscriptions/xxx/.../vaults/prod-vault/secrets/db-password",
                "result":    "Success",
                "ip":        "10.0.1.5",
                "tenant":    self.tenant_id,
                "timestamp": time.time(),
            }
        ]