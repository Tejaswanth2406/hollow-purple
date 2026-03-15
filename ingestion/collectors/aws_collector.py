"""
ingestion/collectors/aws_collector.py — AWS Multi-Service Event Collector

Collects from:
  - CloudTrail (management + data events)
  - CloudWatch Logs (custom log groups)
  - GuardDuty findings
  - Security Hub aggregated findings
  - IAM Access Analyzer findings
  - S3 server access logs

Production integration points are stubbed with realistic structure.
Replace boto3 calls with actual SDK usage in deployment.
"""

import asyncio
import logging
import time
from typing import Any

logger = logging.getLogger("hollow_purple.collector.aws")

# Service identifiers
SERVICES = ("cloudtrail", "guardduty", "securityhub", "iam_analyzer", "cloudwatch")

# CloudTrail management event actions of interest
CLOUDTRAIL_HIGH_VALUE_ACTIONS = frozenset({
    "AssumeRole", "AssumeRoleWithWebIdentity", "AssumeRoleWithSAML",
    "CreateRole", "DeleteRole", "AttachRolePolicy", "DetachRolePolicy",
    "PutRolePolicy", "DeleteRolePolicy", "CreateUser", "DeleteUser",
    "CreateAccessKey", "DeleteAccessKey", "UpdateAccessKey",
    "CreateLoginProfile", "UpdateLoginProfile", "DeactivateMFADevice",
    "ConsoleLogin", "SwitchRole", "GetSessionToken",
    "CreatePolicyVersion", "SetDefaultPolicyVersion",
    "PassRole", "UpdateAssumeRolePolicy",
})


class AWSCollector:
    """
    Async AWS multi-service event collector.

    In production this wraps aiobotocore / boto3 sessions.
    Each service sub-collector runs concurrently.
    """

    def __init__(
        self,
        region: str = "us-east-1",
        account_id: str = "",
        services: tuple = SERVICES,
        cloudtrail_lookback_minutes: int = 5,
    ):
        self.region                      = region
        self.account_id                  = account_id
        self.services                    = services
        self.cloudtrail_lookback_minutes = cloudtrail_lookback_minutes
        self._last_cloudtrail_token: str | None = None

        logger.info("AWSCollector ready (region=%s, account=%s, services=%s)",
                    region, account_id, services)

    async def collect(self) -> list[dict]:
        """
        Collect events from all enabled AWS services concurrently.
        Returns a unified list of normalized raw events.
        """
        tasks = []
        if "cloudtrail"   in self.services: tasks.append(self._collect_cloudtrail())
        if "guardduty"    in self.services: tasks.append(self._collect_guardduty())
        if "securityhub"  in self.services: tasks.append(self._collect_securityhub())
        if "iam_analyzer" in self.services: tasks.append(self._collect_iam_analyzer())
        if "cloudwatch"   in self.services: tasks.append(self._collect_cloudwatch())

        results = await asyncio.gather(*tasks, return_exceptions=True)

        events: list[dict] = []
        for svc, result in zip(self.services, results):
            if isinstance(result, Exception):
                logger.error("AWS sub-collector '%s' failed: %s", svc, result)
            else:
                events.extend(result)

        logger.debug("AWSCollector collected %d events", len(events))
        return events

    # ------------------------------------------------------------------ #
    #  Sub-collectors                                                      #
    # ------------------------------------------------------------------ #

    async def _collect_cloudtrail(self) -> list[dict]:
        """
        Wraps CloudTrail LookupEvents API.
        Filters for high-value management events only.
        """
        # Production: use aiobotocore client.lookup_events(...)
        # Stub returns realistic event structure:
        raw_events = [
            {
                "EventId":        "evt-cloudtrail-001",
                "EventName":      "AssumeRole",
                "EventTime":      time.time(),
                "Username":       "svc-deploy-pipeline",
                "Resources": [{"ResourceType": "AWS::IAM::Role",
                               "ResourceName": "arn:aws:iam::123456789012:role/prod-admin"}],
                "CloudTrailEvent": '{"sourceIPAddress":"203.0.113.10","userAgent":"aws-cli/2.9"}',
                "awsRegion":      self.region,
            }
        ]

        normalized = []
        for e in raw_events:
            action = e.get("EventName", "")
            if action not in CLOUDTRAIL_HIGH_VALUE_ACTIONS:
                continue
            normalized.append({
                "source":       "aws",
                "service":      "cloudtrail",
                "event_id":     e.get("EventId"),
                "action":       action,
                "actor":        e.get("Username"),
                "resource":     (e.get("Resources") or [{}])[0].get("ResourceName", ""),
                "resource_type": (e.get("Resources") or [{}])[0].get("ResourceType", ""),
                "region":       e.get("awsRegion", self.region),
                "account_id":   self.account_id,
                "timestamp":    e.get("EventTime", time.time()),
                "raw":          e.get("CloudTrailEvent"),
            })
        return normalized

    async def _collect_guardduty(self) -> list[dict]:
        """GuardDuty findings → unified event format."""
        # Production: client.list_findings() + get_findings()
        return [
            {
                "source":    "aws",
                "service":   "guardduty",
                "event_id":  "gd-finding-001",
                "action":    "GuardDutyFinding",
                "actor":     "i-0abc123def456",
                "severity":  "high",
                "type":      "UnauthorizedAccess:IAMUser/MaliciousIPCaller",
                "region":    self.region,
                "account_id": self.account_id,
                "timestamp": time.time(),
            }
        ]

    async def _collect_securityhub(self) -> list[dict]:
        """Security Hub aggregated findings."""
        return [
            {
                "source":     "aws",
                "service":    "securityhub",
                "event_id":   "sh-finding-001",
                "action":     "SecurityHubFinding",
                "actor":      "arn:aws:iam::123456789012:user/suspicious-user",
                "severity":   "critical",
                "compliance": "FAILED",
                "region":     self.region,
                "account_id": self.account_id,
                "timestamp":  time.time(),
            }
        ]

    async def _collect_iam_analyzer(self) -> list[dict]:
        """IAM Access Analyzer external access findings."""
        return [
            {
                "source":        "aws",
                "service":       "iam_analyzer",
                "event_id":      "aa-finding-001",
                "action":        "ExternalAccess",
                "resource":      "arn:aws:s3:::sensitive-prod-bucket",
                "resource_type": "AWS::S3::Bucket",
                "principal":     "arn:aws:iam::999999999999:root",
                "region":        self.region,
                "account_id":    self.account_id,
                "timestamp":     time.time(),
            }
        ]

    async def _collect_cloudwatch(self) -> list[dict]:
        """CloudWatch Logs — custom security log groups."""
        return []   # Populated per-deployment based on configured log groups