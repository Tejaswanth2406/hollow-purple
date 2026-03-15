"""
projections/identity_projection.py
====================================
Enterprise security identity intelligence projection.

Responsibilities
----------------
- Build behavioral fingerprints for every observed identity
- Track resource access patterns, action diversity, and temporal behavior
- Detect anomalous identity behavior using statistical baselines
- Compute privilege footprint (resource × action coverage)
- Generate peer-group baselines for role-based anomaly detection
- Emit anomaly flags with structured evidence for SIEM/SOAR integration
- Support incremental update (event stream) and full rebuild modes

Identity intelligence drives
----------------------------
- Insider threat detection
- Credential misuse detection
- Privilege escalation early warning
- Lateral movement attribution
"""

from __future__ import annotations

import logging
import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Anomaly flag types
# ---------------------------------------------------------------------------


class IdentityAnomalyFlag(str, Enum):
    UNUSUAL_RESOURCE_ACCESS = "unusual_resource_access"
    HIGH_ACTION_DIVERSITY    = "high_action_diversity"
    FIRST_TIME_RESOURCE      = "first_time_resource"
    PRIVILEGE_ESCALATION     = "privilege_escalation"
    VELOCITY_SPIKE           = "velocity_spike"          # abnormal event rate
    OFF_HOURS_ACTIVITY       = "off_hours_activity"
    PEER_DEVIATION           = "peer_deviation"          # diverges from role group


# ---------------------------------------------------------------------------
# Identity profile
# ---------------------------------------------------------------------------


@dataclass
class IdentityProfile:
    """
    Behavioral fingerprint for a single identity.

    Fields
    ------
    identity        : Unique identity identifier (user, service account, etc.)
    event_count     : Total observed events.
    resources       : All resources accessed (set).
    actions         : All action types observed (set).
    resource_freq   : {resource: count} access frequency map.
    action_freq     : {action_type: count} action frequency map.
    first_seen      : UTC ISO-8601 timestamp of first observed event.
    last_seen       : UTC ISO-8601 timestamp of most recent event.
    anomaly_flags   : List of detected anomaly flags with evidence.
    risk_score      : Computed risk score (set by RiskProjection).
    role_group      : Inferred peer group for comparative analysis.
    """

    identity: str
    event_count: int = 0
    resources: Set[str] = field(default_factory=set)
    actions: Set[str] = field(default_factory=set)
    resource_freq: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    action_freq: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    anomaly_flags: List[Dict[str, Any]] = field(default_factory=list)
    risk_score: float = 0.0
    role_group: Optional[str] = None

    # Hourly bucket activity for velocity analysis: {hour_bucket: count}
    hourly_activity: Dict[str, int] = field(default_factory=lambda: defaultdict(int))

    def record(self, event: Dict[str, Any]) -> None:
        """Ingest a single raw event into this profile."""
        self.event_count += 1

        resource = event.get("resource")
        action = event.get("event_type") or event.get("action")
        ts = event.get("timestamp") or event.get("recorded_at")

        if resource:
            self.resources.add(resource)
            self.resource_freq[resource] += 1

        if action:
            self.actions.add(action)
            self.action_freq[action] += 1

        now_iso = ts or datetime.now(timezone.utc).isoformat()
        if self.first_seen is None:
            self.first_seen = now_iso
        self.last_seen = now_iso

        # Hourly bucket for velocity analysis (truncate to hour)
        hour_bucket = now_iso[:13]  # "2026-01-15T09"
        self.hourly_activity[hour_bucket] += 1

    def privilege_footprint(self) -> float:
        """
        Privilege footprint score: product of unique resource count
        and unique action count, normalized by log to dampen outliers.
        Higher = broader access profile = higher inherent risk.
        """
        r = len(self.resources)
        a = len(self.actions)
        if r == 0 or a == 0:
            return 0.0
        return round(math.log1p(r) * math.log1p(a), 4)

    def activity_entropy(self) -> float:
        """
        Shannon entropy of the resource access distribution.
        High entropy = accesses many resources evenly (suspicious).
        Low entropy = concentrated on a few resources (normal).
        """
        total = sum(self.resource_freq.values())
        if total == 0:
            return 0.0
        entropy = 0.0
        for count in self.resource_freq.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    def peak_velocity(self) -> int:
        """Maximum events in any single hour bucket."""
        if not self.hourly_activity:
            return 0
        return max(self.hourly_activity.values())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "identity": self.identity,
            "event_count": self.event_count,
            "resource_count": len(self.resources),
            "action_count": len(self.actions),
            "resource_freq": dict(self.resource_freq),
            "action_freq": dict(self.action_freq),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "anomaly_flags": self.anomaly_flags,
            "risk_score": self.risk_score,
            "role_group": self.role_group,
            "privilege_footprint": self.privilege_footprint(),
            "activity_entropy": self.activity_entropy(),
            "peak_velocity": self.peak_velocity(),
        }


# ---------------------------------------------------------------------------
# IdentityProjection
# ---------------------------------------------------------------------------


class IdentityProjection:
    """
    Security identity behavioral intelligence projection.

    Builds fingerprints for every identity observed in the event stream,
    detects anomalies, and provides peer-group comparison.

    Usage
    -----
    ::

        projection = IdentityProjection(
            velocity_threshold=100,
            resource_diversity_threshold=20,
        )

        # Full build from event list
        projection.build(events)

        # Or incremental update
        projection.ingest_event(event)

        # Retrieve profile
        profile = projection.get_profile("user-alice")

        # All anomalous identities
        flagged = projection.anomalous_identities()
    """

    def __init__(
        self,
        *,
        velocity_threshold: int = 200,
        resource_diversity_threshold: int = 30,
        action_diversity_threshold: int = 15,
        entropy_threshold: float = 3.5,
        privileged_actions: Optional[Set[str]] = None,
    ) -> None:
        self._velocity_threshold = velocity_threshold
        self._resource_diversity_threshold = resource_diversity_threshold
        self._action_diversity_threshold = action_diversity_threshold
        self._entropy_threshold = entropy_threshold
        self._privileged_actions: Set[str] = privileged_actions or {
            "privilege_escalation",
            "sudo",
            "assume_role",
            "admin_login",
            "root_exec",
            "iam_modify",
            "policy_change",
            "secret_access",
        }

        self._profiles: Dict[str, IdentityProfile] = {}

        # Role group registry: role_group -> set of identities
        self._role_groups: Dict[str, Set[str]] = defaultdict(set)

        logger.info(
            "IdentityProjection initialised",
            extra={
                "velocity_threshold": velocity_threshold,
                "resource_diversity_threshold": resource_diversity_threshold,
            },
        )

    # ---------------------------------------------------------------------------
    # Build / ingest
    # ---------------------------------------------------------------------------

    def build(self, events: List[Dict[str, Any]]) -> Dict[str, IdentityProfile]:
        """
        Full projection build from a list of raw event dicts.
        Clears any existing projection state.
        """
        self._profiles.clear()
        self._role_groups.clear()

        for event in events:
            self.ingest_event(event)

        self._run_anomaly_detection()
        self._run_peer_group_analysis()

        logger.info(
            "IdentityProjection built",
            extra={
                "identities": len(self._profiles),
                "flagged": len(self.anomalous_identities()),
            },
        )
        return self._profiles

    def ingest_event(self, event: Dict[str, Any]) -> IdentityProfile:
        """
        Incrementally ingest a single event into the projection.
        Does NOT rerun anomaly detection — call ``refresh_anomalies()``
        after a batch of ingestions.
        """
        identity = (
            event.get("identity")
            or event.get("user_id")
            or event.get("principal")
            or "unknown"
        )

        if identity not in self._profiles:
            self._profiles[identity] = IdentityProfile(identity=identity)

        profile = self._profiles[identity]
        profile.record(event)

        # Assign role group if provided
        role = event.get("role") or event.get("role_group")
        if role:
            profile.role_group = role
            self._role_groups[role].add(identity)

        return profile

    # ---------------------------------------------------------------------------
    # Anomaly detection
    # ---------------------------------------------------------------------------

    def _run_anomaly_detection(self) -> None:
        """Run all anomaly detectors over the current profiles."""
        for profile in self._profiles.values():
            profile.anomaly_flags.clear()
            self._detect_velocity_spike(profile)
            self._detect_resource_diversity(profile)
            self._detect_action_diversity(profile)
            self._detect_privileged_actions(profile)
            self._detect_high_entropy(profile)

    def refresh_anomalies(self) -> None:
        """Re-run anomaly detection + peer analysis after incremental ingestion."""
        self._run_anomaly_detection()
        self._run_peer_group_analysis()

    def _flag(
        self,
        profile: IdentityProfile,
        flag: IdentityAnomalyFlag,
        evidence: Dict[str, Any],
    ) -> None:
        profile.anomaly_flags.append(
            {
                "flag": flag.value,
                "evidence": evidence,
                "detected_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        logger.warning(
            "Identity anomaly detected",
            extra={
                "identity": profile.identity,
                "flag": flag.value,
                "evidence": evidence,
            },
        )

    def _detect_velocity_spike(self, profile: IdentityProfile) -> None:
        peak = profile.peak_velocity()
        if peak > self._velocity_threshold:
            self._flag(
                profile,
                IdentityAnomalyFlag.VELOCITY_SPIKE,
                {"peak_events_per_hour": peak, "threshold": self._velocity_threshold},
            )

    def _detect_resource_diversity(self, profile: IdentityProfile) -> None:
        n = len(profile.resources)
        if n > self._resource_diversity_threshold:
            self._flag(
                profile,
                IdentityAnomalyFlag.UNUSUAL_RESOURCE_ACCESS,
                {"unique_resources": n, "threshold": self._resource_diversity_threshold},
            )

    def _detect_action_diversity(self, profile: IdentityProfile) -> None:
        n = len(profile.actions)
        if n > self._action_diversity_threshold:
            self._flag(
                profile,
                IdentityAnomalyFlag.HIGH_ACTION_DIVERSITY,
                {"unique_actions": n, "threshold": self._action_diversity_threshold},
            )

    def _detect_privileged_actions(self, profile: IdentityProfile) -> None:
        seen_privileged = profile.actions & self._privileged_actions
        if seen_privileged:
            self._flag(
                profile,
                IdentityAnomalyFlag.PRIVILEGE_ESCALATION,
                {"privileged_actions": sorted(seen_privileged)},
            )

    def _detect_high_entropy(self, profile: IdentityProfile) -> None:
        entropy = profile.activity_entropy()
        if entropy > self._entropy_threshold:
            self._flag(
                profile,
                IdentityAnomalyFlag.UNUSUAL_RESOURCE_ACCESS,
                {"activity_entropy": entropy, "threshold": self._entropy_threshold},
            )

    # ---------------------------------------------------------------------------
    # Peer group analysis
    # ---------------------------------------------------------------------------

    def _run_peer_group_analysis(self) -> None:
        """
        Compare each identity to its role-group peers.
        Identities that deviate significantly from their peer baseline
        receive a PEER_DEVIATION flag.
        """
        for role, members in self._role_groups.items():
            if len(members) < 3:
                continue  # Need a meaningful peer group

            profiles = [self._profiles[m] for m in members if m in self._profiles]
            if not profiles:
                continue

            # Compute peer baseline: mean event count and resource count
            avg_events = sum(p.event_count for p in profiles) / len(profiles)
            avg_resources = sum(len(p.resources) for p in profiles) / len(profiles)

            stddev_events = math.sqrt(
                sum((p.event_count - avg_events) ** 2 for p in profiles) / len(profiles)
            ) or 1.0
            stddev_resources = math.sqrt(
                sum((len(p.resources) - avg_resources) ** 2 for p in profiles) / len(profiles)
            ) or 1.0

            for profile in profiles:
                z_events = abs(profile.event_count - avg_events) / stddev_events
                z_resources = abs(len(profile.resources) - avg_resources) / stddev_resources

                if z_events > 3.0 or z_resources > 3.0:
                    self._flag(
                        profile,
                        IdentityAnomalyFlag.PEER_DEVIATION,
                        {
                            "role_group": role,
                            "z_events": round(z_events, 2),
                            "z_resources": round(z_resources, 2),
                            "peer_avg_events": round(avg_events, 1),
                            "peer_avg_resources": round(avg_resources, 1),
                        },
                    )

    # ---------------------------------------------------------------------------
    # Query API
    # ---------------------------------------------------------------------------

    def get_profile(self, identity: str) -> Optional[IdentityProfile]:
        return self._profiles.get(identity)

    def all_profiles(self) -> Dict[str, IdentityProfile]:
        return dict(self._profiles)

    def anomalous_identities(self) -> List[IdentityProfile]:
        """Return all profiles with at least one anomaly flag."""
        return [p for p in self._profiles.values() if p.anomaly_flags]

    def top_by_event_count(self, n: int = 10) -> List[IdentityProfile]:
        return sorted(self._profiles.values(), key=lambda p: p.event_count, reverse=True)[:n]

    def top_by_resource_access(self, n: int = 10) -> List[IdentityProfile]:
        return sorted(
            self._profiles.values(),
            key=lambda p: len(p.resources),
            reverse=True,
        )[:n]

    def profiles_by_role(self, role_group: str) -> List[IdentityProfile]:
        members = self._role_groups.get(role_group, set())
        return [self._profiles[m] for m in members if m in self._profiles]

    def summary(self) -> Dict[str, Any]:
        total = len(self._profiles)
        flagged = len(self.anomalous_identities())
        return {
            "total_identities": total,
            "anomalous_identities": flagged,
            "anomaly_rate": round(flagged / total, 4) if total else 0.0,
            "role_groups": len(self._role_groups),
            "total_events": sum(p.event_count for p in self._profiles.values()),
        }