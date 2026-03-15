import math
import time
from collections import Counter
from typing import Any


# Actions considered high-privilege — contribute to privilege pressure score
HIGH_PRIV_ACTIONS = {
    "AssumeRole", "AttachPolicy", "CreateAccessKey",
    "PassRole", "UpdateAssumeRolePolicy", "AddUserToGroup",
    "SetSecurityToken", "PutRolePolicy", "CreateRole",
    "DeleteRolePolicy", "UpdateRole",
}

SENSITIVE_RESOURCE_PREFIXES = ("arn:aws:iam", "arn:aws:kms", "arn:aws:secretsmanager")


class FeatureExtractor:
    """
    Converts a list of raw events for a single identity
    into a rich, normalized feature vector used for baseline
    construction and drift detection.

    Features extracted:
    - Action frequency distribution (Counter + entropy)
    - Resource frequency distribution
    - Unique resource and IP count
    - High-privilege action ratio
    - Sensitive resource access ratio
    - Temporal activity distribution (hour buckets)
    - Session count and mean session duration
    - Error rate (failed API calls)
    - Velocity: events per minute in most recent window
    """

    def extract(self, events: list[dict]) -> dict[str, Any]:
        if not events:
            return self._empty()

        actions   = [e.get("action", "")   for e in events]
        resources = [e.get("resource", "") for e in events]
        ips       = [e.get("source_ip", "unknown") for e in events]
        statuses  = [e.get("status", "success") for e in events]
        timestamps = sorted(
            e.get("timestamp", 0.0) for e in events if e.get("timestamp")
        )

        action_freq   = Counter(actions)
        resource_freq = Counter(resources)

        total = len(events)
        priv_count = sum(1 for a in actions if a in HIGH_PRIV_ACTIONS)
        sens_count = sum(
            1 for r in resources
            if any(r.startswith(p) for p in SENSITIVE_RESOURCE_PREFIXES)
        )
        error_count = sum(1 for s in statuses if s in ("error", "denied", "failed"))

        hour_buckets = Counter(
            int((e.get("timestamp", 0) % 86400) // 3600)
            for e in events
            if e.get("timestamp")
        )

        sessions = self._extract_sessions(events)

        velocity = self._compute_velocity(timestamps, window=300)

        return {
            "action_freq":           dict(action_freq),
            "resource_freq":         dict(resource_freq),
            "unique_resources":      len(set(resources)),
            "unique_ips":            len(set(ips)),
            "total_events":          total,
            "high_priv_ratio":       round(priv_count / total, 4),
            "sensitive_res_ratio":   round(sens_count / total, 4),
            "error_rate":            round(error_count / total, 4),
            "action_entropy":        round(self._entropy(action_freq, total), 4),
            "resource_entropy":      round(self._entropy(resource_freq, total), 4),
            "hour_distribution":     dict(hour_buckets),
            "session_count":         len(sessions),
            "mean_session_duration": round(self._mean_session_duration(sessions), 2),
            "velocity_per_min":      round(velocity, 4),
            "top_actions":           [a for a, _ in action_freq.most_common(5)],
        }

    # ── Helpers ────────────────────────────────────────────────────────────

    @staticmethod
    def _entropy(freq: Counter, total: int) -> float:
        if total == 0:
            return 0.0
        h = 0.0
        for count in freq.values():
            p = count / total
            if p > 0:
                h -= p * math.log2(p)
        return h

    @staticmethod
    def _extract_sessions(events: list[dict], gap: float = 1800) -> list[list[dict]]:
        """Groups events into sessions separated by `gap` seconds of inactivity."""
        if not events:
            return []
        ordered = sorted(events, key=lambda e: e.get("timestamp", 0))
        sessions: list[list[dict]] = [[ordered[0]]]
        for evt in ordered[1:]:
            last_ts = sessions[-1][-1].get("timestamp", 0)
            cur_ts  = evt.get("timestamp", 0)
            if cur_ts - last_ts <= gap:
                sessions[-1].append(evt)
            else:
                sessions.append([evt])
        return sessions

    @staticmethod
    def _mean_session_duration(sessions: list[list[dict]]) -> float:
        if not sessions:
            return 0.0
        durations = []
        for s in sessions:
            ts = [e.get("timestamp", 0) for e in s if e.get("timestamp")]
            if len(ts) >= 2:
                durations.append(max(ts) - min(ts))
        return sum(durations) / len(durations) if durations else 0.0

    @staticmethod
    def _compute_velocity(timestamps: list[float], window: float = 300) -> float:
        if not timestamps:
            return 0.0
        now    = timestamps[-1]
        cutoff = now - window
        recent = sum(1 for t in timestamps if t >= cutoff)
        return recent / (window / 60)

    @staticmethod
    def _empty() -> dict:
        return {
            "action_freq": {}, "resource_freq": {}, "unique_resources": 0,
            "unique_ips": 0, "total_events": 0, "high_priv_ratio": 0.0,
            "sensitive_res_ratio": 0.0, "error_rate": 0.0, "action_entropy": 0.0,
            "resource_entropy": 0.0, "hour_distribution": {}, "session_count": 0,
            "mean_session_duration": 0.0, "velocity_per_min": 0.0, "top_actions": [],
        }