"""
patterns/dormant_identity.py

Detects compromised or reactivated dormant identities.

Strategies:
  1. Classic dormancy: account inactive 30+ days suddenly acts
  2. Off-hours activity: action at unusual time for this identity
  3. First-ever high-privilege action by an identity
  4. Resurrection of a soft-deleted / disabled identity
  5. Action scope explosion: identity suddenly hits far more resource types than baseline
"""

import time
import math
import logging
from collections import defaultdict

logger = logging.getLogger("hollow_purple.dormant")

# --- State ---
_last_seen:          dict[str, float]        = {}        # actor -> last_active_ts
_actor_hour_profile: dict[str, list[int]]    = defaultdict(list)   # actor -> [hour_of_day, ...]
_actor_resource_types: dict[str, set[str]]   = defaultdict(set)
_disabled_actors:    set[str]                = set()
_actor_first_seen:   dict[str, float]        = {}

DORMANCY_THRESHOLD_DAYS   = 30
OFF_HOURS_PROFILE_MIN     = 20      # need at least N samples before flagging off-hours
OFF_HOURS_DEVIATION       = 3.0     # z-score threshold for off-hours detection
SCOPE_EXPLOSION_RATIO     = 3.0     # new resource types > 3× baseline triggers alert

HIGH_PRIV_ACTIONS = {
    "AssumeRole", "CreateRole", "AttachRolePolicy", "PutRolePolicy",
    "CreateUser", "DeleteUser", "CreateAccessKey", "UpdateLoginProfile",
    "CreatePolicyVersion", "AddUserToGroup", "RemoveUserFromGroup",
}


def mark_disabled(actor: str):
    """Call this when an identity is soft-deleted or disabled in IAM."""
    _disabled_actors.add(actor)


def mark_enabled(actor: str):
    _disabled_actors.discard(actor)


def detect_dormant_identity(event: dict) -> list[dict]:
    alerts = []
    actor         = event.get("actor", "")
    action        = event.get("action", "")
    resource_type = event.get("resource_type", "")
    now           = time.time()
    hour          = _utc_hour(now)

    if not actor:
        return alerts

    # Ensure first-seen tracking
    if actor not in _actor_first_seen:
        _actor_first_seen[actor] = now

    # --- 1. Dormancy reactivation ---
    if actor in _last_seen:
        inactivity_sec = now - _last_seen[actor]
        inactivity_days = inactivity_sec / 86400
        if inactivity_days >= DORMANCY_THRESHOLD_DAYS:
            severity = "critical" if inactivity_days > 90 else "high"
            alerts.append({
                "type":           "dormant_identity",
                "subtype":        "dormancy_reactivation",
                "actor":          actor,
                "inactive_days":  round(inactivity_days, 1),
                "severity":       severity,
                "detail":         f"Identity inactive for {inactivity_days:.0f} days "
                                  f"suddenly performed action '{action}'",
            })

    _last_seen[actor] = now

    # --- 2. Off-hours activity ---
    profile = _actor_hour_profile[actor]
    if len(profile) >= OFF_HOURS_PROFILE_MIN:
        mean, std = _mean_std(profile)
        if std > 0:
            z = abs(hour - mean) / std
            if z > OFF_HOURS_DEVIATION:
                alerts.append({
                    "type":     "dormant_identity",
                    "subtype":  "off_hours_activity",
                    "actor":    actor,
                    "hour_utc": hour,
                    "z_score":  round(z, 2),
                    "severity": "medium",
                    "detail":   f"Action at unusual hour {hour}:00 UTC "
                                f"(z={z:.1f}, typical={mean:.1f}±{std:.1f})",
                })
    profile.append(hour)
    if len(profile) > 1000:
        _actor_hour_profile[actor] = profile[-500:]

    # --- 3. First-ever high-privilege action ---
    time_since_first = now - _actor_first_seen[actor]
    if time_since_first > 86400 and action in HIGH_PRIV_ACTIONS:
        if actor not in _actor_resource_types or len(_actor_resource_types[actor]) == 0:
            alerts.append({
                "type":     "dormant_identity",
                "subtype":  "first_high_priv_action",
                "actor":    actor,
                "action":   action,
                "severity": "high",
                "detail":   f"Identity performed first-ever high-privilege action '{action}' "
                            f"after {time_since_first/86400:.1f} days of existence",
            })

    # --- 4. Disabled identity acting ---
    if actor in _disabled_actors:
        alerts.append({
            "type":     "dormant_identity",
            "subtype":  "disabled_identity_active",
            "actor":    actor,
            "action":   action,
            "severity": "critical",
            "detail":   "A disabled or soft-deleted identity performed an action",
        })

    # --- 5. Scope explosion ---
    if resource_type:
        baseline_count = len(_actor_resource_types[actor])
        _actor_resource_types[actor].add(resource_type)
        new_count = len(_actor_resource_types[actor])
        if baseline_count > 3 and new_count > baseline_count * SCOPE_EXPLOSION_RATIO:
            alerts.append({
                "type":          "dormant_identity",
                "subtype":       "scope_explosion",
                "actor":         actor,
                "baseline_types": baseline_count,
                "new_count":     new_count,
                "severity":      "high",
                "detail":        f"Identity resource-type scope grew {baseline_count}→{new_count} "
                                 f"(ratio={new_count/baseline_count:.1f}×)",
            })

    return alerts


# ------------------------------------------------------------------ #
#  Helpers                                                            #
# ------------------------------------------------------------------ #

def _utc_hour(ts: float) -> int:
    import datetime
    return datetime.datetime.utcfromtimestamp(ts).hour


def _mean_std(values: list[float]) -> tuple[float, float]:
    n = len(values)
    mean = sum(values) / n
    variance = sum((x - mean) ** 2 for x in values) / n
    return mean, math.sqrt(variance)