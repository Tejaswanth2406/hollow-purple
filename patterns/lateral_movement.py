"""
patterns/lateral_movement.py

Detects lateral movement across identities and roles.

Strategies:
  1. Role shared by too many distinct actors (role overcrowding)
  2. Actor hopping across multiple roles in a short time window (velocity)
  3. Actor accessing resources across multiple cloud accounts rapidly
  4. Pivot through service account / machine identity toward human-owned resources
  5. Unusual role assumption from a new geographic region
"""

import time
import logging
from collections import defaultdict

logger = logging.getLogger("hollow_purple.lateral")

# --- In-memory state (replace with Redis/DB in production) ---
_role_actors: dict[str, list[tuple[str, float]]]  = defaultdict(list)   # role -> [(actor, ts)]
_actor_roles: dict[str, list[tuple[str, float]]]  = defaultdict(list)   # actor -> [(role, ts)]
_actor_accounts: dict[str, list[tuple[str, float]]] = defaultdict(list) # actor -> [(account, ts)]
_actor_regions: dict[str, set[str]]               = defaultdict(set)

ROLE_CROWD_THRESHOLD   = 5    # distinct actors on same role → suspicious
VELOCITY_THRESHOLD     = 4    # distinct roles per actor in window → suspicious
ACCOUNT_HOP_THRESHOLD  = 3    # distinct accounts per actor in window → suspicious
VELOCITY_WINDOW_SEC    = 300  # 5-minute sliding window
SERVICE_ACCOUNT_PREFIXES = ("svc-", "sa-", "service-", "bot-", "automation-", "ci-")


def detect_lateral_movement(graph, event: dict) -> list[dict]:
    alerts = []
    action  = event.get("action", "")
    actor   = event.get("actor", "")
    role    = event.get("resource", "")
    account = event.get("account_id", "")
    region  = event.get("region", "")
    now     = time.time()

    if action != "AssumeRole":
        return alerts

    _record(actor, role, account, region, now)

    # --- 1. Role overcrowding ---
    recent_actors = _distinct_in_window(_role_actors[role], now)
    if len(recent_actors) > ROLE_CROWD_THRESHOLD:
        alerts.append({
            "type":     "lateral_movement",
            "subtype":  "role_overcrowding",
            "role":     role,
            "actor":    actor,
            "severity": "medium",
            "detail":   f"Role assumed by {len(recent_actors)} distinct identities "
                        f"within {VELOCITY_WINDOW_SEC}s",
            "actors":   list(recent_actors),
        })

    # --- 2. Role velocity (actor hopping roles) ---
    recent_roles = _distinct_in_window(_actor_roles[actor], now)
    if len(recent_roles) > VELOCITY_THRESHOLD:
        alerts.append({
            "type":     "lateral_movement",
            "subtype":  "role_velocity",
            "actor":    actor,
            "severity": "high",
            "detail":   f"Actor assumed {len(recent_roles)} distinct roles "
                        f"in {VELOCITY_WINDOW_SEC}s",
            "roles":    list(recent_roles),
        })

    # --- 3. Cross-account hopping ---
    if account:
        recent_accounts = _distinct_in_window(_actor_accounts[actor], now)
        if len(recent_accounts) > ACCOUNT_HOP_THRESHOLD:
            alerts.append({
                "type":     "lateral_movement",
                "subtype":  "cross_account_hop",
                "actor":    actor,
                "severity": "high",
                "detail":   f"Actor accessed {len(recent_accounts)} cloud accounts rapidly",
                "accounts": list(recent_accounts),
            })

    # --- 4. Service account pivoting to human resource ---
    if any(actor.startswith(p) for p in SERVICE_ACCOUNT_PREFIXES):
        if not any(role.startswith(p) for p in SERVICE_ACCOUNT_PREFIXES):
            alerts.append({
                "type":     "lateral_movement",
                "subtype":  "service_account_pivot",
                "actor":    actor,
                "role":     role,
                "severity": "high",
                "detail":   "Service account assumed a human-owned or non-service role",
            })

    # --- 5. New region for actor ---
    known_regions = _actor_regions[actor]
    if region and region not in known_regions and len(known_regions) > 0:
        alerts.append({
            "type":     "lateral_movement",
            "subtype":  "new_region_activity",
            "actor":    actor,
            "region":   region,
            "severity": "medium",
            "detail":   f"Actor active in new region '{region}'; "
                        f"previously seen in {sorted(known_regions)}",
        })
    if region:
        _actor_regions[actor].add(region)

    return alerts


# ------------------------------------------------------------------ #
#  Helpers                                                            #
# ------------------------------------------------------------------ #

def _record(actor, role, account, region, now):
    _role_actors[role].append((actor, now))
    _actor_roles[actor].append((role, now))
    if account:
        _actor_accounts[actor].append((account, now))


def _distinct_in_window(entries: list[tuple[str, float]], now: float) -> set[str]:
    return {val for val, ts in entries if now - ts <= VELOCITY_WINDOW_SEC}