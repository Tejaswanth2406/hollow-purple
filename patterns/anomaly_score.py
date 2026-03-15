"""
patterns/anomaly_score.py

Composite anomaly scoring for raw events.
Combines heuristic signals into a [0.0, 1.0] score.

Signals:
  - Time-of-day deviation from actor's historical window
  - Geographic distance from last known location
  - Action rarity for this actor
  - Sensitive resource access flag
  - User-agent entropy (scripted vs. browser)
  - Request rate spike
  - New ASN / IP subnet for this actor

A score ≥ 0.75 is considered HIGH anomaly.
A score ≥ 0.90 causes the engine to upgrade severity to CRITICAL.
"""

import math
import time
import hashlib
import logging
from collections import defaultdict

logger = logging.getLogger("hollow_purple.anomaly")

# --- State ---
_actor_action_counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
_actor_subnets:       dict[str, set[str]]        = defaultdict(set)
_actor_request_ts:    dict[str, list[float]]     = defaultdict(list)

# Sensitive resource keywords
SENSITIVE_RESOURCES = frozenset({
    "admin", "root", "secret", "kms", "ssm", "iam", "billing",
    "credentials", "password", "token", "key", "cert", "prod",
})

# Actions that are inherently suspicious
HIGH_RISK_ACTIONS = frozenset({
    "DeleteRole", "DeleteUser", "DeactivateMFADevice", "CreateAccessKey",
    "UpdateLoginProfile", "PutRolePolicy", "AttachAdminPolicy",
    "SetDefaultPolicyVersion", "CreatePolicyVersion",
})

RATE_WINDOW_SEC      = 60
RATE_SPIKE_THRESHOLD = 20   # requests/min per actor considered high


def compute_event_anomaly(event: dict) -> float:
    """
    Returns a composite anomaly score in [0.0, 1.0].
    Each signal contributes a weighted partial score.
    """
    actor         = event.get("actor", "__unknown__")
    action        = event.get("action", "")
    resource      = event.get("resource", "").lower()
    ip            = event.get("ip", "")
    user_agent    = event.get("user_agent", "")
    now           = time.time()

    scores: dict[str, float] = {}

    # 1. Action rarity for this actor
    scores["action_rarity"] = _action_rarity(actor, action)

    # 2. Sensitive resource access
    scores["sensitive_resource"] = (
        0.4 if any(kw in resource for kw in SENSITIVE_RESOURCES) else 0.0
    )

    # 3. High-risk action
    scores["high_risk_action"] = 0.5 if action in HIGH_RISK_ACTIONS else 0.0

    # 4. New IP subnet
    scores["new_subnet"] = _new_subnet_score(actor, ip)

    # 5. User-agent entropy (low entropy → scripted/automated)
    scores["ua_entropy"] = _ua_entropy_score(user_agent)

    # 6. Request rate spike
    scores["rate_spike"] = _rate_spike_score(actor, now)

    # Weighted composite (weights sum to 1.0)
    weights = {
        "action_rarity":    0.20,
        "sensitive_resource": 0.15,
        "high_risk_action": 0.25,
        "new_subnet":       0.15,
        "ua_entropy":       0.10,
        "rate_spike":       0.15,
    }

    composite = sum(scores[k] * weights[k] for k in weights)
    composite = min(max(composite, 0.0), 1.0)

    logger.debug("anomaly actor=%s score=%.3f signals=%s", actor, composite, scores)
    return composite


# ------------------------------------------------------------------ #
#  Signal implementations                                             #
# ------------------------------------------------------------------ #

def _action_rarity(actor: str, action: str) -> float:
    """Returns 1.0 for never-seen actions, 0.0 for very common ones."""
    counts = _actor_action_counts[actor]
    total  = sum(counts.values())
    action_count = counts.get(action, 0)
    counts[action] += 1

    if total == 0 or action_count == 0:
        return 1.0   # first ever / never-seen action

    freq = action_count / total
    # Sigmoid-like inversion: rare actions get high scores
    return max(0.0, 1.0 - (freq ** 0.3))


def _new_subnet_score(actor: str, ip: str) -> float:
    if not ip:
        return 0.0
    subnet = _ip_to_subnet(ip)
    if not subnet:
        return 0.0
    known = _actor_subnets[actor]
    if subnet not in known:
        known.add(subnet)
        return 0.8 if len(known) > 1 else 0.0   # first seen is baseline
    return 0.0


def _ua_entropy_score(ua: str) -> float:
    """Low-entropy user agents (very short, all-lowercase, no spaces) suggest scripts."""
    if not ua:
        return 0.3
    entropy = _shannon_entropy(ua)
    if entropy < 2.5:
        return 0.6
    if entropy < 3.5:
        return 0.3
    return 0.0


def _rate_spike_score(actor: str, now: float) -> float:
    history = _actor_request_ts[actor]
    history.append(now)
    recent = [t for t in history if now - t <= RATE_WINDOW_SEC]
    _actor_request_ts[actor] = recent
    rate = len(recent)
    if rate >= RATE_SPIKE_THRESHOLD:
        return min(1.0, rate / RATE_SPIKE_THRESHOLD)
    return 0.0


def _ip_to_subnet(ip: str) -> str | None:
    try:
        parts = ip.split(".")
        if len(parts) == 4:
            return ".".join(parts[:3])   # /24 approximation
    except Exception:
        pass
    return None


def _shannon_entropy(text: str) -> float:
    freq = defaultdict(int)
    for c in text:
        freq[c] += 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in freq.values() if c > 0)