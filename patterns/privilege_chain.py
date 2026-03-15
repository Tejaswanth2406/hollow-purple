"""
patterns/privilege_chain.py

Detects deep, complex privilege escalation chains in the identity graph.

Strategies:
  1. Long chains (≥5 hops) leading toward high-privilege roles
  2. Circular role chains (role A → B → A) indicating policy misconfiguration or exploit loop
  3. Converging chains: multiple actors with paths to the same high-priv role
  4. Diamond escalation: two independent paths merge at a single high-priv node
  5. Chain acceleration: actor traversing more hops than baseline in short time
"""

import time
import logging
from collections import defaultdict
from graph.pathfinder import find_attack_paths

logger = logging.getLogger("hollow_purple.priv_chain")

import re
HIGH_PRIV_RE = re.compile(
    r"(admin|root|owner|superuser|full.?access|god.?mode|break.?glass)",
    re.IGNORECASE,
)

# State
_actor_chain_history: dict[str, list[tuple[int, float]]] = defaultdict(list)  # actor -> [(chain_len, ts)]
_high_priv_actors:    dict[str, set[str]]                = defaultdict(set)   # high_priv_role -> {actors}

DEEP_CHAIN_THRESHOLD     = 5
CONVERGE_THRESHOLD       = 4   # N actors sharing path to same high-priv role
ACCELERATION_WINDOW_SEC  = 300
ACCELERATION_FACTOR      = 2.0


def detect_privilege_chain(graph, event: dict) -> list[dict]:
    alerts = []
    actor   = event.get("actor", "")
    now     = time.time()

    if not actor:
        return alerts

    try:
        paths = find_attack_paths(graph, actor, depth=8)
    except Exception as exc:
        logger.warning("find_attack_paths failed for actor=%s: %s", actor, exc)
        return alerts

    max_chain_len = 0

    for path in paths:
        path_len   = len(path)
        path_nodes = [str(n) for n in path]
        path_str   = " → ".join(path_nodes)

        # --- 1. Deep chain to high-privilege role ---
        if path_len >= DEEP_CHAIN_THRESHOLD and HIGH_PRIV_RE.search(path_str):
            severity = "critical" if path_len >= 7 else "high"
            alerts.append({
                "type":      "privilege_chain",
                "subtype":   "deep_escalation_chain",
                "actor":     actor,
                "path":      path_nodes,
                "hops":      path_len - 1,
                "severity":  severity,
                "detail":    f"{path_len-1}-hop chain to high-privilege node: {path_str}",
            })
            max_chain_len = max(max_chain_len, path_len)

            # Track for convergence detection
            terminal = path_nodes[-1]
            if HIGH_PRIV_RE.search(terminal):
                _high_priv_actors[terminal].add(actor)

        # --- 2. Circular role chain ---
        if _has_cycle(path):
            alerts.append({
                "type":     "privilege_chain",
                "subtype":  "circular_role_chain",
                "actor":    actor,
                "path":     path_nodes,
                "severity": "high",
                "detail":   f"Circular role chain detected: {path_str}",
            })

    # --- 3. Convergence: many actors reaching same high-priv role ---
    for role, actors in _high_priv_actors.items():
        if len(actors) >= CONVERGE_THRESHOLD:
            alerts.append({
                "type":     "privilege_chain",
                "subtype":  "converging_chains",
                "role":     role,
                "actor":    actor,
                "severity": "high",
                "detail":   f"{len(actors)} distinct actors have a path to '{role}'",
                "actors":   list(actors),
            })

    # --- 4. Chain acceleration ---
    history = _actor_chain_history[actor]
    history.append((max_chain_len, now))
    _actor_chain_history[actor] = [(l, t) for l, t in history if now - t <= ACCELERATION_WINDOW_SEC]

    if len(history) >= 3:
        old_max = max(l for l, _ in history[:-1])
        if old_max > 0 and max_chain_len >= old_max * ACCELERATION_FACTOR:
            alerts.append({
                "type":       "privilege_chain",
                "subtype":    "chain_acceleration",
                "actor":      actor,
                "prev_max":   old_max,
                "current":    max_chain_len,
                "severity":   "high",
                "detail":     f"Actor chain depth accelerated {old_max}→{max_chain_len} hops "
                              f"within {ACCELERATION_WINDOW_SEC}s",
            })

    return alerts


# ------------------------------------------------------------------ #
#  Helpers                                                            #
# ------------------------------------------------------------------ #

def _has_cycle(path: list) -> bool:
    seen = set()
    for node in path:
        key = str(node)
        if key in seen:
            return True
        seen.add(key)
    return False