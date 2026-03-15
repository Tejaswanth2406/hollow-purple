"""
graph_intelligence/lateral_movement_detector.py — Graph-Aware Lateral Movement Detector

Detects sophisticated lateral movement patterns in identity/resource graph.

Strategies:
  1. Hop-chain detection: actor traversing N systems via access edges
  2. Pivot detection: identity moving from low-value → high-value resources
  3. Cross-boundary movement: movement across account / VPC / namespace boundaries
  4. Service account abuse: human identity → service account → privileged resource
  5. Relay node detection: intermediate nodes used only for pivoting
  6. Speed-of-movement analysis: too many distinct nodes accessed in short window
  7. Graph centrality anomaly: actor accessing statistically unusual node combinations
"""

import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

logger = logging.getLogger("hollow_purple.lateral_movement_graph")

# Movement events
MOVEMENT_RELATIONS = frozenset({"access", "AssumeRole", "AssignRole", "SSH", "exec", "connect"})

# Thresholds
HOP_CHAIN_MIN_LENGTH  = 4    # min hops to consider a chain suspicious
PIVOT_WINDOW_SEC      = 600  # 10-minute window for speed analysis
SPEED_NODE_THRESHOLD  = 6    # distinct nodes within window
SERVICE_ACCT_SIGNALS  = ("svc-", "sa-", "service-", "bot-", ".iam.gserviceaccount")


@dataclass
class MovementAlert:
    subtype:   str
    actor:     str
    severity:  str
    detail:    str
    path:      list = field(default_factory=list)
    nodes:     list = field(default_factory=list)
    score:     float = 0.0

    def to_dict(self) -> dict:
        return {
            "type":     "lateral_movement",
            "subtype":  self.subtype,
            "actor":    self.actor,
            "severity": self.severity,
            "detail":   self.detail,
            "path":     self.path,
            "nodes":    self.nodes,
            "score":    round(self.score, 4),
        }


class LateralMovementDetector:
    """
    Graph-aware lateral movement detector.

    Usage:
        detector = LateralMovementDetector(graph_store)
        alerts = detector.detect(identity="user123")
        alerts = detector.detect_from_event(event)
    """

    def __init__(self, graph_store, high_value_nodes: set[str] | None = None):
        self.graph           = graph_store
        self.high_value_nodes = high_value_nodes or set()
        # Movement history: actor → [(node, ts), ...]
        self._movement_log: dict[str, deque] = defaultdict(lambda: deque(maxlen=200))

    # ------------------------------------------------------------------ #
    #  Primary detection entry points                                     #
    # ------------------------------------------------------------------ #

    def detect(self, identity: str, max_depth: int = 8) -> list[dict]:
        """Full graph traversal lateral movement analysis for an identity."""
        alerts: list[MovementAlert] = []

        movement_paths = self._trace_movement(identity, max_depth)

        # 1. Hop chain
        alerts += self._check_hop_chain(identity, movement_paths)

        # 2. Pivot to high-value
        alerts += self._check_pivot(identity, movement_paths)

        # 3. Service account abuse
        alerts += self._check_service_account_abuse(identity, movement_paths)

        # 4. Relay nodes (nodes only used for pivoting)
        alerts += self._check_relay_nodes(identity, movement_paths)

        # 5. Cross-account / cross-namespace
        alerts += self._check_boundary_crossing(identity, movement_paths)

        return [a.to_dict() for a in alerts]

    def detect_from_event(self, event: dict) -> list[dict]:
        """
        Lightweight real-time detection from a single event.
        Records movement history and checks speed/velocity.
        """
        actor    = event.get("actor", "")
        resource = event.get("resource", "")
        action   = event.get("action", "")
        ts       = event.get("timestamp", time.time())

        if not actor or action not in MOVEMENT_RELATIONS:
            return []

        self._movement_log[actor].append((resource, ts))
        return [a.to_dict() for a in self._check_speed(actor, ts)]

    # ------------------------------------------------------------------ #
    #  Detection strategies                                                #
    # ------------------------------------------------------------------ #

    def _trace_movement(self, identity: str, max_depth: int) -> list[tuple[str, str]]:
        """BFS traversal following access/movement edges from identity."""
        visited: set[str]      = set()
        paths:   list[tuple]   = []
        stack:   list[str]     = [identity]

        while stack:
            node = stack.pop()
            if node in visited:
                continue
            visited.add(node)
            for edge in self._safe_neighbors(node):
                rel = edge.get("relation", "")
                tgt = edge.get("target", "")
                if rel in MOVEMENT_RELATIONS and tgt and tgt not in visited:
                    paths.append((node, tgt))
                    stack.append(tgt)

        return paths

    def _check_hop_chain(self, actor: str, paths: list[tuple]) -> list[MovementAlert]:
        alerts = []
        # Build adjacency from movement paths
        adj: dict[str, list[str]] = defaultdict(list)
        for src, tgt in paths:
            adj[src].append(tgt)

        # DFS to find longest chains
        longest = self._longest_chain(actor, adj)
        if len(longest) >= HOP_CHAIN_MIN_LENGTH:
            score = min(1.0, len(longest) / 10)
            alerts.append(MovementAlert(
                subtype="hop_chain",
                actor=actor,
                severity="high" if len(longest) < 7 else "critical",
                detail=f"Identity traversed {len(longest)-1}-hop movement chain",
                path=longest,
                score=score,
            ))
        return alerts

    def _check_pivot(self, actor: str, paths: list[tuple]) -> list[MovementAlert]:
        alerts = []
        reachable = {tgt for _, tgt in paths}
        exposed_hv = reachable & self.high_value_nodes
        if exposed_hv:
            alerts.append(MovementAlert(
                subtype="high_value_pivot",
                actor=actor,
                severity="critical",
                detail=f"Identity can reach {len(exposed_hv)} high-value node(s) via movement",
                nodes=list(exposed_hv),
                score=0.9,
            ))
        # Also check for pattern: low-priv → medium → high
        low_to_high = [
            (src, tgt) for src, tgt in paths
            if not any(s in src.lower() for s in ("admin", "prod", "secret"))
            and any(s in tgt.lower() for s in ("admin", "prod", "secret", "root"))
        ]
        if low_to_high:
            alerts.append(MovementAlert(
                subtype="privilege_pivot",
                actor=actor,
                severity="high",
                detail=f"Movement from low-privilege to high-privilege resource detected ({len(low_to_high)} edges)",
                nodes=[t for _, t in low_to_high],
                score=0.75,
            ))
        return alerts

    def _check_service_account_abuse(self, actor: str, paths: list[tuple]) -> list[MovementAlert]:
        alerts = []
        if any(actor.startswith(sig) for sig in SERVICE_ACCT_SIGNALS):
            human_targets = [
                tgt for _, tgt in paths
                if not any(tgt.startswith(sig) for sig in SERVICE_ACCT_SIGNALS)
                and not any(s in tgt.lower() for s in ("svc", "service", "bot", "automation"))
            ]
            if human_targets:
                alerts.append(MovementAlert(
                    subtype="service_account_human_pivot",
                    actor=actor,
                    severity="high",
                    detail=f"Service account '{actor}' moving toward human-owned resources",
                    nodes=human_targets[:10],
                    score=0.8,
                ))
        return alerts

    def _check_relay_nodes(self, actor: str, paths: list[tuple]) -> list[MovementAlert]:
        """Detect nodes that only serve as pass-through hubs (in-degree ≥1 and out-degree ≥2)."""
        alerts = []
        in_deg:  dict[str, int] = defaultdict(int)
        out_deg: dict[str, int] = defaultdict(int)
        for src, tgt in paths:
            out_deg[src] += 1
            in_deg[tgt]  += 1

        relay_nodes = [
            n for n in set(in_deg) & set(out_deg)
            if in_deg[n] >= 1 and out_deg[n] >= 2
        ]
        if len(relay_nodes) >= 2:
            alerts.append(MovementAlert(
                subtype="relay_node_detected",
                actor=actor,
                severity="medium",
                detail=f"Detected {len(relay_nodes)} potential relay/pivot nodes in movement graph",
                nodes=relay_nodes,
                score=0.55,
            ))
        return alerts

    def _check_boundary_crossing(self, actor: str, paths: list[tuple]) -> list[MovementAlert]:
        """Detect movement across account / namespace boundaries."""
        alerts = []
        cross_boundary = [
            (src, tgt) for src, tgt in paths
            if self._different_boundary(src, tgt)
        ]
        if cross_boundary:
            alerts.append(MovementAlert(
                subtype="cross_boundary_movement",
                actor=actor,
                severity="high",
                detail=f"Movement detected across {len(cross_boundary)} account/namespace boundaries",
                nodes=[tgt for _, tgt in cross_boundary],
                score=0.8,
            ))
        return alerts

    def _check_speed(self, actor: str, now: float) -> list[MovementAlert]:
        """Velocity check: too many distinct nodes in short time window."""
        recent = [
            node for node, ts in self._movement_log[actor]
            if now - ts <= PIVOT_WINDOW_SEC
        ]
        distinct = len(set(recent))
        if distinct >= SPEED_NODE_THRESHOLD:
            return [MovementAlert(
                subtype="movement_velocity",
                actor=actor,
                severity="high",
                detail=f"Actor accessed {distinct} distinct nodes in {PIVOT_WINDOW_SEC}s",
                score=min(1.0, distinct / SPEED_NODE_THRESHOLD),
            )]
        return []

    # ------------------------------------------------------------------ #
    #  Helpers                                                             #
    # ------------------------------------------------------------------ #

    def _longest_chain(self, start: str, adj: dict[str, list[str]]) -> list[str]:
        """DFS to find the longest path from start."""
        best = [start]
        def dfs(node, path, visited):
            nonlocal best
            if len(path) > len(best):
                best = list(path)
            for nxt in adj.get(node, []):
                if nxt not in visited:
                    visited.add(nxt)
                    path.append(nxt)
                    dfs(nxt, path, visited)
                    path.pop()
                    visited.discard(nxt)
        dfs(start, [start], {start})
        return best

    def _different_boundary(self, node_a: str, node_b: str) -> bool:
        """Heuristic: check if two nodes are in different accounts/namespaces."""
        def extract_account(n: str) -> str:
            parts = n.split("::")
            return parts[1] if len(parts) >= 2 else ""
        return extract_account(node_a) != extract_account(node_b) and \
               extract_account(node_a) != "" and extract_account(node_b) != ""

    def _safe_neighbors(self, node: str) -> list[dict]:
        try:
            return self.graph.get_neighbors(node) or []
        except Exception as exc:
            logger.debug("get_neighbors('%s') failed: %s", node, exc)
            return []