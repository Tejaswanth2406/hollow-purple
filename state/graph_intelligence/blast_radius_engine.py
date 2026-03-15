"""
graph_intelligence/blast_radius_engine.py — Compromise Blast Radius Engine

Computes the full impact scope if a node is compromised.

Capabilities:
  1. Reachability analysis  — all transitively accessible nodes
  2. Risk-weighted blast score — aggregate risk of reachable nodes
  3. Crown jewel exposure   — are any critical assets reachable?
  4. Tiered blast radius    — nodes at depth 1, 2, 3... (concentric rings)
  5. Containment suggestions — minimum cut nodes to isolate the breach
  6. Comparative blast radius — how does this node compare to others?
  7. Change tracking        — has the blast radius grown since last check?

Output:
  {
    "start_node": "svc-deploy",
    "reachable_count": 47,
    "blast_score": 0.82,
    "crown_jewels_exposed": ["prod-db", "secret-store"],
    "tiers": {1: [...], 2: [...], 3: [...]},
    "containment_suggestions": ["role-admin", "gateway-svc"],
    "risk_breakdown": {"high": 12, "medium": 20, "low": 15},
  }
"""

import logging
from collections import defaultdict, deque
from typing import Callable

logger = logging.getLogger("hollow_purple.blast_radius")

# Risk scores per node type / privilege level
NODE_RISK_WEIGHTS = {
    "admin":         1.0,
    "elevated":      0.75,
    "normal":        0.4,
    "low":           0.1,
    "crown_jewel":   1.0,
    "secret":        0.9,
    "production":    0.85,
    "database":      0.8,
    "service":       0.5,
    "user":          0.3,
}

HIGH_PRIV_SIGNALS = frozenset({"admin", "root", "owner", "superuser", "full", "prod", "secret", "kms"})


class BlastRadiusEngine:
    """
    Calculates the blast radius of a compromised node.

    Usage:
        engine = BlastRadiusEngine(graph_store, crown_jewels={"prod-db", "secret-store"})
        result = engine.compute("svc-deploy", depth=6)
        critical = engine.is_critical_compromise("svc-deploy")
        suggestions = engine.containment_suggestions("svc-deploy")
    """

    def __init__(
        self,
        graph_store,
        crown_jewels: set[str] | None = None,
        node_risk_fn: Callable[[str], float] | None = None,
    ):
        self.graph       = graph_store
        self.crown_jewels = crown_jewels or set()
        self._node_risk_fn = node_risk_fn or self._default_node_risk
        self._history: dict[str, dict] = {}   # node → last computed blast result

    # ------------------------------------------------------------------ #
    #  Core computation                                                    #
    # ------------------------------------------------------------------ #

    def compute(self, start_node: str, depth: int = 6) -> dict:
        """
        Full blast radius computation for a compromised node.
        Returns structured result with tiered reach, risk score, and crown jewel exposure.
        """
        tiers:   dict[int, list[str]] = defaultdict(list)
        visited: set[str]             = set()
        queue:   deque                = deque([(start_node, 0)])

        while queue:
            node, d = queue.popleft()
            if node in visited or d > depth:
                continue
            visited.add(node)
            if d > 0:
                tiers[d].append(node)
            for edge in self._safe_neighbors(node):
                nxt = edge.get("target", "")
                if nxt and nxt not in visited:
                    queue.append((nxt, d + 1))

        visited.discard(start_node)
        all_reachable = list(visited)

        # Risk scoring
        risk_scores   = {n: self._node_risk_fn(n) for n in all_reachable}
        blast_score   = self._aggregate_risk(risk_scores)
        risk_breakdown = self._risk_breakdown(risk_scores)

        # Crown jewel exposure
        exposed_cj = [n for n in all_reachable if n in self.crown_jewels
                       or any(s in n.lower() for s in {"prod-db", "secret", "kms", "billing"})]

        # Change detection
        changed = self._detect_change(start_node, len(all_reachable), blast_score)

        result = {
            "start_node":           start_node,
            "reachable_count":      len(all_reachable),
            "reachable_nodes":      all_reachable,
            "blast_score":          round(blast_score, 4),
            "crown_jewels_exposed": exposed_cj,
            "tiers":                {str(d): nodes for d, nodes in sorted(tiers.items())},
            "risk_breakdown":       risk_breakdown,
            "severity":             self._severity(blast_score, exposed_cj),
            "changed_since_last":   changed,
            "depth_analyzed":       depth,
        }

        self._history[start_node] = {"count": len(all_reachable), "score": blast_score}
        logger.info("BlastRadius: %s → reachable=%d score=%.3f cj_exposed=%d",
                    start_node, len(all_reachable), blast_score, len(exposed_cj))
        return result

    def is_critical_compromise(self, node: str, depth: int = 5) -> bool:
        """Quick check: would compromising this node expose crown jewels?"""
        result = self.compute(node, depth=depth)
        return len(result["crown_jewels_exposed"]) > 0 or result["blast_score"] > 0.7

    def compare(self, nodes: list[str], depth: int = 5) -> list[dict]:
        """
        Rank multiple nodes by blast score.
        Useful for prioritizing which identities to protect first.
        """
        results = []
        for node in nodes:
            r = self.compute(node, depth=depth)
            results.append({
                "node":                 node,
                "blast_score":          r["blast_score"],
                "reachable_count":      r["reachable_count"],
                "crown_jewels_exposed": len(r["crown_jewels_exposed"]),
                "severity":             r["severity"],
            })
        return sorted(results, key=lambda x: -x["blast_score"])

    def containment_suggestions(self, start_node: str, depth: int = 4) -> list[str]:
        """
        Identify nodes whose removal (access revocation) would most reduce blast radius.
        These are hub nodes with the highest out-degree in the reachable subgraph.
        """
        r = self.compute(start_node, depth=depth)
        reachable = set(r["reachable_nodes"])

        # Count how many reachable nodes each intermediate node connects to
        hub_scores: dict[str, int] = defaultdict(int)
        for node in reachable:
            for edge in self._safe_neighbors(node):
                nxt = edge.get("target", "")
                if nxt in reachable:
                    hub_scores[node] += 1

        sorted_hubs = sorted(hub_scores.items(), key=lambda x: -x[1])
        return [node for node, _ in sorted_hubs[:5]]

    # ------------------------------------------------------------------ #
    #  Internal helpers                                                    #
    # ------------------------------------------------------------------ #

    def _aggregate_risk(self, scores: dict[str, float]) -> float:
        if not scores:
            return 0.0
        values = list(scores.values())
        avg    = sum(values) / len(values)
        # Weight heavily by max individual risk
        return min(1.0, avg * 0.6 + max(values) * 0.4)

    def _risk_breakdown(self, scores: dict[str, float]) -> dict:
        bands = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for s in scores.values():
            if s >= 0.85:   bands["critical"] += 1
            elif s >= 0.65: bands["high"]     += 1
            elif s >= 0.35: bands["medium"]   += 1
            else:           bands["low"]      += 1
        return bands

    def _severity(self, score: float, exposed_cj: list) -> str:
        if exposed_cj or score >= 0.85:
            return "critical"
        if score >= 0.65:
            return "high"
        if score >= 0.35:
            return "medium"
        return "low"

    def _detect_change(self, node: str, count: int, score: float) -> bool:
        prev = self._history.get(node)
        if not prev:
            return False
        return abs(prev["count"] - count) > 2 or abs(prev["score"] - score) > 0.1

    def _default_node_risk(self, node: str) -> float:
        """Heuristic risk weight for a node based on its name."""
        node_lower = node.lower()
        if node in self.crown_jewels:
            return 1.0
        for signal in HIGH_PRIV_SIGNALS:
            if signal in node_lower:
                return NODE_RISK_WEIGHTS.get(signal, 0.7)
        return 0.3

    def _safe_neighbors(self, node: str) -> list[dict]:
        try:
            return self.graph.get_neighbors(node) or []
        except Exception as exc:
            logger.debug("get_neighbors('%s') failed: %s", node, exc)
            return []