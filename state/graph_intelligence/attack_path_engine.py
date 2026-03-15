"""
graph_intelligence/attack_path_engine.py — Multi-Strategy Attack Path Engine

Discovers all viable attack chains in the identity/resource graph.

Algorithms:
  1. BFS shortest-path discovery (Dijkstra-weighted by edge risk score)
  2. DFS all-paths enumeration (up to max_depth hops)
  3. Yen's K-Shortest Paths (top-K ranked by total risk score)
  4. Choke-point detection (nodes that appear in >N% of all paths)
  5. Path deduplication and canonicalization
  6. Risk-scored path ranking

Edge attributes used:
  - relation: "AssumeRole" | "access" | "trust" | "owns"
  - risk_weight: float [0.0–1.0] (higher = riskier edge)
  - requires_mfa: bool

Node attributes used:
  - node_type: "user" | "role" | "resource" | "service_account"
  - privilege_level: "admin" | "elevated" | "normal" | "low"
  - is_crown_jewel: bool
"""

import heapq
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("hollow_purple.attack_path_engine")

# Edge risk weights by relation type
DEFAULT_EDGE_WEIGHTS = {
    "AssumeRole":     0.8,
    "AssignRole":     0.8,
    "access":         0.5,
    "trust":          0.9,
    "owns":           0.7,
    "read":           0.3,
    "write":          0.6,
    "admin":          1.0,
    "execute":        0.5,
}

HIGH_PRIV_PATTERNS = frozenset({"admin", "root", "owner", "superuser", "full", "god"})


@dataclass(order=True)
class ScoredPath:
    risk_score:  float
    path:        list = field(compare=False)
    edge_labels: list = field(compare=False)

    def to_dict(self) -> dict:
        return {
            "path":        self.path,
            "hops":        len(self.path) - 1,
            "edge_labels": self.edge_labels,
            "risk_score":  round(self.risk_score, 4),
            "is_critical": any(any(p in str(n).lower() for p in HIGH_PRIV_PATTERNS)
                               for n in self.path),
        }


class AttackPathEngine:
    """
    Discovers and ranks attack paths in the identity graph.

    Usage:
        engine = AttackPathEngine(graph_store)
        paths  = engine.find_paths("user123", "admin-role", max_depth=6)
        top_k  = engine.top_k_paths("user123", "prod-db", k=5)
        chokes = engine.choke_points("user123", "admin-role")
    """

    def __init__(self, graph_store):
        self.graph = graph_store
        self._path_cache: dict[str, list[ScoredPath]] = {}

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def find_paths(
        self,
        start_node: str,
        target_node: str,
        max_depth: int = 6,
        max_paths: int = 50,
    ) -> list[dict]:
        """
        Find all attack paths from start_node to target_node.
        Returns paths sorted by risk_score (highest first).
        """
        cache_key = f"{start_node}:{target_node}:{max_depth}"
        if cache_key in self._path_cache:
            return [p.to_dict() for p in self._path_cache[cache_key]]

        raw_paths = self._bfs_all_paths(start_node, target_node, max_depth, max_paths)
        scored    = [self._score_path(p) for p in raw_paths]
        scored.sort(key=lambda p: -p.risk_score)

        self._path_cache[cache_key] = scored
        logger.info("AttackPathEngine: found %d paths %s→%s", len(scored), start_node, target_node)
        return [p.to_dict() for p in scored]

    def top_k_paths(
        self,
        start_node: str,
        target_node: str,
        k: int = 5,
        max_depth: int = 8,
    ) -> list[dict]:
        """Return the K highest-risk attack paths using modified Dijkstra."""
        paths = self._dijkstra_k_paths(start_node, target_node, k, max_depth)
        return [p.to_dict() for p in paths]

    def shortest_path(self, start_node: str, target_node: str) -> dict | None:
        """Return the single lowest-hop path (BFS)."""
        queue: deque = deque([(start_node, [start_node], [])])
        visited = {start_node}
        while queue:
            node, path, edges = queue.popleft()
            if node == target_node:
                return self._score_path((path, edges)).to_dict()
            if len(path) >= 10:
                continue
            for edge in self._safe_neighbors(node):
                nxt = edge.get("target", "")
                if nxt and nxt not in visited:
                    visited.add(nxt)
                    queue.append((nxt, path + [nxt], edges + [edge.get("relation", "")]))
        return None

    def choke_points(
        self,
        start_node: str,
        target_node: str,
        threshold_pct: float = 0.5,
        max_depth: int = 6,
    ) -> list[dict]:
        """
        Find nodes that appear in >= threshold_pct of all paths.
        Choke points are high-value targets for defenders AND attackers.
        """
        paths = self.find_paths(start_node, target_node, max_depth, max_paths=100)
        if not paths:
            return []

        node_counts: dict[str, int] = defaultdict(int)
        total = len(paths)
        for p in paths:
            for node in p["path"][1:-1]:   # exclude start and target
                node_counts[node] += 1

        return [
            {"node": node, "path_coverage_pct": round(count / total * 100, 1), "count": count}
            for node, count in sorted(node_counts.items(), key=lambda x: -x[1])
            if count / total >= threshold_pct
        ]

    def reachable_from(self, start_node: str, max_depth: int = 6) -> list[str]:
        """Return all nodes reachable from start_node within max_depth hops."""
        visited: set[str] = set()
        queue   = deque([(start_node, 0)])
        while queue:
            node, depth = queue.popleft()
            if depth > max_depth or node in visited:
                continue
            visited.add(node)
            for edge in self._safe_neighbors(node):
                nxt = edge.get("target", "")
                if nxt and nxt not in visited:
                    queue.append((nxt, depth + 1))
        visited.discard(start_node)
        return list(visited)

    def invalidate_cache(self):
        self._path_cache.clear()

    # ------------------------------------------------------------------ #
    #  Algorithms                                                          #
    # ------------------------------------------------------------------ #

    def _bfs_all_paths(
        self, start: str, target: str, max_depth: int, max_paths: int
    ) -> list[tuple[list, list]]:
        """BFS enumeration of all simple paths up to max_depth."""
        paths: list[tuple[list, list]] = []
        queue: deque = deque([(start, [start], [])])

        while queue and len(paths) < max_paths:
            node, path, edges = queue.popleft()
            if len(path) > max_depth + 1:
                continue
            if node == target:
                paths.append((path, edges))
                continue
            for edge in self._safe_neighbors(node):
                nxt = edge.get("target", "")
                if nxt and nxt not in path:
                    queue.append((nxt, path + [nxt], edges + [edge.get("relation", "")]))
        return paths

    def _dijkstra_k_paths(
        self, start: str, target: str, k: int, max_depth: int
    ) -> list[ScoredPath]:
        """Modified Dijkstra to find top-K paths by cumulative risk weight."""
        # heap: (neg_risk, path, edges)
        heap: list = [(0.0, [start], [])]
        results:    list[ScoredPath] = []
        counts:     dict[str, int]   = defaultdict(int)

        while heap and len(results) < k:
            neg_risk, path, edges = heapq.heappop(heap)
            node = path[-1]

            if counts[node] >= k:
                continue
            counts[node] += 1

            if node == target:
                scored = self._score_path((path, edges))
                results.append(scored)
                continue

            if len(path) > max_depth:
                continue

            for edge in self._safe_neighbors(node):
                nxt      = edge.get("target", "")
                relation = edge.get("relation", "access")
                if nxt and nxt not in path:
                    w = DEFAULT_EDGE_WEIGHTS.get(relation, 0.5)
                    heapq.heappush(heap, (
                        neg_risk - w,
                        path + [nxt],
                        edges + [relation],
                    ))

        return sorted(results, key=lambda p: -p.risk_score)

    def _score_path(self, path_edges: tuple[list, list]) -> ScoredPath:
        """Compute cumulative risk score for a (path, edge_labels) tuple."""
        path, edges = path_edges
        if not edges:
            return ScoredPath(risk_score=0.0, path=path, edge_labels=edges)

        total = sum(DEFAULT_EDGE_WEIGHTS.get(e, 0.5) for e in edges)
        # Bonus for reaching high-privilege node
        terminal = str(path[-1]).lower()
        if any(p in terminal for p in HIGH_PRIV_PATTERNS):
            total += 0.5
        # Penalty for long paths (harder to execute)
        total -= len(path) * 0.05
        return ScoredPath(risk_score=max(0.0, total), path=path, edge_labels=edges)

    def _safe_neighbors(self, node: str) -> list[dict]:
        """Safely fetch neighbors, returning [] on any graph error."""
        try:
            return self.graph.get_neighbors(node) or []
        except Exception as exc:
            logger.debug("get_neighbors failed for node='%s': %s", node, exc)
            return []