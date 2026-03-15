"""
projections/graph_projection.py
================================
Enterprise attack graph projection engine.

Responsibilities
----------------
- Build a query-optimized in-memory view of the system relationship graph
- Materialise adjacency indices for O(1) neighbor lookups
- Compute graph-level structural metrics (degree centrality, density, hubs)
- Identify critical path nodes: high-betweenness assets in attack chains
- Expose shortest-path and reachability APIs backed by BFS/Dijkstra
- Support incremental re-projection (delta updates, not full rebuild)
- Provide subgraph extraction for blast-radius windows
- Emit structured change events when projection is rebuilt

Design
------
The projection is a read-optimized, denormalized view derived from
GraphStore data. It is NOT authoritative — the canonical state lives
in GraphStore. Rebuild the projection after any significant graph mutation.
"""

from __future__ import annotations

import asyncio
import heapq
import logging
import math
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class GraphProjectionResult:
    """Summary statistics emitted after a full projection build."""

    node_count: int
    edge_count: int
    density: float                       # edges / (nodes * (nodes-1))
    isolated_nodes: int                  # nodes with no edges
    hub_nodes: List[str]                 # top-N highest out-degree nodes
    critical_nodes: List[str]            # high betweenness centrality
    projected_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    duration_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "density": round(self.density, 6),
            "isolated_nodes": self.isolated_nodes,
            "hub_nodes": self.hub_nodes,
            "critical_nodes": self.critical_nodes,
            "projected_at": self.projected_at,
            "duration_ms": round(self.duration_ms, 3),
        }


@dataclass
class PathResult:
    """Result of a shortest-path or all-paths query."""

    src: str
    dst: str
    paths: List[List[str]]
    shortest_length: int
    reachable: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "src": self.src,
            "dst": self.dst,
            "paths": self.paths,
            "shortest_length": self.shortest_length,
            "reachable": self.reachable,
        }


# ---------------------------------------------------------------------------
# GraphProjection
# ---------------------------------------------------------------------------


class GraphProjection:
    """
    Query-optimized materialized view of the system attack graph.

    Backed by adjacency lists for O(1) neighbor access and Dijkstra /
    BFS for path queries. Supports both weighted (risk-weighted edges)
    and unweighted traversal.

    Usage
    -----
    ::

        projection = GraphProjection()
        result = await projection.build(graph_store)

        # Shortest attack path
        path = projection.shortest_path("internet", "db-prod-01")

        # All nodes reachable from a compromised entry point
        reachable = projection.reachable_from("attacker-foothold")

        # Structural hubs (high-value targets / pivot points)
        hubs = projection.top_hubs(n=10)
    """

    def __init__(self, *, hub_top_n: int = 10) -> None:
        self._hub_top_n = hub_top_n

        # Core adjacency structures
        # node_id -> {dst_node_id -> [(relation, weight), ...]}
        self._out: Dict[str, Dict[str, List[Tuple[str, float]]]] = defaultdict(
            lambda: defaultdict(list)
        )
        # node_id -> {src_node_id -> [(relation, weight), ...]}
        self._in: Dict[str, Dict[str, List[Tuple[str, float]]]] = defaultdict(
            lambda: defaultdict(list)
        )

        # Node metadata index
        self._nodes: Dict[str, Dict[str, Any]] = {}

        # Degree caches (rebuilt on project())
        self._out_degree: Dict[str, int] = {}
        self._in_degree: Dict[str, int] = {}

        # Betweenness centrality cache (computed lazily)
        self._betweenness: Optional[Dict[str, float]] = None

        self._lock = asyncio.Lock()
        self._last_result: Optional[GraphProjectionResult] = None

        logger.info("GraphProjection initialised")

    # ---------------------------------------------------------------------------
    # Build / project
    # ---------------------------------------------------------------------------

    async def build(self, graph_store) -> GraphProjectionResult:
        """
        Rebuild the full projection from a GraphStore instance.

        Parameters
        ----------
        graph_store : Any GraphStore-compatible object exposing
                      ``all_nodes()`` and ``all_edges()`` coroutines.

        Returns
        -------
        GraphProjectionResult
            Summary statistics for the materialized graph.
        """
        import time as _time

        start_ns = _time.perf_counter_ns()

        logger.info("Building graph projection")

        nodes = await graph_store.all_nodes()
        edges = await graph_store.all_edges()

        async with self._lock:
            # Reset indices
            self._out = defaultdict(lambda: defaultdict(list))
            self._in = defaultdict(lambda: defaultdict(list))
            self._nodes = {}
            self._betweenness = None

            # Index nodes
            for node in nodes:
                self._nodes[node.node_id] = {
                    "node_type": node.node_type,
                    "label": node.label,
                    "tenant_id": node.tenant_id,
                    "metadata": node.metadata,
                }

            # Index edges
            for edge in edges:
                self._out[edge.src][edge.dst].append((edge.relation, edge.weight))
                self._in[edge.dst][edge.src].append((edge.relation, edge.weight))

            # Recompute degree caches
            self._out_degree = {
                nid: sum(len(v) for v in targets.values())
                for nid, targets in self._out.items()
            }
            self._in_degree = {
                nid: sum(len(v) for v in sources.values())
                for nid, sources in self._in.items()
            }

            n = len(self._nodes)
            e = len(edges)
            density = e / (n * (n - 1)) if n > 1 else 0.0
            isolated = sum(
                1 for nid in self._nodes
                if nid not in self._out_degree and nid not in self._in_degree
            )
            hubs = self.top_hubs(n=self._hub_top_n)
            critical = self._approximate_critical_nodes(top_n=self._hub_top_n)

            duration_ms = (_time.perf_counter_ns() - start_ns) / 1_000_000

            result = GraphProjectionResult(
                node_count=n,
                edge_count=e,
                density=density,
                isolated_nodes=isolated,
                hub_nodes=hubs,
                critical_nodes=critical,
                duration_ms=round(duration_ms, 3),
            )
            self._last_result = result

        logger.info(
            "Graph projection built",
            extra={
                "nodes": n,
                "edges": e,
                "density": round(density, 6),
                "duration_ms": round(duration_ms, 2),
            },
        )
        return result

    # ---------------------------------------------------------------------------
    # Neighbor queries
    # ---------------------------------------------------------------------------

    def neighbors(
        self,
        node_id: str,
        *,
        relation: Optional[str] = None,
        direction: str = "out",
    ) -> List[str]:
        """
        Return neighbor node IDs.

        Parameters
        ----------
        direction : ``"out"`` (successors), ``"in"`` (predecessors), ``"both"``.
        relation  : Filter by edge relation type. None = all relations.
        """
        result: Set[str] = set()

        if direction in ("out", "both"):
            for dst, rels in self._out.get(node_id, {}).items():
                if relation is None or any(r == relation for r, _ in rels):
                    result.add(dst)

        if direction in ("in", "both"):
            for src, rels in self._in.get(node_id, {}).items():
                if relation is None or any(r == relation for r, _ in rels):
                    result.add(src)

        result.discard(node_id)
        return list(result)

    def edge_relations(self, src: str, dst: str) -> List[str]:
        """Return all relation types between src and dst."""
        return [r for r, _ in self._out.get(src, {}).get(dst, [])]

    # ---------------------------------------------------------------------------
    # Traversal
    # ---------------------------------------------------------------------------

    def reachable_from(
        self,
        origin: str,
        *,
        max_depth: int = 6,
        relation: Optional[str] = None,
    ) -> Set[str]:
        """
        BFS: all nodes reachable from ``origin`` within ``max_depth`` hops.
        Used for blast-radius computation.
        """
        visited: Set[str] = {origin}
        queue: deque = deque([(origin, 0)])

        while queue:
            current, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for dst, rels in self._out.get(current, {}).items():
                if relation and not any(r == relation for r, _ in rels):
                    continue
                if dst not in visited:
                    visited.add(dst)
                    queue.append((dst, depth + 1))

        visited.discard(origin)
        return visited

    def ancestors_of(
        self,
        node_id: str,
        *,
        max_depth: int = 6,
    ) -> Set[str]:
        """
        BFS backwards: all nodes that can reach ``node_id``.
        Used for root-cause and provenance analysis.
        """
        visited: Set[str] = {node_id}
        queue: deque = deque([(node_id, 0)])

        while queue:
            current, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for src in self._in.get(current, {}):
                if src not in visited:
                    visited.add(src)
                    queue.append((src, depth + 1))

        visited.discard(node_id)
        return visited

    # ---------------------------------------------------------------------------
    # Shortest path (Dijkstra on edge weights)
    # ---------------------------------------------------------------------------

    def shortest_path(
        self,
        src: str,
        dst: str,
        *,
        relation: Optional[str] = None,
        use_weights: bool = True,
    ) -> PathResult:
        """
        Dijkstra shortest path from ``src`` to ``dst``.

        Edge weights default to 1.0. Lower weight = preferred path.
        Set ``use_weights=False`` for pure hop-count BFS.

        Returns
        -------
        PathResult
            ``reachable=False`` with empty paths if no path exists.
        """
        if src not in self._nodes or dst not in self._nodes:
            return PathResult(src=src, dst=dst, paths=[], shortest_length=0, reachable=False)

        # dist[node] = cumulative cost
        dist: Dict[str, float] = {src: 0.0}
        prev: Dict[str, Optional[str]] = {src: None}
        heap: List[Tuple[float, str]] = [(0.0, src)]

        while heap:
            cost, node = heapq.heappop(heap)
            if node == dst:
                break
            if cost > dist.get(node, math.inf):
                continue
            for nb, rels in self._out.get(node, {}).items():
                if relation and not any(r == relation for r, _ in rels):
                    continue
                edge_cost = min(w for _, w in rels) if use_weights else 1.0
                new_cost = cost + edge_cost
                if new_cost < dist.get(nb, math.inf):
                    dist[nb] = new_cost
                    prev[nb] = node
                    heapq.heappush(heap, (new_cost, nb))

        if dst not in dist:
            return PathResult(src=src, dst=dst, paths=[], shortest_length=0, reachable=False)

        # Reconstruct path
        path: List[str] = []
        cursor: Optional[str] = dst
        while cursor is not None:
            path.append(cursor)
            cursor = prev.get(cursor)
        path.reverse()

        return PathResult(
            src=src,
            dst=dst,
            paths=[path],
            shortest_length=len(path) - 1,
            reachable=True,
        )

    def all_paths(
        self,
        src: str,
        dst: str,
        *,
        max_depth: int = 6,
        relation: Optional[str] = None,
    ) -> PathResult:
        """
        All simple paths from ``src`` to ``dst`` (iterative DFS).
        """
        results: List[List[str]] = []
        stack: deque = deque([(src, [src], {src})])

        while stack:
            current, path, seen = stack.pop()
            if current == dst:
                results.append(path)
                continue
            if len(path) > max_depth:
                continue
            for nb, rels in self._out.get(current, {}).items():
                if relation and not any(r == relation for r, _ in rels):
                    continue
                if nb not in seen:
                    stack.append((nb, path + [nb], seen | {nb}))

        min_len = min((len(p) - 1 for p in results), default=0)
        return PathResult(
            src=src,
            dst=dst,
            paths=results,
            shortest_length=min_len,
            reachable=len(results) > 0,
        )

    # ---------------------------------------------------------------------------
    # Structural metrics
    # ---------------------------------------------------------------------------

    def top_hubs(self, *, n: int = 10) -> List[str]:
        """Return the top-N nodes by out-degree (most connections outward)."""
        ranked = sorted(self._out_degree.items(), key=lambda x: x[1], reverse=True)
        return [nid for nid, _ in ranked[:n]]

    def top_targets(self, *, n: int = 10) -> List[str]:
        """Return the top-N nodes by in-degree (most inbound connections — high-value assets)."""
        ranked = sorted(self._in_degree.items(), key=lambda x: x[1], reverse=True)
        return [nid for nid, _ in ranked[:n]]

    def degree(self, node_id: str) -> Dict[str, int]:
        return {
            "out": self._out_degree.get(node_id, 0),
            "in": self._in_degree.get(node_id, 0),
        }

    def _approximate_critical_nodes(self, *, top_n: int = 10) -> List[str]:
        """
        Approximate betweenness centrality via BFS sampling.
        Full Brandes algorithm is O(VE) — acceptable for graphs < 10k nodes.
        For larger graphs, use a graph DB's native centrality function.
        """
        all_nodes = list(self._nodes.keys())
        centrality: Dict[str, float] = defaultdict(float)

        # Sample up to 200 source nodes for large graphs
        sample = all_nodes[:200] if len(all_nodes) > 200 else all_nodes

        for s in sample:
            # BFS from s, track paths
            stack: List[str] = []
            pred: Dict[str, List[str]] = defaultdict(list)
            sigma: Dict[str, float] = defaultdict(float)
            dist_map: Dict[str, int] = {}
            sigma[s] = 1.0
            dist_map[s] = 0
            bfs_q: deque = deque([s])

            while bfs_q:
                v = bfs_q.popleft()
                stack.append(v)
                for w in self._out.get(v, {}):
                    if w not in dist_map:
                        bfs_q.append(w)
                        dist_map[w] = dist_map[v] + 1
                    if dist_map[w] == dist_map[v] + 1:
                        sigma[w] += sigma[v]
                        pred[w].append(v)

            delta: Dict[str, float] = defaultdict(float)
            while stack:
                w = stack.pop()
                for v in pred[w]:
                    if sigma[w] > 0:
                        delta[v] += (sigma[v] / sigma[w]) * (1 + delta[w])
                if w != s:
                    centrality[w] += delta[w]

        ranked = sorted(centrality.items(), key=lambda x: x[1], reverse=True)
        return [nid for nid, _ in ranked[:top_n]]

    # ---------------------------------------------------------------------------
    # Subgraph extraction
    # ---------------------------------------------------------------------------

    def subgraph(self, node_ids: Set[str]) -> Dict[str, Any]:
        """
        Extract a subgraph containing only the specified node IDs.
        Returns an adjacency dict with node metadata.
        """
        nodes_out = {
            nid: self._nodes[nid]
            for nid in node_ids
            if nid in self._nodes
        }
        edges_out: List[Dict[str, Any]] = []
        for src in node_ids:
            for dst, rels in self._out.get(src, {}).items():
                if dst in node_ids:
                    for relation, weight in rels:
                        edges_out.append(
                            {"src": src, "dst": dst, "relation": relation, "weight": weight}
                        )
        return {"nodes": nodes_out, "edges": edges_out}

    # ---------------------------------------------------------------------------
    # Introspection
    # ---------------------------------------------------------------------------

    @property
    def last_result(self) -> Optional[GraphProjectionResult]:
        return self._last_result

    def get_node(self, node_id: str) -> Optional[Dict[str, Any]]:
        return self._nodes.get(node_id)

    def node_count(self) -> int:
        return len(self._nodes)

    def edge_count(self) -> int:
        return sum(
            len(rels)
            for targets in self._out.values()
            for rels in targets.values()
        )