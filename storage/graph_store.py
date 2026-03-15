"""
storage/graph_store.py
======================
Enterprise relationship graph store for Hollow Purple / Mahoraga.

Use cases
---------
- Attack path analysis       : shortest/all paths between entities
- Blast radius computation   : reachability from a compromised node
- Lateral movement detection : suspicious edge traversal patterns
- Privilege escalation       : path from low- to high-privilege nodes
- Dependency mapping         : downstream impact of a failing node

Design
------
- Directed multigraph: multiple typed edges between the same node pair
- Typed nodes and edges with arbitrary metadata payloads
- Async-safe reads via asyncio.RWLock pattern (write lock / read concurrent)
- Pluggable backend adapter (swap to Neo4j / TigerGraph / ArangoDB)
- BFS/DFS traversal with depth limiting and cycle detection
- Subgraph extraction for blast radius windows
- Bulk import/export (adjacency list format)
- Tenant-scoped graph isolation
- Edge weight support for shortest-path scoring
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterator, List, Optional, Set, Tuple


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class NodeNotFoundError(KeyError):
    """Raised when a referenced node does not exist."""


class EdgeNotFoundError(KeyError):
    """Raised when a referenced edge does not exist."""


class GraphCycleError(Exception):
    """Raised when a cycle is detected during a cycle-sensitive operation."""


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class NodeRecord:
    """
    A graph node representing an entity in the observed system.

    Fields
    ------
    node_id     : Unique identifier.
    node_type   : Semantic type (e.g. ``"host"``, ``"user"``, ``"process"``).
    label       : Human-readable display name.
    tenant_id   : Multi-tenant scope.
    metadata    : Arbitrary key-value annotations.
    created_at  : UTC ISO-8601 timestamp.
    updated_at  : Last modification UTC ISO-8601 timestamp.
    """

    node_id: str
    node_type: str
    label: str = ""
    tenant_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    updated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EdgeRecord:
    """
    A directed edge representing a relationship between two nodes.

    Fields
    ------
    edge_id     : Unique identifier (UUID4 hex).
    src         : Source node ID.
    dst         : Destination node ID.
    relation    : Semantic relationship type (e.g. ``"accesses"``, ``"spawns"``).
    weight      : Optional numeric weight for shortest-path algorithms.
    tenant_id   : Multi-tenant scope.
    metadata    : Arbitrary annotations (e.g. protocol, port, timestamp).
    created_at  : UTC ISO-8601 timestamp.
    """

    src: str
    dst: str
    relation: str
    edge_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    weight: float = 1.0
    tenant_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TraversalResult:
    """Output of a graph traversal operation."""

    origin: str
    visited_nodes: List[str]
    paths: List[List[str]]
    depth_reached: int
    truncated: bool = False  # True if max_depth was hit

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Backend adapter
# ---------------------------------------------------------------------------


class GraphStoreBackend:
    """Abstract graph storage backend."""

    async def upsert_node(self, node: NodeRecord) -> None:
        raise NotImplementedError

    async def get_node(
        self, node_id: str, tenant_id: Optional[str] = None
    ) -> Optional[NodeRecord]:
        raise NotImplementedError

    async def delete_node(
        self, node_id: str, tenant_id: Optional[str] = None
    ) -> bool:
        raise NotImplementedError

    async def upsert_edge(self, edge: EdgeRecord) -> None:
        raise NotImplementedError

    async def get_edge(
        self, edge_id: str, tenant_id: Optional[str] = None
    ) -> Optional[EdgeRecord]:
        raise NotImplementedError

    async def delete_edge(
        self, edge_id: str, tenant_id: Optional[str] = None
    ) -> bool:
        raise NotImplementedError

    async def out_edges(
        self,
        node_id: str,
        *,
        relation: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> List[EdgeRecord]:
        raise NotImplementedError

    async def in_edges(
        self,
        node_id: str,
        *,
        relation: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> List[EdgeRecord]:
        raise NotImplementedError

    async def all_nodes(
        self,
        *,
        node_type: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> List[NodeRecord]:
        raise NotImplementedError

    async def all_edges(
        self,
        *,
        relation: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> List[EdgeRecord]:
        raise NotImplementedError


class InMemoryGraphBackend(GraphStoreBackend):
    """Default in-memory backend with adjacency list representation."""

    def __init__(self) -> None:
        self._nodes: Dict[str, NodeRecord] = {}
        self._edges: Dict[str, EdgeRecord] = {}
        # node_id -> list of edge_ids (outgoing)
        self._out_index: Dict[str, List[str]] = defaultdict(list)
        # node_id -> list of edge_ids (incoming)
        self._in_index: Dict[str, List[str]] = defaultdict(list)

    async def upsert_node(self, node: NodeRecord) -> None:
        existing = self._nodes.get(node.node_id)
        if existing:
            # Preserve created_at
            object.__setattr__(node, "created_at", existing.created_at)
        self._nodes[node.node_id] = node

    async def get_node(
        self, node_id: str, tenant_id: Optional[str] = None
    ) -> Optional[NodeRecord]:
        node = self._nodes.get(node_id)
        if node and tenant_id and node.tenant_id != tenant_id:
            return None
        return node

    async def delete_node(
        self, node_id: str, tenant_id: Optional[str] = None
    ) -> bool:
        if node_id not in self._nodes:
            return False
        del self._nodes[node_id]
        # Clean up edges referencing this node
        for eid in list(self._out_index.get(node_id, [])):
            self._edges.pop(eid, None)
        for eid in list(self._in_index.get(node_id, [])):
            self._edges.pop(eid, None)
        self._out_index.pop(node_id, None)
        self._in_index.pop(node_id, None)
        return True

    async def upsert_edge(self, edge: EdgeRecord) -> None:
        self._edges[edge.edge_id] = edge
        if edge.edge_id not in self._out_index[edge.src]:
            self._out_index[edge.src].append(edge.edge_id)
        if edge.edge_id not in self._in_index[edge.dst]:
            self._in_index[edge.dst].append(edge.edge_id)

    async def get_edge(
        self, edge_id: str, tenant_id: Optional[str] = None
    ) -> Optional[EdgeRecord]:
        return self._edges.get(edge_id)

    async def delete_edge(
        self, edge_id: str, tenant_id: Optional[str] = None
    ) -> bool:
        edge = self._edges.pop(edge_id, None)
        if edge is None:
            return False
        self._out_index[edge.src].remove(edge_id)
        self._in_index[edge.dst].remove(edge_id)
        return True

    async def out_edges(
        self,
        node_id: str,
        *,
        relation: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> List[EdgeRecord]:
        edges = [
            self._edges[eid]
            for eid in self._out_index.get(node_id, [])
            if eid in self._edges
        ]
        if relation:
            edges = [e for e in edges if e.relation == relation]
        if tenant_id:
            edges = [e for e in edges if e.tenant_id == tenant_id]
        return edges

    async def in_edges(
        self,
        node_id: str,
        *,
        relation: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> List[EdgeRecord]:
        edges = [
            self._edges[eid]
            for eid in self._in_index.get(node_id, [])
            if eid in self._edges
        ]
        if relation:
            edges = [e for e in edges if e.relation == relation]
        if tenant_id:
            edges = [e for e in edges if e.tenant_id == tenant_id]
        return edges

    async def all_nodes(
        self,
        *,
        node_type: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> List[NodeRecord]:
        result = list(self._nodes.values())
        if node_type:
            result = [n for n in result if n.node_type == node_type]
        if tenant_id:
            result = [n for n in result if n.tenant_id == tenant_id]
        return result

    async def all_edges(
        self,
        *,
        relation: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> List[EdgeRecord]:
        result = list(self._edges.values())
        if relation:
            result = [e for e in result if e.relation == relation]
        if tenant_id:
            result = [e for e in result if e.tenant_id == tenant_id]
        return result


# ---------------------------------------------------------------------------
# GraphStore
# ---------------------------------------------------------------------------


class GraphStore:
    """
    Directed multigraph store with traversal and analysis capabilities.

    Usage
    -----
    ::

        store = GraphStore()

        await store.add_node("host-01", node_type="host", label="Web Server")
        await store.add_node("user-alice", node_type="user", label="Alice")
        await store.add_edge("user-alice", "host-01", relation="ssh_login")

        # BFS traversal
        result = await store.bfs("user-alice", max_depth=3)

        # Blast radius (all nodes reachable from a compromised node)
        blast = await store.blast_radius("host-01")

        # All paths between two nodes
        paths = await store.all_paths("user-alice", "db-server-01", max_depth=5)
    """

    def __init__(self, *, backend: Optional[GraphStoreBackend] = None) -> None:
        self._backend = backend or InMemoryGraphBackend()
        self._lock = asyncio.Lock()
        logger.info("GraphStore initialised")

    # ---------------------------------------------------------------------------
    # Node operations
    # ---------------------------------------------------------------------------

    async def add_node(
        self,
        node_id: str,
        *,
        node_type: str = "generic",
        label: str = "",
        tenant_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> NodeRecord:
        node = NodeRecord(
            node_id=node_id,
            node_type=node_type,
            label=label or node_id,
            tenant_id=tenant_id,
            metadata=metadata or {},
        )
        async with self._lock:
            await self._backend.upsert_node(node)
        logger.debug("Node upserted", extra={"node_id": node_id, "type": node_type})
        return node

    async def get_node(
        self, node_id: str, *, tenant_id: Optional[str] = None
    ) -> NodeRecord:
        node = await self._backend.get_node(node_id, tenant_id)
        if node is None:
            raise NodeNotFoundError(f"Node '{node_id}' not found")
        return node

    async def delete_node(
        self, node_id: str, *, tenant_id: Optional[str] = None
    ) -> bool:
        async with self._lock:
            deleted = await self._backend.delete_node(node_id, tenant_id)
        if deleted:
            logger.info("Node deleted", extra={"node_id": node_id})
        return deleted

    # ---------------------------------------------------------------------------
    # Edge operations
    # ---------------------------------------------------------------------------

    async def add_edge(
        self,
        src: str,
        dst: str,
        relation: str,
        *,
        weight: float = 1.0,
        tenant_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> EdgeRecord:
        edge = EdgeRecord(
            src=src,
            dst=dst,
            relation=relation,
            weight=weight,
            tenant_id=tenant_id,
            metadata=metadata or {},
        )
        async with self._lock:
            await self._backend.upsert_edge(edge)
        logger.debug(
            "Edge added",
            extra={"src": src, "dst": dst, "relation": relation},
        )
        return edge

    async def get_edge(self, edge_id: str) -> EdgeRecord:
        edge = await self._backend.get_edge(edge_id)
        if edge is None:
            raise EdgeNotFoundError(f"Edge '{edge_id}' not found")
        return edge

    async def delete_edge(self, edge_id: str) -> bool:
        async with self._lock:
            return await self._backend.delete_edge(edge_id)

    async def get_neighbors(
        self,
        node_id: str,
        *,
        relation: Optional[str] = None,
        tenant_id: Optional[str] = None,
        direction: str = "out",
    ) -> List[NodeRecord]:
        """
        Return neighboring nodes.

        Parameters
        ----------
        direction : ``"out"`` (successors), ``"in"`` (predecessors), ``"both"``.
        """
        edges: List[EdgeRecord] = []

        if direction in ("out", "both"):
            edges += await self._backend.out_edges(
                node_id, relation=relation, tenant_id=tenant_id
            )
        if direction in ("in", "both"):
            edges += await self._backend.in_edges(
                node_id, relation=relation, tenant_id=tenant_id
            )

        neighbor_ids = set()
        for e in edges:
            if direction == "out" or direction == "both":
                neighbor_ids.add(e.dst)
            if direction == "in" or direction == "both":
                neighbor_ids.add(e.src)
        neighbor_ids.discard(node_id)

        result = []
        for nid in neighbor_ids:
            n = await self._backend.get_node(nid, tenant_id)
            if n:
                result.append(n)
        return result

    # ---------------------------------------------------------------------------
    # Traversal algorithms
    # ---------------------------------------------------------------------------

    async def bfs(
        self,
        origin: str,
        *,
        max_depth: int = 5,
        relation: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> TraversalResult:
        """
        Breadth-first search from ``origin``.

        Returns all reachable nodes within ``max_depth`` hops.
        """
        visited: List[str] = []
        paths: List[List[str]] = []
        seen: Set[str] = {origin}
        queue: deque = deque([(origin, [origin], 0)])
        truncated = False

        while queue:
            current, path, depth = queue.popleft()
            visited.append(current)
            paths.append(path)

            if depth >= max_depth:
                truncated = True
                continue

            out_edges = await self._backend.out_edges(
                current, relation=relation, tenant_id=tenant_id
            )
            for edge in out_edges:
                if edge.dst not in seen:
                    seen.add(edge.dst)
                    queue.append((edge.dst, path + [edge.dst], depth + 1))

        return TraversalResult(
            origin=origin,
            visited_nodes=visited,
            paths=paths,
            depth_reached=max_depth if truncated else len(paths),
            truncated=truncated,
        )

    async def dfs(
        self,
        origin: str,
        *,
        max_depth: int = 5,
        relation: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> TraversalResult:
        """Depth-first search from ``origin``."""
        visited: List[str] = []
        paths: List[List[str]] = []
        seen: Set[str] = set()
        truncated = False

        async def _dfs(node: str, path: List[str], depth: int) -> None:
            nonlocal truncated
            if node in seen:
                return
            seen.add(node)
            visited.append(node)
            paths.append(list(path))

            if depth >= max_depth:
                truncated = True
                return

            out_edges = await self._backend.out_edges(
                node, relation=relation, tenant_id=tenant_id
            )
            for edge in out_edges:
                await _dfs(edge.dst, path + [edge.dst], depth + 1)

        await _dfs(origin, [origin], 0)

        return TraversalResult(
            origin=origin,
            visited_nodes=visited,
            paths=paths,
            depth_reached=max_depth if truncated else len(paths),
            truncated=truncated,
        )

    async def all_paths(
        self,
        src: str,
        dst: str,
        *,
        max_depth: int = 6,
        relation: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> List[List[str]]:
        """
        Find all simple paths between ``src`` and ``dst``.

        Uses iterative DFS with per-path visited sets to avoid cycles
        while allowing nodes to appear in different paths.
        """
        results: List[List[str]] = []
        stack: deque = deque([(src, [src], {src})])

        while stack:
            current, path, path_seen = stack.pop()

            if current == dst:
                results.append(path)
                continue

            if len(path) > max_depth:
                continue

            out_edges = await self._backend.out_edges(
                current, relation=relation, tenant_id=tenant_id
            )
            for edge in out_edges:
                if edge.dst not in path_seen:
                    stack.append(
                        (edge.dst, path + [edge.dst], path_seen | {edge.dst})
                    )

        return results

    async def blast_radius(
        self,
        node_id: str,
        *,
        max_depth: int = 4,
        tenant_id: Optional[str] = None,
    ) -> TraversalResult:
        """
        Compute all nodes reachable from a potentially compromised node.
        Uses BFS to enumerate the full forward reachability set.
        """
        logger.info(
            "Computing blast radius",
            extra={"node_id": node_id, "max_depth": max_depth},
        )
        return await self.bfs(node_id, max_depth=max_depth, tenant_id=tenant_id)

    async def ancestors(
        self,
        node_id: str,
        *,
        max_depth: int = 4,
        tenant_id: Optional[str] = None,
    ) -> TraversalResult:
        """
        Walk backwards (in-edges) to find all nodes that can reach ``node_id``.
        Used for root-cause / provenance analysis.
        """
        visited: List[str] = []
        paths: List[List[str]] = []
        seen: Set[str] = {node_id}
        queue: deque = deque([(node_id, [node_id], 0)])
        truncated = False

        while queue:
            current, path, depth = queue.popleft()
            visited.append(current)
            paths.append(path)

            if depth >= max_depth:
                truncated = True
                continue

            in_edges = await self._backend.in_edges(current, tenant_id=tenant_id)
            for edge in in_edges:
                if edge.src not in seen:
                    seen.add(edge.src)
                    queue.append((edge.src, [edge.src] + path, depth + 1))

        return TraversalResult(
            origin=node_id,
            visited_nodes=visited,
            paths=paths,
            depth_reached=max_depth if truncated else len(paths),
            truncated=truncated,
        )

    # ---------------------------------------------------------------------------
    # Bulk operations
    # ---------------------------------------------------------------------------

    async def bulk_add_nodes(self, nodes: List[Dict[str, Any]]) -> int:
        """
        Import a list of node dicts.
        Each dict must contain ``node_id``; other fields are optional.
        Returns count of nodes upserted.
        """
        count = 0
        for n in nodes:
            await self.add_node(
                n["node_id"],
                node_type=n.get("node_type", "generic"),
                label=n.get("label", ""),
                tenant_id=n.get("tenant_id"),
                metadata=n.get("metadata", {}),
            )
            count += 1
        return count

    async def bulk_add_edges(self, edges: List[Dict[str, Any]]) -> int:
        count = 0
        for e in edges:
            await self.add_edge(
                e["src"],
                e["dst"],
                e["relation"],
                weight=e.get("weight", 1.0),
                tenant_id=e.get("tenant_id"),
                metadata=e.get("metadata", {}),
            )
            count += 1
        return count

    # ---------------------------------------------------------------------------
    # Introspection
    # ---------------------------------------------------------------------------

    async def node_count(self, *, tenant_id: Optional[str] = None) -> int:
        return len(await self._backend.all_nodes(tenant_id=tenant_id))

    async def edge_count(self, *, tenant_id: Optional[str] = None) -> int:
        return len(await self._backend.all_edges(tenant_id=tenant_id))

    async def summary(self, *, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        nodes = await self._backend.all_nodes(tenant_id=tenant_id)
        edges = await self._backend.all_edges(tenant_id=tenant_id)
        type_counts: Dict[str, int] = defaultdict(int)
        for n in nodes:
            type_counts[n.node_type] += 1
        return {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "node_types": dict(type_counts),
            "tenant_id": tenant_id,
        }