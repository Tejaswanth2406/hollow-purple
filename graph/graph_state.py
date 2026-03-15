from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional
import time


@dataclass
class EdgeMeta:
    weight: float = 1.0
    edge_type: str = "access"
    created_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    event_count: int = 1
    risk_multiplier: float = 1.0


class GraphState:
    """
    Directed weighted multigraph with edge metadata.

    Supports:
    - Typed nodes (identity, role, resource, policy)
    - Weighted edges with full metadata
    - Reverse adjacency for ancestor lookup
    - Node attribute storage
    """

    NODE_TYPES = {"identity", "role", "resource", "policy", "group", "service"}

    def __init__(self):
        self.nodes: dict[str, dict] = {}           # node_id → attributes
        self.edges: dict[str, dict[str, EdgeMeta]] = defaultdict(dict)
        self.reverse_edges: dict[str, set] = defaultdict(set)  # inbound
        self._edge_count = 0

    # ── Node management ────────────────────────────────────────────────────

    def add_node(self, node_id: str, node_type: str = "identity", **attrs):
        if node_id not in self.nodes:
            self.nodes[node_id] = {
                "type": node_type,
                "created_at": time.time(),
                **attrs
            }
        else:
            self.nodes[node_id].update(attrs)

    def get_node(self, node_id: str) -> Optional[dict]:
        return self.nodes.get(node_id)

    # ── Edge management ────────────────────────────────────────────────────

    def add_edge(
        self,
        source: str,
        target: str,
        edge_type: str = "access",
        weight: float = 1.0,
        risk_multiplier: float = 1.0,
        source_type: str = "identity",
        target_type: str = "resource",
    ):
        self.add_node(source, source_type)
        self.add_node(target, target_type)

        if target in self.edges[source]:
            meta = self.edges[source][target]
            meta.event_count += 1
            meta.last_seen = time.time()
            meta.weight = max(meta.weight, weight)
            meta.risk_multiplier = max(meta.risk_multiplier, risk_multiplier)
        else:
            self.edges[source][target] = EdgeMeta(
                weight=weight,
                edge_type=edge_type,
                risk_multiplier=risk_multiplier,
            )
            self.reverse_edges[target].add(source)
            self._edge_count += 1

    def remove_edge(self, source: str, target: str):
        if source in self.edges and target in self.edges[source]:
            del self.edges[source][target]
            self.reverse_edges[target].discard(source)
            self._edge_count -= 1

    # ── Traversal ──────────────────────────────────────────────────────────

    def neighbors(self, node: str) -> dict[str, EdgeMeta]:
        return self.edges.get(node, {})

    def predecessors(self, node: str) -> set[str]:
        return self.reverse_edges.get(node, set())

    def all_nodes(self) -> dict[str, dict]:
        return self.nodes

    def all_edges(self):
        for src, targets in self.edges.items():
            for tgt, meta in targets.items():
                yield src, tgt, meta

    # ── Stats ──────────────────────────────────────────────────────────────

    def node_count(self) -> int:
        return len(self.nodes)

    def edge_count(self) -> int:
        return self._edge_count

    def out_degree(self, node: str) -> int:
        return len(self.edges.get(node, {}))

    def in_degree(self, node: str) -> int:
        return len(self.reverse_edges.get(node, set()))

    def degree_centrality(self) -> dict[str, float]:
        n = max(len(self.nodes) - 1, 1)
        return {
            node: (self.out_degree(node) + self.in_degree(node)) / (2 * n)
            for node in self.nodes
        }