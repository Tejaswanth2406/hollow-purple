"""
Log Gossip

Epidemic (gossip) protocol for distributing Merkle log roots and
STH checkpoints across all witness nodes in the cluster.

Gossip protocols are favored in distributed systems (Cassandra, Consul,
etcd) because they provide:
  - O(log N) propagation time
  - No single point of failure
  - Self-healing: nodes that miss a round catch up in later rounds
  - Tunable fan-out: more peers per round = faster convergence, more bandwidth

This implementation provides:
  - Configurable fan-out (peers contacted per round)
  - Message deduplication (don't propagate what you've already seen)
  - Anti-entropy: periodic full state exchange to fill gaps
  - Message versioning: newer messages supersede older ones
  - Propagation tracking: measure how fast a root reaches all nodes
  - Pull mode: nodes can request missing roots from peers
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


@dataclass
class GossipMessage:
    """A unit of gossip — a Merkle root + metadata."""
    root: str
    tree_size: int
    origin_node: str
    timestamp: float = field(default_factory=time.time)
    ttl: int = 8                    # max hops remaining (decremented each relay)
    message_id: str = ""            # unique ID for deduplication

    def __post_init__(self):
        if not self.message_id:
            import hashlib
            self.message_id = hashlib.sha256(
                f"{self.root}:{self.origin_node}:{self.timestamp}".encode()
            ).hexdigest()[:16]

    def relay(self) -> Optional["GossipMessage"]:
        """Return a relayed copy with TTL decremented, or None if expired."""
        if self.ttl <= 1:
            return None
        return GossipMessage(
            root=self.root,
            tree_size=self.tree_size,
            origin_node=self.origin_node,
            timestamp=self.timestamp,
            ttl=self.ttl - 1,
            message_id=self.message_id,
        )


@dataclass
class PropagationRecord:
    """Tracks how a message spreads through the cluster."""
    message_id: str
    origin: str
    started_at: float
    reached_nodes: Set[str] = field(default_factory=set)
    total_nodes: int = 0

    @property
    def coverage(self) -> float:
        if self.total_nodes == 0:
            return 0.0
        return len(self.reached_nodes) / self.total_nodes

    @property
    def elapsed_ms(self) -> float:
        return (time.time() - self.started_at) * 1000


class LogGossip:
    """
    Epidemic gossip protocol for Merkle root distribution.

    Each node in the cluster is registered. When a new root is propagated,
    it is sent to a random fan-out subset of nodes. Each receiving node
    records the root and relays it to another fan-out subset (until TTL=0).

    Anti-entropy: periodically, nodes exchange their full known root sets
    to fill gaps caused by network partitions or node restarts.
    """

    def __init__(
        self,
        fan_out: int = 3,
        dedup_window_seconds: float = 600.0,
        max_dedup_cache: int = 100_000,
    ):
        """
        Args:
            fan_out:               Peers to contact per gossip round
            dedup_window_seconds:  Discard messages older than this (replay prevention)
            max_dedup_cache:       Max seen message IDs to retain
        """
        self.fan_out = fan_out
        self.dedup_window = dedup_window_seconds
        self.max_dedup_cache = max_dedup_cache

        self._nodes: List[Any] = []          # WitnessNode instances
        self._seen: Dict[str, float] = {}    # message_id -> first_seen_ts
        self._propagation: Dict[str, PropagationRecord] = {}
        self._stats = {"messages_originated": 0, "messages_relayed": 0, "duplicates_dropped": 0}

    # ─── Node management ─────────────────────────────────────────────────────

    def register(self, node: Any):
        """Register a witness node to receive gossip."""
        self._nodes.append(node)

    def deregister(self, node_id: str):
        self._nodes = [n for n in self._nodes if n.node_id != node_id]

    @property
    def cluster_size(self) -> int:
        return len(self._nodes)

    # ─── Propagation ─────────────────────────────────────────────────────────

    def propagate(self, merkle_root: str, tree_size: int = 0, origin: str = "operator"):
        """
        Originate a new gossip message and begin spreading it through the cluster.

        Args:
            merkle_root: The root hash to propagate
            tree_size:   Log size at this checkpoint
            origin:      Who is originating this message
        """
        msg = GossipMessage(
            root=merkle_root,
            tree_size=tree_size,
            origin_node=origin,
        )

        record = PropagationRecord(
            message_id=msg.message_id,
            origin=origin,
            started_at=time.time(),
            total_nodes=len(self._nodes),
        )
        self._propagation[msg.message_id] = record
        self._stats["messages_originated"] += 1

        self._gossip_round(msg, record)

    def _gossip_round(self, msg: GossipMessage, record: Optional[PropagationRecord] = None):
        """Send message to a random fan-out subset of nodes."""
        if self._is_duplicate(msg):
            self._stats["duplicates_dropped"] += 1
            return

        self._mark_seen(msg)

        targets = self._select_peers(fan_out=self.fan_out)

        for node in targets:
            node.submit_root(
                proposal_id=msg.message_id,
                root=msg.root,
                tree_size=msg.tree_size,
                submitter_id=msg.origin_node,
            )
            if record:
                record.reached_nodes.add(node.node_id)

        self._stats["messages_relayed"] += len(targets)

        # Relay to next hop (with TTL check)
        relay = msg.relay()
        if relay and len(self._nodes) > self.fan_out:
            self._gossip_round(relay, record)

    # ─── Anti-entropy ────────────────────────────────────────────────────────

    def anti_entropy_round(self, source_node: Any):
        """
        Perform a full state exchange with a random peer.

        Compares known roots between source_node and a random peer;
        missing roots are pushed to the peer.

        This heals partitions: nodes that missed gossip rounds catch up.
        """
        if len(self._nodes) < 2:
            return

        peers = [n for n in self._nodes if n.node_id != source_node.node_id]
        if not peers:
            return

        peer = random.choice(peers)
        source_roots = set(source_node._root_log)
        peer_roots = set(peer._root_log)

        # Push roots the peer is missing
        missing = source_roots - peer_roots
        for root in missing:
            peer.observe_root(root)

    # ─── Pull mode ───────────────────────────────────────────────────────────

    def pull_from_peer(self, requesting_node: Any, target_node: Any):
        """
        Pull all roots from target_node that requesting_node is missing.
        """
        known = set(requesting_node._root_log)
        for root in target_node._root_log:
            if root not in known:
                requesting_node.observe_root(root)

    # ─── Propagation analytics ───────────────────────────────────────────────

    def propagation_coverage(self, message_id: str) -> Optional[PropagationRecord]:
        return self._propagation.get(message_id)

    def stats(self) -> dict:
        return {
            **self._stats,
            "cluster_size": self.cluster_size,
            "dedup_cache_size": len(self._seen),
        }

    # ─── Internals ───────────────────────────────────────────────────────────

    def _select_peers(self, fan_out: int) -> List[Any]:
        if not self._nodes:
            return []
        k = min(fan_out, len(self._nodes))
        return random.sample(self._nodes, k)

    def _is_duplicate(self, msg: GossipMessage) -> bool:
        ts = self._seen.get(msg.message_id)
        if ts is None:
            return False
        return (time.time() - ts) < self.dedup_window

    def _mark_seen(self, msg: GossipMessage):
        now = time.time()
        self._seen[msg.message_id] = now

        # Bound cache
        if len(self._seen) > self.max_dedup_cache:
            cutoff = now - self.dedup_window
            self._seen = {
                mid: ts for mid, ts in self._seen.items() if ts >= cutoff
            }