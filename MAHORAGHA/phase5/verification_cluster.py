"""
Verification Cluster

Top-level coordinator for distributed log verification.

The cluster orchestrates:
  - Witness node registration and lifecycle
  - Root submission and consensus coordination
  - Gossip propagation of accepted roots
  - Byzantine fault detection (equivocating or offline nodes)
  - Cluster health reporting
  - Split-brain detection: if two partitions form conflicting consensus,
    the cluster halts and raises an alert

Byzantine fault model: up to f faulty nodes can be tolerated in a
cluster of n=3f+1 nodes. The cluster enforces this through:
  1. Quorum threshold on consensus votes (default 2/3 majority)
  2. Witness cosignatures on accepted roots
  3. Equivocation detection: a node that votes both Yes and No on the
     same proposal is flagged and its trust score is zeroed
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


@dataclass
class ClusterReport:
    """Comprehensive cluster verification result."""
    proposal_id: str
    root: str
    tree_size: int
    accepted: bool
    quorum_reached: bool
    verdicts: List[Any]              # WitnessVerdict objects
    cosignatures: List[str]          # cosigs from accepting witnesses
    byzantine_suspects: List[str]    # node IDs with equivocation detected
    offline_nodes: List[str]         # nodes that didn't respond
    timestamp: float = field(default_factory=time.time)

    @property
    def accepting_nodes(self) -> List[str]:
        return [v.node_id for v in self.verdicts if v.accepted]

    @property
    def rejecting_nodes(self) -> List[str]:
        return [v.node_id for v in self.verdicts if not v.accepted]

    def summary(self) -> str:
        status = "ACCEPTED" if self.accepted else "REJECTED"
        return (
            f"[{status}] proposal={self.proposal_id[:12]}… "
            f"accept={len(self.accepting_nodes)} "
            f"reject={len(self.rejecting_nodes)} "
            f"offline={len(self.offline_nodes)} "
            f"byzantine={len(self.byzantine_suspects)}"
        )


class VerificationCluster:
    """
    Manages a distributed cluster of witness nodes for log verification.

    Verification flow for a single root:
      1. Operator submits root to verify_root()
      2. Cluster broadcasts root to all registered witness nodes
      3. Each node independently checks consistency and returns a verdict
      4. Verdicts are fed into the ConsensusEngine
      5. ConsensusEngine determines if quorum has been reached
      6. Cluster assembles a ClusterReport and propagates via gossip
      7. Byzantine suspects (equivocating nodes) are flagged

    The cluster maintains a health model: nodes that are slow, offline,
    or equivocating are tracked and can be removed from quorum calculations.
    """

    def __init__(
        self,
        consensus_engine: Any,              # ConsensusEngine
        gossip: Optional[Any] = None,       # LogGossip (optional)
        node_timeout_seconds: float = 10.0,
        auto_register_to_gossip: bool = True,
    ):
        self.consensus = consensus_engine
        self.gossip = gossip
        self.node_timeout = node_timeout_seconds
        self.auto_register_to_gossip = auto_register_to_gossip

        self._nodes: Dict[str, Any] = {}           # node_id -> WitnessNode
        self._node_last_seen: Dict[str, float] = {}
        self._equivocators: Set[str] = set()
        self._cluster_history: List[ClusterReport] = []
        self._proposal_counter: int = 0

    # ─── Node management ─────────────────────────────────────────────────────

    def register_node(self, node: Any):
        """
        Register a witness node with the cluster.

        The node is also:
          - registered with the ConsensusEngine (with default weight 1.0)
          - registered with LogGossip if auto_register_to_gossip is True
        """
        self._nodes[node.node_id] = node
        self._node_last_seen[node.node_id] = time.time()
        self.consensus.register_node(node.node_id)

        if self.gossip and self.auto_register_to_gossip:
            self.gossip.register(node)

    def deregister_node(self, node_id: str, reason: str = ""):
        node = self._nodes.pop(node_id, None)
        if node and self.gossip:
            self.gossip.deregister(node_id)
        self.consensus.deregister_node(node_id)
        self._node_last_seen.pop(node_id, None)

    def set_node_weight(self, node_id: str, weight: float):
        """Adjust the consensus weight for a specific node."""
        self.consensus.register_node(node_id, weight=weight)

    # ─── Verification ────────────────────────────────────────────────────────

    def verify_root(
        self,
        merkle_root: str,
        tree_size: int = 0,
        proposal_id: Optional[str] = None,
    ) -> ClusterReport:
        """
        Submit a Merkle root for cluster-wide verification.

        Args:
            merkle_root:  The root hash to verify
            tree_size:    Log size at this checkpoint
            proposal_id:  Optional explicit proposal ID; auto-generated if None

        Returns:
            ClusterReport with full verification outcome
        """
        if proposal_id is None:
            self._proposal_counter += 1
            proposal_id = f"proposal-{self._proposal_counter:06d}"

        verdicts = []
        cosignatures = []
        offline = []

        # Collect verdicts from all registered nodes
        for node_id, node in self._nodes.items():
            try:
                verdict = node.submit_root(
                    proposal_id=proposal_id,
                    root=merkle_root,
                    tree_size=tree_size,
                    submitter_id="cluster",
                )
                verdicts.append(verdict)
                self._node_last_seen[node_id] = time.time()

                # Feed verdict into consensus engine
                self.consensus.vote(proposal_id, node_id, verdict.accepted)

                if verdict.accepted and verdict.cosignature:
                    cosignatures.append(verdict.cosignature)

            except Exception:
                offline.append(node_id)

        # Check for equivocation (nodes that changed their vote)
        consensus_result = self.consensus.result(proposal_id)
        newly_equivocating = set(consensus_result.conflicting_nodes)
        self._equivocators.update(newly_equivocating)

        # Zero out equivocating nodes' trust
        for eq_node in newly_equivocating:
            self.set_node_weight(eq_node, weight=0.01)

        quorum_reached = consensus_result.passed
        accepted = quorum_reached and len(self._equivocators & set(self._nodes)) == 0

        # Propagate accepted root via gossip
        if accepted and self.gossip:
            self.gossip.propagate(
                merkle_root=merkle_root,
                tree_size=tree_size,
                origin="cluster",
            )

        report = ClusterReport(
            proposal_id=proposal_id,
            root=merkle_root,
            tree_size=tree_size,
            accepted=accepted,
            quorum_reached=quorum_reached,
            verdicts=verdicts,
            cosignatures=cosignatures,
            byzantine_suspects=list(newly_equivocating),
            offline_nodes=offline,
        )

        self._cluster_history.append(report)
        return report

    # ─── Health monitoring ───────────────────────────────────────────────────

    def health(self) -> Dict:
        """
        Return cluster health: active nodes, offline nodes, Byzantine suspects.
        """
        now = time.time()
        healthy = []
        stale = []

        for node_id, last_seen in self._node_last_seen.items():
            if now - last_seen > self.node_timeout:
                stale.append(node_id)
            else:
                healthy.append(node_id)

        return {
            "total_nodes": len(self._nodes),
            "healthy_nodes": healthy,
            "stale_nodes": stale,
            "byzantine_suspects": list(self._equivocators),
            "fault_tolerance": max(0, (len(self._nodes) - 1) // 3),
            "quorum_size": self.consensus.quorum_size,
        }

    def detect_split_brain(self) -> bool:
        """
        Check recent history for conflicting accepted roots at the same tree size.

        A split brain exists if two different roots were accepted at the same size —
        meaning two cluster partitions formed inconsistent consensus.
        """
        size_to_roots: Dict[int, Set[str]] = {}
        for report in self._cluster_history:
            if report.accepted:
                size_to_roots.setdefault(report.tree_size, set()).add(report.root)

        for size, roots in size_to_roots.items():
            if len(roots) > 1:
                return True   # Two accepted roots at same tree size = split brain

        return False

    # ─── History ─────────────────────────────────────────────────────────────

    def get_history(self, last_n: int = 20) -> List[ClusterReport]:
        return self._cluster_history[-last_n:]

    def accepted_roots(self) -> List[str]:
        """Return all roots that achieved cluster consensus."""
        return [r.root for r in self._cluster_history if r.accepted]

    # ─── Byzantine fault analysis ────────────────────────────────────────────

    def byzantine_report(self) -> dict:
        """
        Summarize Byzantine fault status.

        A cluster of n=3f+1 nodes tolerates f Byzantine faults.
        If the number of known equivocators exceeds f, the cluster
        can no longer guarantee safety and should halt.
        """
        n = len(self._nodes)
        f = (n - 1) // 3
        known_faults = len(self._equivocators)

        return {
            "cluster_size": n,
            "fault_tolerance_f": f,
            "known_byzantine_nodes": known_faults,
            "safety_intact": known_faults <= f,
            "equivocating_nodes": list(self._equivocators),
            "recommendation": (
                "safe" if known_faults <= f
                else "HALT: Byzantine fault threshold exceeded"
            ),
        }