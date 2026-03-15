"""
Hollow Purple Phase 5 — Distributed Verification & Trust Layer

Transforms the platform from a single-node verifiable system into a
distributed, Byzantine-fault tolerant trust network.

No single node can unilaterally alter logs or state — consensus across
a quorum of independent witness nodes is required for any root to be
considered authoritative.

Conceptual inspirations:
  - Google Certificate Transparency (RFC 6962) — witness cosigning
  - Apache Kafka                               — distributed log replication
  - etcd / Raft                                — leader election + consensus
  - PBFT                                       — Byzantine fault tolerance

Pipeline position:
    Phase 3 Verifiable Logs → [Phase 5] → Mahoragha Defense Engine
"""

from .consensus import ConsensusEngine, ConsensusResult, RaftLite
from .witness_node import WitnessNode, WitnessVerdict
from .log_gossip import LogGossip, GossipMessage
from .verification_cluster import VerificationCluster, ClusterReport

__all__ = [
    "ConsensusEngine",
    "ConsensusResult",
    "RaftLite",
    "WitnessNode",
    "WitnessVerdict",
    "LogGossip",
    "GossipMessage",
    "VerificationCluster",
    "ClusterReport",
]