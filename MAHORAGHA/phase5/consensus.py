"""
Consensus Engine

Provides quorum-based agreement over distributed verification proposals.

Two implementations are provided:

1. ConsensusEngine — Simple weighted quorum voting suitable for
   synchronous verification clusters. Each node casts one vote (or a
   weighted vote) on a proposal; a proposal passes when enough positive
   votes accumulate to meet the quorum threshold.

2. RaftLite — A simplified single-round Raft-inspired leader election
   and term-based log commitment. Not a full Raft implementation, but
   captures the critical invariants: a leader can only commit an entry
   once a majority of nodes acknowledge it, and terms are strictly
   monotonic so stale leaders cannot commit.

Enterprise additions over the spec:
  - Weighted votes (nodes can have different trust weights)
  - Vote expiry (stale votes don't count toward quorum)
  - Proposal lifecycle: PENDING → ACCEPTED | REJECTED | EXPIRED
  - Conflict detection: identify split-vote and equivocation scenarios
  - RaftLite: term-based leader election with monotonic term enforcement
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set


class ProposalStatus(str, Enum):
    PENDING  = "pending"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    EXPIRED  = "expired"


@dataclass
class Vote:
    node_id: str
    decision: bool
    weight: float
    timestamp: float = field(default_factory=time.time)


@dataclass
class ConsensusResult:
    proposal_id: str
    status: ProposalStatus
    positive_weight: float
    total_weight: float
    quorum_required: float
    votes: Dict[str, Vote]
    conflicting_nodes: List[str]   # nodes that changed their vote

    @property
    def passed(self) -> bool:
        return self.status == ProposalStatus.ACCEPTED

    @property
    def participation_rate(self) -> float:
        return self.total_weight / max(self.quorum_required, 1e-9)


class ConsensusEngine:
    """
    Weighted quorum consensus over distributed verification proposals.

    A proposal is ACCEPTED when the sum of positive vote weights
    meets or exceeds quorum_threshold (fraction of total registered weight).

    Example:
        engine = ConsensusEngine(quorum_threshold=0.67)  # 2/3 majority
        engine.register_node("node-1", weight=1.0)
        engine.register_node("node-2", weight=1.0)
        engine.register_node("node-3", weight=1.5)       # higher-trust node

        engine.vote("root-abc123", "node-1", True)
        engine.vote("root-abc123", "node-2", True)
        result = engine.result("root-abc123")
        # passed=True if 2 positive votes >= 67% of total weight
    """

    def __init__(
        self,
        quorum_size: int = 3,          # min number of positive votes (simple mode)
        quorum_threshold: float = 0.0, # fraction of total weight (weighted mode)
        vote_ttl_seconds: float = 300.0,
    ):
        """
        Args:
            quorum_size:       Minimum raw positive vote count (used if quorum_threshold=0)
            quorum_threshold:  Fraction of total registered weight required (0.0 = use quorum_size)
            vote_ttl_seconds:  Votes older than this are excluded from quorum calculation
        """
        self.quorum_size = quorum_size
        self.quorum_threshold = quorum_threshold
        self.vote_ttl = vote_ttl_seconds

        # {node_id: weight}
        self._node_weights: Dict[str, float] = {}
        # {proposal_id: {node_id: Vote}}
        self._votes: Dict[str, Dict[str, Vote]] = {}
        # Track vote changes for conflict detection
        self._vote_changes: Dict[str, Dict[str, List[bool]]] = {}

    # ─── Node management ─────────────────────────────────────────────────────

    def register_node(self, node_id: str, weight: float = 1.0):
        """Register a voting node with an optional trust weight."""
        self._node_weights[node_id] = weight

    def deregister_node(self, node_id: str):
        self._node_weights.pop(node_id, None)

    @property
    def total_registered_weight(self) -> float:
        return sum(self._node_weights.values())

    # ─── Voting ──────────────────────────────────────────────────────────────

    def vote(self, proposal_id: str, node_id: str, decision: bool):
        """
        Cast or update a vote for a proposal.

        Args:
            proposal_id: The Merkle root or state hash being voted on
            node_id:     Voting node identifier
            decision:    True = accepts the root, False = rejects
        """
        weight = self._node_weights.get(node_id, 1.0)

        if proposal_id not in self._votes:
            self._votes[proposal_id] = {}
            self._vote_changes[proposal_id] = {}

        existing = self._votes[proposal_id].get(node_id)

        # Track vote changes (equivocation indicator)
        if existing is not None and existing.decision != decision:
            self._vote_changes[proposal_id].setdefault(node_id, [existing.decision])
            self._vote_changes[proposal_id][node_id].append(decision)

        self._votes[proposal_id][node_id] = Vote(
            node_id=node_id,
            decision=decision,
            weight=weight,
        )

    # ─── Result computation ──────────────────────────────────────────────────

    def result(self, proposal_id: str, now: Optional[float] = None) -> ConsensusResult:
        """
        Compute the current consensus result for a proposal.

        Expired votes are excluded. The proposal is ACCEPTED if:
          - (quorum_threshold > 0) positive weight / total weight >= threshold
          - (quorum_threshold == 0) positive vote count >= quorum_size
        """
        now = now or time.time()
        cutoff = now - self.vote_ttl
        votes = self._votes.get(proposal_id, {})

        valid_votes = {
            nid: v for nid, v in votes.items() if v.timestamp >= cutoff
        }

        positive_weight = sum(v.weight for v in valid_votes.values() if v.decision)
        total_weight = sum(v.weight for v in valid_votes.values())

        if self.quorum_threshold > 0:
            threshold_weight = self.total_registered_weight * self.quorum_threshold
            accepted = positive_weight >= threshold_weight
            quorum_required = threshold_weight
        else:
            positive_count = sum(1 for v in valid_votes.values() if v.decision)
            accepted = positive_count >= self.quorum_size
            quorum_required = float(self.quorum_size)

        conflicting = list(self._vote_changes.get(proposal_id, {}).keys())

        status = ProposalStatus.ACCEPTED if accepted else (
            ProposalStatus.REJECTED if valid_votes else ProposalStatus.PENDING
        )

        return ConsensusResult(
            proposal_id=proposal_id,
            status=status,
            positive_weight=round(positive_weight, 4),
            total_weight=round(total_weight, 4),
            quorum_required=round(quorum_required, 4),
            votes=valid_votes,
            conflicting_nodes=conflicting,
        )

    def pending_proposals(self) -> List[str]:
        """Return all proposal IDs that haven't yet reached quorum."""
        return [
            pid for pid in self._votes
            if not self.result(pid).passed
        ]

    def clear_proposal(self, proposal_id: str):
        """Remove all votes for a closed proposal (memory management)."""
        self._votes.pop(proposal_id, None)
        self._vote_changes.pop(proposal_id, None)


# ─── RaftLite ─────────────────────────────────────────────────────────────────

@dataclass
class LogEntry:
    index: int
    term: int
    value: str          # Merkle root or state hash
    committed: bool = False


class RaftLite:
    """
    Simplified Raft-inspired consensus for term-based log commitment.

    NOT a complete Raft implementation (no network, no persistence, no
    real RPC). Captures the critical safety invariants:

    1. A leader can only be elected by a majority of nodes.
    2. A log entry is committed only when a majority acknowledges it.
    3. Terms are strictly monotonic — stale leaders cannot commit.
    4. An entry from a previous term is never directly committed
       (it is committed implicitly when a current-term entry commits).

    Suitable for testing consensus logic and understanding the protocol
    before integrating a production Raft library (e.g. python-raft, etcd).
    """

    def __init__(self, node_ids: List[str], node_id: str):
        self.node_id = node_id
        self.all_nodes: Set[str] = set(node_ids)
        self.quorum = len(node_ids) // 2 + 1

        # Persistent state (would survive restarts in production)
        self.current_term: int = 0
        self.voted_for: Optional[str] = None
        self.log: List[LogEntry] = []

        # Volatile state
        self.role: str = "follower"   # follower | candidate | leader
        self.leader_id: Optional[str] = None
        self.commit_index: int = -1
        self.last_applied: int = -1

        # Leader state
        self._next_index: Dict[str, int] = {}
        self._match_index: Dict[str, int] = {}
        self._vote_grants: Set[str] = set()

    @property
    def majority(self) -> int:
        return self.quorum

    # ─── Election ────────────────────────────────────────────────────────────

    def start_election(self) -> int:
        """
        Begin a new election. Returns the new term.
        The node votes for itself and requests votes from peers.
        """
        self.current_term += 1
        self.role = "candidate"
        self.voted_for = self.node_id
        self._vote_grants = {self.node_id}
        return self.current_term

    def receive_vote(self, from_node: str, term: int, granted: bool) -> Optional[str]:
        """
        Process an incoming vote response.

        Returns "leader" if this node has won the election, else None.
        """
        if term < self.current_term:
            return None   # Stale vote response — ignore

        if term > self.current_term:
            self._step_down(term)
            return None

        if granted and self.role == "candidate":
            self._vote_grants.add(from_node)
            if len(self._vote_grants) >= self.majority:
                self._become_leader()
                return "leader"

        return None

    def request_vote(self, candidate_id: str, candidate_term: int, last_log_index: int, last_log_term: int) -> bool:
        """
        Process a RequestVote RPC. Returns True if vote is granted.

        Grant vote iff:
          1. candidate_term >= current_term
          2. This node hasn't voted for someone else this term
          3. Candidate's log is at least as up-to-date as ours
        """
        if candidate_term < self.current_term:
            return False

        if candidate_term > self.current_term:
            self._step_down(candidate_term)

        already_voted = (
            self.voted_for is not None and self.voted_for != candidate_id
        )
        if already_voted:
            return False

        our_last_term = self.log[-1].term if self.log else 0
        our_last_index = len(self.log) - 1

        log_ok = (
            candidate_term > our_last_term
            or (candidate_term == our_last_term and last_log_index >= our_last_index)
        )
        if not log_ok:
            return False

        self.voted_for = candidate_id
        return True

    # ─── Log replication ─────────────────────────────────────────────────────

    def append_entry(self, value: str) -> Optional[LogEntry]:
        """
        Leader appends a new entry to its local log.
        Returns the entry (which must then be replicated to peers).
        """
        if self.role != "leader":
            return None

        entry = LogEntry(
            index=len(self.log),
            term=self.current_term,
            value=value,
        )
        self.log.append(entry)
        return entry

    def receive_ack(self, from_node: str, match_index: int) -> bool:
        """
        Process an AppendEntries acknowledgment from a follower.

        Returns True if a new entry can be committed (majority ack'd it).
        """
        if self.role != "leader":
            return False

        self._match_index[from_node] = match_index
        self._match_index[self.node_id] = len(self.log) - 1

        # Find highest index acknowledged by majority
        match_indices = sorted(self._match_index.values(), reverse=True)
        new_commit = match_indices[self.majority - 1]

        if new_commit > self.commit_index and self.log[new_commit].term == self.current_term:
            # Commit all entries up to new_commit
            for i in range(self.commit_index + 1, new_commit + 1):
                self.log[i].committed = True
            self.commit_index = new_commit
            return True

        return False

    # ─── Internals ───────────────────────────────────────────────────────────

    def _become_leader(self):
        self.role = "leader"
        self.leader_id = self.node_id
        self._next_index = {n: len(self.log) for n in self.all_nodes}
        self._match_index = {n: -1 for n in self.all_nodes}

    def _step_down(self, new_term: int):
        self.current_term = new_term
        self.role = "follower"
        self.voted_for = None
        self._vote_grants = set()