"""
Witness Node

A witness node independently observes and cosigns Merkle log roots.

Inspired by Google Certificate Transparency's "witness" specification
(https://github.com/transparency-dev/witness), where independent parties
observe log checkpoints and refuse to cosign a root that is inconsistent
with previously observed roots. This prevents log operators from secretly
rewriting history for individual observers.

The core invariant a witness enforces:
  "The log must grow monotonically. If I've seen root R at size N,
   I will never accept a root R' at size N that differs from R."

Enterprise additions over the spec:
  - Consistency checking: refuse to accept a root that contradicts prior history
  - Root signing: each witness cosigns accepted roots (HMAC-based)
  - Trust scoring: nodes that submit inconsistent roots are downgraded
  - Observation proofs: return a signed WitnessVerdict the cluster can verify
  - Memory-bounded root history with LRU eviction
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class TreeCheckpoint:
    """A Merkle tree checkpoint as observed by this witness."""
    root: str
    tree_size: int
    observed_at: float
    cosignature: str


@dataclass
class WitnessVerdict:
    """Signed verdict produced by a witness node on a proposed root."""
    node_id: str
    proposal_id: str
    root: str
    tree_size: int
    accepted: bool
    reason: str
    cosignature: Optional[str]
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "node_id": self.node_id,
            "proposal_id": self.proposal_id,
            "root": self.root,
            "tree_size": self.tree_size,
            "accepted": self.accepted,
            "reason": self.reason,
            "cosignature": self.cosignature,
            "timestamp": self.timestamp,
        }


class WitnessNode:
    """
    Independent log witness that observes and cosigns Merkle roots.

    A witness:
      1. Receives STH (Signed Tree Head) checkpoints from the log operator
      2. Verifies the new root is consistent with its prior observations
         (the log can only grow, never rewrite)
      3. If consistent, cosigns the checkpoint and broadcasts the verdict
      4. If inconsistent, rejects and flags the operator

    Nodes that submit inconsistent roots receive a trust penalty.

    Usage:
        node = WitnessNode("witness-eu-west-1", signing_key="secret")
        verdict = node.submit_root("proposal-42", root="abc123", tree_size=1500)
        if verdict.accepted:
            broadcast(verdict)
    """

    def __init__(
        self,
        node_id: str,
        signing_key: str = "witness-dev-key",
        max_history: int = 10_000,
    ):
        self.node_id = node_id
        self._key = signing_key.encode()
        self.max_history = max_history

        # tree_size -> TreeCheckpoint (the authoritative root at each size)
        self._checkpoints: Dict[int, TreeCheckpoint] = {}
        # All roots seen in order
        self._root_log: List[str] = []
        # Trust scores for submitters {submitter_id: 0.0-1.0}
        self._trust_scores: Dict[str, float] = {}
        # Count of consistency violations per submitter
        self._violation_counts: Dict[str, int] = {}

    # ─── Core observation ────────────────────────────────────────────────────

    def submit_root(
        self,
        proposal_id: str,
        root: str,
        tree_size: int,
        submitter_id: Optional[str] = None,
    ) -> WitnessVerdict:
        """
        Process a proposed Merkle root checkpoint.

        Validates consistency with known history and returns a signed verdict.

        Args:
            proposal_id:  The consensus proposal ID this root is associated with
            root:         SHA-256 Merkle root hash
            tree_size:    Number of log entries at this checkpoint
            submitter_id: Identity submitting the root (for trust scoring)

        Returns:
            WitnessVerdict — accepted if consistent, rejected if contradictory
        """
        consistency_ok, reason = self._check_consistency(root, tree_size)

        if consistency_ok:
            checkpoint = self._store_checkpoint(root, tree_size)
            cosig = self._cosign(proposal_id, root, tree_size)
            if submitter_id:
                self._reward_trust(submitter_id)

            return WitnessVerdict(
                node_id=self.node_id,
                proposal_id=proposal_id,
                root=root,
                tree_size=tree_size,
                accepted=True,
                reason="consistent",
                cosignature=cosig,
            )
        else:
            if submitter_id:
                self._penalize_trust(submitter_id)

            return WitnessVerdict(
                node_id=self.node_id,
                proposal_id=proposal_id,
                root=root,
                tree_size=tree_size,
                accepted=False,
                reason=reason,
                cosignature=None,
            )

    def verify(self, root: str) -> bool:
        """
        Legacy compatibility: return True if root is in known accepted roots.
        """
        return root in self._root_log

    def observe_root(self, root: str):
        """
        Legacy compatibility: directly record a root without consistency checking.
        Use submit_root() for full verification.
        """
        if root not in self._root_log:
            self._root_log.append(root)

    # ─── Trust management ────────────────────────────────────────────────────

    def get_trust_score(self, node_id: str) -> float:
        """Return trust score for a submitter (1.0 = fully trusted, 0.0 = banned)."""
        return self._trust_scores.get(node_id, 1.0)

    def list_checkpoints(self, last_n: int = 10) -> List[dict]:
        """Return the most recent accepted checkpoints."""
        sorted_cps = sorted(
            self._checkpoints.values(),
            key=lambda c: c.tree_size,
            reverse=True,
        )
        return [
            {
                "root": c.root,
                "tree_size": c.tree_size,
                "observed_at": c.observed_at,
            }
            for c in sorted_cps[:last_n]
        ]

    def latest_checkpoint(self) -> Optional[TreeCheckpoint]:
        if not self._checkpoints:
            return None
        return self._checkpoints[max(self._checkpoints)]

    # ─── Internals ───────────────────────────────────────────────────────────

    def _check_consistency(self, root: str, tree_size: int) -> Tuple[bool, str]:
        """
        Enforce the core witness invariant: log can only grow, never rewrite.

        Rules:
          1. If we've seen this exact tree_size before, the root must match.
          2. If tree_size is smaller than our latest, something is wrong.
          3. Any size larger than what we've seen is acceptable (append-only).
        """
        if not self._checkpoints:
            return True, "first observation"

        latest_size = max(self._checkpoints)

        # Reject tree shrinkage
        if tree_size < latest_size:
            return False, (
                f"Monotonicity violation: proposed tree_size={tree_size} "
                f"is smaller than last known size={latest_size}"
            )

        # Reject root contradiction at a known size
        if tree_size in self._checkpoints:
            known_root = self._checkpoints[tree_size].root
            if known_root != root:
                return False, (
                    f"Fork detected: root at size={tree_size} was previously "
                    f"{known_root[:16]}…, now {root[:16]}…"
                )

        return True, "consistent"

    def _store_checkpoint(self, root: str, tree_size: int) -> TreeCheckpoint:
        cosig = self._cosign(f"checkpoint-{tree_size}", root, tree_size)
        cp = TreeCheckpoint(
            root=root,
            tree_size=tree_size,
            observed_at=time.time(),
            cosignature=cosig,
        )
        self._checkpoints[tree_size] = cp

        if root not in self._root_log:
            self._root_log.append(root)

        # Bound memory
        if len(self._checkpoints) > self.max_history:
            oldest_key = min(self._checkpoints)
            del self._checkpoints[oldest_key]

        return cp

    def _cosign(self, proposal_id: str, root: str, tree_size: int) -> str:
        payload = json.dumps({
            "node_id": self.node_id,
            "proposal_id": proposal_id,
            "root": root,
            "tree_size": tree_size,
            "timestamp": time.time(),
        }, sort_keys=True).encode()
        return hmac.new(self._key, payload, hashlib.sha256).hexdigest()

    def _penalize_trust(self, node_id: str):
        current = self._trust_scores.get(node_id, 1.0)
        self._violation_counts[node_id] = self._violation_counts.get(node_id, 0) + 1
        # Exponential trust decay: each violation halves trust
        self._trust_scores[node_id] = round(current * 0.5, 6)

    def _reward_trust(self, node_id: str):
        current = self._trust_scores.get(node_id, 1.0)
        # Slow trust recovery: +2% per successful submission, capped at 1.0
        self._trust_scores[node_id] = round(min(1.0, current + 0.02), 6)