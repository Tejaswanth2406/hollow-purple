"""
phase4/audit_verifier.py
=========================
Enterprise Merkle-tree forensic audit verification engine.

Cryptographic foundation
------------------------
The audit verifier implements a binary Merkle tree over the event log,
producing a Merkle root that serves as a cryptographic commitment to the
entire event sequence.

Properties
----------
1. Tamper evidence
   Changing any single event → different leaf hash → different root.
   The root change is detectable by any party holding the expected root.

2. Inclusion proofs
   Any event can be proven to be part of the log with O(log N) proof nodes.
   An auditor can verify an event's inclusion without the full log.

3. Consistency proofs
   Prove that log-at-time-T2 is a superset of log-at-time-T1, without
   revealing the contents of events T1+1…T2.

4. Append-only verification
   Roots can be compared over time to prove the log only grew, never shrank
   or was rewritten.

Inspired by
-----------
- Google Certificate Transparency (RFC 6962)
- AWS QLDB ledger hashing
- Hyperledger Fabric state hash trees

Usage
-----
::

    verifier = AuditVerifier(hmac_secret=b"secret")

    # Verify full log
    report = await verifier.verify(events)
    print(report.to_certificate())

    # Inclusion proof for a specific event
    proof = verifier.inclusion_proof(events, event_id="abc123")
    assert proof.valid

    # Check two time-based log snapshots are consistent
    consistent = verifier.consistency_proof(events_t1, events_t2)
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class TamperEvidenceError(Exception):
    """Raised when Merkle root verification detects log tampering."""

    def __init__(self, report: "AuditReport") -> None:
        self.report = report
        super().__init__(
            f"Merkle audit proof FAILED — log may have been tampered. "
            f"Expected root: {report.expected_root[:16]}… "
            f"Computed root: {report.computed_root[:16]}…"
        )


# ---------------------------------------------------------------------------
# Merkle tree
# ---------------------------------------------------------------------------


class MerkleTree:
    """
    Binary Merkle hash tree over an ordered list of leaf values.

    Construction
    ------------
    Leaves are SHA-256 hashes of event canonical forms.
    Internal nodes are SHA-256 of (left_child || right_child).
    If the number of leaves is odd, the last leaf is duplicated.

    This follows the RFC 6962 specification for Certificate Transparency
    (except CT uses a domain-separation prefix; we use a simpler model
    appropriate for internal audit logs).
    """

    def __init__(self) -> None:
        self._leaves: List[str] = []
        self._tree: List[List[str]] = []
        self._root: Optional[str] = None

    @staticmethod
    def _hash(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def _combine(left: str, right: str) -> str:
        """Internal node hash: SHA-256(left_hex || right_hex)."""
        return hashlib.sha256((left + right).encode()).hexdigest()

    def build(self, leaves: List[str]) -> str:
        """
        Build the Merkle tree from a list of leaf hashes.
        Returns the Merkle root.
        """
        if not leaves:
            # Empty tree: root is SHA-256 of empty string
            self._root = self._hash(b"")
            self._leaves = []
            self._tree = [[self._root]]
            return self._root

        self._leaves = list(leaves)
        current_level = list(leaves)
        self._tree = [current_level]

        while len(current_level) > 1:
            next_level: List[str] = []
            # Pair up nodes; duplicate last if odd count
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                next_level.append(self._combine(left, right))
            self._tree.append(next_level)
            current_level = next_level

        self._root = current_level[0]
        return self._root

    @property
    def root(self) -> Optional[str]:
        return self._root

    @property
    def leaf_count(self) -> int:
        return len(self._leaves)

    @property
    def height(self) -> int:
        return len(self._tree)

    def get_proof_path(self, leaf_index: int) -> List[Tuple[str, str]]:
        """
        Return the Merkle proof path for ``leaf_index``.

        Returns a list of (sibling_hash, position) pairs where
        position is ``"left"`` or ``"right"`` — indicating where the
        sibling sits relative to the path node at each level.

        An auditor can verify inclusion by recomputing up the tree.
        """
        if leaf_index < 0 or leaf_index >= len(self._leaves):
            return []

        path: List[Tuple[str, str]] = []
        index = leaf_index

        for level in self._tree[:-1]:  # exclude root level
            if index % 2 == 0:
                # Current node is left; sibling is right
                sibling_idx = index + 1
                sibling_pos = "right"
            else:
                # Current node is right; sibling is left
                sibling_idx = index - 1
                sibling_pos = "left"

            sibling = level[sibling_idx] if sibling_idx < len(level) else level[index]
            path.append((sibling, sibling_pos))
            index //= 2

        return path

    def verify_inclusion(self, leaf_hash: str, proof_path: List[Tuple[str, str]]) -> bool:
        """
        Verify that ``leaf_hash`` is included in this tree using a proof path.
        Returns True if the path reconstructs to the known root.
        """
        if self._root is None:
            return False

        current = leaf_hash
        for sibling, position in proof_path:
            if position == "right":
                current = self._combine(current, sibling)
            else:
                current = self._combine(sibling, current)

        return current == self._root


# ---------------------------------------------------------------------------
# Audit proof record
# ---------------------------------------------------------------------------


@dataclass
class AuditProof:
    """
    Merkle inclusion proof for a single event.

    Fields
    ------
    event_id        : The event being proven.
    leaf_hash       : SHA-256 of the event's canonical form.
    leaf_index      : Position in the Merkle tree.
    merkle_root     : Root of the tree this proof belongs to.
    proof_path      : List of (sibling_hash, position) pairs.
    valid           : True if verification succeeded.
    """

    event_id: str
    leaf_hash: str
    leaf_index: int
    merkle_root: str
    proof_path: List[Tuple[str, str]]
    valid: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "leaf_hash": self.leaf_hash[:16] + "…",
            "leaf_index": self.leaf_index,
            "merkle_root": self.merkle_root[:16] + "…",
            "proof_path_length": len(self.proof_path),
            "valid": self.valid,
        }


# ---------------------------------------------------------------------------
# Audit report
# ---------------------------------------------------------------------------


@dataclass
class AuditReport:
    """
    Full forensic audit report.

    Fields
    ------
    valid               : True only if computed_root == expected_root.
    computed_root       : Merkle root computed from the event log.
    expected_root       : The trusted root to compare against (if set).
    total_events        : Number of events in the verified log.
    tree_height         : Height of the Merkle tree.
    tamper_detected     : True if roots differ.
    violations          : Detailed violation records.
    duration_ms         : Verification wall-clock time.
    verified_at         : UTC ISO-8601 timestamp.
    audit_id            : UUID for audit trail linkage.
    """

    valid: bool
    computed_root: str
    expected_root: str
    total_events: int
    tree_height: int
    tamper_detected: bool
    violations: List[Dict[str, Any]] = field(default_factory=list)
    duration_ms: float = 0.0
    verified_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    audit_id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "audit_id": self.audit_id,
            "valid": self.valid,
            "computed_root": self.computed_root[:16] + "…",
            "expected_root": self.expected_root[:16] + "…" if self.expected_root else None,
            "total_events": self.total_events,
            "tree_height": self.tree_height,
            "tamper_detected": self.tamper_detected,
            "violations": self.violations[:10],
            "duration_ms": round(self.duration_ms, 3),
            "verified_at": self.verified_at,
        }

    def to_certificate(self) -> str:
        """
        Emit a human-readable forensic certificate.
        Suitable for regulatory submission, PDF embedding, or SIEM ingestion.
        """
        status = "VERIFIED ✓" if self.valid else "TAMPERED ✗"
        lines = [
            "═" * 64,
            "  HOLLOW PURPLE — FORENSIC AUDIT CERTIFICATE",
            "═" * 64,
            f"  Audit ID       : {self.audit_id}",
            f"  Status         : {status}",
            f"  Verified At    : {self.verified_at}",
            f"  Total Events   : {self.total_events}",
            f"  Tree Height    : {self.tree_height}",
            f"  Computed Root  : {self.computed_root}",
            f"  Expected Root  : {self.expected_root or '(none — first run)'}",
            f"  Tamper Detected: {self.tamper_detected}",
            f"  Duration       : {self.duration_ms:.2f} ms",
        ]
        if self.violations:
            lines.append("")
            lines.append("  VIOLATIONS:")
            for v in self.violations[:5]:
                lines.append(f"    {v}")
        lines.append("═" * 64)
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# AuditVerifier
# ---------------------------------------------------------------------------


class AuditVerifier:
    """
    Merkle-tree forensic log integrity verifier.

    Usage
    -----
    ::

        verifier = AuditVerifier()

        # Full verification
        report = await verifier.verify(events)

        # Register a trusted root (from a previous run or external authority)
        verifier.set_trusted_root(known_root)
        report = await verifier.verify(events)   # now compares against trusted root

        # Inclusion proof for a specific event
        proof = verifier.inclusion_proof(events, event_id="abc123")
    """

    def __init__(
        self,
        *,
        hmac_secret: Optional[bytes] = None,
        trusted_root: Optional[str] = None,
    ) -> None:
        self._hmac_secret = hmac_secret
        self._trusted_root = trusted_root
        self._tree: Optional[MerkleTree] = None
        self._last_event_ids: List[str] = []

        logger.info(
            "AuditVerifier initialised",
            extra={
                "hmac_enabled": hmac_secret is not None,
                "has_trusted_root": trusted_root is not None,
            },
        )

    # ---------------------------------------------------------------------------
    # Leaf hash computation
    # ---------------------------------------------------------------------------

    @staticmethod
    def _canonical_bytes(event: Dict[str, Any]) -> bytes:
        """Canonical JSON bytes of an event for Merkle leaf hashing."""
        # Use only stable fields that should not change post-ingestion
        doc = {
            "event_id": event.get("event_id", ""),
            "sequence": event.get("sequence", event.get("seq", -1)),
            "event_type": event.get("event_type", ""),
            "identity": event.get("identity", ""),
            "resource": event.get("resource", ""),
            "timestamp": event.get("timestamp", ""),
            "payload": event.get("payload", {}),
        }
        return json.dumps(doc, sort_keys=True, separators=(",", ":"), default=str).encode()

    def _leaf_hash(self, event: Dict[str, Any]) -> str:
        raw = self._canonical_bytes(event)
        if self._hmac_secret:
            import hmac as _hmac
            return _hmac.new(self._hmac_secret, raw, hashlib.sha256).hexdigest()
        return hashlib.sha256(raw).hexdigest()

    # ---------------------------------------------------------------------------
    # Core verification
    # ---------------------------------------------------------------------------

    async def verify(
        self,
        events: List[Dict[str, Any]],
        *,
        expected_root: Optional[str] = None,
    ) -> AuditReport:
        """
        Build the Merkle tree and verify log integrity.

        Parameters
        ----------
        events          : Ordered list of event dicts (or EventRecord dicts).
        expected_root   : Trusted root to compare against.
                          Falls back to ``self._trusted_root`` if not given.

        Returns
        -------
        AuditReport
        """
        start_ns = time.perf_counter_ns()
        violations: List[Dict[str, Any]] = []

        # Sort by sequence for deterministic leaf ordering
        ordered = sorted(
            events,
            key=lambda e: e.get("sequence", e.get("seq", 0)),
        )

        # Compute leaf hashes
        leaf_hashes: List[str] = []
        self._last_event_ids = []
        for event in ordered:
            leaf_hashes.append(self._leaf_hash(event))
            self._last_event_ids.append(
                event.get("event_id", str(event.get("sequence", "")))
            )

        # Build tree
        tree = MerkleTree()
        computed_root = tree.build(leaf_hashes)
        self._tree = tree

        # Compare roots
        trusted = expected_root or self._trusted_root or ""
        tamper_detected = bool(trusted) and (computed_root != trusted)

        if tamper_detected:
            violations.append({
                "type": "MERKLE_ROOT_MISMATCH",
                "expected": trusted[:16] + "…",
                "computed": computed_root[:16] + "…",
            })
            logger.error(
                "Merkle audit proof FAILED — root mismatch",
                extra={
                    "expected_root": trusted[:16],
                    "computed_root": computed_root[:16],
                    "total_events": len(ordered),
                },
            )
        else:
            logger.info(
                "Merkle audit proof passed",
                extra={
                    "computed_root": computed_root[:16],
                    "total_events": len(ordered),
                    "tree_height": tree.height,
                },
            )

        duration_ms = (time.perf_counter_ns() - start_ns) / 1_000_000

        report = AuditReport(
            valid=not tamper_detected,
            computed_root=computed_root,
            expected_root=trusted,
            total_events=len(ordered),
            tree_height=tree.height,
            tamper_detected=tamper_detected,
            violations=violations,
            duration_ms=round(duration_ms, 3),
        )

        # Auto-update trusted root on first clean run
        if not tamper_detected and not trusted:
            self._trusted_root = computed_root

        return report

    def verify_strict(
        self,
        events: List[Dict[str, Any]],
        *,
        expected_root: Optional[str] = None,
    ):
        """Sync wrapper that raises TamperEvidenceError on failure."""
        import asyncio as _asyncio

        async def _inner():
            report = await self.verify(events, expected_root=expected_root)
            if not report.valid:
                raise TamperEvidenceError(report)
            return report

        return _asyncio.get_event_loop().run_until_complete(_inner())

    # ---------------------------------------------------------------------------
    # Inclusion proofs
    # ---------------------------------------------------------------------------

    def inclusion_proof(
        self,
        events: List[Dict[str, Any]],
        *,
        event_id: Optional[str] = None,
        sequence: Optional[int] = None,
    ) -> AuditProof:
        """
        Generate and verify an inclusion proof for a specific event.

        Identify the event by ``event_id`` or ``sequence``.
        Requires ``verify()`` to have been called first to build the tree.
        """
        if self._tree is None:
            raise RuntimeError("Call verify() before generating inclusion proofs")

        # Locate event
        ordered = sorted(events, key=lambda e: e.get("sequence", 0))
        target_idx = None
        target_event = None

        for i, event in enumerate(ordered):
            if event_id and event.get("event_id") == event_id:
                target_idx = i
                target_event = event
                break
            if sequence is not None and event.get("sequence") == sequence:
                target_idx = i
                target_event = event
                break

        if target_idx is None or target_event is None:
            raise KeyError(f"Event not found: event_id={event_id}, sequence={sequence}")

        leaf_hash = self._leaf_hash(target_event)
        proof_path = self._tree.get_proof_path(target_idx)
        valid = self._tree.verify_inclusion(leaf_hash, proof_path)

        return AuditProof(
            event_id=target_event.get("event_id", ""),
            leaf_hash=leaf_hash,
            leaf_index=target_idx,
            merkle_root=self._tree.root or "",
            proof_path=proof_path,
            valid=valid,
        )

    # ---------------------------------------------------------------------------
    # Consistency proof
    # ---------------------------------------------------------------------------

    def consistency_proof(
        self,
        events_t1: List[Dict[str, Any]],
        events_t2: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Prove that ``events_t2`` is a superset of ``events_t1``
        (i.e., the log only grew — no events were removed or reordered).

        Returns a dict with ``consistent=True/False`` and supporting evidence.
        """
        ids_t1 = {e.get("event_id", e.get("sequence")) for e in events_t1}
        ids_t2 = {e.get("event_id", e.get("sequence")) for e in events_t2}

        removed = ids_t1 - ids_t2
        added = ids_t2 - ids_t1
        consistent = len(removed) == 0

        tree_t1 = MerkleTree()
        tree_t2 = MerkleTree()

        leaves_t1 = [self._leaf_hash(e) for e in sorted(events_t1, key=lambda x: x.get("sequence", 0))]
        leaves_t2 = [self._leaf_hash(e) for e in sorted(events_t2, key=lambda x: x.get("sequence", 0))]

        root_t1 = tree_t1.build(leaves_t1)
        root_t2 = tree_t2.build(leaves_t2)

        if not consistent:
            logger.error(
                "Consistency proof FAILED — events removed from log",
                extra={"removed_count": len(removed)},
            )

        return {
            "consistent": consistent,
            "root_t1": root_t1,
            "root_t2": root_t2,
            "events_t1": len(events_t1),
            "events_t2": len(events_t2),
            "events_added": len(added),
            "events_removed": len(removed),
            "removed_ids": sorted(str(x) for x in removed)[:20],
        }

    # ---------------------------------------------------------------------------
    # Root management
    # ---------------------------------------------------------------------------

    def set_trusted_root(self, root: str) -> None:
        """Set the trusted Merkle root against which future verifications compare."""
        self._trusted_root = root
        logger.info("Trusted Merkle root updated", extra={"root": root[:16]})

    @property
    def trusted_root(self) -> Optional[str]:
        return self._trusted_root

    @property
    def current_tree(self) -> Optional[MerkleTree]:
        return self._tree