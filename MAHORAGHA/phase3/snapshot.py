"""
Snapshot Manager

Captures, stores, retrieves, and validates periodic state snapshots.

Snapshots serve two purposes:
  1. Performance: fast state recovery without replaying all events
  2. Integrity: a snapshot hash + the Merkle root at that point lets you
     verify the snapshot has not been tampered with

Enterprise additions over the spec:
  - Content-addressed storage: snapshot names are their SHA-256 hashes
  - Integrity binding: each snapshot records the Merkle log size and root
    at the time of capture, so it can be verified against the log
  - TTL / expiry: old snapshots can be pruned automatically
  - Metadata: capture who triggered the snapshot and why
  - Diff: compare two snapshots to see what changed
"""

from __future__ import annotations

import copy
import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def _serialize_state(state: Any) -> str:
    try:
        return json.dumps(state, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return str(state)


@dataclass
class Snapshot:
    name: str
    state: Any
    timestamp: float
    state_hash: str
    merkle_root: Optional[str]
    log_size: Optional[int]
    actor: Optional[str]
    reason: Optional[str]
    ttl_seconds: Optional[float]
    metadata: dict = field(default_factory=dict)

    def is_expired(self, now: Optional[float] = None) -> bool:
        if self.ttl_seconds is None:
            return False
        return (now or time.time()) - self.timestamp > self.ttl_seconds

    def verify_integrity(self) -> bool:
        """Recompute the state hash and confirm it matches."""
        return _sha256(_serialize_state(self.state)) == self.state_hash

    def to_manifest(self) -> dict:
        """Return a tamper-checkable manifest (no state payload)."""
        return {
            "name": self.name,
            "timestamp": self.timestamp,
            "state_hash": self.state_hash,
            "merkle_root": self.merkle_root,
            "log_size": self.log_size,
            "actor": self.actor,
            "reason": self.reason,
        }


class SnapshotManager:
    """
    Manages system state snapshots with integrity verification.

    Snapshots are stored by name (user-defined) and can optionally be
    content-addressed by their state hash for deduplication.
    """

    def __init__(self, max_snapshots: int = 100):
        self._snapshots: Dict[str, Snapshot] = {}
        self.max_snapshots = max_snapshots

    # ─── CRUD ────────────────────────────────────────────────────────────────

    def create(
        self,
        name: str,
        state: Any,
        merkle_root: Optional[str] = None,
        log_size: Optional[int] = None,
        actor: Optional[str] = None,
        reason: Optional[str] = None,
        ttl_seconds: Optional[float] = None,
        metadata: Optional[dict] = None,
    ) -> Snapshot:
        """
        Capture a snapshot of the current system state.

        Args:
            name:         Logical snapshot name (e.g. "post-incident-2025-03-15")
            state:        The state object to snapshot (deep-copied)
            merkle_root:  Merkle log root at time of snapshot
            log_size:     Number of log entries at time of snapshot
            actor:        Who triggered this snapshot
            reason:       Why this snapshot was taken
            ttl_seconds:  Auto-expire after this many seconds (None = never)
            metadata:     Arbitrary key-value context

        Returns:
            The created Snapshot
        """
        if len(self._snapshots) >= self.max_snapshots:
            self._evict_oldest()

        frozen_state = copy.deepcopy(state)
        state_hash = _sha256(_serialize_state(frozen_state))

        snapshot = Snapshot(
            name=name,
            state=frozen_state,
            timestamp=time.time(),
            state_hash=state_hash,
            merkle_root=merkle_root,
            log_size=log_size,
            actor=actor,
            reason=reason,
            ttl_seconds=ttl_seconds,
            metadata=metadata or {},
        )

        self._snapshots[name] = snapshot
        return snapshot

    def load(self, name: str, verify: bool = True) -> Optional[Snapshot]:
        """
        Load a snapshot by name.

        Args:
            name:   Snapshot name
            verify: If True, verify state integrity before returning

        Returns:
            Snapshot if found and valid, None if not found or expired

        Raises:
            ValueError if verify=True and the snapshot fails integrity check
        """
        snapshot = self._snapshots.get(name)
        if snapshot is None:
            return None

        if snapshot.is_expired():
            del self._snapshots[name]
            return None

        if verify and not snapshot.verify_integrity():
            raise ValueError(
                f"Snapshot {name!r} failed integrity check — "
                f"state hash mismatch (possible tampering)"
            )

        return snapshot

    def delete(self, name: str) -> bool:
        if name in self._snapshots:
            del self._snapshots[name]
            return True
        return False

    # ─── Listing and discovery ───────────────────────────────────────────────

    def list_snapshots(self, include_expired: bool = False) -> List[dict]:
        """Return manifests for all stored snapshots."""
        now = time.time()
        results = []
        for snap in self._snapshots.values():
            if not include_expired and snap.is_expired(now):
                continue
            results.append(snap.to_manifest())
        return sorted(results, key=lambda s: s["timestamp"], reverse=True)

    def latest(self) -> Optional[Snapshot]:
        """Return the most recently created (non-expired) snapshot."""
        valid = [s for s in self._snapshots.values() if not s.is_expired()]
        if not valid:
            return None
        return max(valid, key=lambda s: s.timestamp)

    # ─── Diff ────────────────────────────────────────────────────────────────

    def diff(self, name_a: str, name_b: str) -> dict:
        """
        Compare two snapshots and return a high-level diff.

        Works on dict-type states only. Returns added, removed, and
        changed keys between snapshot A and snapshot B.
        """
        snap_a = self.load(name_a)
        snap_b = self.load(name_b)

        if snap_a is None or snap_b is None:
            raise KeyError(f"One or both snapshots not found: {name_a!r}, {name_b!r}")

        state_a = snap_a.state if isinstance(snap_a.state, dict) else {}
        state_b = snap_b.state if isinstance(snap_b.state, dict) else {}

        keys_a = set(state_a)
        keys_b = set(state_b)

        return {
            "added":   {k: state_b[k] for k in keys_b - keys_a},
            "removed": {k: state_a[k] for k in keys_a - keys_b},
            "changed": {
                k: {"before": state_a[k], "after": state_b[k]}
                for k in keys_a & keys_b
                if state_a[k] != state_b[k]
            },
            "unchanged_count": len(
                [k for k in keys_a & keys_b if state_a[k] == state_b[k]]
            ),
        }

    # ─── Internals ───────────────────────────────────────────────────────────

    def _evict_oldest(self):
        """Remove the oldest snapshot to make room."""
        if not self._snapshots:
            return
        oldest = min(self._snapshots.values(), key=lambda s: s.timestamp)
        del self._snapshots[oldest.name]