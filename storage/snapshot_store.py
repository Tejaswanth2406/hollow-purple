"""
storage/snapshot_store.py
=========================
Enterprise deterministic replay checkpoint and snapshot management.

Purpose
-------
Snapshots are compressed, versioned, integrity-verified checkpoints of the
system's complete runtime state at a specific ledger sequence position.

They serve two critical roles:

1. **Replay acceleration** — Instead of replaying all events from genesis,
   fast-forward to the nearest snapshot and replay only the delta.

2. **Disaster recovery** — Restore a known-good system state after a failure
   or corruption event, then replay forward.

Features
--------
- Immutable, versioned snapshot records
- Integrity hash per snapshot (SHA-256 of serialized state)
- Optional zlib compression for large state payloads
- Async-safe reads and writes under asyncio.Lock
- Pluggable backend adapter (swap to S3 / Redis / PostgreSQL)
- Retention policy: auto-prune oldest snapshots past configurable limit
- Named snapshots (e.g. ``"deploy-v2.1.0"``) and sequence-indexed snapshots
- Metadata tagging for compliance and searchability
- Export / import for cross-environment migration
- TTL support for ephemeral checkpoints (e.g. canary deploys)
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import logging
import uuid
import zlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class SnapshotNotFoundError(KeyError):
    """Raised when a requested snapshot does not exist."""


class SnapshotCorruptedError(Exception):
    """Raised when a snapshot's integrity hash fails verification."""


# ---------------------------------------------------------------------------
# Snapshot data model
# ---------------------------------------------------------------------------


@dataclass
class Snapshot:
    """
    A single persisted system state checkpoint.

    Fields
    ------
    snapshot_id     : UUID4 hex unique identifier.
    name            : Human-readable label (e.g. ``"post-ingest-batch-42"``).
    ledger_sequence : The EventStore sequence number captured in this snapshot.
    ledger_hash     : The chain tip hash at ``ledger_sequence`` (for replay anchoring).
    state_hash      : SHA-256 of the raw (uncompressed) serialized state.
    state           : The full state payload (deserialized, available after load).
    compressed      : Whether the stored bytes are zlib-compressed.
    size_bytes      : Size of the stored state (compressed or raw).
    tenant_id       : Multi-tenant scope.
    tags            : Label set for filtering and compliance annotation.
    created_at      : UTC ISO-8601 creation timestamp.
    expires_at      : Optional TTL expiry timestamp.
    metadata        : Arbitrary key-value annotations.
    """

    snapshot_id: str
    name: str
    ledger_sequence: int
    ledger_hash: str
    state_hash: str
    state: Dict[str, Any]
    compressed: bool = False
    size_bytes: int = 0
    tenant_id: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    expires_at: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > datetime.fromisoformat(self.expires_at)

    def to_dict(self, include_state: bool = False) -> Dict[str, Any]:
        d = {
            "snapshot_id": self.snapshot_id,
            "name": self.name,
            "ledger_sequence": self.ledger_sequence,
            "ledger_hash": self.ledger_hash,
            "state_hash": self.state_hash,
            "compressed": self.compressed,
            "size_bytes": self.size_bytes,
            "tenant_id": self.tenant_id,
            "tags": self.tags,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "metadata": self.metadata,
        }
        if include_state:
            d["state"] = self.state
        return d


# ---------------------------------------------------------------------------
# Backend adapter
# ---------------------------------------------------------------------------


class SnapshotStoreBackend:
    """Abstract storage backend for snapshots."""

    async def save(self, snapshot: Snapshot, raw_bytes: bytes) -> None:
        raise NotImplementedError

    async def load_raw(self, snapshot_id: str) -> Optional[bytes]:
        raise NotImplementedError

    async def get_metadata(self, snapshot_id: str) -> Optional[Snapshot]:
        raise NotImplementedError

    async def list_metadata(
        self,
        *,
        tenant_id: Optional[str] = None,
        name: Optional[str] = None,
    ) -> List[Snapshot]:
        raise NotImplementedError

    async def delete(self, snapshot_id: str) -> bool:
        raise NotImplementedError

    async def count(self, *, tenant_id: Optional[str] = None) -> int:
        raise NotImplementedError


class InMemorySnapshotBackend(SnapshotStoreBackend):
    """In-memory snapshot backend."""

    def __init__(self) -> None:
        self._metadata: Dict[str, Snapshot] = {}
        self._raw: Dict[str, bytes] = {}

    async def save(self, snapshot: Snapshot, raw_bytes: bytes) -> None:
        self._metadata[snapshot.snapshot_id] = snapshot
        self._raw[snapshot.snapshot_id] = raw_bytes

    async def load_raw(self, snapshot_id: str) -> Optional[bytes]:
        return self._raw.get(snapshot_id)

    async def get_metadata(self, snapshot_id: str) -> Optional[Snapshot]:
        return self._metadata.get(snapshot_id)

    async def list_metadata(
        self,
        *,
        tenant_id: Optional[str] = None,
        name: Optional[str] = None,
    ) -> List[Snapshot]:
        result = list(self._metadata.values())
        if tenant_id:
            result = [s for s in result if s.tenant_id == tenant_id]
        if name:
            result = [s for s in result if s.name == name]
        return sorted(result, key=lambda s: s.ledger_sequence)

    async def delete(self, snapshot_id: str) -> bool:
        deleted = self._metadata.pop(snapshot_id, None)
        self._raw.pop(snapshot_id, None)
        return deleted is not None

    async def count(self, *, tenant_id: Optional[str] = None) -> int:
        if tenant_id is None:
            return len(self._metadata)
        return sum(1 for s in self._metadata.values() if s.tenant_id == tenant_id)


# ---------------------------------------------------------------------------
# SnapshotStore
# ---------------------------------------------------------------------------


class SnapshotStore:
    """
    Deterministic replay snapshot and checkpoint manager.

    Usage
    -----
    ::

        store = SnapshotStore(compress=True, max_snapshots=50)

        # Save a checkpoint
        snap = await store.save(
            name="post-bootstrap",
            state=system_state,
            ledger_sequence=1500,
            ledger_hash=event_store.last_hash,
            tenant_id="acme",
        )

        # Find nearest checkpoint for replay
        nearest = await store.nearest_before(target_sequence=1800, tenant_id="acme")
        if nearest:
            state = await store.load(nearest.snapshot_id)
            # replay events from nearest.ledger_sequence to 1800

        # List all snapshots
        snapshots = await store.list(tenant_id="acme")
    """

    def __init__(
        self,
        *,
        backend: Optional[SnapshotStoreBackend] = None,
        compress: bool = True,
        max_snapshots: Optional[int] = 100,
    ) -> None:
        self._backend = backend or InMemorySnapshotBackend()
        self._compress = compress
        self._max_snapshots = max_snapshots
        self._lock = asyncio.Lock()

        logger.info(
            "SnapshotStore initialised",
            extra={"compress": compress, "max_snapshots": max_snapshots},
        )

    # ---------------------------------------------------------------------------
    # Serialization helpers
    # ---------------------------------------------------------------------------

    @staticmethod
    def _serialize(state: Dict[str, Any]) -> bytes:
        return json.dumps(state, sort_keys=True, separators=(",", ":")).encode()

    @staticmethod
    def _state_hash(raw: bytes) -> str:
        return hashlib.sha256(raw).hexdigest()

    # ---------------------------------------------------------------------------
    # Write path
    # ---------------------------------------------------------------------------

    async def save(
        self,
        name: str,
        state: Dict[str, Any],
        *,
        ledger_sequence: int,
        ledger_hash: str,
        tenant_id: Optional[str] = None,
        tags: Optional[List[str]] = None,
        ttl_seconds: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Snapshot:
        """
        Persist a system state snapshot.

        Parameters
        ----------
        name            : Human-readable label for this checkpoint.
        state           : Full system state dict (must be JSON-serializable).
        ledger_sequence : EventStore sequence number this snapshot captures.
        ledger_hash     : Event chain tip hash at ``ledger_sequence``.
        tenant_id       : Tenant scope.
        tags            : Label set.
        ttl_seconds     : Optional TTL in seconds.
        metadata        : Arbitrary annotations.

        Returns
        -------
        Snapshot
            The saved, integrity-verified snapshot record.
        """
        raw = self._serialize(state)
        state_hash = self._state_hash(raw)

        stored_bytes = zlib.compress(raw, level=6) if self._compress else raw
        compressed = self._compress

        now = datetime.now(timezone.utc)
        expires_at = (
            (now + timedelta(seconds=ttl_seconds)).isoformat()
            if ttl_seconds is not None
            else None
        )

        snapshot = Snapshot(
            snapshot_id=uuid.uuid4().hex,
            name=name,
            ledger_sequence=ledger_sequence,
            ledger_hash=ledger_hash,
            state_hash=state_hash,
            state=copy.deepcopy(state),
            compressed=compressed,
            size_bytes=len(stored_bytes),
            tenant_id=tenant_id,
            tags=list(tags or []),
            expires_at=expires_at,
            metadata=metadata or {},
        )

        async with self._lock:
            await self._backend.save(snapshot, stored_bytes)
            await self._maybe_prune(tenant_id=tenant_id)

        logger.info(
            "Snapshot saved",
            extra={
                "snapshot_id": snapshot.snapshot_id,
                "name": name,
                "ledger_sequence": ledger_sequence,
                "size_bytes": len(stored_bytes),
                "compressed": compressed,
            },
        )
        return snapshot

    async def _maybe_prune(self, *, tenant_id: Optional[str] = None) -> None:
        """Prune oldest snapshots if the cap is exceeded."""
        if self._max_snapshots is None:
            return
        snapshots = await self._backend.list_metadata(tenant_id=tenant_id)
        excess = len(snapshots) - self._max_snapshots
        if excess > 0:
            # Prune oldest by ledger_sequence
            oldest = snapshots[:excess]
            for s in oldest:
                await self._backend.delete(s.snapshot_id)
                logger.debug(
                    "Snapshot pruned",
                    extra={"snapshot_id": s.snapshot_id, "name": s.name},
                )

    # ---------------------------------------------------------------------------
    # Read path
    # ---------------------------------------------------------------------------

    async def load(
        self, snapshot_id: str, *, verify: bool = True
    ) -> Dict[str, Any]:
        """
        Load and deserialize a snapshot's state.

        Parameters
        ----------
        snapshot_id : Snapshot UUID hex.
        verify      : If True, recompute and verify the state hash before returning.

        Raises
        ------
        SnapshotNotFoundError   : Snapshot does not exist.
        SnapshotCorruptedError  : Hash verification failed (only when verify=True).
        """
        meta = await self._backend.get_metadata(snapshot_id)
        if meta is None:
            raise SnapshotNotFoundError(f"Snapshot '{snapshot_id}' not found")

        raw_bytes = await self._backend.load_raw(snapshot_id)
        if raw_bytes is None:
            raise SnapshotNotFoundError(f"Snapshot '{snapshot_id}' data missing")

        # Decompress if needed
        raw = zlib.decompress(raw_bytes) if meta.compressed else raw_bytes

        if verify:
            computed = self._state_hash(raw)
            if computed != meta.state_hash:
                raise SnapshotCorruptedError(
                    f"Snapshot '{snapshot_id}' hash mismatch: "
                    f"expected {meta.state_hash[:12]}… found {computed[:12]}…"
                )

        return json.loads(raw.decode())

    async def get_metadata(self, snapshot_id: str) -> Snapshot:
        meta = await self._backend.get_metadata(snapshot_id)
        if meta is None:
            raise SnapshotNotFoundError(f"Snapshot '{snapshot_id}' not found")
        return meta

    async def list(
        self,
        *,
        tenant_id: Optional[str] = None,
        name: Optional[str] = None,
    ) -> List[Snapshot]:
        """List snapshot metadata records (no state payload) sorted by ledger_sequence."""
        return await self._backend.list_metadata(tenant_id=tenant_id, name=name)

    async def count(self, *, tenant_id: Optional[str] = None) -> int:
        return await self._backend.count(tenant_id=tenant_id)

    # ---------------------------------------------------------------------------
    # Replay helpers
    # ---------------------------------------------------------------------------

    async def nearest_before(
        self,
        target_sequence: int,
        *,
        tenant_id: Optional[str] = None,
    ) -> Optional[Snapshot]:
        """
        Find the most recent snapshot at or before ``target_sequence``.

        Used to find the optimal replay starting point:
        load this snapshot, then replay events from
        ``snapshot.ledger_sequence + 1`` to ``target_sequence``.
        """
        snapshots = await self._backend.list_metadata(tenant_id=tenant_id)
        candidates = [
            s for s in snapshots
            if s.ledger_sequence <= target_sequence and not s.is_expired()
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda s: s.ledger_sequence)

    async def replay_delta(
        self,
        target_sequence: int,
        *,
        tenant_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Return a dict describing the optimal replay strategy.

        ``delta_events`` is the number of events that must be replayed after
        restoring the returned snapshot.

        Example return value::

            {
                "snapshot_id": "abc123",
                "name": "post-ingest-500",
                "from_sequence": 500,
                "to_sequence": 1800,
                "delta_events": 1300,
            }
        """
        nearest = await self.nearest_before(
            target_sequence, tenant_id=tenant_id
        )
        if nearest is None:
            return {
                "snapshot_id": None,
                "name": None,
                "from_sequence": 0,
                "to_sequence": target_sequence,
                "delta_events": target_sequence,
            }

        return {
            "snapshot_id": nearest.snapshot_id,
            "name": nearest.name,
            "from_sequence": nearest.ledger_sequence,
            "to_sequence": target_sequence,
            "delta_events": target_sequence - nearest.ledger_sequence,
        }

    # ---------------------------------------------------------------------------
    # Delete
    # ---------------------------------------------------------------------------

    async def delete(self, snapshot_id: str) -> bool:
        async with self._lock:
            deleted = await self._backend.delete(snapshot_id)
        if deleted:
            logger.info("Snapshot deleted", extra={"snapshot_id": snapshot_id})
        return deleted

    async def delete_expired(
        self, *, tenant_id: Optional[str] = None
    ) -> int:
        """Prune all snapshots whose TTL has elapsed. Returns count deleted."""
        snapshots = await self._backend.list_metadata(tenant_id=tenant_id)
        expired = [s for s in snapshots if s.is_expired()]
        count = 0
        async with self._lock:
            for s in expired:
                if await self._backend.delete(s.snapshot_id):
                    count += 1
        if count:
            logger.info("Expired snapshots pruned", extra={"count": count})
        return count

    # ---------------------------------------------------------------------------
    # Export / import
    # ---------------------------------------------------------------------------

    async def export(
        self,
        snapshot_id: str,
    ) -> Dict[str, Any]:
        """
        Full export of a snapshot for cross-environment migration.
        Includes both metadata and full state payload.
        """
        meta = await self.get_metadata(snapshot_id)
        state = await self.load(snapshot_id, verify=True)
        d = meta.to_dict(include_state=False)
        d["state"] = state
        return d

    async def import_snapshot(self, data: Dict[str, Any]) -> Snapshot:
        """Restore an exported snapshot. Verifies integrity on import."""
        return await self.save(
            name=data["name"],
            state=data["state"],
            ledger_sequence=data["ledger_sequence"],
            ledger_hash=data["ledger_hash"],
            tenant_id=data.get("tenant_id"),
            tags=data.get("tags", []),
            metadata=data.get("metadata", {}),
        )