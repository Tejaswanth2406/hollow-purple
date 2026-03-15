"""
storage/event_store.py
======================
Enterprise append-only tamper-evident event ledger.

Design principles
-----------------
- Append-only: events are never mutated or deleted
- Cryptographic chaining: each record embeds SHA-256(prev_record + payload)
  making retroactive tampering detectable by any observer
- HMAC-signed payloads for authenticity verification (optional secret key)
- Sequence numbers for gap detection in distributed topologies
- Async-safe via asyncio.Lock — single-process safe; extend with Redis
  distributed lock for multi-replica deployments
- Structured EventRecord dataclass — typed, serializable, replayable
- Cursor-based pagination for high-volume ledger traversal
- In-memory backing store with pluggable backend adapter pattern
  (swap to PostgreSQL / Kafka / TimescaleDB without changing call sites)
- TTL-based pruning hooks for compliance retention windows
- Structured logging on every append for external SIEM ingestion
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterator, List, Optional


logger = logging.getLogger(__name__)

GENESIS_HASH = "0" * 64  # canonical chain-start sentinel


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ChainVerificationError(Exception):
    """Raised when the cryptographic event chain is broken."""


class EventNotFoundError(KeyError):
    """Raised when an event ID or sequence index is not present."""


# ---------------------------------------------------------------------------
# Event record
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EventRecord:
    """
    Immutable representation of a single ledger entry.

    Fields
    ------
    event_id       : UUID4 hex — globally unique identifier.
    sequence       : Monotonically increasing integer position in this ledger.
    tenant_id      : Tenant/org scope for multi-tenant partitioning.
    source         : Originating subsystem (e.g. ``"ingestion.kafka"``).
    event_type     : Application-level event classifier.
    payload        : Arbitrary event body (must be JSON-serializable).
    prev_hash      : SHA-256 digest of the previous record's canonical form.
    record_hash    : SHA-256 digest of this record's canonical form.
    hmac_sig       : Optional HMAC-SHA256 signature for authenticity.
    recorded_at    : ISO-8601 UTC timestamp.
    ingestion_ns   : High-resolution monotonic ingestion time (perf_counter_ns).
    """

    event_id: str
    sequence: int
    tenant_id: Optional[str]
    source: str
    event_type: str
    payload: Dict[str, Any]
    prev_hash: str
    record_hash: str
    hmac_sig: Optional[str]
    recorded_at: str
    ingestion_ns: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    @property
    def is_genesis(self) -> bool:
        return self.prev_hash == GENESIS_HASH


# ---------------------------------------------------------------------------
# Backend adapter interface
# ---------------------------------------------------------------------------


class EventStoreBackend:
    """
    Abstract storage backend.
    Swap in PostgreSQL, Kafka, or TimescaleDB adapters without
    touching the EventStore business logic.
    """

    async def append(self, record: EventRecord) -> None:
        raise NotImplementedError

    async def get_by_id(self, event_id: str) -> Optional[EventRecord]:
        raise NotImplementedError

    async def get_by_sequence(self, seq: int) -> Optional[EventRecord]:
        raise NotImplementedError

    async def count(self, tenant_id: Optional[str] = None) -> int:
        raise NotImplementedError

    async def page(
        self,
        after_seq: int = 0,
        limit: int = 100,
        tenant_id: Optional[str] = None,
    ) -> List[EventRecord]:
        raise NotImplementedError

    async def all(self, tenant_id: Optional[str] = None) -> List[EventRecord]:
        raise NotImplementedError


class InMemoryEventBackend(EventStoreBackend):
    """
    Default in-memory backend.
    Thread/async-safe reads; writes are serialized by EventStore's lock.
    """

    def __init__(self) -> None:
        self._records: List[EventRecord] = []
        self._by_id: Dict[str, EventRecord] = {}

    async def append(self, record: EventRecord) -> None:
        self._records.append(record)
        self._by_id[record.event_id] = record

    async def get_by_id(self, event_id: str) -> Optional[EventRecord]:
        return self._by_id.get(event_id)

    async def get_by_sequence(self, seq: int) -> Optional[EventRecord]:
        if 0 <= seq < len(self._records):
            return self._records[seq]
        return None

    async def count(self, tenant_id: Optional[str] = None) -> int:
        if tenant_id is None:
            return len(self._records)
        return sum(1 for r in self._records if r.tenant_id == tenant_id)

    async def page(
        self,
        after_seq: int = 0,
        limit: int = 100,
        tenant_id: Optional[str] = None,
    ) -> List[EventRecord]:
        result = []
        for r in self._records:
            if r.sequence <= after_seq:
                continue
            if tenant_id and r.tenant_id != tenant_id:
                continue
            result.append(r)
            if len(result) >= limit:
                break
        return result

    async def all(self, tenant_id: Optional[str] = None) -> List[EventRecord]:
        if tenant_id is None:
            return list(self._records)
        return [r for r in self._records if r.tenant_id == tenant_id]


# ---------------------------------------------------------------------------
# EventStore
# ---------------------------------------------------------------------------


class EventStore:
    """
    Append-only cryptographically chained event ledger.

    Usage
    -----
    ::

        store = EventStore(hmac_secret=b"super-secret")

        record = await store.append(
            payload={"action": "login", "user": "alice"},
            source="auth.service",
            event_type="user.login",
            tenant_id="acme",
        )

        # Verify full chain integrity
        report = await store.verify_integrity()
        assert report.valid

        # Paginate events
        page = await store.page(after_seq=0, limit=50, tenant_id="acme")

    Parameters
    ----------
    backend         : Storage adapter. Defaults to ``InMemoryEventBackend``.
    hmac_secret     : Optional bytes key for per-record HMAC signing.
    on_append       : Optional async callback fired after each successful append.
    """

    def __init__(
        self,
        *,
        backend: Optional[EventStoreBackend] = None,
        hmac_secret: Optional[bytes] = None,
        on_append: Optional[Callable[[EventRecord], None]] = None,
    ) -> None:
        self._backend = backend or InMemoryEventBackend()
        self._hmac_secret = hmac_secret
        self._on_append = on_append
        self._lock = asyncio.Lock()
        self._last_hash: str = GENESIS_HASH
        self._sequence: int = -1

        logger.info(
            "EventStore initialised",
            extra={"hmac_enabled": hmac_secret is not None},
        )

    # ---------------------------------------------------------------------------
    # Internal helpers
    # ---------------------------------------------------------------------------

    @staticmethod
    def _canonical_form(
        *,
        event_id: str,
        sequence: int,
        tenant_id: Optional[str],
        source: str,
        event_type: str,
        payload: Dict[str, Any],
        prev_hash: str,
        recorded_at: str,
    ) -> bytes:
        """
        Produce a deterministic byte representation for hashing.
        Uses sorted JSON keys to guarantee byte-identical output across
        Python versions and platforms.
        """
        doc = {
            "event_id": event_id,
            "sequence": sequence,
            "tenant_id": tenant_id,
            "source": source,
            "event_type": event_type,
            "payload": payload,
            "prev_hash": prev_hash,
            "recorded_at": recorded_at,
        }
        return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()

    def _compute_hash(self, canonical: bytes) -> str:
        return hashlib.sha256(canonical).hexdigest()

    def _compute_hmac(self, canonical: bytes) -> Optional[str]:
        if self._hmac_secret is None:
            return None
        return hmac.new(self._hmac_secret, canonical, hashlib.sha256).hexdigest()

    # ---------------------------------------------------------------------------
    # Write path
    # ---------------------------------------------------------------------------

    async def append(
        self,
        payload: Dict[str, Any],
        *,
        source: str = "unknown",
        event_type: str = "generic",
        tenant_id: Optional[str] = None,
    ) -> EventRecord:
        """
        Append a new event to the ledger.

        Returns
        -------
        EventRecord
            The immutable, signed, chained record that was persisted.

        Thread safety
        -------------
        The append path is serialized under an asyncio.Lock to guarantee
        monotonic sequence numbers and correct chain linkage.
        """
        async with self._lock:
            now = datetime.now(timezone.utc)
            event_id = uuid.uuid4().hex
            sequence = self._sequence + 1
            recorded_at = now.isoformat()
            prev_hash = self._last_hash

            canonical = self._canonical_form(
                event_id=event_id,
                sequence=sequence,
                tenant_id=tenant_id,
                source=source,
                event_type=event_type,
                payload=payload,
                prev_hash=prev_hash,
                recorded_at=recorded_at,
            )
            record_hash = self._compute_hash(canonical)
            hmac_sig = self._compute_hmac(canonical)

            record = EventRecord(
                event_id=event_id,
                sequence=sequence,
                tenant_id=tenant_id,
                source=source,
                event_type=event_type,
                payload=payload,
                prev_hash=prev_hash,
                record_hash=record_hash,
                hmac_sig=hmac_sig,
                recorded_at=recorded_at,
                ingestion_ns=time.perf_counter_ns(),
            )

            await self._backend.append(record)
            self._last_hash = record_hash
            self._sequence = sequence

            logger.debug(
                "Event appended",
                extra={
                    "event_id": event_id,
                    "sequence": sequence,
                    "event_type": event_type,
                    "tenant_id": tenant_id,
                },
            )

        # Fire callback outside the lock to avoid deadlocks
        if self._on_append:
            try:
                await self._on_append(record)
            except Exception:
                logger.exception("on_append callback error", extra={"event_id": event_id})

        return record

    # ---------------------------------------------------------------------------
    # Read path
    # ---------------------------------------------------------------------------

    async def get_by_id(self, event_id: str) -> EventRecord:
        record = await self._backend.get_by_id(event_id)
        if record is None:
            raise EventNotFoundError(f"Event '{event_id}' not found")
        return record

    async def get_by_sequence(self, seq: int) -> EventRecord:
        record = await self._backend.get_by_sequence(seq)
        if record is None:
            raise EventNotFoundError(f"Sequence {seq} not found")
        return record

    async def count(self, *, tenant_id: Optional[str] = None) -> int:
        return await self._backend.count(tenant_id=tenant_id)

    async def page(
        self,
        *,
        after_seq: int = 0,
        limit: int = 100,
        tenant_id: Optional[str] = None,
    ) -> List[EventRecord]:
        """Cursor-based pagination. Pass last seen sequence as ``after_seq``."""
        return await self._backend.page(
            after_seq=after_seq, limit=limit, tenant_id=tenant_id
        )

    async def all(self, *, tenant_id: Optional[str] = None) -> List[EventRecord]:
        """Return all events. Use ``page()`` for large ledgers."""
        return await self._backend.all(tenant_id=tenant_id)

    # ---------------------------------------------------------------------------
    # Integrity
    # ---------------------------------------------------------------------------

    async def verify_integrity(
        self, *, tenant_id: Optional[str] = None
    ) -> "IntegrityReport":
        """
        Recompute and verify the full cryptographic chain.
        Returns an IntegrityReport with details on any detected tampering.
        """
        from .integrity_store import IntegrityStore, IntegrityReport

        records = await self.all(tenant_id=tenant_id)
        store = IntegrityStore(hmac_secret=self._hmac_secret)
        return store.verify_chain(records)

    # ---------------------------------------------------------------------------
    # Replay
    # ---------------------------------------------------------------------------

    async def replay(
        self,
        handler: Callable[[EventRecord], None],
        *,
        from_seq: int = 0,
        to_seq: Optional[int] = None,
        tenant_id: Optional[str] = None,
    ) -> int:
        """
        Replay events in sequence order through ``handler``.
        Returns the number of events replayed.
        """
        cursor = from_seq
        replayed = 0

        while True:
            batch = await self.page(after_seq=cursor, limit=500, tenant_id=tenant_id)
            if not batch:
                break
            for record in batch:
                if to_seq is not None and record.sequence > to_seq:
                    return replayed
                await handler(record)
                replayed += 1
                cursor = record.sequence

        return replayed