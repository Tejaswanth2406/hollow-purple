"""
phase5/audit_log.py — Immutable Pipeline Audit Log

Every decision the pipeline makes is recorded as an AuditEntry with:
  - ISO timestamp
  - actor (component name)
  - action (what was decided)
  - outcome (ALLOW / DENY / ERROR / INFO)
  - payload (arbitrary dict)
  - entry_hash: SHA256(prev_hash | actor | action | outcome | ts | payload_hash)

This provides a tamper-evident trail that is independent of the Merkle log
(which tracks event data) — the audit log tracks pipeline control decisions.

Hardening:
  H1  — entry_hash chained from previous (tamper breaks chain)
  H2  — Thread-safe: append under lock
  H3  — Bounded in-memory buffer (max 50 000 entries); overflow → disk flush
  H4  — Query API: filter by actor, action, outcome, time range
  H5  — Export to JSONL (one entry per line, newline-delimited JSON)
  H6  — verify_chain() validates full hash chain; returns report
  H7  — AuditOutcome enum with ordering (INFO < ALLOW < DENY < ERROR)
  H8  — payload capped at 4 KB (truncated with warning flag)
"""
from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from pathlib import Path
from typing import Optional, Iterator


# ── Constants ──────────────────────────────────────────────────────────────────

MAX_ENTRIES_IN_MEMORY = 50_000
MAX_PAYLOAD_BYTES     = 4_096
GENESIS_HASH          = "0" * 64      # Initial chain root


# ── AuditOutcome ──────────────────────────────────────────────────────────────

class AuditOutcome(Enum):
    INFO  = 0
    ALLOW = 1
    DENY  = 2
    ERROR = 3

    def __ge__(self, other: "AuditOutcome") -> bool:
        return self.value >= other.value


# ── AuditEntry ────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class AuditEntry:
    """
    Immutable audit record.
    H1: entry_hash chains from prev_hash.
    """
    seq:         int
    ts:          datetime
    actor:       str
    action:      str
    outcome:     AuditOutcome
    payload:     dict
    truncated:   bool
    prev_hash:   str
    entry_hash:  str

    @classmethod
    def _compute_hash(
        cls,
        prev_hash:  str,
        actor:      str,
        action:     str,
        outcome:    str,
        ts:         datetime,
        payload_hash: str,
    ) -> str:
        raw = f"{prev_hash}|{actor}|{action}|{outcome}|{ts.isoformat()}|{payload_hash}"
        return hashlib.sha256(raw.encode()).hexdigest()

    @classmethod
    def create(
        cls,
        seq:       int,
        actor:     str,
        action:    str,
        outcome:   AuditOutcome,
        payload:   dict,
        prev_hash: str,
        ts:        Optional[datetime] = None,
    ) -> "AuditEntry":
        if ts is None:
            ts = datetime.now(timezone.utc)

        # H8: cap payload
        truncated = False
        raw_payload = json.dumps(payload, sort_keys=True, default=str)
        if len(raw_payload.encode()) > MAX_PAYLOAD_BYTES:
            truncated = True
            payload   = {"_truncated": True, "_size": len(raw_payload)}

        payload_hash = hashlib.sha256(
            json.dumps(payload, sort_keys=True, default=str).encode()
        ).hexdigest()

        entry_hash = cls._compute_hash(
            prev_hash, actor, action, outcome.name, ts, payload_hash
        )
        return cls(
            seq        = seq,
            ts         = ts,
            actor      = actor,
            action     = action,
            outcome    = outcome,
            payload    = payload,
            truncated  = truncated,
            prev_hash  = prev_hash,
            entry_hash = entry_hash,
        )

    def to_dict(self) -> dict:
        return {
            "seq":        self.seq,
            "ts":         self.ts.isoformat(),
            "actor":      self.actor,
            "action":     self.action,
            "outcome":    self.outcome.name,
            "payload":    self.payload,
            "truncated":  self.truncated,
            "prev_hash":  self.prev_hash,
            "entry_hash": self.entry_hash,
        }


# ── ChainVerificationReport ───────────────────────────────────────────────────

@dataclass
class ChainVerificationReport:
    entries_checked:   int
    chain_valid:       bool
    first_broken_seq:  Optional[int] = None
    error_detail:      str           = ""

    def is_clean(self) -> bool:
        return self.chain_valid


# ── AuditQueryResult ──────────────────────────────────────────────────────────

@dataclass
class AuditQueryResult:
    entries: list[AuditEntry]
    total:   int

    def __iter__(self) -> Iterator[AuditEntry]:
        return iter(self.entries)

    def __len__(self) -> int:
        return len(self.entries)


# ── AuditLog ──────────────────────────────────────────────────────────────────

class AuditLog:
    """
    Append-only audit log with hash-chained entries.

    H2: thread-safe.
    H3: bounded in-memory buffer; flush_to_disk() for overflow.
    """

    def __init__(self, flush_path: Optional[str] = None):
        self._entries:    list[AuditEntry] = []
        self._lock        = threading.Lock()
        self._seq_counter = 0
        self._flush_path  = flush_path
        self._flushed_count = 0   # entries persisted to disk (not in memory)

    # ── append ─────────────────────────────────────────────────────────────────

    def append(
        self,
        actor:   str,
        action:  str,
        outcome: AuditOutcome,
        payload: Optional[dict] = None,
        ts:      Optional[datetime] = None,
    ) -> AuditEntry:
        """H2: all mutations under lock."""
        with self._lock:
            prev_hash = (
                self._entries[-1].entry_hash
                if self._entries
                else GENESIS_HASH
            )
            seq = self._seq_counter
            self._seq_counter += 1

            entry = AuditEntry.create(
                seq       = seq,
                actor     = actor,
                action    = action,
                outcome   = outcome,
                payload   = payload or {},
                prev_hash = prev_hash,
                ts        = ts,
            )
            self._entries.append(entry)

            # H3: overflow flush
            if len(self._entries) > MAX_ENTRIES_IN_MEMORY and self._flush_path:
                self._flush_oldest_half()

            return entry

    # ── convenience wrappers ──────────────────────────────────────────────────

    def allow(self, actor: str, action: str, payload: Optional[dict] = None) -> AuditEntry:
        return self.append(actor, action, AuditOutcome.ALLOW, payload)

    def deny(self, actor: str, action: str, payload: Optional[dict] = None) -> AuditEntry:
        return self.append(actor, action, AuditOutcome.DENY, payload)

    def error(self, actor: str, action: str, payload: Optional[dict] = None) -> AuditEntry:
        return self.append(actor, action, AuditOutcome.ERROR, payload)

    def info(self, actor: str, action: str, payload: Optional[dict] = None) -> AuditEntry:
        return self.append(actor, action, AuditOutcome.INFO, payload)

    # ── query ─────────────────────────────────────────────────────────────────

    def query(
        self,
        actor:       Optional[str]          = None,
        action:      Optional[str]          = None,
        outcome:     Optional[AuditOutcome] = None,
        since:       Optional[datetime]     = None,
        until:       Optional[datetime]     = None,
        limit:       int                    = 1000,
    ) -> AuditQueryResult:
        """H4: filtered query over in-memory entries."""
        with self._lock:
            entries = list(self._entries)

        results = []
        for e in reversed(entries):   # most-recent first
            if actor   and e.actor   != actor:   continue
            if action  and e.action  != action:  continue
            if outcome and e.outcome != outcome: continue
            if since   and e.ts < since:         continue
            if until   and e.ts > until:         continue
            results.append(e)
            if len(results) >= limit:
                break

        return AuditQueryResult(entries=results, total=len(results))

    # ── chain verification ────────────────────────────────────────────────────

    def verify_chain(self) -> ChainVerificationReport:
        """H6: full hash chain validation."""
        with self._lock:
            entries = list(self._entries)

        if not entries:
            return ChainVerificationReport(entries_checked=0, chain_valid=True)

        for i, entry in enumerate(entries):
            expected_prev = entries[i - 1].entry_hash if i > 0 else GENESIS_HASH
            if entry.prev_hash != expected_prev:
                return ChainVerificationReport(
                    entries_checked  = i + 1,
                    chain_valid      = False,
                    first_broken_seq = entry.seq,
                    error_detail     = (
                        f"seq={entry.seq}: prev_hash mismatch. "
                        f"expected={expected_prev[:16]}... "
                        f"got={entry.prev_hash[:16]}..."
                    ),
                )
            # Recompute entry_hash
            payload_hash = hashlib.sha256(
                json.dumps(entry.payload, sort_keys=True, default=str).encode()
            ).hexdigest()
            recomputed = AuditEntry._compute_hash(
                entry.prev_hash,
                entry.actor,
                entry.action,
                entry.outcome.name,
                entry.ts,
                payload_hash,
            )
            if recomputed != entry.entry_hash:
                return ChainVerificationReport(
                    entries_checked  = i + 1,
                    chain_valid      = False,
                    first_broken_seq = entry.seq,
                    error_detail     = (
                        f"seq={entry.seq}: entry_hash mismatch (tampered)"
                    ),
                )

        return ChainVerificationReport(
            entries_checked = len(entries),
            chain_valid     = True,
        )

    # ── export ────────────────────────────────────────────────────────────────

    def export_jsonl(self, path: str) -> int:
        """H5: write all in-memory entries as JSONL."""
        with self._lock:
            entries = list(self._entries)
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("w", encoding="utf-8") as f:
            for entry in entries:
                f.write(json.dumps(entry.to_dict()) + "\n")
        return len(entries)

    # ── stats ─────────────────────────────────────────────────────────────────

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def head(self, n: int = 10) -> list[AuditEntry]:
        with self._lock:
            return list(self._entries[:n])

    def tail(self, n: int = 10) -> list[AuditEntry]:
        with self._lock:
            return list(self._entries[-n:])

    # ── internal flush (called under lock) ────────────────────────────────────

    def _flush_oldest_half(self) -> None:
        """H3: persist oldest half to disk, remove from memory."""
        cut = len(self._entries) // 2
        to_flush = self._entries[:cut]
        if self._flush_path:
            p = Path(self._flush_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            with p.open("a", encoding="utf-8") as f:
                for entry in to_flush:
                    f.write(json.dumps(entry.to_dict()) + "\n")
        self._flushed_count += len(to_flush)
        del self._entries[:cut]