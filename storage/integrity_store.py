"""
storage/integrity_store.py
==========================
Enterprise cryptographic ledger integrity verification and audit engine.

Responsibilities
----------------
- Full-chain SHA-256 hash recomputation and linkage verification
- HMAC-SHA256 signature verification (when secret key is configured)
- Gap detection: missing sequence numbers in the ledger
- Tamper report generation: exact position and nature of corruption
- Incremental verification: verify from a known-good checkpoint
- Multi-tenant chain isolation
- Structured audit trail for compliance (SOC2, ISO 27001, FedRAMP)
- Export integrity certificates for external auditors

Design
------
The ledger is a hash chain:

    GENESIS → record[0] → record[1] → … → record[N]

Each record contains:
    record_hash = SHA256( canonical_form(record) )
    prev_hash   = record_hash of the previous record (or GENESIS for [0])

Tampering any field in any record, or reordering records, breaks the chain
at the modified position and every record after it.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .event_store import EventRecord


logger = logging.getLogger(__name__)

GENESIS_HASH = "0" * 64


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class TamperDetectedError(Exception):
    """
    Raised by ``verify_chain_strict()`` when tampering is detected.
    Carries the full ``IntegrityReport`` for forensic analysis.
    """

    def __init__(self, report: "IntegrityReport") -> None:
        self.report = report
        super().__init__(
            f"Ledger integrity violation at sequence {report.first_violation_seq}"
        )


# ---------------------------------------------------------------------------
# Violation record
# ---------------------------------------------------------------------------


@dataclass
class ViolationRecord:
    """
    Details a single integrity violation found during chain verification.

    Fields
    ------
    sequence        : Ledger sequence number of the corrupted record.
    event_id        : Event identifier of the corrupted record.
    violation_type  : Short code describing the violation category.
    expected        : The value that was expected (hash or sequence number).
    found           : The value that was actually present in the record.
    """

    sequence: int
    event_id: str
    violation_type: str          # HASH_MISMATCH | HMAC_INVALID | SEQUENCE_GAP | CHAIN_BROKEN
    expected: str
    found: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Integrity report
# ---------------------------------------------------------------------------


@dataclass
class IntegrityReport:
    """
    Comprehensive result of a ledger integrity verification run.

    Fields
    ------
    valid                   : True only if zero violations found.
    total_records_checked   : Number of event records examined.
    violations              : Ordered list of ViolationRecords.
    first_violation_seq     : Sequence number of the first violation (-1 if none).
    verified_at             : UTC ISO-8601 timestamp of verification.
    chain_tip_hash          : The final record's hash (trusted if valid=True).
    tenant_id               : Tenant scope of this verification.
    duration_ms             : Wall-clock time taken to verify.
    """

    valid: bool
    total_records_checked: int
    violations: List[ViolationRecord] = field(default_factory=list)
    first_violation_seq: int = -1
    verified_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    chain_tip_hash: str = ""
    tenant_id: Optional[str] = None
    duration_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d

    def to_certificate(self) -> str:
        """
        Emit a human-readable integrity certificate for compliance reporting.
        Suitable for embedding in audit logs or exporting to PDF.
        """
        status = "PASSED ✓" if self.valid else "FAILED ✗"
        lines = [
            "═" * 60,
            "  HOLLOW PURPLE — LEDGER INTEGRITY CERTIFICATE",
            "═" * 60,
            f"  Status         : {status}",
            f"  Verified At    : {self.verified_at}",
            f"  Tenant         : {self.tenant_id or 'global'}",
            f"  Records Checked: {self.total_records_checked}",
            f"  Violations     : {len(self.violations)}",
            f"  Chain Tip Hash : {self.chain_tip_hash[:16]}…",
            f"  Duration       : {self.duration_ms:.2f} ms",
        ]
        if self.violations:
            lines.append("")
            lines.append("  VIOLATIONS:")
            for v in self.violations[:10]:   # cap display at 10
                lines.append(
                    f"    [seq={v.sequence}] {v.violation_type} "
                    f"event={v.event_id[:12]}…"
                )
            if len(self.violations) > 10:
                lines.append(f"    … and {len(self.violations) - 10} more")
        lines.append("═" * 60)
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# IntegrityStore
# ---------------------------------------------------------------------------


class IntegrityStore:
    """
    Cryptographic ledger integrity verifier.

    Usage
    -----
    ::

        store = IntegrityStore(hmac_secret=b"secret")

        # Verify after loading all records from EventStore
        records = await event_store.all()
        report = store.verify_chain(records)

        if not report.valid:
            print(report.to_certificate())

        # Raise on tampering (useful in CI/CD integrity gates)
        store.verify_chain_strict(records)

        # Incremental — only verify records after a known-good position
        report = store.verify_chain(records, from_sequence=1000, trusted_prev_hash=checkpoint_hash)
    """

    def __init__(self, *, hmac_secret: Optional[bytes] = None) -> None:
        self._hmac_secret = hmac_secret
        logger.info(
            "IntegrityStore initialised",
            extra={"hmac_enabled": hmac_secret is not None},
        )

    # ---------------------------------------------------------------------------
    # Internal helpers (mirror EventStore canonical form exactly)
    # ---------------------------------------------------------------------------

    @staticmethod
    def _canonical_form(record: "EventRecord") -> bytes:
        doc = {
            "event_id": record.event_id,
            "sequence": record.sequence,
            "tenant_id": record.tenant_id,
            "source": record.source,
            "event_type": record.event_type,
            "payload": record.payload,
            "prev_hash": record.prev_hash,
            "recorded_at": record.recorded_at,
        }
        return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()

    def _expected_hash(self, record: "EventRecord") -> str:
        canonical = self._canonical_form(record)
        return hashlib.sha256(canonical).hexdigest()

    def _expected_hmac(self, record: "EventRecord") -> Optional[str]:
        if self._hmac_secret is None:
            return None
        canonical = self._canonical_form(record)
        return _hmac.new(self._hmac_secret, canonical, hashlib.sha256).hexdigest()

    # ---------------------------------------------------------------------------
    # Core verification
    # ---------------------------------------------------------------------------

    def verify_chain(
        self,
        records: List["EventRecord"],
        *,
        from_sequence: int = 0,
        trusted_prev_hash: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> IntegrityReport:
        """
        Verify the full cryptographic integrity of a list of EventRecords.

        Parameters
        ----------
        records             : Ordered list of EventRecords to verify.
        from_sequence       : Skip records with sequence < this value.
        trusted_prev_hash   : Known-good hash at ``from_sequence - 1``.
                              Defaults to GENESIS_HASH.
        tenant_id           : Filter records to a specific tenant.

        Returns
        -------
        IntegrityReport
            Always returned — never raises. Use ``verify_chain_strict()``
            if you need exception-raising behavior.
        """
        import time as _time

        start_ns = _time.perf_counter_ns()
        violations: List[ViolationRecord] = []

        # Filter and sort
        relevant = [r for r in records if r.sequence >= from_sequence]
        if tenant_id:
            relevant = [r for r in relevant if r.tenant_id == tenant_id]
        relevant.sort(key=lambda r: r.sequence)

        prev_hash = trusted_prev_hash or GENESIS_HASH
        prev_seq = from_sequence - 1
        chain_tip = prev_hash
        checked = 0

        for record in relevant:
            checked += 1

            # 1. Sequence gap detection
            if record.sequence != prev_seq + 1:
                violations.append(
                    ViolationRecord(
                        sequence=record.sequence,
                        event_id=record.event_id,
                        violation_type="SEQUENCE_GAP",
                        expected=str(prev_seq + 1),
                        found=str(record.sequence),
                    )
                )
                logger.warning(
                    "Sequence gap detected",
                    extra={
                        "expected_seq": prev_seq + 1,
                        "found_seq": record.sequence,
                    },
                )

            # 2. Chain linkage: prev_hash must equal our computed prev
            if record.prev_hash != prev_hash:
                violations.append(
                    ViolationRecord(
                        sequence=record.sequence,
                        event_id=record.event_id,
                        violation_type="CHAIN_BROKEN",
                        expected=prev_hash,
                        found=record.prev_hash,
                    )
                )
                logger.error(
                    "Chain broken",
                    extra={
                        "sequence": record.sequence,
                        "event_id": record.event_id,
                    },
                )

            # 3. Hash recomputation
            expected_hash = self._expected_hash(record)
            if record.record_hash != expected_hash:
                violations.append(
                    ViolationRecord(
                        sequence=record.sequence,
                        event_id=record.event_id,
                        violation_type="HASH_MISMATCH",
                        expected=expected_hash,
                        found=record.record_hash,
                    )
                )
                logger.error(
                    "Hash mismatch — record tampered",
                    extra={
                        "sequence": record.sequence,
                        "event_id": record.event_id,
                    },
                )

            # 4. HMAC verification (when secret is configured)
            if self._hmac_secret and record.hmac_sig:
                expected_hmac = self._expected_hmac(record)
                if not _hmac.compare_digest(record.hmac_sig, expected_hmac):
                    violations.append(
                        ViolationRecord(
                            sequence=record.sequence,
                            event_id=record.event_id,
                            violation_type="HMAC_INVALID",
                            expected="<valid hmac>",
                            found="<invalid hmac>",
                        )
                    )
                    logger.error(
                        "HMAC verification failed",
                        extra={"sequence": record.sequence},
                    )

            # Advance chain state (use stored hash to propagate the stored chain,
            # so we can report exactly where it diverges)
            prev_hash = record.record_hash
            prev_seq = record.sequence
            chain_tip = record.record_hash

        duration_ms = (_time.perf_counter_ns() - start_ns) / 1_000_000
        first_violation_seq = violations[0].sequence if violations else -1

        report = IntegrityReport(
            valid=len(violations) == 0,
            total_records_checked=checked,
            violations=violations,
            first_violation_seq=first_violation_seq,
            chain_tip_hash=chain_tip,
            tenant_id=tenant_id,
            duration_ms=round(duration_ms, 3),
        )

        if report.valid:
            logger.info(
                "Integrity verification passed",
                extra={"records_checked": checked, "duration_ms": round(duration_ms, 2)},
            )
        else:
            logger.error(
                "Integrity verification FAILED",
                extra={
                    "violations": len(violations),
                    "first_violation_seq": first_violation_seq,
                },
            )

        return report

    def verify_chain_strict(
        self,
        records: List["EventRecord"],
        *,
        from_sequence: int = 0,
        trusted_prev_hash: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> IntegrityReport:
        """
        Like ``verify_chain()`` but raises ``TamperDetectedError`` if any
        violations are found. Use in integrity gates (deploy pipelines, audits).
        """
        report = self.verify_chain(
            records,
            from_sequence=from_sequence,
            trusted_prev_hash=trusted_prev_hash,
            tenant_id=tenant_id,
        )
        if not report.valid:
            raise TamperDetectedError(report)
        return report

    # ---------------------------------------------------------------------------
    # Incremental checkpoint support
    # ---------------------------------------------------------------------------

    def checkpoint_hash(self, records: List["EventRecord"]) -> str:
        """
        Return the hash of the final record in a verified slice.
        Use as ``trusted_prev_hash`` for incremental verification.
        """
        if not records:
            return GENESIS_HASH
        sorted_records = sorted(records, key=lambda r: r.sequence)
        return sorted_records[-1].record_hash