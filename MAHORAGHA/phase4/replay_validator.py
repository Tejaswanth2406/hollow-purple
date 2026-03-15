"""
phase4/replay_validator.py
===========================
Enterprise checkpoint-anchored replay validation engine.

Responsibilities
----------------
- Register known-good state hashes as named checkpoints
- Verify replayed state hashes against registered checkpoints
- Detect state divergence: replay produced wrong state at a known point
- Cross-validate two independent replays produce identical state
- Produce structured ValidationResult with cryptographic proof
- Support sliding-window validation for continuous replay streams
- Export/import checkpoint manifests for offline or cross-system auditing

Checkpoint model
----------------
A checkpoint is a (sequence_number, state_hash) pair registered by a
trusted authority (operator, CI/CD system, or a previous verified replay).

During validation:
    computed_hash = SHA-256(canonical_json(replayed_state))
    valid = (computed_hash == checkpoint.state_hash)

If hashes don't match, the replay diverged — either the events were
tampered with, the state machine logic changed, or the event ordering
was different from the original run.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class CheckpointMismatchError(Exception):
    """
    Raised by ``validate_strict()`` when replayed state diverges from
    the registered checkpoint. Carries the full ValidationResult.
    """

    def __init__(self, result: "ValidationResult") -> None:
        self.result = result
        super().__init__(
            f"Replay diverged at sequence {result.sequence}: "
            f"expected {result.expected_hash[:12]}… "
            f"got {result.computed_hash[:12]}…"
        )


class CheckpointNotFoundError(KeyError):
    """Raised when no checkpoint exists for the given sequence."""


# ---------------------------------------------------------------------------
# Checkpoint record
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Checkpoint:
    """
    A trusted reference point for replay validation.

    Fields
    ------
    checkpoint_id   : UUID4 hex unique identifier.
    sequence        : Ledger sequence number this checkpoint anchors.
    state_hash      : SHA-256 of the canonical state at ``sequence``.
    label           : Human-readable name (e.g. ``"post-bootstrap"``).
    registered_by   : Identity that registered this checkpoint.
    registered_at   : UTC ISO-8601 timestamp.
    tenant_id       : Multi-tenant scope.
    metadata        : Arbitrary annotations.
    signature       : Optional HMAC-SHA256 of (sequence + state_hash).
    """

    checkpoint_id: str
    sequence: int
    state_hash: str
    label: str = ""
    registered_by: str = "system"
    registered_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    tenant_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    signature: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "checkpoint_id": self.checkpoint_id,
            "sequence": self.sequence,
            "state_hash": self.state_hash,
            "label": self.label,
            "registered_by": self.registered_by,
            "registered_at": self.registered_at,
            "tenant_id": self.tenant_id,
            "metadata": self.metadata,
            "signature": self.signature,
        }


# ---------------------------------------------------------------------------
# Validation result
# ---------------------------------------------------------------------------


@dataclass
class ValidationResult:
    """
    Structured outcome of a single checkpoint validation.

    Fields
    ------
    valid               : True only if computed_hash == expected_hash.
    sequence            : Sequence number validated.
    expected_hash       : The registered checkpoint hash.
    computed_hash       : SHA-256 of the replayed state.
    checkpoint_id       : ID of the checkpoint used.
    checkpoint_label    : Human-readable checkpoint name.
    divergence_detected : True if hashes differ (tamper or logic change).
    evidence            : Structured evidence dict for SIEM/SOAR.
    validated_at        : UTC ISO-8601 timestamp.
    elapsed_ms          : Time taken to compute and compare.
    """

    valid: bool
    sequence: int
    expected_hash: str
    computed_hash: str
    checkpoint_id: str
    checkpoint_label: str
    divergence_detected: bool
    evidence: Dict[str, Any] = field(default_factory=dict)
    validated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    elapsed_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid,
            "sequence": self.sequence,
            "expected_hash": self.expected_hash[:16] + "…",
            "computed_hash": self.computed_hash[:16] + "…",
            "checkpoint_id": self.checkpoint_id,
            "checkpoint_label": self.checkpoint_label,
            "divergence_detected": self.divergence_detected,
            "evidence": self.evidence,
            "validated_at": self.validated_at,
            "elapsed_ms": round(self.elapsed_ms, 3),
        }


# ---------------------------------------------------------------------------
# Batch validation report
# ---------------------------------------------------------------------------


@dataclass
class BatchValidationReport:
    """Summary of validating multiple checkpoints in a single replay."""

    total_checkpoints: int
    passed: int
    failed: int
    results: List[ValidationResult]
    overall_valid: bool
    first_divergence_seq: int = -1
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_checkpoints": self.total_checkpoints,
            "passed": self.passed,
            "failed": self.failed,
            "overall_valid": self.overall_valid,
            "first_divergence_seq": self.first_divergence_seq,
            "results": [r.to_dict() for r in self.results],
            "generated_at": self.generated_at,
        }


# ---------------------------------------------------------------------------
# ReplayValidator
# ---------------------------------------------------------------------------


class ReplayValidator:
    """
    Checkpoint-anchored replay validation engine.

    Usage
    -----
    ::

        validator = ReplayValidator(hmac_secret=b"secret")

        # Register known-good checkpoints (from a previous verified run)
        validator.register(sequence=500,  state_hash="abc...", label="mid-batch")
        validator.register(sequence=1000, state_hash="def...", label="end-of-day")

        # Validate a single replayed state
        result = validator.validate(sequence=500, state=replayed_state_at_500)

        # Validate a full replay run against all checkpoints
        report = validator.validate_replay_result(replay_result)
    """

    def __init__(
        self,
        *,
        hmac_secret: Optional[bytes] = None,
        strict: bool = False,
    ) -> None:
        """
        Parameters
        ----------
        hmac_secret : Optional bytes key for checkpoint signature verification.
        strict      : If True, ``validate()`` raises on mismatch instead of
                      returning a failed ValidationResult.
        """
        self._hmac_secret = hmac_secret
        self._strict = strict
        self._checkpoints: Dict[int, Checkpoint] = {}  # seq → Checkpoint

        logger.info(
            "ReplayValidator initialised",
            extra={"hmac_enabled": hmac_secret is not None, "strict": strict},
        )

    # ---------------------------------------------------------------------------
    # Checkpoint registration
    # ---------------------------------------------------------------------------

    def register(
        self,
        *,
        sequence: int,
        state_hash: str,
        label: str = "",
        registered_by: str = "system",
        tenant_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Checkpoint:
        """
        Register a trusted checkpoint.

        Parameters
        ----------
        sequence    : Ledger sequence number.
        state_hash  : Pre-computed SHA-256 of the canonical state at ``sequence``.
        label       : Human-readable name.
        registered_by: Identity registering this checkpoint.
        """
        sig = self._sign(sequence, state_hash) if self._hmac_secret else None

        cp = Checkpoint(
            checkpoint_id=uuid.uuid4().hex,
            sequence=sequence,
            state_hash=state_hash,
            label=label or f"checkpoint@{sequence}",
            registered_by=registered_by,
            tenant_id=tenant_id,
            metadata=metadata or {},
            signature=sig,
        )
        self._checkpoints[sequence] = cp
        logger.info(
            "Checkpoint registered",
            extra={"sequence": sequence, "label": cp.label, "hash": state_hash[:12]},
        )
        return cp

    def register_from_replay(
        self,
        replay_result,
        *,
        label: str = "",
        registered_by: str = "replay_engine",
    ) -> Checkpoint:
        """
        Register the final state of a trusted replay as a new checkpoint.
        Use this to establish the first trusted baseline.
        """
        return self.register(
            sequence=replay_result.to_sequence,
            state_hash=replay_result.state_hash,
            label=label or f"replay@{replay_result.to_sequence}",
            registered_by=registered_by,
        )

    def unregister(self, sequence: int) -> bool:
        return bool(self._checkpoints.pop(sequence, None))

    # ---------------------------------------------------------------------------
    # HMAC signing
    # ---------------------------------------------------------------------------

    def _sign(self, sequence: int, state_hash: str) -> str:
        import hmac as _hmac
        payload = f"{sequence}:{state_hash}".encode()
        return _hmac.new(self._hmac_secret, payload, hashlib.sha256).hexdigest()

    def _verify_signature(self, cp: Checkpoint) -> bool:
        if self._hmac_secret is None or cp.signature is None:
            return True  # No signing configured
        import hmac as _hmac
        expected = self._sign(cp.sequence, cp.state_hash)
        return _hmac.compare_digest(cp.signature, expected)

    # ---------------------------------------------------------------------------
    # State hashing (mirrors DeterministicReplay.hash_state exactly)
    # ---------------------------------------------------------------------------

    @staticmethod
    def _hash_state(state: Dict[str, Any]) -> str:
        canonical = json.dumps(state, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()

    # ---------------------------------------------------------------------------
    # Validation
    # ---------------------------------------------------------------------------

    def validate(
        self,
        sequence: int,
        state: Dict[str, Any],
    ) -> ValidationResult:
        """
        Validate a replayed state at ``sequence`` against the registered checkpoint.

        Parameters
        ----------
        sequence    : The sequence number the state corresponds to.
        state       : The replayed state dict at that sequence.

        Returns
        -------
        ValidationResult
            ``valid=True`` only if hashes match AND signature verifies.

        Raises
        ------
        CheckpointNotFoundError : No checkpoint registered for ``sequence``.
        CheckpointMismatchError : (only when ``strict=True``) Hash mismatch.
        """
        cp = self._checkpoints.get(sequence)
        if cp is None:
            raise CheckpointNotFoundError(
                f"No checkpoint registered for sequence {sequence}"
            )

        start_ns = time.perf_counter_ns()
        computed = self._hash_state(state)
        elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000

        # Signature verification
        sig_valid = self._verify_signature(cp)

        hashes_match = computed == cp.state_hash
        overall_valid = hashes_match and sig_valid

        evidence: Dict[str, Any] = {}
        if not hashes_match:
            evidence["hash_mismatch"] = {
                "expected": cp.state_hash[:16],
                "computed": computed[:16],
            }
        if not sig_valid:
            evidence["signature_invalid"] = True

        result = ValidationResult(
            valid=overall_valid,
            sequence=sequence,
            expected_hash=cp.state_hash,
            computed_hash=computed,
            checkpoint_id=cp.checkpoint_id,
            checkpoint_label=cp.label,
            divergence_detected=not hashes_match,
            evidence=evidence,
            elapsed_ms=round(elapsed_ms, 3),
        )

        level = logging.INFO if overall_valid else logging.ERROR
        logger.log(
            level,
            "Checkpoint validation %s",
            "PASSED" if overall_valid else "FAILED",
            extra={
                "sequence": sequence,
                "label": cp.label,
                "valid": overall_valid,
                "divergence": not hashes_match,
            },
        )

        if self._strict and not overall_valid:
            raise CheckpointMismatchError(result)

        return result

    def validate_hash(self, sequence: int, state_hash: str) -> ValidationResult:
        """
        Validate by providing a pre-computed state hash instead of the state.
        Avoids deserializing large state objects during batch validation.
        """
        cp = self._checkpoints.get(sequence)
        if cp is None:
            raise CheckpointNotFoundError(sequence)

        match = state_hash == cp.state_hash
        return ValidationResult(
            valid=match,
            sequence=sequence,
            expected_hash=cp.state_hash,
            computed_hash=state_hash,
            checkpoint_id=cp.checkpoint_id,
            checkpoint_label=cp.label,
            divergence_detected=not match,
        )

    def validate_replay_result(
        self, replay_result
    ) -> BatchValidationReport:
        """
        Validate a full ReplayResult against all registered checkpoints
        whose sequences fall within the replay window.
        """
        results: List[ValidationResult] = []
        passed = 0
        failed = 0
        first_divergence = -1

        # Find checkpoints within replay window
        in_window = [
            cp for seq, cp in sorted(self._checkpoints.items())
            if replay_result.from_sequence <= seq <= replay_result.to_sequence
        ]

        # Build a sequence→state_hash map from transition log
        transition_hashes: Dict[int, str] = {
            t.sequence: t.state_hash for t in replay_result.transitions
        }

        for cp in in_window:
            sh = transition_hashes.get(cp.sequence)
            if sh is None:
                # No transition at this exact sequence — skip
                continue

            result = self.validate_hash(cp.sequence, sh)
            results.append(result)
            if result.valid:
                passed += 1
            else:
                failed += 1
                if first_divergence == -1:
                    first_divergence = cp.sequence

        # Also validate the final state
        if replay_result.to_sequence in self._checkpoints:
            result = self.validate_hash(
                replay_result.to_sequence, replay_result.state_hash
            )
            results.append(result)
            if result.valid:
                passed += 1
            else:
                failed += 1
                first_divergence = min(
                    first_divergence if first_divergence != -1 else 10**18,
                    replay_result.to_sequence,
                )

        return BatchValidationReport(
            total_checkpoints=len(results),
            passed=passed,
            failed=failed,
            results=results,
            overall_valid=failed == 0,
            first_divergence_seq=first_divergence,
        )

    # ---------------------------------------------------------------------------
    # Cross-replay comparison
    # ---------------------------------------------------------------------------

    def cross_validate(
        self,
        result_a,
        result_b,
    ) -> Dict[str, Any]:
        """
        Compare two independent replays of the same event sequence.
        Both must produce identical state_hash to pass cross-validation.
        This detects non-determinism in the state machine implementation.
        """
        match = result_a.state_hash == result_b.state_hash
        chain_match = result_a.replay_chain_hash == result_b.replay_chain_hash

        if not match:
            logger.error(
                "Cross-replay divergence detected",
                extra={
                    "hash_a": result_a.state_hash[:16],
                    "hash_b": result_b.state_hash[:16],
                },
            )

        return {
            "state_hash_match": match,
            "chain_hash_match": chain_match,
            "valid": match and chain_match,
            "hash_a": result_a.state_hash,
            "hash_b": result_b.state_hash,
            "events_applied_a": result_a.events_applied,
            "events_applied_b": result_b.events_applied,
        }

    # ---------------------------------------------------------------------------
    # Persistence
    # ---------------------------------------------------------------------------

    def export_checkpoints(self) -> List[Dict[str, Any]]:
        """Export all checkpoints for persistence or cross-system transfer."""
        return [cp.to_dict() for cp in self._checkpoints.values()]

    def import_checkpoints(self, records: List[Dict[str, Any]]) -> int:
        """Import previously exported checkpoints. Returns count imported."""
        count = 0
        for r in records:
            self.register(
                sequence=r["sequence"],
                state_hash=r["state_hash"],
                label=r.get("label", ""),
                registered_by=r.get("registered_by", "import"),
                tenant_id=r.get("tenant_id"),
                metadata=r.get("metadata", {}),
            )
            count += 1
        return count

    @property
    def checkpoint_count(self) -> int:
        return len(self._checkpoints)

    def list_checkpoints(self) -> List[Checkpoint]:
        return [cp for _, cp in sorted(self._checkpoints.items())]