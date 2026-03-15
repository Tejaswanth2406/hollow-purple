"""
Signed Tree Head (STH)

A Signed Tree Head is a cryptographically signed checkpoint of the Merkle log
at a specific size. Inspired by RFC 6962 (Certificate Transparency).

Each STH binds:
  - the Merkle root hash
  - the log size at time of signing
  - a timestamp
  - an HMAC-based signature over all of the above

An STH lets any verifier confirm:
  1. The log root they observed was authentic (signature check)
  2. The log has grown monotonically since the last STH (consistency proof)
  3. The timestamp has not been rewound

Enterprise additions over the spec:
  - HMAC-SHA256 signatures (keyed, not just SHA256 of a string)
  - STH chain: each STH references the previous STH's signature
  - Monotonicity enforcement: refuses to sign a smaller log
  - Verification method: verify() accepts an STH dict and re-checks it
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Optional


@dataclass
class STH:
    """Signed Tree Head checkpoint."""
    tree_size: int
    root_hash: str
    timestamp: float
    signature: str
    prev_signature: Optional[str]

    def to_dict(self) -> dict:
        return {
            "tree_size": self.tree_size,
            "root_hash": self.root_hash,
            "timestamp": self.timestamp,
            "signature": self.signature,
            "prev_signature": self.prev_signature,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "STH":
        return cls(
            tree_size=d["tree_size"],
            root_hash=d["root_hash"],
            timestamp=d["timestamp"],
            signature=d["signature"],
            prev_signature=d.get("prev_signature"),
        )


class SignedTreeHead:
    """
    Issues and verifies Signed Tree Head checkpoints.

    Uses HMAC-SHA256 for signatures — the private key is a shared secret
    between the log server and verifiers. In production, replace with an
    asymmetric scheme (ECDSA P-256 or Ed25519).

    Enforces:
      - monotonic tree size (cannot sign a shrinking log)
      - STH chain linkage (each STH references the previous signature)
      - timestamp sanity (refused if clock skew > max_clock_skew_seconds)
    """

    def __init__(
        self,
        private_key: str = "hollow-purple-dev-key",
        max_clock_skew_seconds: float = 300.0,
    ):
        self._key = private_key.encode()
        self.max_clock_skew = max_clock_skew_seconds
        self._history: list[STH] = []

    # ─── Signing ─────────────────────────────────────────────────────────────

    def sign(self, merkle_root: str, tree_size: int, ts: Optional[float] = None) -> STH:
        """
        Issue a new Signed Tree Head.

        Args:
            merkle_root: The current Merkle root hash
            tree_size:   Number of leaves in the log at this point
            ts:          Timestamp to use (defaults to now)

        Returns:
            STH dataclass with signature

        Raises:
            ValueError if tree_size is smaller than the last signed size
        """
        if self._history:
            last = self._history[-1]
            if tree_size < last.tree_size:
                raise ValueError(
                    f"Monotonicity violation: cannot sign tree_size={tree_size} "
                    f"after previously signing tree_size={last.tree_size}"
                )

        timestamp = ts if ts is not None else time.time()
        prev_sig = self._history[-1].signature if self._history else None

        payload = self._build_payload(merkle_root, tree_size, timestamp, prev_sig)
        signature = self._sign_payload(payload)

        sth = STH(
            tree_size=tree_size,
            root_hash=merkle_root,
            timestamp=timestamp,
            signature=signature,
            prev_signature=prev_sig,
        )
        self._history.append(sth)
        return sth

    # ─── Verification ────────────────────────────────────────────────────────

    def verify(self, sth: STH, now: Optional[float] = None) -> bool:
        """
        Verify the signature on an STH.

        Checks:
          1. HMAC signature is valid
          2. Timestamp is not in the future (within clock skew)

        Args:
            sth: The STH to verify
            now: Override wall clock (for testing)

        Returns:
            True if valid
        """
        current_time = now if now is not None else time.time()

        # Clock skew check
        if sth.timestamp > current_time + self.max_clock_skew:
            return False

        # Recompute signature
        payload = self._build_payload(
            sth.root_hash, sth.tree_size, sth.timestamp, sth.prev_signature
        )
        expected_sig = self._sign_payload(payload)

        return hmac.compare_digest(expected_sig, sth.signature)

    def verify_chain(self) -> bool:
        """
        Verify the entire STH chain: each STH correctly references the
        previous one, and all signatures are valid.
        """
        for i, sth in enumerate(self._history):
            if not self.verify(sth):
                return False
            if i > 0:
                expected_prev = self._history[i - 1].signature
                if sth.prev_signature != expected_prev:
                    return False
        return True

    # ─── History access ──────────────────────────────────────────────────────

    def latest(self) -> Optional[STH]:
        """Return the most recently issued STH."""
        return self._history[-1] if self._history else None

    def get_history(self) -> list[STH]:
        return list(self._history)

    # ─── Internals ───────────────────────────────────────────────────────────

    @staticmethod
    def _build_payload(
        root: str,
        size: int,
        ts: float,
        prev_sig: Optional[str],
    ) -> bytes:
        doc = {
            "root": root,
            "tree_size": size,
            "timestamp": ts,
            "prev_signature": prev_sig,
        }
        return json.dumps(doc, sort_keys=True).encode()

    def _sign_payload(self, payload: bytes) -> str:
        return hmac.new(self._key, payload, hashlib.sha256).hexdigest()