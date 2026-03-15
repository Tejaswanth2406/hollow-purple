"""
identity_baseline.py
====================
Immutable behavioral baseline model for an identity in the Hollow Purple system.

Represents a statistical snapshot of an identity's behavior derived from
deterministic feature extraction over historical event streams.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import numpy as np

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BASELINE_SCHEMA_VERSION: str = "1.0.0"
_FLOAT_PRECISION: int = 10  # decimal places for stable rounding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _round_stable(value: float, precision: int = _FLOAT_PRECISION) -> float:
    """Round a float to a fixed number of decimal places for determinism."""
    return round(float(value), precision)


def _vector_to_stable_list(arr: np.ndarray) -> list[float]:
    return [_round_stable(v) for v in arr.tolist()]


# ---------------------------------------------------------------------------
# Core model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IdentityBaseline:
    """
    Immutable statistical baseline of an identity's behavioral features.

    All numeric values are stored as stable rounded floats to ensure
    deterministic serialisation and hashing across platforms.
    """

    # --- identity metadata ---
    identity_id: str
    schema_version: str = field(default=BASELINE_SCHEMA_VERSION)

    # --- feature statistics (fixed-length vectors of equal dimension) ---
    feature_vector: tuple[float, ...]   = field(default_factory=tuple)
    feature_means: tuple[float, ...]    = field(default_factory=tuple)
    feature_variances: tuple[float, ...] = field(default_factory=tuple)
    feature_names: tuple[str, ...]       = field(default_factory=tuple)

    # --- observation metadata ---
    event_count: int = 0
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    last_updated: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    # --- source traceability ---
    source_event_ids: tuple[str, ...] = field(default_factory=tuple)

    # ------------------------------------------------------------------ #
    # Post-init validation
    # ------------------------------------------------------------------ #

    def __post_init__(self) -> None:
        if not self.identity_id or not isinstance(self.identity_id, str):
            raise ValueError("identity_id must be a non-empty string.")
        if self.event_count < 0:
            raise ValueError("event_count must be non-negative.")

        dim = len(self.feature_vector)
        for attr_name, attr_val in (
            ("feature_means", self.feature_means),
            ("feature_variances", self.feature_variances),
        ):
            if len(attr_val) != dim:
                raise ValueError(
                    f"{attr_name} length {len(attr_val)} != "
                    f"feature_vector length {dim}."
                )

        for v in self.feature_variances:
            if v < 0:
                raise ValueError("feature_variances must be non-negative.")

        if self.feature_names and len(self.feature_names) != dim:
            raise ValueError(
                f"feature_names length {len(self.feature_names)} != "
                f"feature_vector length {dim}."
            )

    # ------------------------------------------------------------------ #
    # Derived properties
    # ------------------------------------------------------------------ #

    @property
    def feature_dim(self) -> int:
        return len(self.feature_vector)

    @property
    def feature_stds(self) -> tuple[float, ...]:
        return tuple(_round_stable(v ** 0.5) for v in self.feature_variances)

    def is_empty(self) -> bool:
        return self.event_count == 0 or self.feature_dim == 0

    # ------------------------------------------------------------------ #
    # Deterministic identity hash
    # ------------------------------------------------------------------ #

    def content_hash(self) -> str:
        """
        SHA-256 of the baseline's *content* (excludes timestamps).

        Identical baselines derived from the same event stream will always
        produce the same hash, enabling deterministic replay verification.
        """
        payload = {
            "identity_id": self.identity_id,
            "schema_version": self.schema_version,
            "feature_vector": list(self.feature_vector),
            "feature_means": list(self.feature_means),
            "feature_variances": list(self.feature_variances),
            "feature_names": list(self.feature_names),
            "event_count": self.event_count,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    # ------------------------------------------------------------------ #
    # Comparison
    # ------------------------------------------------------------------ #

    def is_equivalent_to(self, other: IdentityBaseline) -> bool:
        """
        Content-level equality ignoring timestamps.
        Two baselines are equivalent when they represent the same statistical
        model (same event stream replay → same hash).
        """
        return self.content_hash() == other.content_hash()

    def feature_distance(self, other: IdentityBaseline) -> float:
        """
        Euclidean distance between the two baselines' feature vectors.
        Returns –1.0 if dimensions are incompatible.
        """
        if self.feature_dim != other.feature_dim or self.feature_dim == 0:
            logger.warning(
                "feature_distance called on incompatible baselines "
                "(%s dim=%d, %s dim=%d)",
                self.identity_id, self.feature_dim,
                other.identity_id, other.feature_dim,
            )
            return -1.0
        a = np.array(self.feature_vector, dtype=np.float64)
        b = np.array(other.feature_vector, dtype=np.float64)
        return _round_stable(float(np.linalg.norm(a - b)))

    # ------------------------------------------------------------------ #
    # Serialization
    # ------------------------------------------------------------------ #

    def to_dict(self) -> dict[str, Any]:
        return {
            "identity_id": self.identity_id,
            "schema_version": self.schema_version,
            "feature_vector": list(self.feature_vector),
            "feature_means": list(self.feature_means),
            "feature_variances": list(self.feature_variances),
            "feature_names": list(self.feature_names),
            "event_count": self.event_count,
            "created_at": self.created_at,
            "last_updated": self.last_updated,
            "source_event_ids": list(self.source_event_ids),
            "content_hash": self.content_hash(),
        }

    def to_json(self, *, indent: int | None = None) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> IdentityBaseline:
        required = {
            "identity_id", "feature_vector", "feature_means",
            "feature_variances", "event_count",
        }
        missing = required - data.keys()
        if missing:
            raise ValueError(f"Missing required fields: {missing}")

        stored_hash = data.pop("content_hash", None)
        instance = cls(
            identity_id=data["identity_id"],
            schema_version=data.get("schema_version", BASELINE_SCHEMA_VERSION),
            feature_vector=tuple(
                _round_stable(v) for v in data["feature_vector"]
            ),
            feature_means=tuple(
                _round_stable(v) for v in data["feature_means"]
            ),
            feature_variances=tuple(
                _round_stable(v) for v in data["feature_variances"]
            ),
            feature_names=tuple(data.get("feature_names", [])),
            event_count=int(data["event_count"]),
            created_at=data.get(
                "created_at", datetime.now(timezone.utc).isoformat()
            ),
            last_updated=data.get(
                "last_updated", datetime.now(timezone.utc).isoformat()
            ),
            source_event_ids=tuple(data.get("source_event_ids", [])),
        )

        if stored_hash and instance.content_hash() != stored_hash:
            raise ValueError(
                f"Integrity check failed for identity '{instance.identity_id}': "
                f"stored hash {stored_hash!r} != computed {instance.content_hash()!r}"
            )

        return instance

    @classmethod
    def from_json(cls, raw: str) -> IdentityBaseline:
        return cls.from_dict(json.loads(raw))

    # ------------------------------------------------------------------ #
    # Factories
    # ------------------------------------------------------------------ #

    @classmethod
    def empty(
        cls,
        identity_id: str,
        feature_names: tuple[str, ...] = (),
    ) -> IdentityBaseline:
        """Return a zero-observation baseline for a given identity."""
        return cls(
            identity_id=identity_id,
            feature_names=feature_names,
            event_count=0,
        )

    @classmethod
    def from_numpy(
        cls,
        identity_id: str,
        feature_vector: np.ndarray,
        feature_means: np.ndarray,
        feature_variances: np.ndarray,
        event_count: int,
        feature_names: tuple[str, ...] = (),
        source_event_ids: tuple[str, ...] = (),
        last_updated: str | None = None,
    ) -> IdentityBaseline:
        """Construct from NumPy arrays with stable rounding applied."""
        return cls(
            identity_id=identity_id,
            feature_vector=tuple(
                _round_stable(v) for v in feature_vector.tolist()
            ),
            feature_means=tuple(
                _round_stable(v) for v in feature_means.tolist()
            ),
            feature_variances=tuple(
                _round_stable(v) for v in feature_variances.tolist()
            ),
            feature_names=feature_names,
            event_count=event_count,
            last_updated=(
                last_updated or datetime.now(timezone.utc).isoformat()
            ),
            source_event_ids=source_event_ids,
        )

    # ------------------------------------------------------------------ #
    # Dunder helpers
    # ------------------------------------------------------------------ #

    def __repr__(self) -> str:
        return (
            f"IdentityBaseline("
            f"identity_id={self.identity_id!r}, "
            f"event_count={self.event_count}, "
            f"feature_dim={self.feature_dim}, "
            f"hash={self.content_hash()[:12]}…)"
        )