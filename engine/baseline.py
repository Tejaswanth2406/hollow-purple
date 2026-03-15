"""
engine/baseline.py — Hollow Purple Engine Layer
=================================================
BaselineRuntimeEngine: runtime controller that coordinates identity behavioral
baselines using the policy_engine components.

Data flow per event:
    Event → FeatureExtractor → BaselineStore (load) → BaselineEngine (update)
          → DriftDetector → BaselineStore (save) → BaselineProcessingResult

Design principles:
  • All operations are deterministic and replay-safe.
  • No global mutable state; all dependencies are injected.
  • Events are processed in sequence order to guarantee reproducibility.
  • Nondeterministic entropy sources (random, os.urandom) are never used.

Author: Hollow Purple Infrastructure Team
Version: 1.0.0
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterator, Optional, Protocol, Sequence, runtime_checkable

from ..core.constants import HASH_ALGORITHM, HASH_ENCODING, TIMESTAMP_FORMAT
from ..core.models import Event

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Timestamp helper
# ---------------------------------------------------------------------------

def _utcnow_iso() -> str:
    """Return the current UTC time as an ISO-8601 microsecond-precision string."""
    return datetime.now(tz=timezone.utc).strftime(TIMESTAMP_FORMAT)


# ---------------------------------------------------------------------------
# Policy-engine Protocol interfaces
# ---------------------------------------------------------------------------
# These protocols decouple engine/baseline.py from concrete policy_engine
# implementations, enabling easy substitution and testing.

@runtime_checkable
class FeatureVector(Protocol):
    """Minimal contract for a feature vector returned by FeatureExtractor."""

    identity_id: str
    features: dict[str, float]
    event_id: str
    timestamp: str


@runtime_checkable
class IdentityBaselineProtocol(Protocol):
    """Minimal contract for an IdentityBaseline model object."""

    identity_id: str
    feature_means: dict[str, float]
    feature_stds: dict[str, float]
    event_count: int
    last_updated: str

    def to_dict(self) -> dict[str, Any]: ...

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "IdentityBaselineProtocol": ...


class FeatureExtractorProtocol(Protocol):
    """Contract for policy_engine.feature_extractor.FeatureExtractor."""

    def extract(self, event: Event) -> FeatureVector:
        """Extract a feature vector from a single event."""
        ...


class BaselineEngineProtocol(Protocol):
    """Contract for policy_engine.baseline_engine.BaselineEngine."""

    def update(
        self,
        baseline: Optional[IdentityBaselineProtocol],
        features: FeatureVector,
    ) -> IdentityBaselineProtocol:
        """Apply features to a baseline and return the updated model."""
        ...

    def create_initial(self, features: FeatureVector) -> IdentityBaselineProtocol:
        """Create a baseline from the first observation."""
        ...


class BaselineStoreProtocol(Protocol):
    """Contract for policy_engine.baseline_store.BaselineStore."""

    def load(self, identity_id: str) -> Optional[IdentityBaselineProtocol]:
        """Load a baseline for the given identity; None if not present."""
        ...

    def save(self, baseline: IdentityBaselineProtocol) -> None:
        """Persist a baseline."""
        ...

    def exists(self, identity_id: str) -> bool:
        """Return True if a baseline exists for this identity."""
        ...

    def all_identity_ids(self) -> list[str]:
        """Return sorted list of all identity IDs with stored baselines."""
        ...


class DriftDetectorProtocol(Protocol):
    """Contract for policy_engine.drift_detector.DriftDetector."""

    def compute_drift(
        self,
        baseline: IdentityBaselineProtocol,
        features: FeatureVector,
    ) -> float:
        """Return a drift score in [0.0, ∞). Higher = more anomalous."""
        ...

    def is_anomaly(self, drift_score: float) -> bool:
        """Return True if the drift score exceeds the anomaly threshold."""
        ...


# ---------------------------------------------------------------------------
# Result models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BaselineProcessingResult:
    """
    Structured output from processing a single event through the baseline engine.

    Fields:
        identity_id:       Actor identity associated with the processed event.
        event_reference:   The event_id of the processed event.
        drift_score:       Numerical anomaly score (higher = more unusual).
        is_anomaly:        True if drift_score exceeds the configured threshold.
        updated_baseline:  Serialized snapshot of the baseline after update.
        features_used:     Feature vector values extracted from the event.
        processed_at:      ISO-8601 UTC timestamp of processing.
        sequence:          Event sequence number (for deterministic ordering).
    """

    identity_id: str
    event_reference: str
    drift_score: float
    is_anomaly: bool
    updated_baseline: dict[str, Any]
    features_used: dict[str, float]
    processed_at: str
    sequence: int

    def to_dict(self) -> dict[str, Any]:
        """Serialize result to a plain JSON-safe dictionary."""
        return {
            "identity_id": self.identity_id,
            "event_reference": self.event_reference,
            "drift_score": self.drift_score,
            "is_anomaly": self.is_anomaly,
            "updated_baseline": self.updated_baseline,
            "features_used": self.features_used,
            "processed_at": self.processed_at,
            "sequence": self.sequence,
        }

    def content_hash(self, algorithm: str = HASH_ALGORITHM) -> str:
        """Return a deterministic hash of this result's content."""
        serialized = json.dumps(
            self.to_dict(), sort_keys=True, separators=(",", ":"), default=str
        )
        h = hashlib.new(algorithm)
        h.update(serialized.encode(HASH_ENCODING))
        return h.hexdigest()


@dataclass(frozen=True)
class BatchProcessingResult:
    """
    Aggregated output from processing a batch of events.

    Fields:
        results:           Ordered list of per-event results.
        total_events:      Total events processed.
        total_anomalies:   Count of anomaly detections.
        identity_ids:      Deduplicated sorted list of actor identities seen.
        processed_at:      ISO-8601 UTC timestamp of batch completion.
        batch_hash:        Deterministic hash of all result content hashes.
    """

    results: tuple[BaselineProcessingResult, ...]
    total_events: int
    total_anomalies: int
    identity_ids: tuple[str, ...]
    processed_at: str
    batch_hash: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize batch result to a plain dictionary."""
        return {
            "results": [r.to_dict() for r in self.results],
            "total_events": self.total_events,
            "total_anomalies": self.total_anomalies,
            "identity_ids": list(self.identity_ids),
            "processed_at": self.processed_at,
            "batch_hash": self.batch_hash,
        }


# ---------------------------------------------------------------------------
# BaselineRuntimeEngine
# ---------------------------------------------------------------------------

class BaselineRuntimeEngine:
    """
    Runtime controller that coordinates identity behavioral baselines.

    This class wires together FeatureExtractor, BaselineEngine, BaselineStore,
    and DriftDetector to produce drift-detection results for every incoming event.

    All operations are deterministic and replay-safe:
      - Events are always processed in ascending sequence order.
      - No entropy sources (random, uuid4, os.urandom) are used internally.
      - Identical event logs always produce identical results.

    All dependencies are injected via the constructor. No singletons are used
    inside this class.

    Args:
        feature_extractor: Extracts a feature vector from a raw Event.
        baseline_engine:   Updates or creates an IdentityBaseline from features.
        baseline_store:    Persists and loads IdentityBaseline objects.
        drift_detector:    Computes drift scores and classifies anomalies.
        node_id:           Logical node identifier for audit logging.
    """

    def __init__(
        self,
        feature_extractor: FeatureExtractorProtocol,
        baseline_engine: BaselineEngineProtocol,
        baseline_store: BaselineStoreProtocol,
        drift_detector: DriftDetectorProtocol,
        node_id: str = "node-default",
    ) -> None:
        if not feature_extractor:
            raise ValueError("feature_extractor must not be None.")
        if not baseline_engine:
            raise ValueError("baseline_engine must not be None.")
        if not baseline_store:
            raise ValueError("baseline_store must not be None.")
        if not drift_detector:
            raise ValueError("drift_detector must not be None.")
        if not node_id or not node_id.strip():
            raise ValueError("node_id must not be empty.")

        self._feature_extractor: FeatureExtractorProtocol = feature_extractor
        self._baseline_engine: BaselineEngineProtocol = baseline_engine
        self._baseline_store: BaselineStoreProtocol = baseline_store
        self._drift_detector: DriftDetectorProtocol = drift_detector
        self._node_id: str = node_id.strip()

        logger.info(
            "BaselineRuntimeEngine initialised.",
            extra={"node_id": self._node_id},
        )

    # ------------------------------------------------------------------
    # Core public API
    # ------------------------------------------------------------------

    def process_event(self, event: Event) -> BaselineProcessingResult:
        """
        Process a single event through the full baseline pipeline.

        Steps:
            1. Validate the event.
            2. Extract behavioral features.
            3. Load existing baseline for the identity (or None if first).
            4. Detect drift against the existing baseline (if present).
            5. Update (or create) the baseline model.
            6. Persist the updated baseline.
            7. Return a structured BaselineProcessingResult.

        Note: Drift detection is performed *before* updating the baseline so
        the score reflects deviation from the prior distribution, not the
        post-update one. This matches standard anomaly detection semantics.

        Args:
            event: The Event to process. Must be a valid, non-null Event.

        Returns:
            BaselineProcessingResult with drift score, anomaly flag, and
            updated baseline snapshot.

        Raises:
            ValueError: If the event is None or has an empty actor_identity.
        """
        self._validate_event(event)

        identity_id: str = event.actor_identity
        processed_at: str = _utcnow_iso()

        logger.debug(
            "Processing event.",
            extra={
                "event_id": event.event_id,
                "identity_id": identity_id,
                "event_type": event.event_type,
                "sequence": event.sequence,
            },
        )

        # Step 1: Extract features
        features: FeatureVector = self._feature_extractor.extract(event)

        # Step 2: Load existing baseline
        existing_baseline: Optional[IdentityBaselineProtocol] = (
            self._baseline_store.load(identity_id)
        )

        # Step 3: Drift detection against prior baseline
        drift_score: float
        anomaly: bool
        if existing_baseline is not None:
            drift_score = self._drift_detector.compute_drift(existing_baseline, features)
            anomaly = self._drift_detector.is_anomaly(drift_score)
        else:
            # First observation: no prior baseline → drift is 0.0 by definition
            drift_score = 0.0
            anomaly = False

        # Step 4: Update (or create) baseline
        if existing_baseline is not None:
            updated_baseline = self._baseline_engine.update(existing_baseline, features)
        else:
            updated_baseline = self._baseline_engine.create_initial(features)

        # Step 5: Persist updated baseline
        self._baseline_store.save(updated_baseline)

        if anomaly:
            logger.warning(
                "Drift anomaly detected.",
                extra={
                    "identity_id": identity_id,
                    "event_id": event.event_id,
                    "drift_score": drift_score,
                    "sequence": event.sequence,
                    "node_id": self._node_id,
                },
            )
        else:
            logger.debug(
                "Baseline updated; no anomaly.",
                extra={
                    "identity_id": identity_id,
                    "drift_score": drift_score,
                    "sequence": event.sequence,
                },
            )

        return BaselineProcessingResult(
            identity_id=identity_id,
            event_reference=event.event_id,
            drift_score=drift_score,
            is_anomaly=anomaly,
            updated_baseline=updated_baseline.to_dict(),
            features_used=dict(features.features),
            processed_at=processed_at,
            sequence=event.sequence,
        )

    def process_event_batch(
        self,
        events: Sequence[Event],
    ) -> BatchProcessingResult:
        """
        Process a batch of events in deterministic sequence order.

        Events are sorted by their sequence number before processing so that
        replay always produces identical results regardless of input ordering.

        Args:
            events: Collection of Event objects. May be unsorted.

        Returns:
            BatchProcessingResult containing per-event results and aggregate
            statistics.

        Raises:
            ValueError: If events is None or contains any invalid events.
        """
        if events is None:
            raise ValueError("events must not be None.")

        # Sort deterministically by sequence, then event_id as tiebreaker
        sorted_events: list[Event] = sorted(
            events, key=lambda e: (e.sequence, e.event_id)
        )

        logger.info(
            "Processing event batch.",
            extra={"event_count": len(sorted_events), "node_id": self._node_id},
        )

        results: list[BaselineProcessingResult] = []
        for event in sorted_events:
            result = self.process_event(event)
            results.append(result)

        total_anomalies: int = sum(1 for r in results if r.is_anomaly)
        identity_ids: tuple[str, ...] = tuple(
            sorted({r.identity_id for r in results})
        )
        processed_at: str = _utcnow_iso()

        # Build a deterministic batch hash from all result hashes in sequence order
        combined = "".join(r.content_hash() for r in results)
        batch_h = hashlib.new(HASH_ALGORITHM)
        batch_h.update(combined.encode(HASH_ENCODING))
        batch_hash: str = batch_h.hexdigest()

        logger.info(
            "Batch processing complete.",
            extra={
                "total_events": len(results),
                "total_anomalies": total_anomalies,
                "batch_hash": batch_hash[:16],
            },
        )

        return BatchProcessingResult(
            results=tuple(results),
            total_events=len(results),
            total_anomalies=total_anomalies,
            identity_ids=identity_ids,
            processed_at=processed_at,
            batch_hash=batch_hash,
        )

    def get_identity_baseline(
        self, identity_id: str
    ) -> Optional[IdentityBaselineProtocol]:
        """
        Load the current baseline for an identity from the baseline store.

        Args:
            identity_id: The identity whose baseline should be retrieved.

        Returns:
            IdentityBaseline if one exists, otherwise None.

        Raises:
            ValueError: If identity_id is empty.
        """
        self._validate_identity_id(identity_id)
        baseline = self._baseline_store.load(identity_id)
        logger.debug(
            "Baseline load.",
            extra={"identity_id": identity_id, "found": baseline is not None},
        )
        return baseline

    def update_identity_baseline(
        self,
        identity_id: str,
        events: Sequence[Event],
    ) -> IdentityBaselineProtocol:
        """
        Rebuild and persist a baseline for a specific identity using a set of events.

        Events are filtered to those belonging to the identity, then processed
        in sequence order to produce a deterministic baseline update.

        Args:
            identity_id: The identity to update.
            events: Events to incorporate (may contain other identities; filtered).

        Returns:
            The updated IdentityBaseline after processing all relevant events.

        Raises:
            ValueError: If identity_id is empty or no events match.
        """
        self._validate_identity_id(identity_id)

        # Filter and sort deterministically
        identity_events: list[Event] = sorted(
            [e for e in events if e.actor_identity == identity_id],
            key=lambda e: (e.sequence, e.event_id),
        )

        if not identity_events:
            raise ValueError(
                f"No events found for identity '{identity_id}' in the supplied batch."
            )

        logger.info(
            "Updating identity baseline from events.",
            extra={"identity_id": identity_id, "event_count": len(identity_events)},
        )

        current_baseline: Optional[IdentityBaselineProtocol] = (
            self._baseline_store.load(identity_id)
        )

        for event in identity_events:
            features = self._feature_extractor.extract(event)
            if current_baseline is None:
                current_baseline = self._baseline_engine.create_initial(features)
            else:
                current_baseline = self._baseline_engine.update(
                    current_baseline, features
                )

        self._baseline_store.save(current_baseline)

        logger.info(
            "Identity baseline updated.",
            extra={"identity_id": identity_id, "event_count": len(identity_events)},
        )
        return current_baseline

    def detect_identity_drift(
        self,
        identity_id: str,
        features: FeatureVector,
    ) -> float:
        """
        Compute the drift score for an identity against its stored baseline.

        This is a read-only operation: the baseline is not mutated.

        Args:
            identity_id: The identity to evaluate.
            features: Pre-extracted feature vector to compare against baseline.

        Returns:
            Drift score as a float. Returns 0.0 if no baseline exists yet.

        Raises:
            ValueError: If identity_id is empty.
        """
        self._validate_identity_id(identity_id)

        baseline = self._baseline_store.load(identity_id)
        if baseline is None:
            logger.debug(
                "No baseline for identity; drift = 0.0.",
                extra={"identity_id": identity_id},
            )
            return 0.0

        score: float = self._drift_detector.compute_drift(baseline, features)
        logger.debug(
            "Drift score computed.",
            extra={"identity_id": identity_id, "drift_score": score},
        )
        return score

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_event(event: Event) -> None:
        """
        Assert that an event is non-null and has a non-empty actor_identity.

        Args:
            event: Event to validate.

        Raises:
            ValueError: On any validation failure.
        """
        if event is None:
            raise ValueError("event must not be None.")
        if not event.actor_identity or not event.actor_identity.strip():
            raise ValueError(
                f"event '{event.event_id}' has an empty actor_identity."
            )

    @staticmethod
    def _validate_identity_id(identity_id: str) -> None:
        """
        Assert that an identity_id string is non-empty.

        Args:
            identity_id: String to validate.

        Raises:
            ValueError: If empty or whitespace.
        """
        if not identity_id or not identity_id.strip():
            raise ValueError("identity_id must not be empty.")