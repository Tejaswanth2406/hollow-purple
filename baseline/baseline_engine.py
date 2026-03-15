"""
baseline_engine.py
==================
Deterministic construction and incremental update of identity baselines.

All operations are pure/functional where possible.  No global mutable state.
Updates use Welford's online algorithm for numerically stable, incremental
mean/variance computation without accumulating the full dataset.

References
----------
Welford, B.P. (1962). "Note on a method for calculating corrected sums of
squares and products." Technometrics 4(3):419–420.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Sequence

import numpy as np

from .feature_extractor import (
    FEATURE_DIM,
    FEATURE_NAMES,
    RawEvent,
    extract_features,
    validate_feature_vector,
)
from .identity_baseline import IdentityBaseline, _round_stable

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Welford accumulator (mutable, never exposed directly)
# ---------------------------------------------------------------------------


@dataclass
class _WelfordState:
    """
    Running mean & M2 accumulator for Welford's online variance algorithm.
    One instance per identity, kept only inside BaselineEngine.
    """

    n: int = 0
    mean: np.ndarray = field(default_factory=lambda: np.zeros(FEATURE_DIM))
    M2: np.ndarray = field(default_factory=lambda: np.zeros(FEATURE_DIM))

    def update(self, x: np.ndarray) -> None:
        """Incorporate a new observation vector."""
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        delta2 = x - self.mean
        self.M2 += delta * delta2

    def variance(self) -> np.ndarray:
        """Population variance (n).  Returns zeros if n < 2."""
        if self.n < 2:
            return np.zeros(FEATURE_DIM)
        return self.M2 / self.n

    def clone(self) -> _WelfordState:
        return _WelfordState(
            n=self.n,
            mean=self.mean.copy(),
            M2=self.M2.copy(),
        )


# ---------------------------------------------------------------------------
# Public engine
# ---------------------------------------------------------------------------


class BaselineEngine:
    """
    Builds and incrementally updates identity baselines.

    Thread-safety
    -------------
    This class is NOT thread-safe by design.  Callers that share an engine
    across threads must provide external synchronisation.  The recommended
    pattern is one engine instance per worker/task.

    Determinism guarantee
    ---------------------
    Given the same ordered event stream, ``build_baseline`` and
    ``update_baseline`` always produce numerically identical results because:

    * events are sorted by (timestamp, event_id) before processing,
    * Welford's algorithm is applied in that stable order,
    * all floats are rounded to ``_FLOAT_PRECISION`` decimal places.
    """

    def __init__(self) -> None:
        # identity_id → Welford accumulator
        self._accumulators: dict[str, _WelfordState] = {}
        # identity_id → list of event_ids seen (for traceability)
        self._event_ids: dict[str, list[str]] = {}

    # ------------------------------------------------------------------ #
    # Build
    # ------------------------------------------------------------------ #

    def build_baseline(
        self,
        identity_id: str,
        events: Sequence[RawEvent],
    ) -> IdentityBaseline:
        """
        Construct a fresh baseline from a historical event batch.

        Any previously accumulated state for ``identity_id`` is discarded.

        Parameters
        ----------
        identity_id:
            The identity whose baseline is being constructed.
        events:
            Historical events belonging to this identity.
            Events from other identities are silently skipped.

        Returns
        -------
        An immutable ``IdentityBaseline``.
        """
        if not identity_id:
            raise ValueError("identity_id must be non-empty.")

        own_events = [e for e in events if e.identity_id == identity_id]

        if not own_events:
            logger.warning(
                "build_baseline: no events for identity %r – returning empty baseline.",
                identity_id,
            )
            return IdentityBaseline.empty(identity_id, feature_names=FEATURE_NAMES)

        # Sort for determinism
        own_events = sorted(own_events, key=lambda e: (e.timestamp, e.event_id))

        acc = _WelfordState()
        event_ids: list[str] = []

        for evt in own_events:
            vec = extract_features([evt])
            acc.update(vec)
            event_ids.append(evt.event_id)

        self._accumulators[identity_id] = acc
        self._event_ids[identity_id] = event_ids

        baseline = self._snapshot(identity_id, acc, tuple(event_ids))
        logger.info(
            "build_baseline: identity=%r events=%d hash=%s",
            identity_id, acc.n, baseline.content_hash()[:12],
        )
        return baseline

    # ------------------------------------------------------------------ #
    # Update
    # ------------------------------------------------------------------ #

    def update_baseline(
        self,
        baseline: IdentityBaseline,
        new_events: Sequence[RawEvent],
    ) -> IdentityBaseline:
        """
        Incrementally update an existing baseline with new events.

        Uses Welford's algorithm to maintain a running mean/variance without
        requiring access to the full historical dataset.

        Parameters
        ----------
        baseline:
            The current immutable baseline.
        new_events:
            New events to incorporate (from any identity; others are skipped).

        Returns
        -------
        A new immutable ``IdentityBaseline`` with updated statistics.
        """
        identity_id = baseline.identity_id
        own_events = [
            e for e in new_events if e.identity_id == identity_id
        ]

        if not own_events:
            logger.debug(
                "update_baseline: no new events for identity %r – unchanged.",
                identity_id,
            )
            return baseline

        own_events = sorted(own_events, key=lambda e: (e.timestamp, e.event_id))

        # Rehydrate or reconstruct accumulator from stored baseline
        acc = self._get_or_reconstruct_accumulator(baseline)
        event_ids = list(self._event_ids.get(identity_id, []))

        for evt in own_events:
            vec = extract_features([evt])
            acc.update(vec)
            event_ids.append(evt.event_id)

        self._accumulators[identity_id] = acc
        self._event_ids[identity_id] = event_ids

        updated = self._snapshot(identity_id, acc, tuple(event_ids))
        logger.info(
            "update_baseline: identity=%r +%d events, total=%d hash=%s",
            identity_id, len(own_events), acc.n, updated.content_hash()[:12],
        )
        return updated

    # ------------------------------------------------------------------ #
    # Merge
    # ------------------------------------------------------------------ #

    def merge_baselines(
        self,
        baselines: Sequence[IdentityBaseline],
    ) -> IdentityBaseline:
        """
        Merge multiple baselines for the **same identity** into one.

        Uses the parallel Welford combination formula so no raw events
        are needed.

        Raises
        ------
        ValueError
            If baselines belong to different identities or have inconsistent
            feature dimensions.
        """
        if not baselines:
            raise ValueError("merge_baselines requires at least one baseline.")

        identity_ids = {b.identity_id for b in baselines}
        if len(identity_ids) > 1:
            raise ValueError(
                f"All baselines must share the same identity_id. "
                f"Got: {identity_ids}"
            )

        identity_id = next(iter(identity_ids))

        dims = {b.feature_dim for b in baselines}
        if len(dims) > 1:
            raise ValueError(
                f"Baselines have inconsistent feature dimensions: {dims}"
            )

        # Combine via parallel Welford
        merged_acc = _WelfordState()
        all_event_ids: list[str] = []

        for b in sorted(baselines, key=lambda x: x.last_updated):
            if b.is_empty():
                continue
            n_b = b.event_count
            mean_b = np.array(b.feature_means, dtype=np.float64)
            var_b = np.array(b.feature_variances, dtype=np.float64)

            if merged_acc.n == 0:
                merged_acc.n = n_b
                merged_acc.mean = mean_b.copy()
                merged_acc.M2 = var_b * n_b
            else:
                n_a = merged_acc.n
                mean_a = merged_acc.mean
                combined_n = n_a + n_b
                delta = mean_b - mean_a
                merged_acc.mean = (
                    mean_a * n_a + mean_b * n_b
                ) / combined_n
                merged_acc.M2 += (
                    var_b * n_b
                    + delta ** 2 * n_a * n_b / combined_n
                )
                merged_acc.n = combined_n

            all_event_ids.extend(b.source_event_ids)

        # Deduplicate & sort event ids deterministically
        unique_ids = tuple(sorted(set(all_event_ids)))

        result = self._snapshot(identity_id, merged_acc, unique_ids)
        logger.info(
            "merge_baselines: identity=%r merged=%d baselines, "
            "total_events=%d hash=%s",
            identity_id, len(baselines), merged_acc.n,
            result.content_hash()[:12],
        )
        return result

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    def _get_or_reconstruct_accumulator(
        self, baseline: IdentityBaseline
    ) -> _WelfordState:
        """
        Return a live accumulator for the identity, reconstructing from the
        stored baseline snapshot when the engine has been cold-started.
        """
        if baseline.identity_id in self._accumulators:
            return self._accumulators[baseline.identity_id]

        # Cold-start: rebuild accumulator state from stored statistics.
        # We can recover (n, mean, M2) from (n, means, variances).
        acc = _WelfordState()
        acc.n = baseline.event_count
        acc.mean = np.array(baseline.feature_means, dtype=np.float64)
        acc.M2 = (
            np.array(baseline.feature_variances, dtype=np.float64)
            * baseline.event_count
        )
        return acc

    @staticmethod
    def _snapshot(
        identity_id: str,
        acc: _WelfordState,
        source_event_ids: tuple[str, ...],
    ) -> IdentityBaseline:
        """Materialise an immutable baseline from a Welford state snapshot."""
        means = acc.mean.copy()
        variances = acc.variance()
        # Use means as the current feature vector
        feature_vec = means.copy()

        return IdentityBaseline.from_numpy(
            identity_id=identity_id,
            feature_vector=feature_vec,
            feature_means=means,
            feature_variances=variances,
            event_count=acc.n,
            feature_names=FEATURE_NAMES,
            source_event_ids=source_event_ids,
            last_updated=datetime.now(timezone.utc).isoformat(),
        )

    # ------------------------------------------------------------------ #
    # Utility
    # ------------------------------------------------------------------ #

    def reset(self, identity_id: str) -> None:
        """Discard all accumulated state for a given identity."""
        self._accumulators.pop(identity_id, None)
        self._event_ids.pop(identity_id, None)
        logger.debug("reset: cleared state for identity %r", identity_id)

    def known_identities(self) -> frozenset[str]:
        return frozenset(self._accumulators.keys())