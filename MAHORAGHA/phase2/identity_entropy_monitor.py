"""
Identity Entropy Monitor

Behavioral entropy measures the unpredictability of an identity's actions.

A legitimate user has LOW entropy — they mostly do the same things in
predictable patterns. A compromised identity exploring the environment
(or an attacker doing recon) exhibits HIGH entropy — touching many
different resource types, systems, or actions.

This module supports:
  - Shannon entropy (single-window)
  - Time-windowed rolling entropy (detects entropy spikes in short bursts)
  - Conditional entropy (given prior events, how surprising is the next?)
  - Per-category entropy breakdown (which action categories are diverging?)
  - Anomaly classification with configurable thresholds
"""

from __future__ import annotations

import math
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Deque, Dict, List, Optional, Tuple


@dataclass
class EntropyResult:
    identity_id: str
    entropy: float
    threshold: float
    is_anomalous: bool
    event_count: int
    top_events: List[Tuple[Any, int]]          # (event_type, count) most frequent
    rare_events: List[Any]                      # events seen only once
    category_entropy: Dict[str, float] = field(default_factory=dict)

    @property
    def severity(self) -> str:
        ratio = self.entropy / self.threshold if self.threshold else float("inf")
        if ratio > 2.5:
            return "critical"
        if ratio > 1.8:
            return "high"
        if ratio > 1.0:
            return "medium"
        return "low"


@dataclass
class _WindowedEvent:
    event: Any
    timestamp: float


class IdentityEntropyMonitor:
    """
    Measures behavioral entropy of identities to detect anomalies.

    Usage patterns:
        # Stateless single-window check
        monitor = IdentityEntropyMonitor()
        entropy = monitor.calculate_entropy(events)
        anomalous = monitor.is_anomalous(events)

        # Stateful per-identity windowed tracking
        monitor.observe("user-123", "LOGIN", ts=time.time())
        monitor.observe("user-123", "READ_SECRETS", ts=time.time())
        result = monitor.evaluate("user-123")
    """

    def __init__(
        self,
        default_threshold: float = 2.0,
        window_seconds: float = 3600.0,
        max_window_events: int = 1000,
    ):
        """
        Args:
            default_threshold:  Entropy value above which behavior is anomalous
            window_seconds:     Rolling time window for stateful tracking
            max_window_events:  Max events to keep per identity window
        """
        self.default_threshold = default_threshold
        self.window_seconds = window_seconds
        self.max_window_events = max_window_events

        # Per-identity rolling event windows
        self._windows: Dict[str, Deque[_WindowedEvent]] = {}
        # Per-identity threshold overrides
        self._threshold_overrides: Dict[str, float] = {}
        # Category taxonomy: maps event → category
        self._category_map: Dict[Any, str] = {}

    # ─── Stateless API ───────────────────────────────────────────────────────

    def calculate_entropy(self, events: List[Any]) -> float:
        """
        Compute Shannon entropy of an event sequence.

        H(X) = -Σ p(x) * log2(p(x))

        Returns 0 for empty or single-unique-event sequences.
        """
        if not events:
            return 0.0

        counts = Counter(events)
        total = len(events)
        entropy = 0.0

        for count in counts.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)

        return round(entropy, 6)

    def is_anomalous(
        self,
        events: List[Any],
        threshold: Optional[float] = None,
    ) -> bool:
        """Stateless boolean anomaly check."""
        return self.calculate_entropy(events) > (
            threshold if threshold is not None else self.default_threshold
        )

    def conditional_entropy(
        self,
        events: List[Any],
    ) -> float:
        """
        Compute conditional entropy H(X_t | X_{t-1}).

        Measures how surprising each event is given the preceding event.
        High conditional entropy → each action is unpredictable given context.
        """
        if len(events) < 2:
            return 0.0

        bigrams = list(zip(events[:-1], events[1:]))
        bigram_counts = Counter(bigrams)
        prev_counts = Counter(events[:-1])

        total = len(bigrams)
        cond_entropy = 0.0

        for (prev, curr), count in bigram_counts.items():
            p_bigram = count / total
            p_prev = prev_counts[prev] / total
            if p_prev > 0 and p_bigram > 0:
                cond_entropy -= p_bigram * math.log2(p_bigram / p_prev)

        return round(cond_entropy, 6)

    # ─── Stateful windowed API ───────────────────────────────────────────────

    def register_identity(self, identity_id: str, threshold: Optional[float] = None):
        """Explicitly register an identity (auto-registered on first observe)."""
        if identity_id not in self._windows:
            self._windows[identity_id] = deque(maxlen=self.max_window_events)
        if threshold is not None:
            self._threshold_overrides[identity_id] = threshold

    def observe(self, identity_id: str, event: Any, ts: Optional[float] = None):
        """
        Record an event for a tracked identity.

        Args:
            identity_id: The identity performing the action
            event:       Event type (string, enum, or any hashable)
            ts:          Unix timestamp (defaults to now)
        """
        import time
        if identity_id not in self._windows:
            self.register_identity(identity_id)

        self._windows[identity_id].append(
            _WindowedEvent(event=event, timestamp=ts or time.time())
        )

    def evaluate(
        self,
        identity_id: str,
        as_of: Optional[float] = None,
    ) -> EntropyResult:
        """
        Evaluate entropy anomaly for a tracked identity within the rolling window.

        Args:
            identity_id: The identity to evaluate
            as_of:       Evaluate as of this Unix timestamp (defaults to now)

        Returns:
            EntropyResult with entropy score, anomaly flag, and breakdown
        """
        import time
        now = as_of or time.time()

        if identity_id not in self._windows:
            raise KeyError(f"No observation window for identity: {identity_id!r}")

        cutoff = now - self.window_seconds
        recent = [e for e in self._windows[identity_id] if e.timestamp >= cutoff]
        events = [e.event for e in recent]

        threshold = self._threshold_overrides.get(identity_id, self.default_threshold)
        entropy = self.calculate_entropy(events)
        counts = Counter(events)

        top_events = counts.most_common(5)
        rare_events = [e for e, c in counts.items() if c == 1]
        category_entropy = self._compute_category_entropy(events)

        return EntropyResult(
            identity_id=identity_id,
            entropy=entropy,
            threshold=threshold,
            is_anomalous=entropy > threshold,
            event_count=len(events),
            top_events=top_events,
            rare_events=rare_events,
            category_entropy=category_entropy,
        )

    def set_category_map(self, category_map: Dict[Any, str]):
        """
        Define event → category mappings for per-category entropy breakdown.

        Example:
            monitor.set_category_map({
                "LOGIN": "auth",
                "LOGOUT": "auth",
                "READ_FILE": "data",
                "EXEC_CMD": "execution",
            })
        """
        self._category_map = category_map

    def entropy_spike_detection(
        self,
        identity_id: str,
        short_window: float = 300.0,
        long_window: float = 3600.0,
        spike_ratio: float = 2.0,
    ) -> Tuple[bool, float, float]:
        """
        Detect sudden entropy spikes by comparing short vs long window entropy.

        Returns:
            (is_spike, short_entropy, long_entropy)
        """
        import time
        now = time.time()

        if identity_id not in self._windows:
            return False, 0.0, 0.0

        all_events = list(self._windows[identity_id])
        short_cutoff = now - short_window
        long_cutoff = now - long_window

        short_events = [e.event for e in all_events if e.timestamp >= short_cutoff]
        long_events = [e.event for e in all_events if e.timestamp >= long_cutoff]

        short_entropy = self.calculate_entropy(short_events)
        long_entropy = self.calculate_entropy(long_events)

        is_spike = (
            short_entropy > self.default_threshold
            and long_entropy > 0
            and short_entropy / long_entropy >= spike_ratio
        )
        return is_spike, short_entropy, long_entropy

    # ─── Internals ───────────────────────────────────────────────────────────

    def _compute_category_entropy(self, events: List[Any]) -> Dict[str, float]:
        """Break entropy down by event category (if category map is configured)."""
        if not self._category_map:
            return {}

        categories: Dict[str, List[Any]] = {}
        for event in events:
            cat = self._category_map.get(event, "unknown")
            categories.setdefault(cat, []).append(event)

        return {
            cat: self.calculate_entropy(evts)
            for cat, evts in categories.items()
        }