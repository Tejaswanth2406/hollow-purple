import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional
import bisect


@dataclass(order=True)
class TemporalEdge:
    timestamp: float
    source: str    = field(compare=False)
    target: str    = field(compare=False)
    edge_type: str = field(compare=False)
    weight: float  = field(compare=False, default=1.0)
    session_id: Optional[str] = field(compare=False, default=None)


class TemporalGraph:
    """
    Time-aware edge store supporting:
    - Efficient time-range queries (bisect)
    - Session reconstruction
    - Velocity / frequency analysis
    - TTL-based edge expiration
    """

    def __init__(self, ttl_seconds: float = 86400):
        self._edges: list[TemporalEdge] = []           # sorted by timestamp
        self._by_source: dict[str, list[TemporalEdge]] = defaultdict(list)
        self._by_session: dict[str, list[TemporalEdge]] = defaultdict(list)
        self.ttl = ttl_seconds

    # ── Ingestion ──────────────────────────────────────────────────────────

    def add_edge(
        self,
        source: str,
        target: str,
        timestamp: float,
        edge_type: str = "access",
        weight: float = 1.0,
        session_id: Optional[str] = None,
    ):
        edge = TemporalEdge(
            timestamp=timestamp,
            source=source,
            target=target,
            edge_type=edge_type,
            weight=weight,
            session_id=session_id,
        )
        bisect.insort(self._edges, edge)
        self._by_source[source].append(edge)

        if session_id:
            self._by_session[session_id].append(edge)

    # ── Queries ────────────────────────────────────────────────────────────

    def edges_in_window(self, start: float, end: float) -> list[TemporalEdge]:
        lo = bisect.bisect_left(self._edges, TemporalEdge(start, "", "", ""))
        hi = bisect.bisect_right(self._edges, TemporalEdge(end, "", "", ""))
        return self._edges[lo:hi]

    def neighbors_at(self, node: str, timestamp: float, window: float = 300) -> list[TemporalEdge]:
        start = timestamp - window
        end   = timestamp + window
        return [
            e for e in self._by_source.get(node, [])
            if start <= e.timestamp <= end
        ]

    def session_edges(self, session_id: str) -> list[TemporalEdge]:
        return self._by_session.get(session_id, [])

    # ── Velocity ───────────────────────────────────────────────────────────

    def event_velocity(self, node: str, window_seconds: float = 300) -> float:
        now    = time.time()
        cutoff = now - window_seconds
        count  = sum(1 for e in self._by_source.get(node, []) if e.timestamp >= cutoff)
        return count / (window_seconds / 60)  # events per minute

    def burst_score(self, node: str, window_seconds: float = 60, threshold: int = 10) -> float:
        velocity = self.event_velocity(node, window_seconds)
        return min(velocity / threshold, 1.0)

    # ── Expiry ─────────────────────────────────────────────────────────────

    def purge_expired(self):
        cutoff = time.time() - self.ttl
        self._edges = [e for e in self._edges if e.timestamp >= cutoff]
        for src in list(self._by_source):
            self._by_source[src] = [e for e in self._by_source[src] if e.timestamp >= cutoff]
            if not self._by_source[src]:
                del self._by_source[src]

    # ── Replay ─────────────────────────────────────────────────────────────

    def replay(self, start: float, end: float):
        """Generator: yields edges in chronological order for a time window."""
        for edge in self.edges_in_window(start, end):
            yield edge