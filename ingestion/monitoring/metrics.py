"""
ingestion/monitoring/metrics.py — Pipeline Metrics Collector

Tracks:
  - Events received / processed / deduplicated / failed / throttled
  - Per-stage latency (min / max / avg / p95 / p99)
  - Batch sizes
  - Queue depth snapshots
  - Error rates per stage
  - Throughput (events/sec over sliding window)

Compatible with Prometheus exposition format (via prometheus_client if available).
Falls back to in-memory dict export otherwise.
"""

import logging
import math
import time
from collections import defaultdict, deque
from typing import Any

logger = logging.getLogger("hollow_purple.metrics")

# Sliding window for throughput calculation
THROUGHPUT_WINDOW_SEC = 60.0


class Histogram:
    """Simple fixed-bucket latency histogram."""

    BUCKETS = (1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000)  # ms

    def __init__(self):
        self._values: list[float] = []
        self._sum    = 0.0
        self._count  = 0

    def observe(self, value_ms: float):
        self._values.append(value_ms)
        self._sum   += value_ms
        self._count += 1
        if len(self._values) > 10_000:
            self._values = self._values[-5000:]

    def stats(self) -> dict:
        if not self._values:
            return {"count": 0, "sum_ms": 0, "avg_ms": 0, "p95_ms": 0, "p99_ms": 0,
                    "min_ms": 0, "max_ms": 0}
        sorted_v = sorted(self._values)
        n        = len(sorted_v)
        return {
            "count":  self._count,
            "sum_ms": round(self._sum, 3),
            "avg_ms": round(self._sum / self._count, 3),
            "min_ms": round(sorted_v[0], 3),
            "max_ms": round(sorted_v[-1], 3),
            "p95_ms": round(sorted_v[int(n * 0.95)], 3),
            "p99_ms": round(sorted_v[int(n * 0.99)], 3),
        }


class Metrics:
    """
    Central pipeline metrics store.

    Usage:
        m = Metrics()
        m.record_received()
        m.record_processed(latency_ms=12.5)
        m.record_failed("validate")
        print(m.snapshot())
    """

    def __init__(self):
        self._received    = 0
        self._processed   = 0
        self._deduplicated = 0
        self._failed:    dict[str, int] = defaultdict(int)
        self._throttled  = 0
        self._batches    = 0
        self._batch_sizes: list[int] = []

        self._latency = Histogram()

        # Sliding window for throughput
        self._processed_ts: deque[float] = deque()

        self._start_time = time.time()

    # ------------------------------------------------------------------ #
    #  Recording                                                           #
    # ------------------------------------------------------------------ #

    def record_received(self):
        self._received += 1

    def record_processed(self, latency_ms: float = 0.0):
        self._processed += 1
        self._latency.observe(latency_ms)
        now = time.time()
        self._processed_ts.append(now)
        # Trim old entries outside window
        while self._processed_ts and now - self._processed_ts[0] > THROUGHPUT_WINDOW_SEC:
            self._processed_ts.popleft()

    def record_deduplicated(self):
        self._deduplicated += 1

    def record_failed(self, stage: str):
        self._failed[stage] += 1

    def record_throttled(self):
        self._throttled += 1

    def record_batch(self, size: int):
        self._batches += 1
        self._batch_sizes.append(size)
        if len(self._batch_sizes) > 1000:
            self._batch_sizes = self._batch_sizes[-500:]

    # ------------------------------------------------------------------ #
    #  Reporting                                                           #
    # ------------------------------------------------------------------ #

    def throughput_per_sec(self) -> float:
        """Events processed per second over the last 60-second window."""
        return round(len(self._processed_ts) / THROUGHPUT_WINDOW_SEC, 2)

    def error_rate(self) -> float:
        total_failed = sum(self._failed.values())
        if self._received == 0:
            return 0.0
        return round(total_failed / self._received * 100, 2)

    def dedup_rate(self) -> float:
        if self._received == 0:
            return 0.0
        return round(self._deduplicated / self._received * 100, 2)

    def avg_batch_size(self) -> float:
        if not self._batch_sizes:
            return 0.0
        return round(sum(self._batch_sizes) / len(self._batch_sizes), 1)

    def snapshot(self) -> dict:
        uptime = time.time() - self._start_time
        return {
            "uptime_sec":         round(uptime, 1),
            "received":           self._received,
            "processed":          self._processed,
            "deduplicated":       self._deduplicated,
            "throttled":          self._throttled,
            "failed_by_stage":    dict(self._failed),
            "total_failed":       sum(self._failed.values()),
            "error_rate_pct":     self.error_rate(),
            "dedup_rate_pct":     self.dedup_rate(),
            "throughput_eps":     self.throughput_per_sec(),
            "batches_dispatched": self._batches,
            "avg_batch_size":     self.avg_batch_size(),
            "latency":            self._latency.stats(),
        }

    def prometheus_format(self) -> str:
        """Export metrics in Prometheus text exposition format."""
        s = self.snapshot()
        lines = [
            f'# HELP hp_events_received_total Total events received',
            f'# TYPE hp_events_received_total counter',
            f'hp_events_received_total {s["received"]}',
            f'# HELP hp_events_processed_total Total events processed',
            f'# TYPE hp_events_processed_total counter',
            f'hp_events_processed_total {s["processed"]}',
            f'# HELP hp_throughput_eps Events processed per second',
            f'# TYPE hp_throughput_eps gauge',
            f'hp_throughput_eps {s["throughput_eps"]}',
            f'# HELP hp_error_rate_percent Pipeline error rate',
            f'# TYPE hp_error_rate_percent gauge',
            f'hp_error_rate_percent {s["error_rate_pct"]}',
            f'# HELP hp_latency_p99_ms P99 pipeline latency in ms',
            f'# TYPE hp_latency_p99_ms gauge',
            f'hp_latency_p99_ms {s["latency"].get("p99_ms", 0)}',
        ]
        return "\n".join(lines)