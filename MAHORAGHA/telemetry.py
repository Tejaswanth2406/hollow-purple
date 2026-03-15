import time
from collections import defaultdict
from typing import Any, Dict, List, Optional


class TelemetryManager:
    """
    Collects in-process system telemetry (counters, gauges, histograms).

    In production, metrics are exported to Prometheus / OpenTelemetry.
    This implementation provides the core collection layer.
    """

    def __init__(self):
        self._metrics: Dict[str, List[dict]] = defaultdict(list)
        self._counters: Dict[str, float] = defaultdict(float)
        self._gauges: Dict[str, float] = {}

    # ─── Raw time-series ─────────────────────────────────────────────────────

    def record(self, metric: str, value: float, tags: Optional[Dict[str, str]] = None):
        """
        Append a timestamped value to a metric series.

        Args:
            metric: Metric name (e.g. "graph.query.latency_ms")
            value:  Numeric value
            tags:   Optional key-value labels (e.g. {"service": "graph"})
        """
        self._metrics[metric].append({
            "value": value,
            "timestamp": time.time(),
            "tags": tags or {},
        })

    def get_metric(self, metric: str) -> List[dict]:
        return self._metrics.get(metric, [])

    # ─── Counters ─────────────────────────────────────────────────────────────

    def increment(self, counter: str, amount: float = 1.0):
        """Increment a monotonic counter."""
        self._counters[counter] += amount

    def get_counter(self, counter: str) -> float:
        return self._counters.get(counter, 0.0)

    # ─── Gauges ───────────────────────────────────────────────────────────────

    def set_gauge(self, gauge: str, value: float):
        """Set a point-in-time gauge value."""
        self._gauges[gauge] = value

    def get_gauge(self, gauge: str) -> Optional[float]:
        return self._gauges.get(gauge)

    # ─── Summaries ────────────────────────────────────────────────────────────

    def summary(self, metric: str) -> Dict[str, Any]:
        """Return min/max/avg/count for a recorded metric series."""
        series = self._metrics.get(metric, [])
        if not series:
            return {}

        values = [e["value"] for e in series]
        return {
            "count": len(values),
            "min": min(values),
            "max": max(values),
            "avg": sum(values) / len(values),
            "latest": values[-1],
        }

    def export(self) -> Dict[str, Any]:
        """
        Export all collected telemetry.
        Hook this into a Prometheus push gateway or OTEL exporter.
        """
        return {
            "series": dict(self._metrics),
            "counters": dict(self._counters),
            "gauges": dict(self._gauges),
        }

    def reset(self):
        """Clear all collected metrics (e.g. after an export flush)."""
        self._metrics.clear()
        self._counters.clear()
        self._gauges.clear()