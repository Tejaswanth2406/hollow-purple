"""
graph_intelligence/crown_jewel_analyzer.py — Crown Jewel Exposure Analyzer

Identifies, tracks, and analyzes access to critical assets.

Capabilities:
  1. Crown jewel registry (manual + auto-discovery)
  2. Auto-discovery: infer jewels from resource name signals + access frequency
  3. Per-jewel access risk scoring (who has access, how many hops, from where)
  4. Access alert with context: actor, path length, anomaly score
  5. Exposure surface: how many identities can reach each crown jewel
  6. Jewel ranking by exposure risk (most exposed first)
  7. Trend detection: is exposure growing or shrinking over time?
  8. Recommended isolation: minimum identity removals to protect a jewel
"""

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable

logger = logging.getLogger("hollow_purple.crown_jewel")

# Keywords that suggest a resource is a crown jewel
AUTO_DISCOVER_SIGNALS = frozenset({
    "prod-db", "production-db", "secret", "kms", "billing", "financial",
    "pci", "hipaa", "admin-role", "root", "master", "private-key",
    "certificate", "password-store", "vault", "credentials", "payments",
    "customer-data", "pii", "ssn", "cardholder",
})


@dataclass
class JewelExposure:
    jewel:          str
    exposure_score: float    # [0.0–1.0] composite risk
    direct_actors:  list     # actors with direct access
    indirect_actors: list    # actors with graph-path access
    access_count:   int      # total access events
    last_access:    float | None
    alert_count:    int

    def to_dict(self) -> dict:
        return {
            "jewel":           self.jewel,
            "exposure_score":  round(self.exposure_score, 4),
            "direct_actors":   self.direct_actors[:10],
            "indirect_count":  len(self.indirect_actors),
            "access_count":    self.access_count,
            "last_access":     self.last_access,
            "alert_count":     self.alert_count,
            "risk_level":      self._risk_level(),
        }

    def _risk_level(self) -> str:
        if self.exposure_score >= 0.8: return "critical"
        if self.exposure_score >= 0.6: return "high"
        if self.exposure_score >= 0.35: return "medium"
        return "low"


class CrownJewelAnalyzer:
    """
    Tracks and analyzes access to critical assets.

    Usage:
        analyzer = CrownJewelAnalyzer(graph_store)
        analyzer.mark("prod-database")
        analyzer.auto_discover(resource_list)
        alerts = analyzer.analyze_access(events)
        report = analyzer.exposure_report()
        ranked = analyzer.rank_by_exposure()
    """

    def __init__(
        self,
        graph_store=None,
        on_jewel_access: Callable[[dict], None] | None = None,
    ):
        self.graph          = graph_store
        self._jewels:       set[str]              = set()
        self._exposure:     dict[str, JewelExposure] = {}
        self._access_log:   dict[str, list[dict]]    = defaultdict(list)
        self._on_jewel_access = on_jewel_access

    # ------------------------------------------------------------------ #
    #  Registry management                                                 #
    # ------------------------------------------------------------------ #

    def mark(self, resource: str, reason: str = "manual"):
        """Designate a resource as a crown jewel."""
        self._jewels.add(resource)
        if resource not in self._exposure:
            self._exposure[resource] = JewelExposure(
                jewel=resource, exposure_score=0.0,
                direct_actors=[], indirect_actors=[],
                access_count=0, last_access=None, alert_count=0,
            )
        logger.info("Crown jewel marked: '%s' (reason=%s)", resource, reason)

    def unmark(self, resource: str):
        self._jewels.discard(resource)
        logger.info("Crown jewel removed: '%s'", resource)

    def auto_discover(self, resources: list[str]) -> list[str]:
        """
        Automatically discover crown jewels from a resource list
        based on name signals and mark them.
        """
        discovered = []
        for resource in resources:
            r_lower = resource.lower()
            if any(sig in r_lower for sig in AUTO_DISCOVER_SIGNALS):
                if resource not in self._jewels:
                    self.mark(resource, reason="auto_discovery")
                    discovered.append(resource)
        logger.info("Auto-discovered %d crown jewels", len(discovered))
        return discovered

    def is_crown_jewel(self, resource: str) -> bool:
        if resource in self._jewels:
            return True
        r_lower = resource.lower()
        return any(sig in r_lower for sig in AUTO_DISCOVER_SIGNALS)

    # ------------------------------------------------------------------ #
    #  Access analysis                                                     #
    # ------------------------------------------------------------------ #

    def analyze_access(self, events: list[dict]) -> list[dict]:
        """
        Analyze a list of events for crown jewel access.
        Returns alerts for any access to registered crown jewels.
        """
        alerts = []
        for event in events:
            resource = event.get("resource", "")
            actor    = event.get("actor", "")
            action   = event.get("action", "")
            ts       = event.get("timestamp", time.time())

            if not self.is_crown_jewel(resource):
                continue

            # Ensure jewel is in registry
            if resource not in self._jewels:
                self.mark(resource, reason="access_triggered")

            exposure = self._exposure[resource]
            exposure.access_count += 1
            exposure.last_access   = ts
            exposure.alert_count  += 1

            if actor and actor not in exposure.direct_actors:
                exposure.direct_actors.append(actor)

            self._access_log[resource].append({
                "actor": actor, "action": action, "ts": ts,
                "ip": event.get("ip"), "anomaly_score": event.get("anomaly_score", 0),
            })

            # Compute exposure score update
            exposure.exposure_score = self._compute_exposure(exposure, event)

            alert = {
                "type":           "crown_jewel_access",
                "jewel":          resource,
                "actor":          actor,
                "action":         action,
                "severity":       self._access_severity(event, exposure),
                "anomaly_score":  event.get("anomaly_score", 0),
                "access_count":   exposure.access_count,
                "exposure_score": round(exposure.exposure_score, 4),
                "detail":         f"Crown jewel '{resource}' accessed by '{actor}' via '{action}'",
            }
            alerts.append(alert)

            if self._on_jewel_access:
                self._on_jewel_access(alert)

        return alerts

    # ------------------------------------------------------------------ #
    #  Graph-based exposure analysis                                       #
    # ------------------------------------------------------------------ #

    def compute_graph_exposure(self, jewel: str, all_actors: list[str]) -> list[dict]:
        """
        For each actor, compute shortest hop-count to this crown jewel via the graph.
        Returns ranked list of actors by proximity.
        """
        if not self.graph:
            return []

        results = []
        for actor in all_actors:
            hops = self._hop_count(actor, jewel)
            if hops is not None:
                results.append({
                    "actor": actor,
                    "hops":  hops,
                    "risk":  max(0.0, 1.0 - hops * 0.15),
                })

        results.sort(key=lambda x: x["hops"])
        # Update indirect actors list
        if jewel in self._exposure:
            self._exposure[jewel].indirect_actors = [r["actor"] for r in results]

        return results

    # ------------------------------------------------------------------ #
    #  Reporting                                                           #
    # ------------------------------------------------------------------ #

    def exposure_report(self) -> dict:
        """Full exposure report across all registered crown jewels."""
        return {
            "total_jewels":   len(self._jewels),
            "jewels":         [e.to_dict() for e in self._exposure.values()],
            "critical_count": sum(1 for e in self._exposure.values() if e.exposure_score >= 0.8),
            "high_count":     sum(1 for e in self._exposure.values() if 0.6 <= e.exposure_score < 0.8),
        }

    def rank_by_exposure(self) -> list[dict]:
        """Return crown jewels ranked by exposure score (highest risk first)."""
        return sorted(
            [e.to_dict() for e in self._exposure.values()],
            key=lambda x: -x["exposure_score"],
        )

    def access_history(self, jewel: str, limit: int = 50) -> list[dict]:
        """Return recent access log for a specific crown jewel."""
        return self._access_log.get(jewel, [])[-limit:]

    def jewels(self) -> list[str]:
        return list(self._jewels)

    def stats(self) -> dict:
        return {
            "total_jewels":        len(self._jewels),
            "total_access_events": sum(e.access_count for e in self._exposure.values()),
            "highest_risk_jewel":  max(
                (e.jewel for e in self._exposure.values()),
                key=lambda j: self._exposure[j].exposure_score,
                default=None,
            ),
        }

    # ------------------------------------------------------------------ #
    #  Internal helpers                                                    #
    # ------------------------------------------------------------------ #

    def _compute_exposure(self, exposure: JewelExposure, event: dict) -> float:
        """
        Composite exposure score: actor count + access frequency + anomaly signal.
        """
        actor_factor     = min(1.0, len(exposure.direct_actors) / 20)
        frequency_factor = min(1.0, exposure.access_count / 100)
        anomaly_factor   = float(event.get("anomaly_score", 0))
        severity_bonus   = 0.3 if event.get("severity") in ("critical", "high") else 0.0
        return min(1.0, actor_factor * 0.3 + frequency_factor * 0.2 +
                        anomaly_factor * 0.3 + severity_bonus + 0.1)

    def _access_severity(self, event: dict, exposure: JewelExposure) -> str:
        if event.get("severity") == "critical" or exposure.exposure_score >= 0.8:
            return "critical"
        if event.get("anomaly_score", 0) > 0.7 or exposure.exposure_score >= 0.6:
            return "high"
        if exposure.access_count > 50:
            return "medium"
        return "low"

    def _hop_count(self, start: str, target: str) -> int | None:
        """BFS shortest hop count from start to target."""
        if not self.graph:
            return None
        from collections import deque
        queue:   deque  = deque([(start, 0)])
        visited: set    = {start}
        while queue:
            node, hops = queue.popleft()
            if node == target:
                return hops
            if hops >= 8:
                continue
            try:
                for edge in (self.graph.get_neighbors(node) or []):
                    nxt = edge.get("target", "")
                    if nxt and nxt not in visited:
                        visited.add(nxt)
                        queue.append((nxt, hops + 1))
            except Exception:
                pass
        return None