"""
projections/exposure_projection.py
====================================
Enterprise exposure surface projection engine.

Responsibilities
----------------
- Identify internet-facing, publicly accessible, and laterally exposed assets
- Classify exposure severity using a multi-factor model
- Compute each exposed node's blast radius (downstream impact)
- Detect transitive exposure: internal nodes reachable through exposed nodes
- Track exposure chains: full path from public entry point to sensitive asset
- Score overall organizational attack surface
- Emit structured exposure records for SIEM/SOAR ingestion

Exposure model
--------------
A node is "exposed" if it:
  1. Has a direct "public_access" or "internet_facing" edge (primary exposure)
  2. Is reachable from an exposed node within N hops (transitive exposure)
  3. Has a "secret" / "credential" / "sensitive_data" metadata tag
     and is reachable from any exposed node (data-at-risk exposure)

Severity tiers
--------------
    CRITICAL : Directly internet-facing AND contains sensitive data
    HIGH     : Directly internet-facing OR sensitive data reachable from internet
    MEDIUM   : Transitively exposed (reachable within 2 hops from exposed)
    LOW      : Weakly reachable (3+ hops) or marginal exposure signal
    INFO     : Monitored but below threshold
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Severity classification
# ---------------------------------------------------------------------------


class ExposureSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"

    @property
    def score(self) -> int:
        return {"critical": 100, "high": 75, "medium": 40, "low": 15, "info": 5}[self.value]


# ---------------------------------------------------------------------------
# Exposure record
# ---------------------------------------------------------------------------


@dataclass
class ExposureRecord:
    """
    A single exposed or at-risk node with full exposure context.

    Fields
    ------
    node_id             : Exposed node identifier.
    node_type           : Node type (host, service, database, …).
    severity            : Computed exposure severity tier.
    exposure_type       : direct | transitive | data_at_risk
    entry_points        : Directly internet-facing nodes on the path.
    exposure_path       : Shortest path from an entry point to this node.
    hop_distance        : Number of hops from the nearest entry point.
    blast_radius_count  : Nodes reachable from this node (downstream impact).
    sensitive_data_tags : Detected sensitive data metadata tags.
    relations           : Edge relation types on the exposure path.
    detected_at         : UTC ISO-8601 timestamp.
    """

    node_id: str
    node_type: str
    severity: ExposureSeverity
    exposure_type: str
    entry_points: List[str] = field(default_factory=list)
    exposure_path: List[str] = field(default_factory=list)
    hop_distance: int = 0
    blast_radius_count: int = 0
    sensitive_data_tags: List[str] = field(default_factory=list)
    relations: List[str] = field(default_factory=list)
    detected_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type,
            "severity": self.severity.value,
            "severity_score": self.severity.score,
            "exposure_type": self.exposure_type,
            "entry_points": self.entry_points,
            "exposure_path": self.exposure_path,
            "hop_distance": self.hop_distance,
            "blast_radius_count": self.blast_radius_count,
            "sensitive_data_tags": self.sensitive_data_tags,
            "relations": self.relations,
            "detected_at": self.detected_at,
        }


# ---------------------------------------------------------------------------
# Exposure surface summary
# ---------------------------------------------------------------------------


@dataclass
class ExposureSurface:
    """Aggregated exposure surface metrics."""

    total_exposed: int
    by_severity: Dict[str, int]
    attack_surface_score: float      # weighted sum of severity scores
    entry_point_count: int
    transitive_exposed_count: int
    data_at_risk_count: int
    top_exposed: List[ExposureRecord]
    computed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_exposed": self.total_exposed,
            "by_severity": self.by_severity,
            "attack_surface_score": round(self.attack_surface_score, 2),
            "entry_point_count": self.entry_point_count,
            "transitive_exposed_count": self.transitive_exposed_count,
            "data_at_risk_count": self.data_at_risk_count,
            "top_exposed": [r.to_dict() for r in self.top_exposed[:10]],
            "computed_at": self.computed_at,
        }


# ---------------------------------------------------------------------------
# ExposureProjection
# ---------------------------------------------------------------------------


class ExposureProjection:
    """
    Multi-factor exposure surface computation engine.

    Works against a ``GraphProjection`` instance (not raw GraphStore)
    so it can leverage pre-computed adjacency indices and path algorithms.

    Usage
    -----
    ::

        exposure = ExposureProjection(
            transitive_depth=3,
            sensitive_tags={"pii", "secret", "credential"},
        )

        surface = exposure.compute(graph_projection)

        # All CRITICAL and HIGH exposures
        critical = exposure.by_severity(ExposureSeverity.CRITICAL)

        # Exposure paths from internet to a specific node
        paths = exposure.paths_to("db-prod-01")
    """

    # Edge relation types that indicate direct internet / public exposure
    PUBLIC_RELATIONS: Set[str] = {
        "public_access",
        "internet_facing",
        "external_access",
        "public_endpoint",
        "ingress",
        "exposed_port",
    }

    # Node metadata tags that indicate sensitive data
    DEFAULT_SENSITIVE_TAGS: Set[str] = {
        "pii",
        "secret",
        "credential",
        "sensitive_data",
        "phi",
        "pci",
        "classified",
        "private_key",
        "password",
        "token",
    }

    def __init__(
        self,
        *,
        transitive_depth: int = 3,
        sensitive_tags: Optional[Set[str]] = None,
        blast_radius_depth: int = 4,
    ) -> None:
        self._transitive_depth = transitive_depth
        self._sensitive_tags = sensitive_tags or self.DEFAULT_SENSITIVE_TAGS
        self._blast_radius_depth = blast_radius_depth

        self._records: Dict[str, ExposureRecord] = {}
        self._entry_points: Set[str] = set()

        logger.info(
            "ExposureProjection initialised",
            extra={"transitive_depth": transitive_depth},
        )

    # ---------------------------------------------------------------------------
    # Main computation
    # ---------------------------------------------------------------------------

    def compute(self, graph_projection) -> ExposureSurface:
        """
        Compute the full exposure surface from a GraphProjection.

        Parameters
        ----------
        graph_projection : A built ``GraphProjection`` instance.

        Returns
        -------
        ExposureSurface
            Aggregated surface metrics and top exposure records.
        """
        self._records.clear()
        self._entry_points.clear()

        # Phase 1: identify direct (primary) entry points
        self._find_entry_points(graph_projection)

        # Phase 2: compute transitive exposure
        self._find_transitive_exposure(graph_projection)

        # Phase 3: data-at-risk analysis
        self._find_data_at_risk(graph_projection)

        # Phase 4: severity classification
        self._classify_severity(graph_projection)

        return self._build_surface()

    def _is_sensitive(self, node_meta: Optional[Dict[str, Any]]) -> List[str]:
        """Return list of sensitive tags found in node metadata."""
        if not node_meta:
            return []
        tags = set()
        meta_values = {
            str(v).lower()
            for v in node_meta.get("metadata", {}).values()
        }
        meta_keys = {k.lower() for k in node_meta.get("metadata", {}).keys()}
        all_signals = meta_values | meta_keys
        # Also check node_type
        all_signals.add(node_meta.get("node_type", "").lower())
        return sorted(self._sensitive_tags & all_signals)

    def _find_entry_points(self, gp) -> None:
        """Identify directly internet-exposed nodes via public edge relations."""
        all_node_ids = list(gp._nodes.keys())

        for node_id in all_node_ids:
            for relation in self.PUBLIC_RELATIONS:
                neighbors = gp.neighbors(node_id, relation=relation, direction="in")
                if neighbors:
                    # This node receives connections on a public relation
                    self._entry_points.add(node_id)
                    node_meta = gp.get_node(node_id)
                    sensitive = self._is_sensitive(node_meta)

                    record = ExposureRecord(
                        node_id=node_id,
                        node_type=node_meta.get("node_type", "unknown") if node_meta else "unknown",
                        severity=ExposureSeverity.HIGH,  # refined in phase 4
                        exposure_type="direct",
                        entry_points=[node_id],
                        exposure_path=[node_id],
                        hop_distance=0,
                        sensitive_data_tags=sensitive,
                        relations=[relation],
                    )
                    self._records[node_id] = record
                    logger.debug(
                        "Direct exposure found",
                        extra={"node_id": node_id, "relation": relation},
                    )
                    break

    def _find_transitive_exposure(self, gp) -> None:
        """BFS from each entry point to find transitively exposed nodes."""
        from collections import deque

        for entry in self._entry_points:
            visited: Dict[str, int] = {entry: 0}  # node -> hop distance
            path_map: Dict[str, List[str]] = {entry: [entry]}
            queue: deque = deque([(entry, 0)])

            while queue:
                current, depth = queue.popleft()
                if depth >= self._transitive_depth:
                    continue

                for neighbor in gp.neighbors(current, direction="out"):
                    if neighbor in visited:
                        continue
                    hop = depth + 1
                    visited[neighbor] = hop
                    path_map[neighbor] = path_map[current] + [neighbor]
                    queue.append((neighbor, hop))

                    if neighbor not in self._records and neighbor not in self._entry_points:
                        node_meta = gp.get_node(neighbor)
                        sensitive = self._is_sensitive(node_meta)
                        relations = gp.edge_relations(current, neighbor)

                        record = ExposureRecord(
                            node_id=neighbor,
                            node_type=node_meta.get("node_type", "unknown") if node_meta else "unknown",
                            severity=ExposureSeverity.MEDIUM,  # refined later
                            exposure_type="transitive",
                            entry_points=[entry],
                            exposure_path=path_map[neighbor],
                            hop_distance=hop,
                            sensitive_data_tags=sensitive,
                            relations=relations,
                        )
                        self._records[neighbor] = record

                    elif neighbor in self._records:
                        # Update if this path is shorter
                        existing = self._records[neighbor]
                        if hop < existing.hop_distance:
                            existing.hop_distance = hop
                            existing.exposure_path = path_map[neighbor]
                            if entry not in existing.entry_points:
                                existing.entry_points.append(entry)

    def _find_data_at_risk(self, gp) -> None:
        """Flag records that contain sensitive data."""
        for record in self._records.values():
            if record.sensitive_data_tags:
                if record.exposure_type == "transitive":
                    record.exposure_type = "data_at_risk"

    def _classify_severity(self, gp) -> None:
        """Apply multi-factor severity classification to all records."""
        for record in self._records.values():
            sensitive = bool(record.sensitive_data_tags)
            direct = record.exposure_type == "direct"
            data_risk = record.exposure_type == "data_at_risk"
            hop = record.hop_distance

            # Compute blast radius
            blast = gp.reachable_from(record.node_id, max_depth=self._blast_radius_depth)
            record.blast_radius_count = len(blast)

            if direct and sensitive:
                record.severity = ExposureSeverity.CRITICAL
            elif direct:
                record.severity = ExposureSeverity.HIGH
            elif data_risk:
                record.severity = ExposureSeverity.HIGH
            elif hop <= 1:
                record.severity = ExposureSeverity.HIGH
            elif hop == 2:
                record.severity = ExposureSeverity.MEDIUM
            elif hop == 3:
                record.severity = ExposureSeverity.LOW
            else:
                record.severity = ExposureSeverity.INFO

            # Elevate if large blast radius
            if record.blast_radius_count > 50 and record.severity in (
                ExposureSeverity.MEDIUM, ExposureSeverity.LOW
            ):
                record.severity = ExposureSeverity.HIGH

    def _build_surface(self) -> ExposureSurface:
        records = list(self._records.values())
        by_severity: Dict[str, int] = {s.value: 0 for s in ExposureSeverity}
        score = 0.0

        for r in records:
            by_severity[r.severity.value] += 1
            score += r.severity.score

        transitive_count = sum(
            1 for r in records if r.exposure_type in ("transitive", "data_at_risk")
        )
        data_risk_count = sum(1 for r in records if r.sensitive_data_tags)

        top = sorted(records, key=lambda r: r.severity.score, reverse=True)

        surface = ExposureSurface(
            total_exposed=len(records),
            by_severity=by_severity,
            attack_surface_score=score,
            entry_point_count=len(self._entry_points),
            transitive_exposed_count=transitive_count,
            data_at_risk_count=data_risk_count,
            top_exposed=top[:20],
        )

        logger.info(
            "Exposure surface computed",
            extra={
                "total_exposed": len(records),
                "entry_points": len(self._entry_points),
                "critical": by_severity.get("critical", 0),
                "high": by_severity.get("high", 0),
                "score": round(score, 2),
            },
        )
        return surface

    # ---------------------------------------------------------------------------
    # Query API
    # ---------------------------------------------------------------------------

    def get_record(self, node_id: str) -> Optional[ExposureRecord]:
        return self._records.get(node_id)

    def all_records(self) -> List[ExposureRecord]:
        return sorted(
            self._records.values(),
            key=lambda r: r.severity.score,
            reverse=True,
        )

    def by_severity(self, severity: ExposureSeverity) -> List[ExposureRecord]:
        return [r for r in self._records.values() if r.severity == severity]

    def entry_points(self) -> List[str]:
        return sorted(self._entry_points)

    def paths_to(self, node_id: str) -> List[List[str]]:
        """Return all known exposure paths leading to a node."""
        record = self._records.get(node_id)
        if record:
            return [record.exposure_path]
        return []

    def is_exposed(self, node_id: str) -> bool:
        return node_id in self._records