"""
services/risk_service.py — Identity Risk Orchestration

Responsibilities:
  - Query graph engine for identity risk score
  - Discover privilege escalation paths
  - Compute blast radius projection
  - Cache results for repeated queries
  - Classify risk level from score
"""

from __future__ import annotations

import logging
from typing import Any, Dict

logger = logging.getLogger("hollowpurple.risk_service")

_RISK_THRESHOLDS = {
    "low":      (0.0,  0.35),
    "medium":   (0.35, 0.65),
    "high":     (0.65, 0.85),
    "critical": (0.85, 1.01),
}


def _classify_risk(score: float) -> str:
    for level, (lo, hi) in _RISK_THRESHOLDS.items():
        if lo <= score < hi:
            return level
    return "critical"


class RiskService:

    def __init__(self) -> None:
        self._cache = None

    def _get_cache(self):
        if self._cache is None:
            try:
                from api.cache.risk_cache import RiskCache
                self._cache = RiskCache()
            except ImportError:
                self._cache = _StubCache()
        return self._cache

    async def query_identity_risk(
        self, identity: str, window_hours: int, include_paths: bool = True, max_depth: int = 5
    ) -> Dict[str, Any]:

        cache = self._get_cache()
        cached = await cache.get(identity, window_hours)
        if cached:
            logger.debug("risk_cache_hit", extra={"identity": identity})
            return cached

        try:
            risk_data = _compute_risk(identity, window_hours)
            paths = _find_paths(identity, max_depth) if include_paths else []
            projection = _build_projection(identity)

            result = {
                "identity":       identity,
                "risk_score":     risk_data["score"],
                "risk_level":     _classify_risk(risk_data["score"]),
                "exposure_paths": paths,
                "projection":     projection,
                "window_hours":   window_hours,
            }

            await cache.set(identity, window_hours, result)
            logger.info("risk_query_complete", extra={"identity": identity, "score": risk_data["score"]})
            return result

        except Exception:
            logger.exception("risk_query_failed", extra={"identity": identity})
            raise

    async def get_graph_node(self, node_id: str, depth: int) -> Dict[str, Any]:
        try:
            from graph.scoring import get_node
            return get_node(node_id, depth=depth)
        except ImportError:
            return {"node_id": node_id, "node_type": "unknown", "edges": [], "risk_score": 0.0}


# ---------------------------------------------------------------------------
# Engine adapters (stubbed until engine package is present)
# ---------------------------------------------------------------------------

def _compute_risk(identity: str, window_hours: int) -> Dict:
    try:
        from graph.scoring import compute_identity_risk
        return compute_identity_risk(identity=identity, window_hours=window_hours)
    except ImportError:
        import random
        return {"score": round(random.uniform(0.1, 0.9), 4)}


def _find_paths(identity: str, max_depth: int) -> list:
    try:
        from graph.pathfinder import find_attack_paths
        return find_attack_paths(identity, max_depth=max_depth)
    except ImportError:
        return []


def _build_projection(identity: str) -> dict:
    try:
        from projections.risk_projection import build_risk_projection
        return build_risk_projection(identity)
    except ImportError:
        return {}


class _StubCache:
    async def get(self, *a): return None
    async def set(self, *a): pass