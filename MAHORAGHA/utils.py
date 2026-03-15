"""
phase2/utils.py — Shared utilities for Phase 2

quantize_float:        Round float to N decimal places as int (for stable hashing)
stable_id_with_floats: _stable_id variant that handles float fields
case_integrity_hash:   Compute deterministic hash of CaseBuilt content fields
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Optional


def quantize_float(v: float, precision: int = 6) -> int:
    """Convert float to a deterministic integer representation at given precision."""
    return int(round(v * (10 ** precision)))


def stable_id_with_floats(*parts: Any, precision: int = 6) -> str:
    """Stable ID that handles floats, datetimes, and nested structures."""
    def _canon(x: Any) -> Any:
        if isinstance(x, float):
            return quantize_float(x, precision)
        if isinstance(x, datetime):
            if x.tzinfo is not None:
                x = x.astimezone(timezone.utc)
            else:
                x = x.replace(tzinfo=timezone.utc)
            return x.strftime("%Y-%m-%dT%H:%M:%S.%f+00:00")
        if isinstance(x, dict):
            return {str(k): _canon(v) for k, v in sorted(x.items())}
        if isinstance(x, (list, tuple)):
            return [_canon(i) for i in x]
        return x

    converted = []
    for p in parts:
        c = _canon(p)
        if isinstance(c, (dict, list)):
            converted.append(json.dumps(c, sort_keys=True, separators=(",", ":")))
        else:
            converted.append(str(c))
    raw = "|".join(converted)
    return hashlib.sha256(raw.encode()).hexdigest()[:24]


def case_integrity_hash(
    top_signals: tuple,
    provenance_edges: tuple,
    cascade_path: tuple,
    temporal_window: Any,
    risk_score: float,
) -> str:
    """
    Deterministic hash of CaseBuilt content fields.
    Used by InvestigationEngine and validated by invariants.
    Same inputs → same hash, always.
    """
    def _edge_repr(e: Any) -> dict:
        return {
            "src":               getattr(e, "src", ""),
            "dst":               getattr(e, "dst", ""),
            "edge_type":         getattr(e, "edge_type", ""),
            "edge_id":           getattr(e, "edge_id", ""),
            "criticality_score": quantize_float(getattr(e, "criticality_score", 0.0)),
            "signal_source":     getattr(e, "signal_source", ""),
        }

    def _cascade_repr(n: Any) -> dict:
        return {
            "identity":        getattr(n, "identity", ""),
            "privilege_level": getattr(n, "privilege_level", 0),
            "depth":           getattr(n, "depth", 0),
            "edge_to_parent":  getattr(n, "edge_to_parent", ""),
        }

    def _tw_repr(tw: Any) -> dict:
        def _dt(v: Optional[datetime]) -> Optional[str]:
            if v is None:
                return None
            if v.tzinfo is not None:
                v = v.astimezone(timezone.utc)
            return v.strftime("%Y-%m-%dT%H:%M:%S.%f+00:00")
        return {
            "first_drift":  _dt(getattr(tw, "first_drift_crossing_timestamp", None)),
            "accel_start":  _dt(getattr(tw, "acceleration_start_timestamp", None)),
            "time_to_peak": getattr(tw, "time_to_peak_drift_seconds", None),
            "detection":    _dt(getattr(tw, "detection_timestamp", None)),
        }

    payload = {
        "top_signals":   sorted([(str(s), quantize_float(float(v))) for s, v in top_signals]),
        "provenance":    sorted([_edge_repr(e) for e in provenance_edges],
                                key=lambda x: (x["edge_id"],)),
        "cascade":       [_cascade_repr(n) for n in cascade_path],
        "temporal":      _tw_repr(temporal_window),
        "risk_score":    quantize_float(risk_score),
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()[:32]