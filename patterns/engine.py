"""
patterns/engine.py — HOLLOW_PURPLE Central Pattern Orchestrator

Parallelized, priority-scored multi-detector engine.
Every event is analyzed across all detection modules concurrently.
Alerts are deduplicated, enriched, and ranked by composite severity.
"""

import uuid
import time
import logging
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from patterns.privilege_escalation import detect_privilege_escalation
from patterns.lateral_movement import detect_lateral_movement
from patterns.token_abuse import detect_token_abuse
from patterns.dormant_identity import detect_dormant_identity
from patterns.privilege_chain import detect_privilege_chain
from patterns.anomaly_score import compute_event_anomaly

logger = logging.getLogger("hollow_purple.engine")

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

DETECTORS = [
    ("privilege_escalation", detect_privilege_escalation, True),   # (name, fn, needs_graph)
    ("lateral_movement",     detect_lateral_movement,     True),
    ("token_abuse",          detect_token_abuse,           False),
    ("dormant_identity",     detect_dormant_identity,      False),
    ("privilege_chain",      detect_privilege_chain,        True),
]


class PatternEngine:
    """
    Central orchestrator for all HOLLOW_PURPLE detection patterns.

    Features:
    - Parallel execution of all detectors via ThreadPoolExecutor
    - Per-event anomaly scoring fused into alert severity
    - Alert deduplication by content fingerprint (30-second window)
    - Suppression list for known-benign actors/tokens
    - Full alert enrichment with trace ID, timestamps, and anomaly scores
    - Alert callbacks for real-time downstream consumers (SIEM, webhook, etc.)
    """

    def __init__(self, graph, suppression_list: set = None, alert_callbacks=None):
        self.graph = graph
        self.suppression_list: set = suppression_list or set()
        self.alert_callbacks: list = alert_callbacks or []
        self._seen_fingerprints: dict[str, float] = {}
        self._dedup_window_seconds = 30
        self._executor = ThreadPoolExecutor(max_workers=8, thread_name_prefix="hp_detector")
        logger.info("PatternEngine initialized with %d detectors", len(DETECTORS))

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def analyze(self, event: dict) -> list[dict]:
        """
        Run all detectors against a single normalized event.
        Returns a list of enriched, deduplicated, severity-sorted alerts.
        """
        actor = event.get("actor", "")
        if actor in self.suppression_list:
            logger.debug("Suppressed event from whitelisted actor: %s", actor)
            return []

        anomaly_score = compute_event_anomaly(event)

        futures = {}
        for name, fn, needs_graph in DETECTORS:
            args = (self.graph, event) if needs_graph else (event,)
            futures[self._executor.submit(fn, *args)] = name

        raw_alerts: list[dict] = []
        for future in as_completed(futures):
            detector_name = futures[future]
            try:
                results = future.result(timeout=2)
                raw_alerts.extend(results)
            except Exception as exc:
                logger.error("Detector '%s' raised an exception: %s", detector_name, exc)

        enriched = [self._enrich(a, event, anomaly_score) for a in raw_alerts]
        deduped  = self._deduplicate(enriched)
        sorted_alerts = sorted(
            deduped,
            key=lambda a: SEVERITY_RANK.get(a["severity"], 0),
            reverse=True,
        )

        for alert in sorted_alerts:
            self._dispatch(alert)

        return sorted_alerts

    def add_suppression(self, actor: str):
        self.suppression_list.add(actor)

    def remove_suppression(self, actor: str):
        self.suppression_list.discard(actor)

    def register_callback(self, fn):
        """Register a callable(alert) invoked for every emitted alert."""
        self.alert_callbacks.append(fn)

    def shutdown(self):
        self._executor.shutdown(wait=True)

    # ------------------------------------------------------------------ #
    #  Internal helpers                                                    #
    # ------------------------------------------------------------------ #

    def _enrich(self, alert: dict, event: dict, anomaly_score: float) -> dict:
        """Attach trace IDs, timestamps, anomaly score, and source event context."""
        severity = alert.get("severity", "medium")
        # Bump severity to critical if anomaly score is very high
        if anomaly_score > 0.90 and severity == "high":
            severity = "critical"

        alert.update({
            "alert_id":      str(uuid.uuid4()),
            "trace_id":      event.get("trace_id", str(uuid.uuid4())),
            "timestamp":     time.time(),
            "anomaly_score": round(anomaly_score, 4),
            "severity":      severity,
            "source_event":  {
                "actor":    event.get("actor"),
                "action":   event.get("action"),
                "resource": event.get("resource"),
                "ip":       event.get("ip"),
                "region":   event.get("region"),
            },
        })
        return alert

    def _fingerprint(self, alert: dict) -> str:
        key = f"{alert['type']}:{alert.get('actor', '')}:{alert.get('role', '')}:{alert.get('token', '')}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def _deduplicate(self, alerts: list[dict]) -> list[dict]:
        now = time.time()
        # Purge expired fingerprints
        expired = [k for k, ts in self._seen_fingerprints.items() if now - ts > self._dedup_window_seconds]
        for k in expired:
            del self._seen_fingerprints[k]

        unique = []
        for alert in alerts:
            fp = self._fingerprint(alert)
            if fp not in self._seen_fingerprints:
                self._seen_fingerprints[fp] = now
                unique.append(alert)
            else:
                logger.debug("Deduped alert fingerprint=%s", fp)
        return unique

    def _dispatch(self, alert: dict):
        for cb in self.alert_callbacks:
            try:
                cb(alert)
            except Exception as exc:
                logger.error("Alert callback raised: %s", exc)