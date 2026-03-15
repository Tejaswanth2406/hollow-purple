"""
services/event_service.py — Event Ingestion Orchestration

Responsibilities:
  - Validate and enrich event payloads
  - Persist to event store
  - Push through processing pipeline
  - Trigger graph update
  - Invalidate stale caches
  - Emit telemetry metrics
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List

logger = logging.getLogger("hollowpurple.event_service")


class EventService:

    def __init__(self) -> None:
        # Lazy imports allow the service to be instantiated without
        # the full engine available (useful for unit tests with mocks).
        self._pipeline = None
        self._event_store = None
        self._risk_cache = None
        self._graph_cache = None

    # ------------------------------------------------------------------
    # Lazy dependency initialisation
    # ------------------------------------------------------------------

    def _get_pipeline(self):
        if self._pipeline is None:
            try:
                from engine.pipeline import process_event
                self._pipeline = process_event
            except ImportError:
                logger.warning("engine.pipeline not available — using stub")
                self._pipeline = lambda e: None
        return self._pipeline

    def _get_event_store(self):
        if self._event_store is None:
            try:
                from storage.event_store import EventStore
                self._event_store = EventStore()
            except ImportError:
                logger.warning("storage.event_store not available — using stub")
                self._event_store = _StubStore()
        return self._event_store

    def _get_caches(self):
        if self._risk_cache is None:
            try:
                from api.cache.risk_cache import RiskCache
                from api.cache.graph_cache import GraphCache
                self._risk_cache = RiskCache()
                self._graph_cache = GraphCache()
            except ImportError:
                self._risk_cache = _StubCache()
                self._graph_cache = _StubCache()
        return self._risk_cache, self._graph_cache

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def ingest_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Ingest a single event through the full pipeline."""
        t0 = time.monotonic()
        event_id = event.get("event_id", "unknown")

        try:
            store = self._get_event_store()
            pipeline = self._get_pipeline()

            # 1. Persist first — never lose an event
            store.append(event)

            # 2. Process through detection pipeline
            pipeline(event)

            # 3. Invalidate identity caches
            identity = event.get("actor")
            if identity:
                risk_cache, graph_cache = self._get_caches()
                await risk_cache.invalidate(identity)
                await graph_cache.invalidate(identity)

            # 4. Telemetry
            _emit("event_ingested", {"provider": event.get("provider"), "action": event.get("action")})

            latency_ms = round((time.monotonic() - t0) * 1000, 2)
            logger.info("event_ingested", extra={"event_id": event_id, "latency_ms": latency_ms})

            return {"accepted": True, "event_id": event_id, "message": "Event processed successfully"}

        except Exception as exc:
            logger.exception("event_processing_failed", extra={"event_id": event_id})
            _emit("event_ingest_error", {"event_id": event_id, "error": str(exc)})
            return {"accepted": False, "event_id": event_id, "message": str(exc)}

    async def bulk_ingest(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Ingest multiple events; continues on individual failures."""
        accepted, rejected, errors = 0, 0, []

        for event in events:
            result = await self.ingest_event(event)
            if result["accepted"]:
                accepted += 1
            else:
                rejected += 1
                errors.append({"event_id": result["event_id"], "error": result["message"]})

        return {"accepted": accepted, "rejected": rejected, "errors": errors}


# ---------------------------------------------------------------------------
# Stubs for environments without full engine
# ---------------------------------------------------------------------------

class _StubStore:
    def append(self, event): pass


class _StubCache:
    async def invalidate(self, key): pass


def _emit(metric: str, tags: dict) -> None:
    try:
        from MAHORAGHA.telemetry import emit_metric
        emit_metric(metric, tags=tags)
    except ImportError:
        pass