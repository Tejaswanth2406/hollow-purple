"""Ingestion startup helpers for Hollow Purple."""

from __future__ import annotations

import logging

from ingestion.orchestrator import IngestionOrchestrator

logger = logging.getLogger("hollowpurple.ingestion.startup")

_ingestion_orchestrator: IngestionOrchestrator | None = None


async def start_ingestion_pipeline() -> None:
    global _ingestion_orchestrator
    if _ingestion_orchestrator is None:
        _ingestion_orchestrator = IngestionOrchestrator()
    await _ingestion_orchestrator.start()


async def stop_ingestion_pipeline() -> None:
    if _ingestion_orchestrator is not None:
        await _ingestion_orchestrator.stop()
