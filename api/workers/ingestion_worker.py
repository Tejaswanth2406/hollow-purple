"""
workers/ingestion_worker.py — Buffered High-Throughput Event Ingestion Worker

Batches high-volume events before flushing to the pipeline.
This prevents per-event overhead from saturating the engine at peak load.

Design:
  - Events arrive via enqueue()
  - Worker accumulates up to BATCH_SIZE events or FLUSH_INTERVAL_SEC seconds
  - Flushes batch to EventService.bulk_ingest()
  - Emits throughput metrics
  - Back-pressure: rejects when buffer exceeds HIGH_WATER_MARK
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from typing import Any, Deque, Dict, List, Optional

logger = logging.getLogger("hollowpurple.workers.ingestion")

BATCH_SIZE        = 100
FLUSH_INTERVAL    = 2.0   # seconds
HIGH_WATER_MARK   = 5000  # max buffered events before back-pressure
LOW_WATER_MARK    = 1000  # resume accepting after draining below this


class IngestionWorker:
    """
    Micro-batching ingestion buffer.

    Usage:
        worker = IngestionWorker()
        await worker.start()
        await worker.enqueue(event_dict)
        await worker.stop()
    """

    def __init__(
        self,
        batch_size: int = BATCH_SIZE,
        flush_interval: float = FLUSH_INTERVAL,
    ) -> None:
        self._batch_size     = batch_size
        self._flush_interval = flush_interval
        self._buffer: Deque[Dict[str, Any]] = deque()
        self._lock    = asyncio.Lock()
        self._flush_event = asyncio.Event()
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._paused = False

        # Metrics
        self._total_received  = 0
        self._total_processed = 0
        self._total_failed    = 0
        self._last_flush_at: Optional[float] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._run_loop(), name="ingestion_worker")
        logger.info("ingestion_worker_started", extra={
            "batch_size": self._batch_size,
            "flush_interval_sec": self._flush_interval,
        })

    async def stop(self) -> None:
        self._running = False
        self._flush_event.set()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        # Drain remaining buffer
        if self._buffer:
            await self._flush()
        logger.info("ingestion_worker_stopped", extra={"total_processed": self._total_processed})

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def enqueue(self, event: Dict[str, Any]) -> bool:
        """
        Add an event to the ingestion buffer.
        Returns False if the buffer is above high-water mark (back-pressure).
        """
        async with self._lock:
            if len(self._buffer) >= HIGH_WATER_MARK:
                logger.warning("ingestion_back_pressure", extra={"buffer_size": len(self._buffer)})
                return False
            self._buffer.append(event)
            self._total_received += 1

            # Signal flush if batch is ready
            if len(self._buffer) >= self._batch_size:
                self._flush_event.set()

        return True

    def metrics(self) -> Dict[str, Any]:
        return {
            "buffer_size":     len(self._buffer),
            "total_received":  self._total_received,
            "total_processed": self._total_processed,
            "total_failed":    self._total_failed,
            "last_flush_at":   self._last_flush_at,
            "paused":          self._paused,
        }

    # ------------------------------------------------------------------
    # Internal worker loop
    # ------------------------------------------------------------------

    async def _run_loop(self) -> None:
        while self._running:
            try:
                await asyncio.wait_for(
                    self._flush_event.wait(),
                    timeout=self._flush_interval,
                )
            except asyncio.TimeoutError:
                pass  # timer-driven flush

            self._flush_event.clear()
            await self._flush()

    async def _flush(self) -> None:
        async with self._lock:
            if not self._buffer:
                return
            batch: List[Dict] = []
            while self._buffer and len(batch) < self._batch_size:
                batch.append(self._buffer.popleft())

            # Resume accepting if we drained below low-water mark
            if self._paused and len(self._buffer) < LOW_WATER_MARK:
                self._paused = False

        if not batch:
            return

        t0 = time.monotonic()
        try:
            from api.services.event_service import EventService
            svc = EventService()
            result = await svc.bulk_ingest(batch)
            self._total_processed += result["accepted"]
            self._total_failed    += result["rejected"]
        except Exception as exc:
            self._total_failed += len(batch)
            logger.exception("ingestion_flush_failed", extra={"batch_size": len(batch), "error": str(exc)})

        self._last_flush_at = time.monotonic()
        latency_ms = round((self._last_flush_at - t0) * 1000, 2)

        logger.info("ingestion_flush_complete", extra={
            "batch_size":  len(batch),
            "latency_ms":  latency_ms,
            "buffer_remaining": len(self._buffer),
        })

        # Emit throughput metric
        try:
            from MAHORAGHA.telemetry import emit_metric
            emit_metric("ingestion_batch_processed", tags={"size": str(len(batch))})
        except ImportError:
            pass


# Global singleton
ingestion_worker = IngestionWorker()