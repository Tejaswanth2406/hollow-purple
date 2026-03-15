"""
ingestion/orchestrator.py — Central Ingestion Controller

The Orchestrator is the single entry point for the entire ingestion subsystem.
It owns and manages:
  - All cloud collectors (AWS, GCP, Azure, Webhook)
  - The event queue + backpressure controller
  - The batch consumer
  - The processing pipeline
  - Background maintenance tasks (dedup flush, metrics emit)
  - Graceful startup and shutdown sequence

Lifecycle:
    orchestrator = IngestionOrchestrator()
    await orchestrator.start()
    # ... running ...
    await orchestrator.stop()

The orchestrator is designed to be a long-lived async service.
It is started inside the FastAPI lifespan context and stopped on shutdown.

Event flow:
    Collector.poll()
        → BackpressureController.should_accept()
        → EventQueue.put(event, priority)
        → BatchConsumer yields batch
        → for each event: IngestionPipeline.process(raw)
            → store + graph update + streaming broadcast
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional

from ingestion.queue.event_queue import EventQueue, QueuePriority
from ingestion.queue.backpressure import BackpressureController, BackpressureState
from ingestion.queue.batching import BatchConsumer
from ingestion.pipeline import IngestionPipeline, PipelineConfig
from ingestion.monitoring.metrics import ingestion_metrics
from ingestion.monitoring.healthcheck import IngestionHealthChecker

logger = logging.getLogger("hollowpurple.ingestion.orchestrator")


class IngestionOrchestrator:
    """
    Central controller for the full ingestion subsystem.

    Parameters
    ----------
    pipeline_config : Override default pipeline stage settings
    batch_size      : Events per processing batch
    flush_interval  : Max seconds between batch flushes
    """

    def __init__(
        self,
        pipeline_config: Optional[PipelineConfig] = None,
        batch_size:      int   = 100,
        flush_interval:  float = 2.0,
    ) -> None:
        # Core components
        self._queue       = EventQueue(
            maxsize_high=1_000,
            maxsize_normal=10_000,
            maxsize_low=5_000,
        )
        self._backpressure = BackpressureController(
            queue=self._queue,
            max_total_depth=16_000,
        )
        self._batch_consumer = BatchConsumer(
            queue=self._queue,
            backpressure=self._backpressure,
            batch_size=batch_size,
            flush_interval=flush_interval,
        )
        self._pipeline = IngestionPipeline(config=pipeline_config)
        self._health   = IngestionHealthChecker(self)

        # Collectors (initialised in start())
        self._collectors: Dict[str, Any] = {}

        # Runtime state
        self._running = False
        self._tasks: List[asyncio.Task] = []
        self._started_at: Optional[float] = None

        # Backpressure state change logging
        self._backpressure.on_state_change(self._on_backpressure_change)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        if self._running:
            logger.warning("orchestrator_already_running")
            return

        self._running    = True
        self._started_at = time.time()
        logger.info("ingestion_orchestrator_starting")

        # 1. Start backpressure monitor
        await self._backpressure.start()

        # 2. Initialise and start collectors
        await self._start_collectors()

        # 3. Start batch processing loop
        self._tasks.append(
            asyncio.create_task(self._processing_loop(), name="ingestion_processing_loop")
        )

        # 4. Background maintenance tasks
        self._tasks.append(
            asyncio.create_task(self._maintenance_loop(), name="ingestion_maintenance")
        )

        logger.info(
            "ingestion_orchestrator_started",
            extra={"collectors": list(self._collectors.keys())},
        )

    async def stop(self) -> None:
        if not self._running:
            return

        self._running = False
        logger.info("ingestion_orchestrator_stopping")

        # 1. Stop collectors first (no new events)
        for name, collector in self._collectors.items():
            try:
                await collector.stop()
                logger.info("collector_stopped", extra={"name": name})
            except Exception as exc:
                logger.error("collector_stop_error", extra={"name": name, "error": str(exc)})

        # 2. Drain the queue
        try:
            drained = await asyncio.wait_for(self._queue.drain(), timeout=30.0)
            logger.info("queue_drained", extra={"events": drained})
        except asyncio.TimeoutError:
            logger.warning("queue_drain_timeout")

        # 3. Cancel background tasks
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()

        # 4. Stop backpressure
        await self._backpressure.stop()

        logger.info("ingestion_orchestrator_stopped")

    # ------------------------------------------------------------------
    # Collector management
    # ------------------------------------------------------------------

    async def _start_collectors(self) -> None:
        """Initialise each collector if its configuration is present."""

        # AWS
        try:
            from ingestion.collectors.aws_collector import AWSCollector
            import os
            if os.getenv("HP_SQS_CLOUDTRAIL_URL") or os.getenv("HP_SQS_GUARDDUTY_URL"):
                aws = AWSCollector(self._queue, self._backpressure)
                await aws.start()
                self._collectors["aws"] = aws
        except Exception as exc:
            logger.warning("aws_collector_start_failed", extra={"error": str(exc)})

        # GCP
        try:
            from ingestion.collectors.gcp_collector import GCPCollector
            import os
            if os.getenv("HP_GCP_PROJECT_ID"):
                gcp = GCPCollector(self._queue, self._backpressure)
                await gcp.start()
                self._collectors["gcp"] = gcp
        except Exception as exc:
            logger.warning("gcp_collector_start_failed", extra={"error": str(exc)})

        # Azure
        try:
            from ingestion.collectors.azure_collector import AzureCollector
            import os
            if os.getenv("HP_AZURE_EVENTHUB_CONN_STR"):
                azure = AzureCollector(self._queue, self._backpressure)
                await azure.start()
                self._collectors["azure"] = azure
        except Exception as exc:
            logger.warning("azure_collector_start_failed", extra={"error": str(exc)})

        # Webhook (always available)
        try:
            from ingestion.collectors.webhook_collector import WebhookCollector
            webhook = WebhookCollector(self._queue, self._backpressure)
            self._collectors["webhook"] = webhook
            logger.info("webhook_collector_ready")
        except Exception as exc:
            logger.warning("webhook_collector_start_failed", extra={"error": str(exc)})

        if not self._collectors:
            logger.warning("no_collectors_started — add env vars to enable cloud collectors")

    # ------------------------------------------------------------------
    # Processing loop
    # ------------------------------------------------------------------

    async def _processing_loop(self) -> None:
        """Consumes batches from the queue and runs the pipeline."""
        logger.info("processing_loop_started")
        try:
            async for batch in self._batch_consumer.batches():
                if not batch:
                    continue
                await self._process_batch(batch)
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.exception("processing_loop_crashed", extra={"error": str(exc)})
        finally:
            logger.info("processing_loop_stopped")

    async def _process_batch(self, batch: List) -> None:
        """Process a single batch through the pipeline."""
        t0 = time.monotonic()
        success_count = 0
        fail_count    = 0

        # Run pipeline in thread pool for CPU-bound normalisation/validation
        results = await asyncio.to_thread(
            self._pipeline.process_batch,
            [e.to_dict() if hasattr(e, "to_dict") else e for e in batch],
            "batch",
        )

        for result in results:
            if result.success:
                success_count += 1
            else:
                if not result.event.duplicate_of:   # real failure, not dedup
                    fail_count += 1

        batch_ms = (time.monotonic() - t0) * 1000
        logger.debug(
            "batch_processed",
            extra={
                "size":       len(batch),
                "success":    success_count,
                "failed":     fail_count,
                "latency_ms": round(batch_ms, 2),
            },
        )

    # ------------------------------------------------------------------
    # Maintenance loop
    # ------------------------------------------------------------------

    async def _maintenance_loop(self) -> None:
        """Periodic background tasks: dedup flush, metrics emit, health log."""
        while self._running:
            try:
                await asyncio.sleep(60)

                # Flush expired dedup fingerprints
                self._pipeline.dedup_stats()
                self._pipeline._deduplicator.flush_expired()

                # Emit metrics snapshot to telemetry
                try:
                    from MAHORAGHA.telemetry import emit_snapshot
                    emit_snapshot("ingestion", ingestion_metrics.snapshot())
                except ImportError:
                    pass

                # Log health summary
                report = await self._health.check()
                logger.info(
                    "ingestion_health_tick",
                    extra={"level": report.level.value, "components": len(report.components)},
                )

            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.exception("maintenance_loop_error", extra={"error": str(exc)})

    # ------------------------------------------------------------------
    # Back-pressure callback
    # ------------------------------------------------------------------

    def _on_backpressure_change(
        self, old_state: BackpressureState, new_state: BackpressureState
    ) -> None:
        if new_state == BackpressureState.RED:
            logger.critical(
                "backpressure_red",
                extra={"queue_depth": self._queue.total_depth()},
            )
        elif old_state == BackpressureState.RED and new_state != BackpressureState.RED:
            logger.info("backpressure_recovered", extra={"new_state": new_state.value})

    # ------------------------------------------------------------------
    # Public accessors
    # ------------------------------------------------------------------

    async def health(self):
        return await self._health.check()

    def metrics(self) -> Dict[str, Any]:
        return {
            "uptime_sec":    round(time.time() - (self._started_at or time.time()), 1),
            "queue":         self._queue.metrics(),
            "backpressure":  self._backpressure.metrics(),
            "batch_consumer": self._batch_consumer.metrics(),
            "pipeline":      ingestion_metrics.snapshot(),
            "collectors":    {
                name: col.metrics()
                for name, col in self._collectors.items()
            },
        }

    def get_webhook_collector(self):
        """Return webhook collector for router mounting."""
        return self._collectors.get("webhook")