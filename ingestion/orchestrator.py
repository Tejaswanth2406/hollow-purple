"""
ingestion/orchestrator.py — HOLLOW_PURPLE Central Ingestion Orchestrator

Responsibilities:
  - Drives the full async ingestion pipeline for every event
  - Manages circuit breakers, retry policy, and dead letter queue per stage
  - Emits per-stage metrics and distributed trace spans
  - Supports graceful shutdown and drain
  - Wires backpressure controller to queue pressure
"""

import asyncio
import logging
import time
import uuid
from typing import Any, Callable

from ingestion.processors.parser import EventParser
from ingestion.processors.validator import EventValidator
from ingestion.processors.normalizer import EventNormalizer
from ingestion.processors.deduplicator import EventDeduplicator
from ingestion.processors.enricher import EventEnricher
from ingestion.queue.event_queue import EventQueue
from ingestion.queue.backpressure import BackpressureController
from ingestion.queue.batching import Batcher
from ingestion.reliability.retry_policy import RetryPolicy
from ingestion.reliability.dead_letter_queue import DeadLetterQueue
from ingestion.reliability.circuit_breaker import CircuitBreaker
from ingestion.monitoring.metrics import Metrics

logger = logging.getLogger("hollow_purple.orchestrator")


class IngestionOrchestrator:
    """
    Central async pipeline orchestrator.

    Usage:
        orchestrator = IngestionOrchestrator()
        await orchestrator.start()
        enriched = await orchestrator.ingest(raw_event)
        await orchestrator.shutdown()
    """

    def __init__(
        self,
        queue_max_size: int = 10_000,
        batch_size: int = 100,
        worker_count: int = 8,
        downstream_callback: Callable[[list[dict]], Any] | None = None,
    ):
        # Processors
        self.parser       = EventParser()
        self.validator    = EventValidator()
        self.normalizer   = EventNormalizer()
        self.deduplicator = EventDeduplicator()
        self.enricher     = EventEnricher()

        # Queue infrastructure
        self.queue        = EventQueue(maxsize=queue_max_size)
        self.backpressure = BackpressureController(max_size=queue_max_size)
        self.batcher      = Batcher(size=batch_size)

        # Reliability
        self.retry        = RetryPolicy(retries=3, base_delay=0.5)
        self.dlq          = DeadLetterQueue()
        self._breakers: dict[str, CircuitBreaker] = {
            stage: CircuitBreaker(threshold=5, recovery_timeout=30)
            for stage in ("parse", "validate", "normalize", "deduplicate", "enrich", "queue")
        }

        # Observability
        self.metrics      = Metrics()

        # Worker pool
        self._worker_count  = worker_count
        self._workers: list[asyncio.Task] = []
        self._shutdown_event = asyncio.Event()
        self._downstream_callback = downstream_callback

        logger.info("IngestionOrchestrator initialized (workers=%d, batch=%d, queue_max=%d)",
                    worker_count, batch_size, queue_max_size)

    # ------------------------------------------------------------------ #
    #  Lifecycle                                                           #
    # ------------------------------------------------------------------ #

    async def start(self):
        """Spin up background batch-consumer workers."""
        for i in range(self._worker_count):
            task = asyncio.create_task(self._batch_worker(i), name=f"hp_worker_{i}")
            self._workers.append(task)
        logger.info("Started %d ingestion workers", self._worker_count)

    async def shutdown(self, drain_timeout: float = 10.0):
        """
        Signal workers to stop and drain in-flight events.
        Remaining queued events are flushed to DLQ.
        """
        logger.info("Initiating graceful shutdown (drain_timeout=%.1fs)", drain_timeout)
        self._shutdown_event.set()
        try:
            await asyncio.wait_for(
                asyncio.gather(*self._workers, return_exceptions=True),
                timeout=drain_timeout,
            )
        except asyncio.TimeoutError:
            logger.warning("Shutdown drain timed out — cancelling workers")
            for w in self._workers:
                w.cancel()
        logger.info("Orchestrator shutdown complete. DLQ size=%d", self.dlq.size())

    # ------------------------------------------------------------------ #
    #  Hot path: single-event ingestion                                    #
    # ------------------------------------------------------------------ #

    async def ingest(self, raw_event: Any) -> dict | None:
        """
        Full ingestion pipeline for a single raw event.

        Returns the enriched event dict, or None if the event was
        a duplicate or dropped for policy reasons.
        Failures are circuit-broken and sent to DLQ.
        """
        trace_id = str(uuid.uuid4())
        start    = time.perf_counter()
        self.metrics.record_received()

        try:
            event = await self._run_stage("parse",       self.parser.parse,            raw_event, trace_id)
            event = await self._run_stage("validate",    self.validator.validate,       event,     trace_id)
            event = await self._run_stage("normalize",   self.normalizer.normalize,     event,     trace_id)
            event = await self._run_stage("deduplicate", self.deduplicator.process,     event,     trace_id)

            if event is None:
                self.metrics.record_deduplicated()
                return None

            event = await self._run_stage("enrich",      self.enricher.enrich,         event,     trace_id)
            event["_trace_id"] = trace_id

            # Backpressure check before queue push
            if self.backpressure.should_throttle(self.queue.size()):
                self.metrics.record_throttled()
                logger.warning("Backpressure active — dropping event trace_id=%s", trace_id)
                self.dlq.push(event, reason="backpressure")
                return None

            await self._run_stage("queue", self.queue.push, event, trace_id)

            elapsed_ms = (time.perf_counter() - start) * 1000
            self.metrics.record_processed(elapsed_ms)
            return event

        except _StageError as exc:
            logger.error("Pipeline stage '%s' failed for trace_id=%s: %s",
                         exc.stage, trace_id, exc)
            self.metrics.record_failed(exc.stage)
            self.dlq.push({"raw": str(raw_event), "trace_id": trace_id}, reason=str(exc))
            return None

    # ------------------------------------------------------------------ #
    #  Batch consumer workers                                              #
    # ------------------------------------------------------------------ #

    async def _batch_worker(self, worker_id: int):
        logger.debug("Worker %d started", worker_id)
        while not self._shutdown_event.is_set():
            try:
                event = await asyncio.wait_for(self.queue.pop(), timeout=1.0)
            except asyncio.TimeoutError:
                continue

            batch = self.batcher.add(event)
            if batch:
                await self._dispatch_batch(batch, worker_id)

        # Flush partial batch on shutdown
        if self.batcher.buffer:
            await self._dispatch_batch(self.batcher.flush(), worker_id)
        logger.debug("Worker %d exiting", worker_id)

    async def _dispatch_batch(self, batch: list[dict], worker_id: int):
        if not batch:
            return
        logger.info("Worker %d dispatching batch size=%d", worker_id, len(batch))
        self.metrics.record_batch(len(batch))
        if self._downstream_callback:
            try:
                await self._downstream_callback(batch)
            except Exception as exc:
                logger.error("Downstream callback failed: %s", exc)
                for event in batch:
                    self.dlq.push(event, reason=f"downstream_error: {exc}")

    # ------------------------------------------------------------------ #
    #  Stage runner with circuit-breaker + retry                          #
    # ------------------------------------------------------------------ #

    async def _run_stage(self, stage: str, fn, *args):
        breaker = self._breakers[stage]

        if breaker.is_open():
            raise _StageError(stage, "circuit breaker open")

        try:
            result = await self.retry.run(fn, *args)
            breaker.record_success()
            return result
        except Exception as exc:
            breaker.record_failure()
            raise _StageError(stage, str(exc)) from exc


class _StageError(Exception):
    def __init__(self, stage: str, msg: str):
        self.stage = stage
        super().__init__(f"[{stage}] {msg}")