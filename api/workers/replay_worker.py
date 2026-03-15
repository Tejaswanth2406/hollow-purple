"""
workers/replay_worker.py — Async Replay Verification Worker

Offloads expensive deterministic replay jobs to a background queue
so the API response returns immediately with a job_id.

Flow:
    POST /replay/verify
        → ReplayWorker.enqueue(job)   → returns job_id
        → worker coroutine picks up job
        → runs ReplayService.verify_replay()
        → stores result in job store
        → broadcasts result on /stream/alerts if divergence found

Job states: PENDING → RUNNING → COMPLETE | FAILED
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional

logger = logging.getLogger("hollowpurple.workers.replay")


class JobState(str, Enum):
    PENDING  = "pending"
    RUNNING  = "running"
    COMPLETE = "complete"
    FAILED   = "failed"


@dataclass
class ReplayJob:
    job_id:     str
    start_time: datetime
    end_time:   datetime
    identity_filter: Optional[str]
    state:      JobState = JobState.PENDING
    result:     Optional[Dict[str, Any]] = None
    error:      Optional[str] = None
    queued_at:  float = field(default_factory=time.monotonic)
    started_at: Optional[float] = None
    finished_at: Optional[float] = None

    @property
    def duration_ms(self) -> Optional[float]:
        if self.started_at and self.finished_at:
            return round((self.finished_at - self.started_at) * 1000, 2)
        return None


class ReplayWorker:
    """
    Single-process async replay job queue.
    Replace queue + job_store with Redis Streams for multi-process scale.
    """

    MAX_QUEUE   = 256
    MAX_HISTORY = 1000
    CONCURRENCY = 2   # max parallel replay jobs

    def __init__(self) -> None:
        self._queue: asyncio.Queue[ReplayJob] = asyncio.Queue(maxsize=self.MAX_QUEUE)
        self._jobs:  Dict[str, ReplayJob]     = {}
        self._sem    = asyncio.Semaphore(self.CONCURRENCY)
        self._running = False
        self._task: Optional[asyncio.Task] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._run_loop(), name="replay_worker")
        logger.info("replay_worker_started")

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("replay_worker_stopped")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def enqueue(
        self,
        start_time: datetime,
        end_time: datetime,
        identity_filter: Optional[str] = None,
    ) -> str:
        job = ReplayJob(
            job_id=str(uuid.uuid4()),
            start_time=start_time,
            end_time=end_time,
            identity_filter=identity_filter,
        )
        try:
            self._queue.put_nowait(job)
        except asyncio.QueueFull:
            raise RuntimeError("Replay worker queue is full — try again later")

        self._jobs[job.job_id] = job
        logger.info("replay_job_queued", extra={"job_id": job.job_id})
        return job.job_id

    def get_job(self, job_id: str) -> Optional[ReplayJob]:
        return self._jobs.get(job_id)

    def job_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        job = self._jobs.get(job_id)
        if not job:
            return None
        return {
            "job_id":      job.job_id,
            "state":       job.state,
            "result":      job.result,
            "error":       job.error,
            "duration_ms": job.duration_ms,
        }

    # ------------------------------------------------------------------
    # Internal worker loop
    # ------------------------------------------------------------------

    async def _run_loop(self) -> None:
        while self._running:
            try:
                job = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                asyncio.create_task(self._process(job))
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.exception("replay_worker_loop_error", extra={"error": str(exc)})

    async def _process(self, job: ReplayJob) -> None:
        async with self._sem:
            job.state = JobState.RUNNING
            job.started_at = time.monotonic()
            logger.info("replay_job_started", extra={"job_id": job.job_id})

            try:
                from api.services.replay_service import ReplayService
                svc = ReplayService()
                result = await svc.verify_replay(
                    start_time=job.start_time,
                    end_time=job.end_time,
                    identity_filter=job.identity_filter,
                )
                job.result = result
                job.state  = JobState.COMPLETE

                # Stream alert if divergence detected
                if result.get("divergence_detected"):
                    await self._emit_divergence_alert(job, result)

                logger.info(
                    "replay_job_complete",
                    extra={"job_id": job.job_id, "verified": result.get("verified")},
                )

            except Exception as exc:
                job.error = str(exc)
                job.state = JobState.FAILED
                logger.exception("replay_job_failed", extra={"job_id": job.job_id})
            finally:
                job.finished_at = time.monotonic()
                self._queue.task_done()
                self._trim_history()

    async def _emit_divergence_alert(self, job: ReplayJob, result: Dict) -> None:
        try:
            from api.streaming.streams import broadcast_alert
            await broadcast_alert({
                "type":       "replay_divergence",
                "job_id":     job.job_id,
                "severity":   "critical",
                "message":    "Replay divergence detected — possible tamper event",
                "divergence_count": result.get("divergence_count", 0),
                "merkle_root": result.get("merkle_root"),
            })
        except Exception:
            pass

    def _trim_history(self) -> None:
        if len(self._jobs) > self.MAX_HISTORY:
            oldest = sorted(self._jobs, key=lambda k: self._jobs[k].queued_at)
            for k in oldest[:len(self._jobs) - self.MAX_HISTORY]:
                del self._jobs[k]


# Global singleton — imported by routes and server
replay_worker = ReplayWorker()