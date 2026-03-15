"""
workers/graph_worker.py — Background Graph Rebuild Worker

Handles expensive graph operations asynchronously:
  - Full graph rebuild after bulk ingestion
  - Incremental edge updates for single identity changes
  - Attack-path recomputation after topology change
  - Stale node pruning (inactive identities)

Uses a priority queue so critical identity updates run before routine rebuilds.
"""

from __future__ import annotations

import asyncio
import heapq
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, List, Optional

logger = logging.getLogger("hollowpurple.workers.graph")


class GraphTaskPriority(IntEnum):
    CRITICAL  = 0   # compromised identity — run immediately
    HIGH      = 1   # new privilege escalation path
    NORMAL    = 2   # routine incremental update
    LOW       = 3   # full rebuild / background maintenance


@dataclass(order=True)
class GraphTask:
    priority:   int
    task_id:    str              = field(compare=False)
    task_type:  str              = field(compare=False)
    payload:    Dict[str, Any]   = field(compare=False)
    queued_at:  float            = field(default_factory=time.monotonic, compare=False)
    result:     Optional[Any]    = field(default=None, compare=False)
    error:      Optional[str]    = field(default=None, compare=False)


class GraphWorker:
    """
    Priority-queue driven graph update worker.

    Task types:
        rebuild_full        — full graph reconstruction from event store
        rebuild_identity    — recompute all edges for one identity
        recompute_paths     — re-run attack path discovery for identity
        prune_stale_nodes   — remove nodes inactive beyond threshold
    """

    CONCURRENCY = 1   # graph mutations are serialised to avoid race conditions

    def __init__(self) -> None:
        self._heap:   List[GraphTask] = []
        self._heap_lock = asyncio.Lock()
        self._event   = asyncio.Event()
        self._tasks:  Dict[str, GraphTask] = {}
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._sem = asyncio.Semaphore(self.CONCURRENCY)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._run_loop(), name="graph_worker")
        logger.info("graph_worker_started")

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("graph_worker_stopped")

    # ------------------------------------------------------------------
    # Public enqueue helpers
    # ------------------------------------------------------------------

    async def enqueue_identity_rebuild(
        self, identity: str, priority: GraphTaskPriority = GraphTaskPriority.NORMAL
    ) -> str:
        return await self._enqueue(
            task_type="rebuild_identity",
            payload={"identity": identity},
            priority=priority,
        )

    async def enqueue_full_rebuild(self) -> str:
        return await self._enqueue(
            task_type="rebuild_full",
            payload={},
            priority=GraphTaskPriority.LOW,
        )

    async def enqueue_path_recompute(self, identity: str) -> str:
        return await self._enqueue(
            task_type="recompute_paths",
            payload={"identity": identity},
            priority=GraphTaskPriority.HIGH,
        )

    async def enqueue_prune(self, inactive_days: int = 90) -> str:
        return await self._enqueue(
            task_type="prune_stale_nodes",
            payload={"inactive_days": inactive_days},
            priority=GraphTaskPriority.LOW,
        )

    def task_status(self, task_id: str) -> Optional[Dict]:
        t = self._tasks.get(task_id)
        if not t:
            return None
        return {"task_id": t.task_id, "type": t.task_type, "error": t.error, "result": t.result}

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _enqueue(self, task_type: str, payload: dict, priority: int) -> str:
        task = GraphTask(
            priority=priority,
            task_id=str(uuid.uuid4()),
            task_type=task_type,
            payload=payload,
        )
        async with self._heap_lock:
            heapq.heappush(self._heap, task)
            self._tasks[task.task_id] = task
        self._event.set()
        logger.debug("graph_task_queued", extra={"type": task_type, "priority": priority})
        return task.task_id

    async def _pop(self) -> Optional[GraphTask]:
        async with self._heap_lock:
            if self._heap:
                return heapq.heappop(self._heap)
        return None

    async def _run_loop(self) -> None:
        while self._running:
            await self._event.wait()
            while True:
                task = await self._pop()
                if task is None:
                    self._event.clear()
                    break
                asyncio.create_task(self._execute(task))

    async def _execute(self, task: GraphTask) -> None:
        async with self._sem:
            logger.info("graph_task_started", extra={"type": task.task_type, "id": task.task_id})
            try:
                handler = getattr(self, f"_handle_{task.task_type}", self._handle_unknown)
                task.result = await handler(task.payload)
                logger.info("graph_task_complete", extra={"type": task.task_type})
            except Exception as exc:
                task.error = str(exc)
                logger.exception("graph_task_failed", extra={"type": task.task_type})

    # ------------------------------------------------------------------
    # Task handlers
    # ------------------------------------------------------------------

    async def _handle_rebuild_identity(self, payload: dict) -> dict:
        identity = payload["identity"]
        try:
            from graph.builder import rebuild_identity_subgraph
            result = await asyncio.to_thread(rebuild_identity_subgraph, identity)
        except ImportError:
            result = {"identity": identity, "edges_rebuilt": 0}

        # Invalidate graph cache after rebuild
        try:
            from api.cache.graph_cache import GraphCache
            await GraphCache().invalidate(identity)
        except ImportError:
            pass

        # Broadcast topology change
        try:
            from api.streaming.streams import broadcast_graph_update
            await broadcast_graph_update({"identity": identity, "type": "rebuild_complete"})
        except Exception:
            pass

        return result

    async def _handle_rebuild_full(self, payload: dict) -> dict:
        try:
            from graph.builder import rebuild_full_graph
            result = await asyncio.to_thread(rebuild_full_graph)
        except ImportError:
            result = {"nodes_rebuilt": 0, "edges_rebuilt": 0}
        logger.info("full_graph_rebuild_complete", extra=result)
        return result

    async def _handle_recompute_paths(self, payload: dict) -> dict:
        identity = payload["identity"]
        try:
            from graph.pathfinder import find_attack_paths
            paths = await asyncio.to_thread(find_attack_paths, identity)
            result = {"identity": identity, "paths_found": len(paths)}
        except ImportError:
            result = {"identity": identity, "paths_found": 0}

        # Alert if new critical paths discovered
        if result.get("paths_found", 0) > 0:
            try:
                from api.streaming.streams import broadcast_path_discovered
                await broadcast_path_discovered({"identity": identity, "count": result["paths_found"]})
            except Exception:
                pass
        return result

    async def _handle_prune_stale_nodes(self, payload: dict) -> dict:
        days = payload.get("inactive_days", 90)
        try:
            from graph.maintenance import prune_inactive_nodes
            result = await asyncio.to_thread(prune_inactive_nodes, days)
        except ImportError:
            result = {"pruned": 0}
        logger.info("graph_prune_complete", extra=result)
        return result

    async def _handle_unknown(self, payload: dict) -> dict:
        logger.warning("unknown_graph_task_type")
        return {}


# Global singleton
graph_worker = GraphWorker()