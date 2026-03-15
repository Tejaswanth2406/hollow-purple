"""
streaming/graph_updates.py — Identity Graph Update Feed (ws /stream/graph)

Streams live identity exposure graph topology changes:
  - node/edge additions and removals
  - attack path discoveries
  - privilege escalation chain updates

Useful for live dashboards, graph visualisation tools, and monitoring
privilege expansion in real time.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from .connection_manager import ConnectionManager

logger = logging.getLogger("hollowpurple.streaming.graph")

router = APIRouter()
graph_manager = ConnectionManager()


@router.websocket("/graph")
async def graph_stream(websocket: WebSocket):
    """
    Subscribe to live identity graph topology changes.

    Messages:
        { "type": "graph_update",    "data": { "node": ..., "edges_added": [...] } }
        { "type": "path_discovered", "data": { "identity": ..., "path": [...] } }
    """
    await graph_manager.connect(websocket, channel="graph")
    logger.info("client_subscribed", extra={"channel": "graph"})
    try:
        while True:
            await asyncio.wait_for(websocket.receive_text(), timeout=30)
    except (WebSocketDisconnect, asyncio.TimeoutError):
        pass
    finally:
        await graph_manager.disconnect(websocket, channel="graph")


async def broadcast_graph_update(update: Dict[str, Any]) -> None:
    """Called by graph engine when edges / nodes change."""
    await graph_manager.broadcast_channel(
        "graph", {"type": "graph_update", "data": update}
    )


async def broadcast_path_discovered(path_info: Dict[str, Any]) -> None:
    """Called when a new attack path is discovered."""
    await graph_manager.broadcast_channel(
        "graph", {"type": "path_discovered", "data": path_info}
    )