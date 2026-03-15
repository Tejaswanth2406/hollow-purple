"""
streaming/event_stream.py — Live Event Ingestion Feed (ws /stream/events)

Streams every event entering the ingestion pipeline in real time.
Security teams and SIEM forwarders subscribe here to observe
cloud activity as it arrives.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from .connection_manager import ConnectionManager

logger = logging.getLogger("hollowpurple.streaming.events")

router = APIRouter()
event_manager = ConnectionManager()


@router.websocket("/events")
async def event_stream(websocket: WebSocket):
    """
    Subscribe to the live event ingestion feed.

    Messages:
        { "type": "event_ingested",   "data": { ...event fields... } }
        { "type": "pipeline_metric",  "data": { "throughput": N, "lag_ms": N } }
    """
    await event_manager.connect(websocket, channel="events")
    logger.info("client_subscribed", extra={"channel": "events"})
    try:
        while True:
            await asyncio.wait_for(websocket.receive_text(), timeout=30)
    except (WebSocketDisconnect, asyncio.TimeoutError):
        pass
    finally:
        await event_manager.disconnect(websocket, channel="events")


async def broadcast_event(event: Dict[str, Any]) -> None:
    """Called by EventService after successful ingestion."""
    await event_manager.broadcast_channel(
        "events", {"type": "event_ingested", "data": event}
    )