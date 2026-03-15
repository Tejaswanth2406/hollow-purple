"""
streaming/connection_manager.py — WebSocket Connection Manager

Manages all live WebSocket clients with:
  - async-safe connect/disconnect
  - targeted personal messages
  - broadcast to all subscribers
  - channel filtering (topic-based fanout)
  - dead connection cleanup
"""

from __future__ import annotations

import asyncio
import logging
from typing import Dict, List, Optional, Set

from fastapi import WebSocket

logger = logging.getLogger("hollowpurple.streaming")


class ConnectionManager:
    """
    Central registry for active WebSocket connections.

    Supports both broadcast (all clients) and channel fanout
    (clients subscribed to a specific topic string).
    """

    def __init__(self) -> None:
        self._connections: List[WebSocket] = []
        self._channels: Dict[str, Set[WebSocket]] = {}
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def connect(self, websocket: WebSocket, channel: Optional[str] = None) -> None:
        await websocket.accept()
        async with self._lock:
            self._connections.append(websocket)
            if channel:
                self._channels.setdefault(channel, set()).add(websocket)
        logger.debug("ws_connect", extra={"channel": channel, "total": len(self._connections)})

    async def disconnect(self, websocket: WebSocket, channel: Optional[str] = None) -> None:
        async with self._lock:
            if websocket in self._connections:
                self._connections.remove(websocket)
            if channel and channel in self._channels:
                self._channels[channel].discard(websocket)
        logger.debug("ws_disconnect", extra={"channel": channel, "total": len(self._connections)})

    # ------------------------------------------------------------------
    # Messaging
    # ------------------------------------------------------------------

    async def send(self, message: dict, websocket: WebSocket) -> None:
        try:
            await websocket.send_json(message)
        except Exception as exc:
            logger.warning("ws_send_failed", extra={"error": str(exc)})
            await self.disconnect(websocket)

    async def broadcast(self, message: dict) -> None:
        """Send to ALL connected clients."""
        dead: List[WebSocket] = []
        for ws in list(self._connections):
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            await self.disconnect(ws)

    async def broadcast_channel(self, channel: str, message: dict) -> None:
        """Send only to clients subscribed to `channel`."""
        subscribers = list(self._channels.get(channel, set()))
        dead: List[WebSocket] = []
        for ws in subscribers:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            await self.disconnect(ws, channel=channel)

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    @property
    def connection_count(self) -> int:
        return len(self._connections)

    def channel_counts(self) -> Dict[str, int]:
        return {ch: len(subs) for ch, subs in self._channels.items()}