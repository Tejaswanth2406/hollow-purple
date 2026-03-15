"""
api/streaming — Real-Time WebSocket Streaming Subsystem

Channels:
  ws /stream/events  — live event ingestion feed
  ws /stream/alerts  — security alert feed
  ws /stream/graph   — identity graph update feed
"""
from .connection_manager import ConnectionManager

__all__ = ["ConnectionManager"]