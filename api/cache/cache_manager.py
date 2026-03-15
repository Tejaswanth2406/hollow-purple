"""
cache/cache_manager.py — Generic Async TTL Cache

Features:
  - Async-safe with asyncio.Lock
  - TTL-based expiration (lazy eviction + periodic sweep)
  - Memory bounded (max_size evicts LRU entries)
  - Pluggable: swap store dict for Redis client in production
"""

from __future__ import annotations

import asyncio
import time
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

logger = logging.getLogger("hollowpurple.cache")


@dataclass
class _Entry:
    value: Any
    expires_at: float

    def is_alive(self) -> bool:
        return time.monotonic() < self.expires_at


class CacheManager:
    """
    In-memory key-value cache with TTL and optional size cap.

    Parameters
    ----------
    ttl      : seconds before an entry expires
    max_size : maximum number of live entries (0 = unlimited)
    """

    def __init__(self, ttl: float = 60.0, max_size: int = 0) -> None:
        self._ttl = ttl
        self._max_size = max_size
        self._store: Dict[str, _Entry] = {}
        self._lock = asyncio.Lock()
        self._hits = 0
        self._misses = 0

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    async def get(self, key: str) -> Optional[Any]:
        async with self._lock:
            entry = self._store.get(key)
            if entry is None:
                self._misses += 1
                return None
            if not entry.is_alive():
                del self._store[key]
                self._misses += 1
                return None
            self._hits += 1
            return entry.value

    async def set(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        async with self._lock:
            if self._max_size and len(self._store) >= self._max_size:
                self._evict_oldest()
            self._store[key] = _Entry(value=value, expires_at=time.monotonic() + (ttl or self._ttl))

    async def delete(self, key: str) -> bool:
        async with self._lock:
            if key in self._store:
                del self._store[key]
                return True
            return False

    async def invalidate_prefix(self, prefix: str) -> int:
        """Delete all keys that start with `prefix`."""
        async with self._lock:
            keys = [k for k in self._store if k.startswith(prefix)]
            for k in keys:
                del self._store[k]
            return len(keys)

    async def clear(self) -> None:
        async with self._lock:
            self._store.clear()

    # ------------------------------------------------------------------
    # Maintenance
    # ------------------------------------------------------------------

    async def sweep(self) -> int:
        """Evict all expired entries. Returns count removed."""
        async with self._lock:
            expired = [k for k, e in self._store.items() if not e.is_alive()]
            for k in expired:
                del self._store[k]
            return len(expired)

    def stats(self) -> Dict[str, Any]:
        total = self._hits + self._misses
        return {
            "size":       len(self._store),
            "hits":       self._hits,
            "misses":     self._misses,
            "hit_rate":   round(self._hits / total, 4) if total else 0.0,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _evict_oldest(self) -> None:
        """Remove the entry with the earliest expiry (LRU-lite)."""
        if not self._store:
            return
        oldest_key = min(self._store, key=lambda k: self._store[k].expires_at)
        del self._store[oldest_key]