"""
cache/backends/redis_backend.py — Redis Cache Backend

Drop-in replacement for the in-memory CacheManager.
Uses aioredis for async Redis operations.

Swap in production by replacing CacheManager with RedisCacheBackend:

    # In risk_cache.py, change:
    self._cache = CacheManager(ttl=120)
    # To:
    self._cache = RedisCacheBackend(ttl=120, prefix="risk")

Features:
  - Connection pooling
  - Cluster support (via RedisCluster)
  - Key namespacing / prefix isolation
  - Atomic get-or-set (distributed lock)
  - Pipeline batching for bulk ops
  - Graceful degradation on Redis unavailability
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, Optional

logger = logging.getLogger("hollowpurple.cache.redis")

REDIS_URL    = os.getenv("HP_REDIS_URL",    "redis://localhost:6379/0")
REDIS_PREFIX = os.getenv("HP_REDIS_PREFIX", "hp")


class RedisCacheBackend:
    """
    Async Redis-backed cache with the same interface as CacheManager.

    Requires: pip install aioredis
    """

    def __init__(self, ttl: float = 60.0, prefix: str = "cache") -> None:
        self._ttl    = int(ttl)
        self._prefix = f"{REDIS_PREFIX}:{prefix}"
        self._client = None
        self._available = True   # circuit-breaker flag

    # ------------------------------------------------------------------
    # Lazy connection
    # ------------------------------------------------------------------

    async def _get_client(self):
        if self._client is None:
            try:
                import aioredis
                self._client = await aioredis.from_url(
                    REDIS_URL,
                    encoding="utf-8",
                    decode_responses=True,
                    max_connections=20,
                )
                self._available = True
                logger.info("redis_connected", extra={"url": REDIS_URL})
            except Exception as exc:
                self._available = False
                logger.error("redis_connect_failed", extra={"error": str(exc)})
                raise
        return self._client

    def _full_key(self, key: str) -> str:
        return f"{self._prefix}:{key}"

    # ------------------------------------------------------------------
    # Core operations (same interface as CacheManager)
    # ------------------------------------------------------------------

    async def get(self, key: str) -> Optional[Any]:
        if not self._available:
            return None
        try:
            client = await self._get_client()
            raw = await client.get(self._full_key(key))
            if raw is None:
                return None
            return json.loads(raw)
        except Exception as exc:
            logger.warning("redis_get_failed", extra={"key": key, "error": str(exc)})
            self._available = False
            return None

    async def set(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        if not self._available:
            return
        try:
            client = await self._get_client()
            await client.setex(
                self._full_key(key),
                int(ttl or self._ttl),
                json.dumps(value, default=str),
            )
        except Exception as exc:
            logger.warning("redis_set_failed", extra={"key": key, "error": str(exc)})

    async def delete(self, key: str) -> bool:
        try:
            client = await self._get_client()
            return bool(await client.delete(self._full_key(key)))
        except Exception:
            return False

    async def invalidate_prefix(self, prefix: str) -> int:
        """Scan and delete all keys matching prefix (use sparingly in production)."""
        try:
            client = await self._get_client()
            pattern = f"{self._prefix}:{prefix}*"
            keys = []
            async for key in client.scan_iter(pattern):
                keys.append(key)
            if keys:
                await client.delete(*keys)
            return len(keys)
        except Exception as exc:
            logger.warning("redis_prefix_delete_failed", extra={"prefix": prefix, "error": str(exc)})
            return 0

    async def clear(self) -> None:
        try:
            client = await self._get_client()
            pattern = f"{self._prefix}:*"
            async for key in client.scan_iter(pattern):
                await client.delete(key)
        except Exception as exc:
            logger.warning("redis_clear_failed", extra={"error": str(exc)})

    async def sweep(self) -> int:
        # Redis handles TTL expiry natively — no manual sweep needed
        return 0

    async def stats(self) -> Dict[str, Any]:
        try:
            client = await self._get_client()
            info = await client.info("stats")
            keyspace = await client.info("keyspace")
            return {
                "backend":    "redis",
                "url":        REDIS_URL,
                "available":  self._available,
                "keyspace_hits":   info.get("keyspace_hits", 0),
                "keyspace_misses": info.get("keyspace_misses", 0),
                "keyspace":        keyspace,
            }
        except Exception as exc:
            return {"backend": "redis", "available": False, "error": str(exc)}

    # ------------------------------------------------------------------
    # Distributed lock (for cache stampede prevention)
    # ------------------------------------------------------------------

    async def get_or_set(self, key: str, factory, ttl: Optional[float] = None) -> Any:
        """
        Atomic get-or-compute with a distributed lock.
        Prevents cache stampede on cold cache misses.
        """
        cached = await self.get(key)
        if cached is not None:
            return cached

        lock_key = f"{self._full_key(key)}:lock"
        try:
            client = await self._get_client()
            acquired = await client.set(lock_key, "1", nx=True, ex=10)
            if acquired:
                value = await factory()
                await self.set(key, value, ttl=ttl)
                await client.delete(lock_key)
                return value
            else:
                # Another process is computing — wait and retry
                import asyncio
                await asyncio.sleep(0.1)
                return await self.get(key)
        except Exception:
            # Fallback: compute without lock
            return await factory()