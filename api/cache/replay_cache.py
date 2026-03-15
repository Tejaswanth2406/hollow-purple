"""
cache/replay_cache.py — Replay Verification Cache (TTL: 300s)
"""
from .cache_manager import CacheManager


class ReplayCache:
    """Cache for replay verification results. TTL is long — replay is expensive."""

    def __init__(self, ttl: int = 300, max_size: int = 500) -> None:
        self._cache = CacheManager(ttl=ttl, max_size=max_size)

    def _key(self, start, end) -> str:
        return f"replay:{start}:{end}"

    async def get(self, start, end):
        return await self._cache.get(self._key(start, end))

    async def set(self, start, end, result) -> None:
        await self._cache.set(self._key(start, end), result)

    async def invalidate_all(self) -> None:
        await self._cache.clear()

    def stats(self):
        return self._cache.stats()