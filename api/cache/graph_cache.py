"""
cache/graph_cache.py — Graph Exposure Cache (TTL: 60s)
"""
from .cache_manager import CacheManager


class GraphCache:
    """Cache for graph exposure / attack-path lookups."""

    def __init__(self, ttl: int = 60, max_size: int = 2000) -> None:
        self._cache = CacheManager(ttl=ttl, max_size=max_size)

    def _key(self, identity: str) -> str:
        return f"graph:{identity}"

    async def get(self, identity: str):
        return await self._cache.get(self._key(identity))

    async def set(self, identity: str, result) -> None:
        await self._cache.set(self._key(identity), result)

    async def invalidate(self, identity: str) -> bool:
        return await self._cache.delete(self._key(identity))

    def stats(self):
        return self._cache.stats()