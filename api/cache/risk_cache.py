"""
cache/risk_cache.py — Identity Risk Query Cache (TTL: 120s)
"""
from .cache_manager import CacheManager


class RiskCache:
    """Cache for identity risk query results."""

    def __init__(self, ttl: int = 120, max_size: int = 5000) -> None:
        self._cache = CacheManager(ttl=ttl, max_size=max_size)

    def _key(self, identity: str, window_hours: int) -> str:
        return f"risk:{identity}:{window_hours}"

    async def get(self, identity: str, window_hours: int):
        return await self._cache.get(self._key(identity, window_hours))

    async def set(self, identity: str, window_hours: int, result) -> None:
        await self._cache.set(self._key(identity, window_hours), result)

    async def invalidate(self, identity: str) -> int:
        return await self._cache.invalidate_prefix(f"risk:{identity}:")

    def stats(self):
        return self._cache.stats()