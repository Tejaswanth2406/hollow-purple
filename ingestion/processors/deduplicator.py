"""
ingestion/processors/deduplicator.py — Event Deduplication Processor

Strategies:
  1. Content hash deduplication (SHA-256 of canonical fields)
  2. Event ID deduplication (exact event_id match)
  3. Near-duplicate suppression: same actor+action+resource within N seconds
  4. Configurable TTL-based cache expiry (avoids unbounded memory growth)
  5. LRU eviction when cache exceeds max size
  6. Stats tracking: total seen, deduped, cache size
"""

import hashlib
import logging
import time
from collections import OrderedDict
from typing import Any

logger = logging.getLogger("hollow_purple.deduplicator")

# Content-hash fields: only these determine uniqueness
CANONICAL_FIELDS = ("source", "service", "action", "actor", "resource", "account_id")

# Near-duplicate suppression window
NEAR_DUP_WINDOW_SEC  = 10.0

# Cache TTL and max size
DEFAULT_TTL_SEC      = 300     # 5-minute dedup window
DEFAULT_MAX_CACHE    = 100_000


class EventDeduplicator:
    """
    Multi-strategy event deduplicator with bounded LRU cache.

    Returns None for duplicate events (pipeline drops them cleanly).
    Returns the event unchanged if it is unique.
    """

    def __init__(
        self,
        ttl: float       = DEFAULT_TTL_SEC,
        max_cache: int   = DEFAULT_MAX_CACHE,
        near_dup_window: float = NEAR_DUP_WINDOW_SEC,
    ):
        self.ttl            = ttl
        self.max_cache      = max_cache
        self.near_dup_window = near_dup_window

        # {fingerprint: last_seen_ts}  — ordered for LRU eviction
        self._hash_cache:    OrderedDict[str, float] = OrderedDict()
        # {event_id: last_seen_ts}
        self._id_cache:      OrderedDict[str, float] = OrderedDict()
        # {near_dup_key: last_seen_ts}
        self._near_dup_cache: OrderedDict[str, float] = OrderedDict()

        self.total_seen   = 0
        self.total_deduped = 0

    async def process(self, event: dict) -> dict | None:
        if not isinstance(event, dict):
            return event

        self.total_seen += 1
        now = time.time()

        # 1. Event ID exact match
        event_id = event.get("event_id")
        if event_id and self._is_cached(self._id_cache, str(event_id), now):
            logger.debug("Deduped by event_id: %s", event_id)
            self.total_deduped += 1
            return None

        # 2. Content hash dedup
        content_hash = self._content_hash(event)
        if self._is_cached(self._hash_cache, content_hash, now):
            logger.debug("Deduped by content hash: %s", content_hash)
            self.total_deduped += 1
            return None

        # 3. Near-duplicate suppression (same actor+action+resource within window)
        near_key = self._near_dup_key(event)
        if near_key and self._is_near_dup(near_key, now):
            logger.debug("Deduped as near-duplicate: %s", near_key)
            self.total_deduped += 1
            return None

        # Not a duplicate — register in all caches
        if event_id:
            self._insert(self._id_cache, str(event_id), now)
        self._insert(self._hash_cache, content_hash, now)
        if near_key:
            self._near_dup_cache[near_key] = now
            self._evict_expired(self._near_dup_cache, now, self.near_dup_window)

        return event

    # ------------------------------------------------------------------ #
    #  Cache management                                                    #
    # ------------------------------------------------------------------ #

    def _is_cached(self, cache: OrderedDict, key: str, now: float) -> bool:
        if key not in cache:
            return False
        last = cache[key]
        if now - last > self.ttl:
            del cache[key]
            return False
        cache.move_to_end(key)   # refresh LRU position
        return True

    def _is_near_dup(self, key: str, now: float) -> bool:
        last = self._near_dup_cache.get(key)
        if last is None:
            return False
        return (now - last) <= self.near_dup_window

    def _insert(self, cache: OrderedDict, key: str, now: float):
        cache[key] = now
        cache.move_to_end(key)
        if len(cache) > self.max_cache:
            # Evict oldest (LRU)
            cache.popitem(last=False)

    def _evict_expired(self, cache: OrderedDict, now: float, ttl: float):
        expired = [k for k, ts in cache.items() if now - ts > ttl]
        for k in expired:
            del cache[k]

    # ------------------------------------------------------------------ #
    #  Hash helpers                                                        #
    # ------------------------------------------------------------------ #

    def _content_hash(self, event: dict) -> str:
        parts = ":".join(str(event.get(f, "")) for f in CANONICAL_FIELDS)
        return hashlib.sha256(parts.encode()).hexdigest()[:20]

    def _near_dup_key(self, event: dict) -> str | None:
        actor    = event.get("actor", "")
        action   = event.get("action", "")
        resource = event.get("resource", "")
        if not (actor and action):
            return None
        return f"{actor}:{action}:{resource}"

    def stats(self) -> dict:
        return {
            "total_seen":        self.total_seen,
            "total_deduped":     self.total_deduped,
            "dedup_rate_pct":    round(100 * self.total_deduped / max(1, self.total_seen), 2),
            "hash_cache_size":   len(self._hash_cache),
            "id_cache_size":     len(self._id_cache),
            "near_dup_cache":    len(self._near_dup_cache),
        }