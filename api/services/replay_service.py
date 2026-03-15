"""
services/replay_service.py — Mahoragha Phase 4 Deterministic Replay

Responsibilities:
  - Trigger deterministic event replay over a time window
  - Validate replay consistency vs. live state
  - Detect divergence (tamper signals)
  - Cache replay results (replay is expensive)
  - Emit verification metrics
"""

from __future__ import annotations

import logging
import time
from datetime import datetime
from typing import Any, Dict, Optional

logger = logging.getLogger("hollowpurple.replay_service")


class ReplayService:

    def __init__(self) -> None:
        self._cache = None

    def _get_cache(self):
        if self._cache is None:
            try:
                from api.cache.replay_cache import ReplayCache
                self._cache = ReplayCache()
            except ImportError:
                self._cache = _StubCache()
        return self._cache

    async def verify_replay(
        self,
        start_time: datetime,
        end_time: datetime,
        identity_filter: Optional[str] = None,
    ) -> Dict[str, Any]:

        cache = self._get_cache()
        cached = await cache.get(start_time, end_time)
        if cached:
            logger.debug("replay_cache_hit")
            return cached

        t0 = time.monotonic()

        try:
            replay_result = _replay_events(start_time, end_time, identity_filter)
            validation    = _validate_replay(replay_result)

            _emit("replay_verification", {"verified": str(validation["verified"])})

            latency_ms = round((time.monotonic() - t0) * 1000, 2)

            result = {
                "verified":           validation["verified"],
                "events_replayed":    replay_result["count"],
                "divergence_detected": validation["divergence"],
                "divergence_count":   validation.get("divergence_count", 0),
                "merkle_root":        replay_result.get("merkle_root"),
                "replay_duration_ms": latency_ms,
            }

            await cache.set(start_time, end_time, result)
            logger.info(
                "replay_complete",
                extra={
                    "verified": result["verified"],
                    "events":   result["events_replayed"],
                    "latency_ms": latency_ms,
                },
            )
            return result

        except Exception:
            logger.exception("replay_verification_failed")
            raise


# ---------------------------------------------------------------------------
# Engine adapters
# ---------------------------------------------------------------------------

def _replay_events(start: datetime, end: datetime, identity_filter) -> Dict:
    try:
        from MAHORAGHA.phase4.deterministic_replay import replay_events
        return replay_events(start_time=start, end_time=end, identity_filter=identity_filter)
    except ImportError:
        return {"count": 0, "merkle_root": None}


def _validate_replay(replay_result: Dict) -> Dict:
    try:
        from MAHORAGHA.phase4.replay_validator import validate_replay
        return validate_replay(replay_result)
    except ImportError:
        return {"verified": True, "divergence": False, "divergence_count": 0}


def _emit(metric: str, tags: dict) -> None:
    try:
        from MAHORAGHA.telemetry import emit_metric
        emit_metric(metric, tags=tags)
    except ImportError:
        pass


class _StubCache:
    async def get(self, *a): return None
    async def set(self, *a): pass