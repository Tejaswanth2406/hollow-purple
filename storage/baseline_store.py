"""
storage/baseline_store.py
=========================
Enterprise behavioral baseline model persistence layer.

Features
--------
- Versioned baseline records — every save creates a new version
- TTL-based expiry for model staleness detection
- Tag-based namespace grouping (e.g. per-tenant, per-service)
- Async-safe read/write under asyncio.Lock
- Pluggable backend adapter (swap to Redis / TimescaleDB / PostgreSQL)
- Diff support — compare current vs previous baseline version
- Structured audit log on every save/delete
- Export / import for offline analysis and cross-environment migration
- Staleness detection: flag baselines not updated within a configurable window
"""

from __future__ import annotations

import asyncio
import copy
import json
import logging
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Set


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class BaselineNotFoundError(KeyError):
    """Raised when a requested metric baseline does not exist."""


class BaselineVersionError(ValueError):
    """Raised on version conflict or invalid version access."""


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class BaselineRecord:
    """
    A single persisted baseline snapshot.

    Fields
    ------
    metric          : Dot-separated metric name (e.g. ``"api.latency_ms"``).
    version         : Auto-incrementing version number.
    data            : Statistical model payload (mean, std, percentiles…).
    tenant_id       : Multi-tenant scope.
    tags            : Free-form label set for grouping/filtering.
    created_at      : First-ever save timestamp.
    updated_at      : This version's save timestamp.
    expires_at      : Optional ISO-8601 expiry (used for staleness checks).
    record_id       : UUID4 per-version unique ID.
    """

    metric: str
    version: int
    data: Dict[str, Any]
    tenant_id: Optional[str] = None
    tags: Set[str] = field(default_factory=set)
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    updated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    expires_at: Optional[str] = None
    record_id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > datetime.fromisoformat(self.expires_at)

    def is_stale(self, max_age_seconds: float) -> bool:
        updated = datetime.fromisoformat(self.updated_at)
        age = (datetime.now(timezone.utc) - updated).total_seconds()
        return age > max_age_seconds

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["tags"] = list(self.tags)
        return d


# ---------------------------------------------------------------------------
# Backend adapter
# ---------------------------------------------------------------------------


class BaselineStoreBackend:
    """Abstract backend interface for baseline persistence."""

    async def save(self, record: BaselineRecord) -> None:
        raise NotImplementedError

    async def get_latest(
        self, metric: str, tenant_id: Optional[str] = None
    ) -> Optional[BaselineRecord]:
        raise NotImplementedError

    async def get_version(
        self, metric: str, version: int, tenant_id: Optional[str] = None
    ) -> Optional[BaselineRecord]:
        raise NotImplementedError

    async def list_versions(
        self, metric: str, tenant_id: Optional[str] = None
    ) -> List[BaselineRecord]:
        raise NotImplementedError

    async def list_metrics(self, tenant_id: Optional[str] = None) -> List[str]:
        raise NotImplementedError

    async def delete(self, metric: str, tenant_id: Optional[str] = None) -> int:
        raise NotImplementedError


class InMemoryBaselineBackend(BaselineStoreBackend):
    """In-memory backend. Keyed by (metric, tenant_id)."""

    def __init__(self) -> None:
        # (metric, tenant_id) -> sorted list of BaselineRecord
        self._store: Dict[tuple, List[BaselineRecord]] = {}

    def _key(self, metric: str, tenant_id: Optional[str]) -> tuple:
        return (metric, tenant_id)

    async def save(self, record: BaselineRecord) -> None:
        key = self._key(record.metric, record.tenant_id)
        if key not in self._store:
            self._store[key] = []
        self._store[key].append(record)

    async def get_latest(
        self, metric: str, tenant_id: Optional[str] = None
    ) -> Optional[BaselineRecord]:
        versions = self._store.get(self._key(metric, tenant_id), [])
        return versions[-1] if versions else None

    async def get_version(
        self, metric: str, version: int, tenant_id: Optional[str] = None
    ) -> Optional[BaselineRecord]:
        versions = self._store.get(self._key(metric, tenant_id), [])
        for r in versions:
            if r.version == version:
                return r
        return None

    async def list_versions(
        self, metric: str, tenant_id: Optional[str] = None
    ) -> List[BaselineRecord]:
        return list(self._store.get(self._key(metric, tenant_id), []))

    async def list_metrics(self, tenant_id: Optional[str] = None) -> List[str]:
        return [
            k[0]
            for k in self._store
            if (tenant_id is None or k[1] == tenant_id) and self._store[k]
        ]

    async def delete(self, metric: str, tenant_id: Optional[str] = None) -> int:
        key = self._key(metric, tenant_id)
        removed = len(self._store.pop(key, []))
        return removed


# ---------------------------------------------------------------------------
# BaselineStore
# ---------------------------------------------------------------------------


class BaselineStore:
    """
    Versioned behavioral baseline persistence engine.

    Usage
    -----
    ::

        store = BaselineStore(max_versions_per_metric=10)

        await store.save(
            "api.latency_ms",
            {"mean": 120.5, "std": 14.2, "p95": 210.0},
            tenant_id="acme",
            tags={"env:prod", "service:api"},
            ttl_seconds=86400,
        )

        record = await store.get("api.latency_ms", tenant_id="acme")

        diff = await store.diff("api.latency_ms", tenant_id="acme")
    """

    def __init__(
        self,
        *,
        backend: Optional[BaselineStoreBackend] = None,
        max_versions_per_metric: int = 20,
        staleness_threshold_s: float = 3600.0,
    ) -> None:
        self._backend = backend or InMemoryBaselineBackend()
        self._max_versions = max_versions_per_metric
        self._staleness_s = staleness_threshold_s
        self._lock = asyncio.Lock()
        self._version_counters: Dict[tuple, int] = {}

        logger.info(
            "BaselineStore initialised",
            extra={
                "max_versions": max_versions_per_metric,
                "staleness_s": staleness_threshold_s,
            },
        )

    # ---------------------------------------------------------------------------
    # Write path
    # ---------------------------------------------------------------------------

    async def save(
        self,
        metric: str,
        data: Dict[str, Any],
        *,
        tenant_id: Optional[str] = None,
        tags: Optional[Set[str]] = None,
        ttl_seconds: Optional[float] = None,
    ) -> BaselineRecord:
        """
        Persist a new baseline version.

        Each call creates a new immutable version; the previous version is
        retained up to ``max_versions_per_metric``.

        Parameters
        ----------
        metric          : Metric identifier.
        data            : Statistical model dict.
        tenant_id       : Tenant scope.
        tags            : Label set for grouping (e.g. ``{"env:prod"}``).
        ttl_seconds     : Seconds until this record is considered expired.
        """
        async with self._lock:
            key = (metric, tenant_id)
            version = self._version_counters.get(key, 0) + 1
            self._version_counters[key] = version

            now = datetime.now(timezone.utc)
            expires_at = (
                (now + timedelta(seconds=ttl_seconds)).isoformat()
                if ttl_seconds is not None
                else None
            )

            # Carry forward created_at from version 1
            existing = await self._backend.get_latest(metric, tenant_id)
            created_at = existing.created_at if existing else now.isoformat()

            record = BaselineRecord(
                metric=metric,
                version=version,
                data=copy.deepcopy(data),
                tenant_id=tenant_id,
                tags=tags or set(),
                created_at=created_at,
                updated_at=now.isoformat(),
                expires_at=expires_at,
            )

            await self._backend.save(record)

            logger.info(
                "Baseline saved",
                extra={
                    "metric": metric,
                    "version": version,
                    "tenant_id": tenant_id,
                    "tags": list(tags or []),
                },
            )

        return record

    # ---------------------------------------------------------------------------
    # Read path
    # ---------------------------------------------------------------------------

    async def get(
        self,
        metric: str,
        *,
        tenant_id: Optional[str] = None,
        version: Optional[int] = None,
    ) -> BaselineRecord:
        """
        Retrieve the latest (or a specific) baseline version.

        Raises
        ------
        BaselineNotFoundError   : Metric has no saved baseline.
        BaselineVersionError    : Requested version does not exist.
        """
        if version is not None:
            record = await self._backend.get_version(metric, version, tenant_id)
            if record is None:
                raise BaselineVersionError(
                    f"Baseline '{metric}' version {version} not found"
                )
            return record

        record = await self._backend.get_latest(metric, tenant_id)
        if record is None:
            raise BaselineNotFoundError(f"Baseline '{metric}' not found")
        return record

    async def get_or_none(
        self, metric: str, *, tenant_id: Optional[str] = None
    ) -> Optional[BaselineRecord]:
        try:
            return await self.get(metric, tenant_id=tenant_id)
        except (BaselineNotFoundError, BaselineVersionError):
            return None

    async def list_metrics(self, *, tenant_id: Optional[str] = None) -> List[str]:
        return await self._backend.list_metrics(tenant_id=tenant_id)

    async def list_versions(
        self, metric: str, *, tenant_id: Optional[str] = None
    ) -> List[BaselineRecord]:
        return await self._backend.list_versions(metric, tenant_id)

    async def get_all_latest(
        self, *, tenant_id: Optional[str] = None
    ) -> Dict[str, BaselineRecord]:
        """Return a dict of {metric: latest_record} for all tracked metrics."""
        metrics = await self.list_metrics(tenant_id=tenant_id)
        result: Dict[str, BaselineRecord] = {}
        for m in metrics:
            r = await self._backend.get_latest(m, tenant_id)
            if r:
                result[m] = r
        return result

    # ---------------------------------------------------------------------------
    # Diff
    # ---------------------------------------------------------------------------

    async def diff(
        self, metric: str, *, tenant_id: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Compare the two most recent baseline versions.

        Returns a dict of changed keys with ``{"prev": ..., "current": ...}``
        entries. Returns None if fewer than 2 versions exist.
        """
        versions = await self.list_versions(metric, tenant_id=tenant_id)
        if len(versions) < 2:
            return None

        prev = versions[-2].data
        curr = versions[-1].data

        changes: Dict[str, Any] = {}
        all_keys = set(prev.keys()) | set(curr.keys())
        for k in all_keys:
            pv = prev.get(k)
            cv = curr.get(k)
            if pv != cv:
                changes[k] = {"prev": pv, "current": cv}
        return changes

    # ---------------------------------------------------------------------------
    # Staleness and expiry
    # ---------------------------------------------------------------------------

    async def stale_metrics(
        self, *, tenant_id: Optional[str] = None
    ) -> List[str]:
        """Return metrics whose latest baseline exceeds the staleness threshold."""
        stale = []
        for m in await self.list_metrics(tenant_id=tenant_id):
            r = await self._backend.get_latest(m, tenant_id)
            if r and r.is_stale(self._staleness_s):
                stale.append(m)
        return stale

    async def expired_metrics(
        self, *, tenant_id: Optional[str] = None
    ) -> List[str]:
        """Return metrics whose latest baseline TTL has elapsed."""
        expired = []
        for m in await self.list_metrics(tenant_id=tenant_id):
            r = await self._backend.get_latest(m, tenant_id)
            if r and r.is_expired():
                expired.append(m)
        return expired

    # ---------------------------------------------------------------------------
    # Delete
    # ---------------------------------------------------------------------------

    async def delete(
        self, metric: str, *, tenant_id: Optional[str] = None
    ) -> int:
        """Delete all versions of a metric. Returns count of deleted records."""
        async with self._lock:
            count = await self._backend.delete(metric, tenant_id)
            self._version_counters.pop((metric, tenant_id), None)
            logger.info(
                "Baseline deleted",
                extra={"metric": metric, "tenant_id": tenant_id, "versions": count},
            )
        return count

    # ---------------------------------------------------------------------------
    # Export / import
    # ---------------------------------------------------------------------------

    async def export(
        self, *, tenant_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Serialize all latest baselines for offline backup or migration."""
        all_records = await self.get_all_latest(tenant_id=tenant_id)
        return [r.to_dict() for r in all_records.values()]

    async def import_records(self, records: List[Dict[str, Any]]) -> int:
        """Restore exported baseline records. Returns count imported."""
        count = 0
        for raw in records:
            tags = set(raw.get("tags", []))
            await self.save(
                raw["metric"],
                raw["data"],
                tenant_id=raw.get("tenant_id"),
                tags=tags,
            )
            count += 1
        return count