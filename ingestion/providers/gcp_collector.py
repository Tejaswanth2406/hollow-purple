"""
ingestion/providers/gcp_collector.py — GCP Provider Wrapper
"""

import asyncio
import logging
from ingestion.collectors.gcp_collector import GCPCollector

logger = logging.getLogger("hollow_purple.provider.gcp")


class GCPProvider:
    """Multi-project GCP event provider."""

    def __init__(
        self,
        organization_id: str = "",
        project_ids: list[str] | None = None,
        services: tuple = ("audit_log", "scc"),
    ):
        self.organization_id = organization_id
        self.project_ids     = project_ids or ["default"]
        self._collectors = {
            pid: GCPCollector(project_id=pid, organization_id=organization_id, services=services)
            for pid in self.project_ids
        }
        logger.info("GCPProvider ready (%d projects)", len(self.project_ids))

    async def fetch(self) -> list[dict]:
        results = await asyncio.gather(
            *[c.collect() for c in self._collectors.values()],
            return_exceptions=True,
        )
        events: list[dict] = []
        for pid, result in zip(self.project_ids, results):
            if isinstance(result, Exception):
                logger.error("GCPProvider project '%s' failed: %s", pid, result)
            else:
                events.extend(result)
        return events

    async def collect(self) -> list[dict]:
        return await self.fetch()