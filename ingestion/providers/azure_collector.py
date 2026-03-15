"""
ingestion/providers/azure_collector.py — Azure Provider Wrapper

Multi-subscription Azure event provider with tenant-level aggregation.
"""

import asyncio
import logging
from ingestion.collectors.azure_collector import AzureCollector

logger = logging.getLogger("hollow_purple.provider.azure")


class AzureProvider:
    """
    Multi-subscription Azure provider.
    Collects from all configured subscriptions concurrently.
    """

    def __init__(
        self,
        tenant_id: str = "",
        subscription_ids: list[str] | None = None,
        services: tuple = ("activity_log", "entra_id", "defender"),
    ):
        self.tenant_id        = tenant_id
        self.subscription_ids = subscription_ids or ["default"]
        self._collectors = {
            sub: AzureCollector(subscription_id=sub, tenant_id=tenant_id, services=services)
            for sub in self.subscription_ids
        }
        logger.info("AzureProvider ready (%d subscriptions)", len(self.subscription_ids))

    async def fetch(self) -> list[dict]:
        results = await asyncio.gather(
            *[c.collect() for c in self._collectors.values()],
            return_exceptions=True,
        )
        events: list[dict] = []
        for sub, result in zip(self.subscription_ids, results):
            if isinstance(result, Exception):
                logger.error("AzureProvider subscription '%s' failed: %s", sub, result)
            else:
                events.extend(result)
        return events

    async def collect(self) -> list[dict]:
        return await self.fetch()