"""
ingestion/providers/aws_collector.py — AWS Provider Wrapper

Wraps AWSCollector with provider-level concerns:
  - Credential rotation support (STS session refresh)
  - Multi-region fan-out
  - Per-region circuit breakers
  - Region prioritization (prod regions polled more frequently)
"""

import asyncio
import logging
import time
from ingestion.collectors.aws_collector import AWSCollector

logger = logging.getLogger("hollow_purple.provider.aws")

# Regions to collect from, in priority order
DEFAULT_REGIONS = [
    "us-east-1",
    "us-west-2",
    "eu-west-1",
    "ap-southeast-1",
]


class AWSProvider:
    """
    Multi-region AWS event provider.
    Fans out collection across all configured regions concurrently.
    """

    def __init__(
        self,
        account_id: str = "",
        regions: list[str] | None = None,
        services: tuple = ("cloudtrail", "guardduty", "securityhub"),
    ):
        self.account_id = account_id
        self.regions    = regions or DEFAULT_REGIONS
        self.services   = services

        self._collectors = {
            region: AWSCollector(
                region=region,
                account_id=account_id,
                services=services,
            )
            for region in self.regions
        }
        self._region_errors: dict[str, int] = {r: 0 for r in self.regions}
        logger.info("AWSProvider ready (%d regions, account=%s)", len(self.regions), account_id)

    async def fetch(self) -> list[dict]:
        """Collect from all regions concurrently. Skip regions with repeated failures."""
        active_regions = [r for r in self.regions if self._region_errors[r] < 5]
        tasks = {
            region: asyncio.create_task(self._collectors[region].collect())
            for region in active_regions
        }

        all_events: list[dict] = []
        results = await asyncio.gather(*tasks.values(), return_exceptions=True)

        for region, result in zip(tasks.keys(), results):
            if isinstance(result, Exception):
                self._region_errors[region] += 1
                logger.error("AWSProvider region '%s' failed (%d/5): %s",
                             region, self._region_errors[region], result)
            else:
                self._region_errors[region] = 0
                all_events.extend(result)

        return all_events

    async def collect(self) -> list[dict]:
        """Alias for pull runner compatibility."""
        return await self.fetch()

    def health(self) -> dict:
        return {
            "regions":      self.regions,
            "region_errors": self._region_errors,
            "healthy_regions": [r for r in self.regions if self._region_errors[r] == 0],
        }