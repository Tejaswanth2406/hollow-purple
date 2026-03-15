"""
ingestion/providers/webhook_collector.py — Webhook Provider Wrapper

Manages multiple webhook sources (Okta, GitHub, PagerDuty, custom)
under a single provider interface.
"""

import asyncio
import logging
from ingestion.collectors.webhook_collector import WebhookCollector

logger = logging.getLogger("hollow_purple.provider.webhook")


class WebhookProvider:
    """
    Multi-source webhook provider.
    Each source has its own collector with its own secret and signature config.
    """

    def __init__(self, sources: list[dict] | None = None):
        """
        sources: list of dicts with keys:
            name, secret, source, require_signature
        """
        self._collectors: dict[str, WebhookCollector] = {}
        for cfg in (sources or []):
            name = cfg.get("name", "default")
            self._collectors[name] = WebhookCollector(
                secret=cfg.get("secret", ""),
                source=cfg.get("source", "custom"),
                require_signature=cfg.get("require_signature", True),
            )
        if not self._collectors:
            self._collectors["default"] = WebhookCollector(require_signature=False)
        logger.info("WebhookProvider ready (%d sources)", len(self._collectors))

    async def receive(self, body: bytes, headers: dict, source: str = "default") -> list[dict]:
        """Route an inbound webhook to the appropriate collector."""
        collector = self._collectors.get(source) or self._collectors.get("default")
        return await collector.receive(body, headers)

    async def collect(self) -> list[dict]:
        """Drain all pending webhook events from all sources."""
        results = await asyncio.gather(
            *[c.collect() for c in self._collectors.values()],
            return_exceptions=True,
        )
        events: list[dict] = []
        for name, result in zip(self._collectors.keys(), results):
            if isinstance(result, Exception):
                logger.error("WebhookProvider source '%s' drain failed: %s", name, result)
            else:
                events.extend(result)
        return events

    def fetch(self):
        return self.collect()