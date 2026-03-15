"""
ingestion/collectors/webhook_collector.py — Async Webhook Event Receiver

Supports:
  - HMAC-SHA256 signature verification (GitHub, Okta, Slack style)
  - Content-type negotiation (JSON, CloudEvents, custom)
  - Per-source payload adapters
  - Replay attack prevention (timestamp tolerance window)
  - Batch webhook payloads (arrays of events)
  - Async queue-backed receive for decoupling from HTTP handler
"""

import asyncio
import hashlib
import hmac
import json
import logging
import time

logger = logging.getLogger("hollow_purple.collector.webhook")

# Supported webhook sources and their signature header names
SIGNATURE_HEADERS = {
    "github":    "X-Hub-Signature-256",
    "okta":      "X-Okta-Signature",
    "pagerduty": "X-PagerDuty-Signature",
    "custom":    "X-HP-Signature",
}

TIMESTAMP_TOLERANCE_SEC = 300   # reject webhooks older than 5 minutes


class WebhookCollector:
    """
    Receives webhook payloads from external systems.
    Designed to be wired into a FastAPI/aiohttp route handler.

    Usage:
        collector = WebhookCollector(secret="my-secret", source="github")
        # In HTTP handler:
        events = await collector.receive(body_bytes, headers)
        # Later, drain:
        batch = await collector.drain(max_items=100)
    """

    def __init__(
        self,
        secret: str = "",
        source: str = "custom",
        max_queue: int = 5000,
        require_signature: bool = True,
        timestamp_tolerance: int = TIMESTAMP_TOLERANCE_SEC,
    ):
        self.secret              = secret.encode() if isinstance(secret, str) else secret
        self.source              = source
        self.require_signature   = require_signature
        self.timestamp_tolerance = timestamp_tolerance
        self._queue              = asyncio.Queue(maxsize=max_queue)

        self.received  = 0
        self.rejected  = 0
        self.signature_failures = 0

        logger.info("WebhookCollector ready (source=%s, sig_required=%s)",
                    source, require_signature)

    async def receive(self, body: bytes, headers: dict) -> list[dict]:
        """
        Validate, parse, and enqueue a raw webhook payload.

        Returns the list of parsed events (may be empty on validation failure).
        """
        # --- Signature verification ---
        if self.require_signature and self.secret:
            sig_header = SIGNATURE_HEADERS.get(self.source, "X-HP-Signature")
            signature  = headers.get(sig_header, "")
            if not self._verify_signature(body, signature):
                self.signature_failures += 1
                self.rejected += 1
                logger.warning("Webhook signature verification failed (source=%s)", self.source)
                return []

        # --- Timestamp replay protection ---
        ts_str = headers.get("X-Webhook-Timestamp") or headers.get("X-Event-Time")
        if ts_str:
            try:
                ts = float(ts_str)
                age = abs(time.time() - ts)
                if age > self.timestamp_tolerance:
                    self.rejected += 1
                    logger.warning("Webhook replay rejected: age=%.0fs > tolerance=%ds",
                                   age, self.timestamp_tolerance)
                    return []
            except ValueError:
                pass

        # --- Parse payload ---
        try:
            payload = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            self.rejected += 1
            logger.error("Webhook payload JSON parse error: %s", exc)
            return []

        # --- Normalize to event list ---
        raw_events = payload if isinstance(payload, list) else [payload]
        events = []
        for raw in raw_events:
            event = self._adapt(raw)
            if event:
                events.append(event)
                try:
                    self._queue.put_nowait(event)
                except asyncio.QueueFull:
                    logger.warning("Webhook queue full — dropping event (source=%s)", self.source)

        self.received += len(events)
        return events

    async def collect(self) -> list[dict]:
        """Pull interface: drain all currently queued events."""
        return await self.drain(max_items=500)

    async def drain(self, max_items: int = 100) -> list[dict]:
        """Drain up to max_items events from the internal queue."""
        events = []
        while not self._queue.empty() and len(events) < max_items:
            try:
                events.append(self._queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        return events

    # ------------------------------------------------------------------ #
    #  Internal helpers                                                    #
    # ------------------------------------------------------------------ #

    def _verify_signature(self, body: bytes, signature: str) -> bool:
        if not signature:
            return False
        # Strip algorithm prefix (e.g. "sha256=...")
        if "=" in signature:
            _, _, sig_value = signature.partition("=")
        else:
            sig_value = signature
        expected = hmac.new(self.secret, body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, sig_value)

    def _adapt(self, raw: dict) -> dict | None:
        """
        Adapt source-specific webhook payload to canonical event format.
        Extend with source-specific adapters as needed.
        """
        if not isinstance(raw, dict):
            return None

        base = {
            "source":    self.source,
            "service":   "webhook",
            "timestamp": raw.get("timestamp") or raw.get("time") or time.time(),
            "raw":       raw,
        }

        if self.source == "okta":
            return {**base,
                    "event_id": raw.get("uuid"),
                    "action":   raw.get("eventType"),
                    "actor":    raw.get("actor", {}).get("alternateId"),
                    "ip":       raw.get("client", {}).get("ipAddress")}

        if self.source == "github":
            return {**base,
                    "event_id": raw.get("delivery"),
                    "action":   raw.get("action"),
                    "actor":    raw.get("sender", {}).get("login"),
                    "resource": raw.get("repository", {}).get("full_name")}

        # Generic passthrough
        return {**base,
                "event_id": raw.get("id") or raw.get("event_id"),
                "action":   raw.get("action") or raw.get("event_type"),
                "actor":    raw.get("actor") or raw.get("user")}