"""
phase5/alert_router.py — Escalation Alert Router

Routes pipeline escalation events to notification channels.
Channels are pluggable; built-in stubs for webhook, PagerDuty, Slack.

Architecture:
  AlertEvent  — normalized alert payload (channel-agnostic)
  AlertChannel — base class; subclass and implement send()
  AlertRouter  — fan-out to configured channels with dedup + rate-limit

Hardening:
  H1  — Channel send() wrapped in try/except; failure logged, not raised
  H2  — Per-channel rate limit: max N alerts per window
  H3  — Deduplication: same (source, fingerprint) within cooldown_s suppressed
  H4  — Thread-safe: rate-limit and dedup state under lock
  H5  — AlertSeverity ordering enforced; channel can filter by min_severity
  H6  — Dead-letter queue for failed deliveries (bounded, max 1000)
  H7  — RouterStats: delivered, suppressed, failed counters
  H8  — Graceful no-op on empty channel list
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum, auto
from typing import Optional, Callable


# ── AlertSeverity ──────────────────────────────────────────────────────────────

class AlertSeverity(Enum):
    INFO     = 0
    WARN     = 1
    ALERT    = 2
    CRITICAL = 3

    def __ge__(self, other: "AlertSeverity") -> bool:
        return self.value >= other.value

    def __gt__(self, other: "AlertSeverity") -> bool:
        return self.value > other.value


# ── AlertEvent ─────────────────────────────────────────────────────────────────

@dataclass
class AlertEvent:
    """
    Normalised alert payload, channel-agnostic.

    `fingerprint` is computed from (source, title, severity) if not provided.
    """
    source:      str                            # e.g. "pipeline.escalation"
    title:       str
    body:        str
    severity:    AlertSeverity
    occurred_at: datetime
    labels:      dict[str, str]                 = field(default_factory=dict)
    fingerprint: str                            = field(default="")

    def __post_init__(self):
        if not self.fingerprint:
            raw = f"{self.source}|{self.title}|{self.severity.name}"
            self.fingerprint = hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {
            "source":      self.source,
            "title":       self.title,
            "body":        self.body,
            "severity":    self.severity.name,
            "occurred_at": self.occurred_at.isoformat(),
            "labels":      self.labels,
            "fingerprint": self.fingerprint,
        }


# ── AlertChannel base ─────────────────────────────────────────────────────────

class AlertChannel:
    """
    Abstract base. Subclass and implement send().

    `min_severity` filters out lower-severity events at channel level.
    `rate_limit`   is max events per `rate_window_s` seconds.
    """

    def __init__(
        self,
        name:            str,
        min_severity:    AlertSeverity = AlertSeverity.WARN,
        rate_limit:      int           = 100,
        rate_window_s:   float         = 60.0,
    ):
        self.name          = name
        self.min_severity  = min_severity
        self._rate_limit   = rate_limit
        self._rate_window_s = rate_window_s
        self._sent_times:  list[float] = []
        self._lock         = threading.Lock()

    def _within_rate_limit(self) -> bool:
        """H2: sliding window rate check."""
        now = time.monotonic()
        cutoff = now - self._rate_window_s
        with self._lock:
            self._sent_times = [t for t in self._sent_times if t >= cutoff]
            if len(self._sent_times) >= self._rate_limit:
                return False
            self._sent_times.append(now)
            return True

    def accepts(self, event: AlertEvent) -> bool:
        """H5: severity filter."""
        return event.severity >= self.min_severity

    def send(self, event: AlertEvent) -> None:
        """Override in subclasses. Called only when accepts() is True."""
        raise NotImplementedError


# ── NullChannel ────────────────────────────────────────────────────────────────

class NullChannel(AlertChannel):
    """No-op channel — useful as default / in tests."""

    def __init__(self, name: str = "null", **kwargs):
        super().__init__(name, **kwargs)
        self.received: list[AlertEvent] = []

    def send(self, event: AlertEvent) -> None:
        self.received.append(event)


# ── WebhookChannel ─────────────────────────────────────────────────────────────

class WebhookChannel(AlertChannel):
    """
    HTTP POST webhook stub.

    `sender` is a callable(url, payload_dict) → bool (True=success).
    Defaults to a no-op that always succeeds — replace with requests.post wrapper.
    """

    def __init__(
        self,
        name:     str,
        url:      str,
        sender:   Optional[Callable[[str, dict], bool]] = None,
        **kwargs,
    ):
        super().__init__(name, **kwargs)
        self.url    = url
        self._sender = sender or (lambda _url, _payload: True)

    def send(self, event: AlertEvent) -> None:
        payload = event.to_dict()
        payload["channel"] = self.name
        self._sender(self.url, payload)


# ── PagerDutyChannel ───────────────────────────────────────────────────────────

class PagerDutyChannel(AlertChannel):
    """
    PagerDuty Events API v2 stub.
    
    Real implementation: POST to https://events.pagerduty.com/v2/enqueue
    with `routing_key` and payload. This stub records calls for testing.
    """

    def __init__(
        self,
        name:        str,
        routing_key: str,
        sender:      Optional[Callable[[str, dict], bool]] = None,
        **kwargs,
    ):
        super().__init__(name, min_severity=AlertSeverity.ALERT, **kwargs)
        self.routing_key = routing_key
        self._sender     = sender or (lambda _key, _payload: True)
        self.calls: list[dict] = []

    def send(self, event: AlertEvent) -> None:
        payload = {
            "routing_key":  self.routing_key,
            "event_action": "trigger",
            "dedup_key":    event.fingerprint,
            "payload": {
                "summary":   event.title,
                "source":    event.source,
                "severity":  event.severity.name.lower(),
                "timestamp": event.occurred_at.isoformat(),
                "custom_details": event.labels,
            },
        }
        self.calls.append(payload)
        self._sender(self.routing_key, payload)


# ── SlackChannel ───────────────────────────────────────────────────────────────

class SlackChannel(AlertChannel):
    """
    Slack Incoming Webhooks stub.
    """

    SEVERITY_COLORS = {
        AlertSeverity.INFO:     "#36a64f",
        AlertSeverity.WARN:     "#ffcc00",
        AlertSeverity.ALERT:    "#ff8800",
        AlertSeverity.CRITICAL: "#ff0000",
    }

    def __init__(
        self,
        name:        str,
        webhook_url: str,
        sender:      Optional[Callable[[str, dict], bool]] = None,
        **kwargs,
    ):
        super().__init__(name, **kwargs)
        self.webhook_url = webhook_url
        self._sender     = sender or (lambda _url, _payload: True)
        self.calls: list[dict] = []

    def send(self, event: AlertEvent) -> None:
        payload = {
            "attachments": [{
                "color":  self.SEVERITY_COLORS.get(event.severity, "#aaaaaa"),
                "title":  f"[{event.severity.name}] {event.title}",
                "text":   event.body,
                "footer": event.source,
                "ts":     int(event.occurred_at.timestamp()),
                "fields": [
                    {"title": k, "value": v, "short": True}
                    for k, v in event.labels.items()
                ],
            }]
        }
        self.calls.append(payload)
        self._sender(self.webhook_url, payload)


# ── Dead-letter entry ─────────────────────────────────────────────────────────

@dataclass
class _DeadLetter:
    channel_name: str
    event:        AlertEvent
    error:        str
    failed_at:    datetime


MAX_DEAD_LETTER = 1_000


# ── RouterStats ────────────────────────────────────────────────────────────────

@dataclass
class RouterStats:
    delivered:  int = 0
    suppressed: int = 0    # rate-limited or deduped
    failed:     int = 0
    dead_letter_queue_size: int = 0


# ── AlertRouter ───────────────────────────────────────────────────────────────

class AlertRouter:
    """
    Fan-out router.

    Deduplication: identical fingerprint within `cooldown_s` is suppressed.
    Rate limit:    per-channel sliding window (see AlertChannel._within_rate_limit).
    Dead-letter:   failed sends go into bounded DLQ (H6).
    Thread-safe:   H4.
    """

    def __init__(
        self,
        channels:    Optional[list[AlertChannel]] = None,
        cooldown_s:  float                        = 300.0,   # 5 min default dedup window
    ):
        self._channels    = list(channels or [])
        self._cooldown_s  = cooldown_s
        self._lock        = threading.Lock()

        # H3: dedup state {fingerprint: last_sent_monotonic}
        self._last_sent:  dict[str, float] = {}

        # H6: dead-letter queue
        self._dlq:        list[_DeadLetter] = []

        # H7: stats
        self._stats = RouterStats()

    # ── channel management ────────────────────────────────────────────────────

    def add_channel(self, channel: AlertChannel) -> None:
        with self._lock:
            self._channels.append(channel)

    def channels(self) -> list[AlertChannel]:
        with self._lock:
            return list(self._channels)

    # ── routing ───────────────────────────────────────────────────────────────

    def route(self, event: AlertEvent) -> None:
        """
        Fan event out to all eligible channels.

        H8: no-op if no channels registered.
        """
        now_mono = time.monotonic()

        # H3: dedup check
        with self._lock:
            last = self._last_sent.get(event.fingerprint, 0.0)
            if now_mono - last < self._cooldown_s:
                self._stats.suppressed += 1
                return
            self._last_sent[event.fingerprint] = now_mono
            channels_snapshot = list(self._channels)

        # H8
        if not channels_snapshot:
            return

        for channel in channels_snapshot:
            # H5: severity filter
            if not channel.accepts(event):
                continue

            # H2: rate limit
            if not channel._within_rate_limit():
                with self._lock:
                    self._stats.suppressed += 1
                continue

            # H1: send with error isolation
            try:
                channel.send(event)
                with self._lock:
                    self._stats.delivered += 1
            except Exception as exc:
                dl = _DeadLetter(
                    channel_name = channel.name,
                    event        = event,
                    error        = str(exc),
                    failed_at    = datetime.now(timezone.utc),
                )
                with self._lock:
                    self._stats.failed += 1
                    if len(self._dlq) < MAX_DEAD_LETTER:
                        self._dlq.append(dl)
                    self._stats.dead_letter_queue_size = len(self._dlq)

    def route_batch(self, events: list[AlertEvent]) -> None:
        for event in events:
            self.route(event)

    # ── stats and DLQ ─────────────────────────────────────────────────────────

    def stats(self) -> RouterStats:
        with self._lock:
            return RouterStats(
                delivered               = self._stats.delivered,
                suppressed              = self._stats.suppressed,
                failed                  = self._stats.failed,
                dead_letter_queue_size  = len(self._dlq),
            )

    def dead_letters(self) -> list[_DeadLetter]:
        with self._lock:
            return list(self._dlq)

    def flush_dead_letters(self) -> list[_DeadLetter]:
        with self._lock:
            items = list(self._dlq)
            self._dlq.clear()
            self._stats.dead_letter_queue_size = 0
            return items

    def reset_dedup(self) -> None:
        """Clear dedup cache (useful in tests)."""
        with self._lock:
            self._last_sent.clear()

    # ── convenience factory ───────────────────────────────────────────────────

    @classmethod
    def from_escalation_event(
        cls,
        escalation,
        source: str = "pipeline.temporal_engine",
    ) -> AlertEvent:
        """
        Convert a Phase 2/3 EscalationEvent to an AlertEvent.
        Accepts any object with risk_band, identity_key, score attrs.
        """
        band_map = {
            "CRITICAL": AlertSeverity.CRITICAL,
            "ALERT":    AlertSeverity.ALERT,
            "ELEVATED": AlertSeverity.WARN,
            "NORMAL":   AlertSeverity.INFO,
        }
        band     = getattr(escalation, "risk_band", "NORMAL")
        severity = band_map.get(band, AlertSeverity.INFO)
        identity = getattr(escalation, "identity_key", "unknown")
        score    = getattr(escalation, "score", 0.0)

        return AlertEvent(
            source      = source,
            title       = f"{band}: {identity}",
            body        = (
                f"Identity '{identity}' triggered {band} escalation. "
                f"Score: {score:.3f}"
            ),
            severity    = severity,
            occurred_at = datetime.now(timezone.utc),
            labels      = {"identity": identity, "risk_band": band},
        )