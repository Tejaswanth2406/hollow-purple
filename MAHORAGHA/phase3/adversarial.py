"""
Adversarial Guard

Detects attempts to manipulate, poison, or abuse the system's inputs.

Adversarial input attacks against security platforms include:
  - Log injection: crafting events that break parsers or spoof structure
  - Replay attacks: replaying old legitimate events to mask malicious ones
  - Flooding: overwhelming the pipeline with noise to hide signal
  - Enumeration: probing for system responses to map internals
  - Payload injection: embedding active content in event fields

Enterprise additions over the spec:
  - Named rules with metadata (description, severity, action)
  - Rule hit counters and cooldowns (rate-aware detection)
  - Event sanitization pipeline (strip/escape dangerous payloads)
  - Replay attack detection via nonce/timestamp tracking
  - Detection result with matched rules and recommended action
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set


@dataclass
class GuardRule:
    name: str
    predicate: Callable[[dict], bool]
    description: str
    severity: str = "medium"             # low | medium | high | critical
    action: str = "flag"                 # flag | drop | halt
    cooldown_seconds: float = 0.0        # min time between repeated triggers
    _last_triggered: float = field(default=0.0, repr=False, compare=False)
    _hit_count: int = field(default=0, repr=False, compare=False)

    def on_cooldown(self) -> bool:
        if self.cooldown_seconds <= 0:
            return False
        return (time.time() - self._last_triggered) < self.cooldown_seconds

    def record_hit(self):
        self._last_triggered = time.time()
        self._hit_count += 1


@dataclass
class GuardResult:
    event: dict
    is_adversarial: bool
    matched_rules: List[GuardRule]
    recommended_action: str              # flag | drop | halt
    sanitized_event: Optional[dict]
    timestamp: float = field(default_factory=time.time)

    @property
    def severity(self) -> str:
        if not self.matched_rules:
            return "none"
        levels = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        return max(self.matched_rules, key=lambda r: levels.get(r.severity, 0)).severity


class AdversarialGuard:
    """
    Multi-layer adversarial input detection.

    Layers:
      1. Rule-based detection (configurable named rules)
      2. Replay attack detection (timestamp + nonce tracking)
      3. Event sanitization (strip injection payloads from string fields)
    """

    # Fields to sanitize for injection patterns
    _SANITIZE_FIELDS = {"action", "user", "resource", "source", "message", "data"}
    # Strings that indicate injection attempts in field values
    _INJECTION_PATTERNS = [
        "<script", "javascript:", "' OR '", "'; DROP", "{{", "{%",
        "\x00", "\r\n", "../", "cmd.exe", "/etc/passwd",
    ]

    def __init__(
        self,
        replay_window_seconds: float = 300.0,
        max_replay_cache: int = 50_000,
    ):
        """
        Args:
            replay_window_seconds: Nonces older than this are expired
            max_replay_cache:      Maximum seen-nonces cache size
        """
        self._rules: Dict[str, GuardRule] = {}
        self._seen_nonces: Dict[str, float] = {}   # nonce -> first_seen_ts
        self.replay_window = replay_window_seconds
        self.max_replay_cache = max_replay_cache
        self._total_events = 0
        self._total_adversarial = 0

    # ─── Rule management ─────────────────────────────────────────────────────

    def add_rule(
        self,
        name: str,
        predicate: Callable[[dict], bool],
        description: str = "",
        severity: str = "medium",
        action: str = "flag",
        cooldown_seconds: float = 0.0,
    ):
        """Register a named detection rule."""
        self._rules[name] = GuardRule(
            name=name,
            predicate=predicate,
            description=description,
            severity=severity,
            action=action,
            cooldown_seconds=cooldown_seconds,
        )

    def remove_rule(self, name: str):
        self._rules.pop(name, None)

    def list_rules(self) -> List[dict]:
        return [
            {
                "name": r.name,
                "description": r.description,
                "severity": r.severity,
                "action": r.action,
                "hit_count": r._hit_count,
            }
            for r in self._rules.values()
        ]

    # ─── Evaluation ──────────────────────────────────────────────────────────

    def evaluate(self, event: dict, sanitize: bool = True) -> GuardResult:
        """
        Evaluate an event for adversarial characteristics.

        Args:
            event:    The event dict to evaluate
            sanitize: If True, return a sanitized copy of the event

        Returns:
            GuardResult with matched rules and recommended action
        """
        self._total_events += 1
        matched: List[GuardRule] = []

        # Layer 1: rule-based detection
        for rule in self._rules.values():
            if rule.on_cooldown():
                continue
            try:
                if rule.predicate(event):
                    matched.append(rule)
                    rule.record_hit()
            except Exception:
                pass  # Broken rules don't crash the guard

        # Layer 2: replay attack detection
        nonce = self._extract_nonce(event)
        if nonce and self._is_replay(nonce):
            replay_rule = GuardRule(
                name="_replay_detection",
                predicate=lambda _: True,
                description="Replay attack: nonce already seen",
                severity="high",
                action="drop",
            )
            matched.append(replay_rule)

        # Layer 3: injection detection in string fields
        injection_found = self._check_injection(event)
        if injection_found:
            injection_rule = GuardRule(
                name="_injection_detection",
                predicate=lambda _: True,
                description=f"Injection pattern detected: {injection_found!r}",
                severity="critical",
                action="drop",
            )
            matched.append(injection_rule)

        is_adversarial = len(matched) > 0
        if is_adversarial:
            self._total_adversarial += 1

        # Escalate to most severe action
        action_priority = {"flag": 0, "drop": 1, "halt": 2}
        recommended = max(
            (r.action for r in matched),
            key=lambda a: action_priority.get(a, 0),
            default="flag",
        ) if matched else "accept"

        sanitized = self._sanitize(event) if sanitize and is_adversarial else None

        return GuardResult(
            event=event,
            is_adversarial=is_adversarial,
            matched_rules=matched,
            recommended_action=recommended,
            sanitized_event=sanitized,
        )

    # ─── Stats ───────────────────────────────────────────────────────────────

    def stats(self) -> dict:
        return {
            "total_events": self._total_events,
            "total_adversarial": self._total_adversarial,
            "adversarial_rate": round(
                self._total_adversarial / self._total_events, 4
            ) if self._total_events else 0.0,
            "active_rules": len(self._rules),
            "replay_cache_size": len(self._seen_nonces),
        }

    # ─── Internals ───────────────────────────────────────────────────────────

    def _extract_nonce(self, event: dict) -> Optional[str]:
        nonce = event.get("nonce") or event.get("event_id") or event.get("id")
        return str(nonce) if nonce is not None else None

    def _is_replay(self, nonce: str) -> bool:
        now = time.time()
        self._expire_nonces(now)

        if nonce in self._seen_nonces:
            return True

        # Bound cache size
        if len(self._seen_nonces) >= self.max_replay_cache:
            # Evict oldest half
            sorted_nonces = sorted(self._seen_nonces.items(), key=lambda x: x[1])
            self._seen_nonces = dict(sorted_nonces[len(sorted_nonces)//2:])

        self._seen_nonces[nonce] = now
        return False

    def _expire_nonces(self, now: float):
        cutoff = now - self.replay_window
        self._seen_nonces = {
            n: ts for n, ts in self._seen_nonces.items() if ts >= cutoff
        }

    def _check_injection(self, event: dict) -> Optional[str]:
        for field_name in self._SANITIZE_FIELDS:
            value = event.get(field_name, "")
            if not isinstance(value, str):
                continue
            lower = value.lower()
            for pattern in self._INJECTION_PATTERNS:
                if pattern.lower() in lower:
                    return pattern
        return None

    def _sanitize(self, event: dict) -> dict:
        """Return a copy of event with dangerous content stripped."""
        sanitized = dict(event)
        for field_name in self._SANITIZE_FIELDS:
            if field_name in sanitized and isinstance(sanitized[field_name], str):
                val = sanitized[field_name]
                for pattern in self._INJECTION_PATTERNS:
                    val = val.replace(pattern, "[REDACTED]")
                sanitized[field_name] = val
        return sanitized


# ─── Built-in rules ───────────────────────────────────────────────────────────

def rule_rapid_privilege_escalation(
    event: dict,
    threshold: int = 5,
) -> Callable[[dict], bool]:
    """
    Factory: flag if privilege_escalation_count exceeds threshold.
    """
    def predicate(e: dict) -> bool:
        return e.get("privilege_escalation_count", 0) > threshold
    predicate.__name__ = f"rapid_priv_escalation_>{threshold}"
    return predicate


def rule_impossible_geo(event: dict) -> bool:
    """Flag events where geo_distance_km indicates impossible travel speed."""
    speed = event.get("travel_speed_kmh", 0)
    return speed > 900   # faster than commercial aircraft = suspicious


def rule_service_account_interactive(event: dict) -> bool:
    """Flag service accounts performing interactive human-like logins."""
    return (
        event.get("account_type") == "service"
        and event.get("login_type") == "interactive"
    )