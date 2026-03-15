"""
phase2/governance.py — Automation Governor

Stateless governor: all state from event log via projections.
Downgrade: precision < 0.80 for 5 consecutive verifications.
Upgrade:   precision > 0.90 for 20 consecutive verifications.
Hysteresis: asymmetric (5 down, 20 up).
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from events import AutomationStateChanged, _stable_id
from Event_log import Phase2EventLog
from Projections import (
    AutomationProjection, PrecisionProjection,
    DOWNGRADE_PRECISION_THRESHOLD, DOWNGRADE_CONSECUTIVE_REQUIRED,
    UPGRADE_PRECISION_THRESHOLD, UPGRADE_CONSECUTIVE_REQUIRED,
    DEFAULT_AUTOMATION_STATE,
)

_STATE_ORDER = ["observe", "staged_contain", "isolate"]


def _state_index(state: str) -> int:
    try:
        return _STATE_ORDER.index(state)
    except ValueError:
        return 0


def _state_down(state: str) -> str:
    return _STATE_ORDER[max(0, _state_index(state) - 1)]


def _state_up(state: str) -> str:
    return _STATE_ORDER[min(len(_STATE_ORDER) - 1, _state_index(state) + 1)]


class AutomationGovernor:

    def __init__(self, log: Phase2EventLog, auto_proj: AutomationProjection,
                 precision_proj: PrecisionProjection):
        self._log            = log
        self._auto_proj      = auto_proj
        self._precision_proj = precision_proj

    def evaluate_scope(self, signal: str, tier: int, action: str,
                        timestamp: datetime, event_index: int) -> Optional[AutomationStateChanged]:
        current_state = self._auto_proj.get_state(signal, tier, action, timestamp)

        downgrade = self._check_downgrade(signal, tier, action, current_state, timestamp, event_index)
        if downgrade is not None:
            return downgrade

        if _state_index(current_state) < len(_STATE_ORDER) - 1:
            upgrade = self._check_upgrade(signal, tier, action, current_state, timestamp, event_index)
            if upgrade is not None:
                return upgrade

        return None

    def current_state(self, signal: str, tier: int, action: str,
                       timestamp: Optional[datetime] = None) -> str:
        return self._auto_proj.get_state(signal, tier, action, timestamp)

    def evaluate_all(self, timestamp: datetime, event_index: int) -> list[AutomationStateChanged]:
        known_scopes: set[tuple] = set()
        for event in self._log.replay_type(AutomationStateChanged, end_timestamp=timestamp):
            known_scopes.add((event.scope_signal, event.scope_tier, event.scope_action))
        known_scopes.add(("composite", 0, "isolate"))
        known_scopes.add(("composite", 0, "staged_contain"))

        results = []
        for signal, tier, action in sorted(known_scopes):
            ev = self.evaluate_scope(signal, tier, action, timestamp, event_index)
            if ev is not None:
                results.append(ev)
                event_index += 1
        return results

    def _check_downgrade(self, signal, tier, action, current_state, timestamp, event_index):
        if current_state == "observe":
            return None

        consecutive = self._precision_proj.consecutive_below(
            signal=signal, tier=tier, action=action,
            threshold=DOWNGRADE_PRECISION_THRESHOLD,
            n=DOWNGRADE_CONSECUTIVE_REQUIRED,
            end_timestamp=timestamp,
        )
        if consecutive < DOWNGRADE_CONSECUTIVE_REQUIRED:
            return None

        new_state = _state_down(current_state)
        if new_state == current_state:
            return None

        recent = self._precision_proj.get_recent_precisions(
            signal, tier, action, DOWNGRADE_CONSECUTIVE_REQUIRED, timestamp
        )
        reason = (
            f"precision below {DOWNGRADE_PRECISION_THRESHOLD} for "
            f"{consecutive} consecutive verifications"
        )
        return self._build(signal, tier, action, current_state, new_state,
                           "downgrade", reason, consecutive, tuple(recent), timestamp, event_index)

    def _check_upgrade(self, signal, tier, action, current_state, timestamp, event_index):
        consecutive = self._precision_proj.consecutive_above(
            signal=signal, tier=tier, action=action,
            threshold=UPGRADE_PRECISION_THRESHOLD,
            n=UPGRADE_CONSECUTIVE_REQUIRED,
            end_timestamp=timestamp,
        )
        if consecutive < UPGRADE_CONSECUTIVE_REQUIRED:
            return None

        new_state = _state_up(current_state)
        if new_state == current_state:
            return None

        recent = self._precision_proj.get_recent_precisions(
            signal, tier, action, UPGRADE_CONSECUTIVE_REQUIRED, timestamp
        )
        reason = (
            f"precision above {UPGRADE_PRECISION_THRESHOLD} for "
            f"{consecutive} consecutive verifications"
        )
        return self._build(signal, tier, action, current_state, new_state,
                           "upgrade", reason, consecutive,
                           tuple(recent[-DOWNGRADE_CONSECUTIVE_REQUIRED:]), timestamp, event_index)

    def _build(self, signal, tier, action, previous_state, new_state,
               direction, trigger_reason, consecutive_count, precision_history,
               timestamp, event_index) -> AutomationStateChanged:
        event_id = _stable_id(
            "AutomationStateChanged", signal, str(tier), action,
            new_state, timestamp.isoformat(),
        )
        return AutomationStateChanged(
            event_id=event_id,
            event_index=event_index,
            timestamp=timestamp,
            scope_signal=signal,
            scope_tier=tier,
            scope_action=action,
            previous_state=previous_state,
            new_state=new_state,
            direction=direction,
            trigger_reason=trigger_reason,
            consecutive_count=consecutive_count,
            precision_history=precision_history,
        )