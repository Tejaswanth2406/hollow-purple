"""
Shadow Rebuild

Deterministic state reconstruction from a verified event log.

In forensic investigations, the ability to replay the exact sequence of
events and reproduce the system state at any point in time is essential.
This module provides that capability.

Enterprise additions over the spec:
  - Checkpointing: resume replay from a snapshot rather than event 0
  - Event filtering: replay only events matching a predicate
  - Divergence detection: compare shadow state vs live state
  - Replay audit trail: track which events were replayed and in what order
  - Rollback support: reverse-apply events to reconstruct prior states
    (requires state machine to implement reverse_event)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Protocol, Tuple


class StateMachine(Protocol):
    """
    Interface expected by ShadowRebuild.

    The concrete state machine must implement apply_event(state, event) -> state.
    Optionally implement reverse_event(state, event) -> state for rollback.
    """

    def apply_event(self, state: Any, event: Any) -> Any:
        ...


@dataclass
class ReplayResult:
    final_state: Any
    events_applied: int
    events_skipped: int
    duration_seconds: float
    diverged: bool = False
    divergence_detail: Optional[str] = None
    audit_trail: List[dict] = field(default_factory=list)


class ShadowRebuild:
    """
    Reconstructs system state deterministically from an event log.

    Supports:
      - Full replay from genesis
      - Checkpointed replay (start from a known-good snapshot)
      - Filtered replay (only events matching a predicate)
      - Divergence detection against live state
      - Partial replay up to a target index or timestamp
    """

    def __init__(
        self,
        state_machine: StateMachine,
        record_audit: bool = False,
    ):
        """
        Args:
            state_machine:  Implements apply_event(state, event) -> state
            record_audit:   If True, record per-event audit entries
                            (expensive for large replays; use for forensics)
        """
        self.state_machine = state_machine
        self.record_audit = record_audit

    # ─── Core rebuild ────────────────────────────────────────────────────────

    def rebuild(
        self,
        events: List[Any],
        initial_state: Optional[Any] = None,
        event_filter: Optional[Callable[[Any], bool]] = None,
        stop_at_index: Optional[int] = None,
        stop_at_timestamp: Optional[float] = None,
    ) -> ReplayResult:
        """
        Replay events deterministically to reconstruct state.

        Args:
            events:             Ordered list of events to replay
            initial_state:      Starting state (default: {})
            event_filter:       Optional predicate; events returning False are skipped
            stop_at_index:      Stop after replaying this many events (0-based)
            stop_at_timestamp:  Stop at first event whose timestamp > this value
                                (events must have a 'timestamp' field)

        Returns:
            ReplayResult with final state, counts, duration, and audit trail
        """
        state = initial_state if initial_state is not None else {}
        applied = 0
        skipped = 0
        audit: List[dict] = []
        t0 = time.monotonic()

        for i, event in enumerate(events):
            # Stop conditions
            if stop_at_index is not None and applied >= stop_at_index:
                break
            if stop_at_timestamp is not None:
                ts = event.get("timestamp") if isinstance(event, dict) else None
                if ts is not None and ts > stop_at_timestamp:
                    break

            # Filter
            if event_filter is not None and not event_filter(event):
                skipped += 1
                continue

            try:
                state = self.state_machine.apply_event(state, event)
                applied += 1

                if self.record_audit:
                    audit.append({
                        "index": i,
                        "event": event,
                        "applied_at": time.time(),
                    })

            except Exception as exc:
                skipped += 1
                if self.record_audit:
                    audit.append({
                        "index": i,
                        "event": event,
                        "error": str(exc),
                    })

        return ReplayResult(
            final_state=state,
            events_applied=applied,
            events_skipped=skipped,
            duration_seconds=round(time.monotonic() - t0, 6),
            audit_trail=audit,
        )

    def rebuild_from_checkpoint(
        self,
        checkpoint_state: Any,
        events_after_checkpoint: List[Any],
        **kwargs,
    ) -> ReplayResult:
        """
        Resume replay from a saved checkpoint snapshot rather than genesis.

        This is the primary performance optimization for large event logs —
        instead of replaying from event 0, load the nearest snapshot and
        replay only the delta.
        """
        return self.rebuild(
            events=events_after_checkpoint,
            initial_state=checkpoint_state,
            **kwargs,
        )

    # ─── Divergence detection ────────────────────────────────────────────────

    def detect_divergence(
        self,
        events: List[Any],
        live_state: Any,
        comparator: Optional[Callable[[Any, Any], bool]] = None,
        initial_state: Optional[Any] = None,
    ) -> ReplayResult:
        """
        Replay events and compare the resulting state against live state.

        Divergence indicates either:
          - The event log is incomplete / tampered
          - The live system applied out-of-order or unauthorized state changes

        Args:
            events:      Events to replay
            live_state:  The state the live system claims to be in
            comparator:  Custom equality function (default: ==)
            initial_state: Starting state for replay

        Returns:
            ReplayResult with diverged=True if mismatch detected
        """
        result = self.rebuild(events, initial_state=initial_state)
        eq = comparator or (lambda a, b: a == b)

        if not eq(result.final_state, live_state):
            result.diverged = True
            result.divergence_detail = (
                f"Replayed state does not match live state. "
                f"Replayed={result.final_state!r}, Live={live_state!r}"
            )

        return result

    # ─── Rollback ────────────────────────────────────────────────────────────

    def rollback(
        self,
        state: Any,
        events_to_reverse: List[Any],
    ) -> Tuple[Any, int]:
        """
        Reverse-apply a sequence of events to roll back state.

        Requires the state machine to implement reverse_event(state, event) -> state.

        Returns:
            (rolled_back_state, events_reversed_count)
        """
        if not hasattr(self.state_machine, "reverse_event"):
            raise NotImplementedError(
                "Rollback requires state_machine.reverse_event(state, event) -> state"
            )

        reversed_count = 0
        for event in reversed(events_to_reverse):
            state = self.state_machine.reverse_event(state, event)
            reversed_count += 1

        return state, reversed_count