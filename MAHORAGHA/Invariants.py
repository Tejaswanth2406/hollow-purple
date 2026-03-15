"""
phase2/invariants.py — Global Invariant Enforcement Registry

All invariants enforced inside Phase2EventLog.append().
No event may be appended unless all relevant invariants pass.

Invariants:
  validate_event_base()                  — schema_version >= 1, non-empty event_id, tz-aware ts
  validate_case_references()             — CaseBuilt.escalation_event_id exists
  validate_case_integrity_hash()         — FIX 6: hash populated and verifiable
  validate_response_references()         — ResponseExecuted.case_id exists
  validate_verification_references()     — PostActionVerified.response_event_id exists, ts ordered
  validate_threshold_bounds()            — ThresholdAdjusted.new_value within [lower, upper]
  validate_drift_threshold_consistency() — DriftCrossingRecorded.threshold_used matches projection
  validate_acceleration_bounds()         — FIX 7: acceleration <= MAX_ACCEL, bounded flag correct
  validate_feedback_case_exists()        — FeedbackSubmitted.case_id exists
  validate_cooldown()                    — ITEM 7: per-identity 600s cooldown
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from Event_log import Phase2EventLog
    from events import Phase2Event


# ── Exception ─────────────────────────────────────────────────────────────────

class InvariantViolation(ValueError):
    def __init__(self, invariant: str, detail: str):
        self.invariant = invariant
        self.detail    = detail
        super().__init__(f"INVARIANT VIOLATION [{invariant}]: {detail}")


# ── Constants ─────────────────────────────────────────────────────────────────

PENDING_TTL      = timedelta(minutes=30)
COOLDOWN_SECONDS = 600
DRIFT_TOL        = 1e-6
MAX_ACCEL        = 10.0


# ── Base ──────────────────────────────────────────────────────────────────────

def validate_event_base(event: "Phase2Event", log: "Phase2EventLog") -> None:
    if not getattr(event, "event_id", ""):
        raise InvariantViolation("event_base", "event_id is empty")

    sv = getattr(event, "schema_version", None)
    if sv is None:
        raise InvariantViolation(
            "schema_version",
            f"{type(event).__name__} missing schema_version field"
        )
    if sv < 1:
        raise InvariantViolation(
            "schema_version",
            f"schema_version={sv} must be >= 1"
        )

    ts = getattr(event, "timestamp", None)
    if ts is None:
        raise InvariantViolation("event_base", "timestamp is None")
    if ts.tzinfo is None:
        raise InvariantViolation("event_base", "timestamp must be timezone-aware")


# ── CaseBuilt references ──────────────────────────────────────────────────────

def validate_case_references(event: "Phase2Event", log: "Phase2EventLog") -> None:
    from events import CaseBuilt, EscalationDetected

    if not isinstance(event, CaseBuilt):
        return

    esc_id = event.escalation_event_id
    found = log.contains_event_id(esc_id)
    if not found:
        raise InvariantViolation(
            "case_references",
            f"CaseBuilt.escalation_event_id={esc_id!r} not found in log"
        )


def validate_case_integrity_hash(event: "Phase2Event", log: "Phase2EventLog") -> None:
    from events import CaseBuilt
    from utils import case_integrity_hash

    if not isinstance(event, CaseBuilt):
        return

    if not event.case_integrity_hash:
        raise InvariantViolation(
            "case_integrity_hash",
            f"CaseBuilt.case_integrity_hash is empty for case_id={event.case_id!r}."
        )

    recomputed = case_integrity_hash(
        top_signals=event.top_signals,
        provenance_edges=event.provenance_edges,
        cascade_path=event.cascade_path,
        temporal_window=event.temporal_window,
        risk_score=event.risk_score,
    )
    if recomputed != event.case_integrity_hash:
        raise InvariantViolation(
            "case_integrity_hash",
            f"CaseBuilt.case_integrity_hash mismatch for case_id={event.case_id!r}. "
            f"Stored={event.case_integrity_hash!r}, recomputed={recomputed!r}."
        )


# ── ResponseExecuted references ───────────────────────────────────────────────

def validate_response_references(event: "Phase2Event", log: "Phase2EventLog") -> None:
    from events import ResponseExecuted, CaseBuilt

    if not isinstance(event, ResponseExecuted):
        return

    found = any(
        e.case_id == event.case_id
        for e in log.replay_type(CaseBuilt)
    )
    if not found:
        raise InvariantViolation(
            "response_references",
            f"ResponseExecuted.case_id={event.case_id!r} not found in CaseBuilt events"
        )


# ── PostActionVerified references ─────────────────────────────────────────────

def validate_verification_references(event: "Phase2Event", log: "Phase2EventLog") -> None:
    from events import PostActionVerified, ResponseExecuted

    if not isinstance(event, PostActionVerified):
        return

    resp = None
    for e in log.replay_type(ResponseExecuted):
        if e.event_id == event.response_event_id:
            resp = e
            break

    if resp is None:
        raise InvariantViolation(
            "verification_references",
            f"PostActionVerified.response_event_id={event.response_event_id!r} not found"
        )
    if resp.case_id != event.case_id:
        raise InvariantViolation(
            "verification_references",
            f"case_id mismatch: PostActionVerified.case_id={event.case_id!r} "
            f"but ResponseExecuted.case_id={resp.case_id!r}"
        )
    if event.timestamp < resp.timestamp:
        raise InvariantViolation(
            "verification_references",
            f"PostActionVerified.timestamp={event.timestamp} is before "
            f"ResponseExecuted.timestamp={resp.timestamp}"
        )


# ── ThresholdAdjusted bounds ──────────────────────────────────────────────────

def validate_threshold_bounds(event: "Phase2Event", log: "Phase2EventLog") -> None:
    from events import ThresholdAdjusted
    from Projections import DEFAULT_THRESHOLDS, THRESHOLD_LOWER_FACTOR, THRESHOLD_UPPER_FACTOR

    if not isinstance(event, ThresholdAdjusted):
        return

    sig  = event.signal_type
    tier = str(event.tier)
    default_val = DEFAULT_THRESHOLDS.get(sig, {}).get(tier, 0.5)
    lower = default_val * THRESHOLD_LOWER_FACTOR
    upper = default_val * THRESHOLD_UPPER_FACTOR

    if not (lower - DRIFT_TOL <= event.new_value <= upper + DRIFT_TOL):
        raise InvariantViolation(
            "threshold_bounds",
            f"ThresholdAdjusted.new_value={event.new_value:.6f} for signal={sig!r} "
            f"tier={event.tier} is outside bounds [{lower:.6f}, {upper:.6f}]"
        )

    if abs(event.new_value - event.previous_value) < 1e-10:
        raise InvariantViolation(
            "threshold_bounds",
            "ThresholdAdjusted.delta is effectively zero — no-op events not permitted"
        )


# ── DriftCrossingRecorded consistency ─────────────────────────────────────────

def validate_drift_threshold_consistency(event: "Phase2Event", log: "Phase2EventLog") -> None:
    from events import DriftCrossingRecorded
    from Projections import ThresholdProjection

    if not isinstance(event, DriftCrossingRecorded):
        return

    proj = ThresholdProjection(log)
    tier_int = getattr(event, "tier", 0)
    expected = proj.get_threshold("drift", tier_int, event.timestamp)
    actual   = event.threshold_used

    if abs(actual - expected) > DRIFT_TOL:
        raise InvariantViolation(
            "drift_threshold_consistency",
            f"DriftCrossingRecorded.threshold_used={actual:.8f} but "
            f"ThresholdProjection says {expected:.8f} at {event.timestamp} "
            f"(diff={abs(actual-expected):.2e} > tol={DRIFT_TOL})"
        )


# ── DriftCrossingRecorded acceleration bounds ─────────────────────────────────

def validate_acceleration_bounds(event: "Phase2Event", log: "Phase2EventLog") -> None:
    from events import DriftCrossingRecorded

    if not isinstance(event, DriftCrossingRecorded):
        return

    BOUND_TOL = 1e-6
    accel = event.acceleration

    if abs(accel) > MAX_ACCEL + BOUND_TOL:
        raise InvariantViolation(
            "acceleration_bounds",
            f"DriftCrossingRecorded.acceleration={accel:.6f} exceeds MAX_ACCEL={MAX_ACCEL}."
        )

    if event.acceleration_bounded:
        if abs(abs(accel) - MAX_ACCEL) > BOUND_TOL:
            raise InvariantViolation(
                "acceleration_bounds",
                f"acceleration_bounded=True but abs(acceleration)={abs(accel):.6f} "
                f"!= MAX_ACCEL={MAX_ACCEL}."
            )


# ── FeedbackSubmitted case exists ─────────────────────────────────────────────

def validate_feedback_case_exists(event: "Phase2Event", log: "Phase2EventLog") -> None:
    from events import FeedbackSubmitted, CaseBuilt

    if not isinstance(event, FeedbackSubmitted):
        return

    found = any(
        e.case_id == event.case_id
        for e in log.replay_type(CaseBuilt)
    )
    if not found:
        raise InvariantViolation(
            "feedback_case_exists",
            f"FeedbackSubmitted.case_id={event.case_id!r} not found in CaseBuilt events"
        )


# ── Cooldown ──────────────────────────────────────────────────────────────────

def validate_cooldown(event: "Phase2Event", log: "Phase2EventLog",
                       cooldown_seconds: int = COOLDOWN_SECONDS) -> None:
    from events import ResponseExecuted

    if not isinstance(event, ResponseExecuted):
        return
    if event.action_type == "observe":
        return

    cutoff = event.timestamp - timedelta(seconds=cooldown_seconds)
    for e in log.replay_type(ResponseExecuted):
        if (e.identity == event.identity
                and e.action_type != "observe"
                and e.timestamp > cutoff
                and e.event_id != event.event_id):
            raise InvariantViolation(
                "cooldown",
                f"Identity {event.identity!r} has a {e.action_type!r} action at "
                f"{e.timestamp} — cooldown of {cooldown_seconds}s not yet expired "
                f"(current: {event.timestamp})"
            )


# ── Registry ──────────────────────────────────────────────────────────────────

VALIDATORS = [
    validate_event_base,
    validate_case_references,
    validate_case_integrity_hash,
    validate_response_references,
    validate_verification_references,
    validate_threshold_bounds,
    validate_drift_threshold_consistency,
    validate_acceleration_bounds,
    validate_feedback_case_exists,
    validate_cooldown,
]


def run_all_invariants(
    event: "Phase2Event",
    log:   "Phase2EventLog",
    skip:  Optional[set] = None,
) -> None:
    for validator in VALIDATORS:
        if skip and validator.__name__ in skip:
            continue
        validator(event, log)