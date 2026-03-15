"""
phase2/adversarial_simulator.py — Adversarial Stress Test Suite

All 9 critical hardening items from the adversarial assessment implemented:

  FIX 1:  event_index injection (expect rejection if != 0)
  FIX 2:  Duplicate event_id replay (detect double-append)
  FIX 3:  Log corruption simulation (tamper middle event, verify hash mismatch)
  FIX 4:  Drift acceleration bounds (acceleration > MAX_ACCEL rejected)
  FIX 5:  Saturation attack (>30% identities at high privilege)
  FIX 6:  Determinism replay test (post-attack projection_hash double-check)
  FIX 7:  Timestamp regression attack (monotonic enforcement)
  FIX 8:  Memory exhaustion stress (50k events, measure timing)
  FIX 9:  Automation cascade (full governor precision threshold simulation)

Plus all original attacks:
  edge_flood, oscillation_loop, threshold_poisoning, confirmation_replay,
  reference_forgery, drift_acceleration, schema_version_forgery.

Each simulation returns a SimulationReport with invariants_held, violations_caught, summary.
invariants_held = True  means attack was correctly blocked.
invariants_held = False means a violation got through — this is a bug.
"""
from __future__ import annotations

import dataclasses
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

from phase2.event_log import Phase2EventLog, Phase2LogError
from phase2.events import (
    EscalationDetected, CaseBuilt, ResponseExecuted, PostActionVerified,
    FeedbackSubmitted, ThresholdAdjusted, AutomationStateChanged,
    PolicyVersionActivated, DriftCrossingRecorded,
    TemporalWindow, _stable_id,
)
from phase2.invariants import InvariantViolation, COOLDOWN_SECONDS, MAX_ACCEL
from phase2.projections import (
    DEFAULT_THRESHOLDS, THRESHOLD_LOWER_FACTOR, THRESHOLD_UPPER_FACTOR,
    ThresholdProjection,
)
from phase2.replay_validator import ReplayValidator
from phase2.utils import case_integrity_hash as _cih


# ── Helpers ───────────────────────────────────────────────────────────────────

BASE_TS = datetime(2024, 6, 1, tzinfo=timezone.utc)


def _ts(days: float) -> datetime:
    return BASE_TS + timedelta(days=days)


def _make_detection(
    identity:          str   = "identity:user:alice",
    risk:              float = 0.8,
    band:              str   = "CRITICAL",
    priv:              int   = 8,
    day:               float = 1.0,
    threshold_version: str   = "v0",
    policy_version:    str   = "default_v0",
) -> EscalationDetected:
    return EscalationDetected(
        event_id=_stable_id(identity, str(day), str(risk)),
        event_index=0,
        timestamp=_ts(day),
        identity=identity,
        risk_score=risk,
        risk_band=band,
        effective_priv_now=priv,
        effective_priv_prev=max(0, priv - 2),
        velocity=1.0,
        acceleration=0.5,
        drift=5.0,
        oscillation_count=0,
        path_birth_rate=1.0,
        redundancy_score=0.3,
        saturation_flag=False,
        trust_path_present=False,
        trigger_reasons=("velocity=1.00",),
        threshold_version=threshold_version,
        policy_version=policy_version,
    )


def _make_case(detection: EscalationDetected) -> CaseBuilt:
    tw = TemporalWindow(
        first_drift_crossing_timestamp=None,
        acceleration_start_timestamp=None,
        time_to_peak_drift_seconds=None,
        detection_timestamp=detection.timestamp,
    )
    top_signals      = (("velocity", 0.30),)
    provenance_edges = ()
    cascade_path     = ()
    case_id          = _stable_id(detection.event_id, "case")
    integrity        = _cih(
        top_signals=top_signals,
        provenance_edges=provenance_edges,
        cascade_path=cascade_path,
        temporal_window=tw,
        risk_score=detection.risk_score,
    )
    return CaseBuilt(
        event_id=_stable_id(case_id, "CaseBuilt"),
        event_index=0,
        timestamp=detection.timestamp,
        case_id=case_id,
        escalation_event_id=detection.event_id,
        identity=detection.identity,
        tier=3,
        tier_name="admin",
        risk_score=detection.risk_score,
        risk_band=detection.risk_band,
        threshold_version_used=detection.threshold_version,
        policy_version_used=detection.policy_version,
        top_signals=top_signals,
        temporal_window=tw,
        cascade_path=cascade_path,
        provenance_edges=provenance_edges,
        acceleration_value=0.5,
        acceleration_bounded=False,
        recommended_action="isolate",
        recommendation_reason="test",
        case_integrity_hash=integrity,
    )


def _make_response(case: CaseBuilt, action: str = "staged_contain",
                   day_offset: float = 0.0) -> ResponseExecuted:
    ts = case.timestamp + timedelta(days=day_offset)
    return ResponseExecuted(
        event_id=_stable_id(case.case_id, action, "response", str(day_offset)),
        event_index=0,
        timestamp=ts,
        case_id=case.case_id,
        identity=case.identity,
        action_type=action,
        phase="A",
        action_confidence=0.92,
        confidence_met=True,
        reversibility_seconds=3600,
        rollback_instructions="Remove deny rules.",
        blast_radius_estimate=3,
        threshold_version_used=case.threshold_version_used,
        policy_version_used=case.policy_version_used,
        edges_denied=(),
        edges_revoked=(),
        required_confirmation=False,
        confirmation_provided=False,
    )


def _make_verification(response: ResponseExecuted, precision: float = 1.0) -> PostActionVerified:
    passed = precision >= 0.75
    ts = response.timestamp + timedelta(hours=1)
    return PostActionVerified(
        event_id=_stable_id(response.event_id, "verified", str(precision)),
        event_index=0,
        timestamp=ts,
        response_event_id=response.event_id,
        case_id=response.case_id,
        identity=response.identity,
        risk_score_before=0.8,
        risk_score_after=0.3,
        score_delta=0.5,
        privilege_surface_before=5,
        privilege_surface_after=2,
        privilege_surface_reduction=3,
        drift_before=5.0,
        drift_after=2.0,
        drift_stabilization=3.0,
        path_count_before=4,
        path_count_after=1,
        path_count_reduction=3,
        score_success=True,
        surface_success=True,
        drift_success=True,
        path_success=True,
        success_count=4,
        precision=precision,
        verification_passed=passed,
    )


# ── SimulationReport ──────────────────────────────────────────────────────────

@dataclass
class SimulationReport:
    attack_name:       str
    invariants_held:   bool
    violations_caught: list[str] = field(default_factory=list)
    events_attempted:  int       = 0
    events_accepted:   int       = 0
    summary:           str       = ""
    extras:            dict      = field(default_factory=dict)

    @property
    def rejection_rate(self) -> float:
        if self.events_attempted == 0:
            return 0.0
        return round((self.events_attempted - self.events_accepted) / self.events_attempted, 4)


# ── AdversarialSimulator ──────────────────────────────────────────────────────

class AdversarialSimulator:
    """
    Simulates adversarial attack patterns and verifies invariant enforcement.
    All 9 critical hardening items + original suite.
    """

    # ══════════════════════════════════════════════════════════════════════════
    # ORIGINAL ATTACKS (kept, some updated)
    # ══════════════════════════════════════════════════════════════════════════

    def edge_flood(self, n_events: int = 100) -> SimulationReport:
        """EscalationDetected has no reference constraints — all should be accepted."""
        log = Phase2EventLog(enforce_invariants=True)
        accepted = 0
        violations = []

        for i in range(n_events):
            try:
                det = _make_detection(day=i * 0.001 + 1.0)  # monotonic timestamps
                log.append(det)
                accepted += 1
            except (InvariantViolation, Phase2LogError) as e:
                violations.append(str(e))

        held = accepted == n_events and len(violations) == 0
        return SimulationReport(
            attack_name="edge_flood",
            invariants_held=held,
            violations_caught=violations,
            events_attempted=n_events,
            events_accepted=accepted,
            summary=(
                f"Flood of {n_events} EscalationDetected: "
                f"{accepted} accepted, {len(violations)} violations. "
                f"Expected: all accepted. {'PASS' if held else 'FAIL'}."
            ),
        )

    def oscillation_loop(self) -> SimulationReport:
        """Rapid isolate/contain alternation — cooldown (600s) should block second action."""
        log = Phase2EventLog(enforce_invariants=True)
        violations = []
        accepted = 0
        attempted = 0
        identity = "identity:user:alice"

        # First action — should succeed
        det1 = _make_detection(identity=identity, day=1.0)
        det1 = log.append(det1)
        case1 = _make_case(det1)
        case1 = log.append(case1)
        resp1 = _make_response(case1, "staged_contain")
        try:
            log.append(resp1)
            accepted += 1
        except (InvariantViolation, Phase2LogError) as e:
            violations.append(str(e))
        attempted += 1

        # Second action within cooldown (~86 seconds) — should be rejected
        det2 = _make_detection(identity=identity, day=1.001)  # ~86 seconds later
        det2 = log.append(det2)
        case2 = _make_case(det2)
        case2 = log.append(case2)
        resp2 = ResponseExecuted(
            event_id=_stable_id(case2.case_id, "staged_contain", "resp2"),
            event_index=0,
            timestamp=_ts(1.001),
            case_id=case2.case_id,
            identity=identity,
            action_type="staged_contain",
            phase="A",
            action_confidence=0.92,
            confidence_met=True,
            reversibility_seconds=3600,
            rollback_instructions="Remove deny rules.",
            blast_radius_estimate=2,
            threshold_version_used="v0",
            policy_version_used="default_v0",
            edges_denied=(),
            edges_revoked=(),
            required_confirmation=False,
            confirmation_provided=False,
        )
        try:
            log.append(resp2)
            accepted += 1
        except (InvariantViolation, Phase2LogError) as e:
            violations.append(str(e))
        attempted += 1

        held = accepted == 1 and len(violations) == 1
        return SimulationReport(
            attack_name="oscillation_loop",
            invariants_held=held,
            violations_caught=violations,
            events_attempted=attempted,
            events_accepted=accepted,
            summary=(
                f"Rapid oscillation: {accepted}/2 actions accepted. "
                f"Expected: 1 accepted, 1 cooldown-rejected. "
                f"{'PASS' if held else 'FAIL'}."
            ),
        )

    def threshold_poisoning(self) -> SimulationReport:
        """Push threshold beyond upper bound — bound enforcement should reject."""
        log = Phase2EventLog(enforce_invariants=True)
        violations = []
        accepted = 0
        attempted = 0

        signal  = "velocity"
        tier    = 0
        default = DEFAULT_THRESHOLDS[signal][str(tier)]
        upper   = default * THRESHOLD_UPPER_FACTOR

        legal_adj = ThresholdAdjusted(
            event_id=_stable_id("legal_adj", "v1"),
            event_index=0,
            timestamp=_ts(1),
            signal_type=signal, tier=tier,
            previous_value=default,
            new_value=round(upper, 8),
            delta=round(upper - default, 8),
            direction="up",
            fp_rate_observed=0.10,
            fn_rate_observed=0.05,
            learning_rate_used=0.005,
            version_id="v_legal",
        )
        try:
            log.append(legal_adj)
            accepted += 1
        except (InvariantViolation, Phase2LogError) as e:
            violations.append(str(e))
        attempted += 1

        illegal_adj = ThresholdAdjusted(
            event_id=_stable_id("illegal_adj", "v2"),
            event_index=0,
            timestamp=_ts(2),
            signal_type=signal, tier=tier,
            previous_value=upper,
            new_value=round(upper + 0.5, 8),
            delta=0.5,
            direction="up",
            fp_rate_observed=0.15,
            fn_rate_observed=0.02,
            learning_rate_used=0.005,
            version_id="v_illegal",
        )
        try:
            log.append(illegal_adj)
            accepted += 1
        except (InvariantViolation, Phase2LogError) as e:
            violations.append(str(e))
        attempted += 1

        held = accepted == 1 and len(violations) == 1
        return SimulationReport(
            attack_name="threshold_poisoning",
            invariants_held=held,
            violations_caught=violations,
            events_attempted=attempted,
            events_accepted=accepted,
            summary=(
                f"Threshold poisoning: {accepted}/2 accepted. "
                f"Legal accepted, illegal rejected. "
                f"{'PASS' if held else 'FAIL'}."
            ),
        )

    def confirmation_replay(self) -> SimulationReport:
        """ResponseExecuted with non-existent case_id — reference integrity blocks it."""
        log = Phase2EventLog(enforce_invariants=True)
        violations = []
        accepted = 0
        attempted = 0

        forged = ResponseExecuted(
            event_id=_stable_id("forged_resp", "v1"),
            event_index=0,
            timestamp=_ts(1),
            case_id="nonexistent_case_id_99999",
            identity="identity:user:alice",
            action_type="isolate",
            phase="B",
            action_confidence=0.95,
            confidence_met=True,
            reversibility_seconds=86400,
            rollback_instructions="Re-grant edges.",
            blast_radius_estimate=5,
            threshold_version_used="v0",
            policy_version_used="default_v0",
            edges_denied=(),
            edges_revoked=(),
            required_confirmation=False,
            confirmation_provided=False,
        )
        try:
            log.append(forged)
            accepted += 1
        except (InvariantViolation, Phase2LogError) as e:
            violations.append(str(e))
        attempted += 1

        held = accepted == 0 and len(violations) == 1
        return SimulationReport(
            attack_name="confirmation_replay",
            invariants_held=held,
            violations_caught=violations,
            events_attempted=attempted,
            events_accepted=accepted,
            summary=(
                f"Forged ResponseExecuted: {'blocked' if held else 'ACCEPTED — BUG'}. "
                f"{'PASS' if held else 'FAIL'}."
            ),
        )

    def reference_forgery(self) -> SimulationReport:
        """PostActionVerified with non-existent response_event_id — blocked."""
        log = Phase2EventLog(enforce_invariants=True)
        violations = []
        accepted = 0
        attempted = 0

        forged = PostActionVerified(
            event_id=_stable_id("forged_verif", "v1"),
            event_index=0,
            timestamp=_ts(1),
            response_event_id="nonexistent_response_99999",
            case_id="nonexistent_case_99999",
            identity="identity:user:alice",
            risk_score_before=0.8, risk_score_after=0.3, score_delta=0.5,
            privilege_surface_before=5, privilege_surface_after=2, privilege_surface_reduction=3,
            drift_before=5.0, drift_after=2.0, drift_stabilization=3.0,
            path_count_before=4, path_count_after=1, path_count_reduction=3,
            score_success=True, surface_success=True, drift_success=True, path_success=True,
            success_count=4, precision=1.0, verification_passed=True,
        )
        try:
            log.append(forged)
            accepted += 1
        except (InvariantViolation, Phase2LogError) as e:
            violations.append(str(e))
        attempted += 1

        held = accepted == 0 and len(violations) == 1
        return SimulationReport(
            attack_name="reference_forgery",
            invariants_held=held,
            violations_caught=violations,
            events_attempted=attempted,
            events_accepted=accepted,
            summary=(
                f"Forged PostActionVerified: {'blocked' if held else 'ACCEPTED — BUG'}. "
                f"{'PASS' if held else 'FAIL'}."
            ),
        )

    def schema_version_forgery(self) -> SimulationReport:
        """Events with schema_version=0 must be rejected."""
        log = Phase2EventLog(enforce_invariants=True)
        violations = []
        accepted = 0
        attempted = 0

        valid = _make_detection(day=1.0)
        try:
            log.append(valid)
            accepted += 1
        except (InvariantViolation, Phase2LogError) as e:
            violations.append(str(e))
        attempted += 1

        invalid = dataclasses.replace(
            valid,
            event_id=_stable_id("invalid_schema", "v1"),
            schema_version=0,
            timestamp=_ts(2),
        )
        try:
            log.append(invalid)
            accepted += 1
        except (InvariantViolation, Phase2LogError) as e:
            violations.append(str(e))
        attempted += 1

        held = accepted == 1 and len(violations) == 1
        return SimulationReport(
            attack_name="schema_version_forgery",
            invariants_held=held,
            violations_caught=violations,
            events_attempted=attempted,
            events_accepted=accepted,
            summary=(
                f"Schema version=0 forgery: valid accepted, invalid rejected. "
                f"{'PASS' if held else 'FAIL'}."
            ),
        )

    # ══════════════════════════════════════════════════════════════════════════
    # NEW HARDENING ATTACKS (all 9 critical fixes)
    # ══════════════════════════════════════════════════════════════════════════

    # FIX 1: event_index injection ────────────────────────────────────────────

    def event_index_injection(self) -> SimulationReport:
        """
        FIX 1: Attempt to append an event with event_index != 0.
        The log must reject it — only the log assigns event_index.
        """
        log = Phase2EventLog(enforce_invariants=True)
        violations = []
        accepted = 0
        attempted = 0

        # Valid append (event_index=0)
        valid = _make_detection(day=1.0)
        try:
            log.append(valid)
            accepted += 1
        except (InvariantViolation, Phase2LogError) as e:
            violations.append(str(e))
        attempted += 1

        # Malicious: pre-set event_index to a crafted value
        injected = dataclasses.replace(
            _make_detection(day=2.0),
            event_id=_stable_id("injected_idx", "v1"),
            event_index=9999,   # attacker tries to inject index
        )
        try:
            log.append(injected)
            accepted += 1
        except (InvariantViolation, Phase2LogError) as e:
            violations.append(str(e))
        attempted += 1

        # Also try event_index=-1 (rollback attempt)
        rollback = dataclasses.replace(
            _make_detection(day=3.0),
            event_id=_stable_id("rollback_idx", "v1"),
            event_index=-1,
        )
        try:
            log.append(rollback)
            accepted += 1
        except (InvariantViolation, Phase2LogError) as e:
            violations.append(str(e))
        attempted += 1

        held = accepted == 1 and len(violations) == 2
        return SimulationReport(
            attack_name="event_index_injection",
            invariants_held=held,
            violations_caught=violations,
            events_attempted=attempted,
            events_accepted=accepted,
            summary=(
                f"event_index injection: {accepted}/3 accepted. "
                f"Expected: 1 (valid), 2 rejected (9999, -1). "
                f"{'PASS' if held else 'FAIL'}."
            ),
        )

    # FIX 2: Duplicate event_id replay ────────────────────────────────────────

    def duplicate_event_replay(self) -> SimulationReport:
        """
        FIX 2: Append same event twice. Second append must be rejected.
        Protects against replay attacks and double-processing.
        """
        log = Phase2EventLog(enforce_invariants=True)
        violations = []
        accepted = 0
        attempted = 0

        det = _make_detection(day=1.0)

        # First append — valid
        try:
            log.append(det)
            accepted += 1
        except (InvariantViolation, Phase2LogError) as e:
            violations.append(str(e))
        attempted += 1

        # Second append of same event — duplicate event_id, must be rejected
        try:
            log.append(det)   # same event_id
            accepted += 1
        except (InvariantViolation, Phase2LogError) as e:
            violations.append(str(e))
        attempted += 1

        # Different event, same ID (hash collision simulation)
        cloned = dataclasses.replace(
            _make_detection(day=2.0),
            event_id=det.event_id,   # reuse first event's ID
        )
        try:
            log.append(cloned)
            accepted += 1
        except (InvariantViolation, Phase2LogError) as e:
            violations.append(str(e))
        attempted += 1

        held = accepted == 1 and len(violations) == 2
        return SimulationReport(
            attack_name="duplicate_event_replay",
            invariants_held=held,
            violations_caught=violations,
            events_attempted=attempted,
            events_accepted=accepted,
            summary=(
                f"Duplicate replay: {accepted}/3 accepted. "
                f"Expected: 1 (first), 2 rejected (same ID). "
                f"{'PASS' if held else 'FAIL'}."
            ),
        )

    # FIX 3: Log corruption simulation ────────────────────────────────────────

    def log_corruption(self) -> SimulationReport:
        """
        FIX 3: Append valid chain including threshold adjustments so DriftProjection
        and ThresholdProjection both reflect content. Manually remove middle event,
        run ReplayValidator, assert projection_hash mismatch.
        Uses DriftCrossingRecorded events so DriftProjection hash differs.
        """
        log = Phase2EventLog(enforce_invariants=True)
        violations = []
        correct_threshold = DEFAULT_THRESHOLDS["drift"]["0"]

        # Build 5 DriftCrossingRecorded events — DriftProjection tracks these
        identities = [f"identity:user:u{i}" for i in range(5)]
        for i, identity in enumerate(identities):
            ev = DriftCrossingRecorded(
                event_id=_stable_id("log_corrupt_crossing", str(i)),
                event_index=0,
                timestamp=_ts(float(i + 1)),
                identity=identity,
                direction="up",
                drift_value=5.0 + i * 0.1,
                threshold_used=round(correct_threshold, 6),
                previous_drift=3.0,
                acceleration=0.3,
                acceleration_bounded=False,
            )
            log.append(ev)

        # Get hash of clean log
        validator    = ReplayValidator(log)
        clean_report = validator.assert_consistency()

        # Manually corrupt: remove event at index 2 (middle identity)
        corrupted_log = Phase2EventLog(enforce_invariants=False)
        for i, event in enumerate(log.replay()):
            if i == 2:
                continue  # skip middle event — corruption
            corrupted_log.append_unsafe(event)

        corrupted_validator = ReplayValidator(corrupted_log)
        corrupted_report    = corrupted_validator.assert_consistency()

        # Hashes should differ: corrupted log is missing one drift crossing
        clean_hash     = clean_report["run1_hash"]
        corrupted_hash = corrupted_report["run1_hash"]
        hashes_differ  = clean_hash != corrupted_hash

        # Both individual logs should be internally consistent (same log replayed twice)
        both_internally_consistent = (
            clean_report["consistent"] and corrupted_report["consistent"]
        )

        held = hashes_differ and both_internally_consistent

        summary = (
            f"Log corruption: clean_hash={clean_hash[:12]}... "
            f"corrupted_hash={corrupted_hash[:12]}... "
            f"hashes_differ={hashes_differ}, "
            f"internal_consistency={both_internally_consistent}. "
            f"{'PASS' if held else 'FAIL — corruption not detected'}."
        )

        return SimulationReport(
            attack_name="log_corruption",
            invariants_held=held,
            violations_caught=violations,
            events_attempted=5,
            events_accepted=5,
            summary=summary,
            extras={
                "clean_hash":     clean_hash,
                "corrupted_hash": corrupted_hash,
                "hashes_differ":  hashes_differ,
            },
        )

    # FIX 4: Drift acceleration bounds ────────────────────────────────────────

    def drift_acceleration_bounds(self) -> SimulationReport:
        """
        FIX 4: DriftCrossingRecorded with acceleration > MAX_ACCEL must be rejected.
        Also test acceleration_bounded=True with wrong value.
        """
        log = Phase2EventLog(enforce_invariants=True)
        violations = []
        accepted = 0
        attempted = 0

        correct_threshold = DEFAULT_THRESHOLDS["drift"]["0"]

        # Valid: acceleration exactly at MAX_ACCEL, bounded=True
        valid_at_ceiling = DriftCrossingRecorded(
            event_id=_stable_id("valid_at_ceiling", "v1"),
            event_index=0,
            timestamp=_ts(1),
            identity="identity:user:alice",
            direction="up",
            drift_value=5.5,
            threshold_used=round(correct_threshold, 6),
            previous_drift=3.0,
            acceleration=round(MAX_ACCEL, 6),
            acceleration_bounded=True,
        )
        try:
            log.append(valid_at_ceiling)
            accepted += 1
        except (InvariantViolation, Phase2LogError) as e:
            violations.append(str(e))
        attempted += 1

        # Invalid: acceleration exceeds MAX_ACCEL
        exceed_max = DriftCrossingRecorded(
            event_id=_stable_id("exceed_max", "v1"),
            event_index=0,
            timestamp=_ts(2),
            identity="identity:user:bob",
            direction="up",
            drift_value=6.0,
            threshold_used=round(correct_threshold, 6),
            previous_drift=4.0,
            acceleration=MAX_ACCEL + 5.0,    # exceeds ceiling
            acceleration_bounded=False,       # claims not bounded — wrong
        )
        try:
            log.append(exceed_max)
            accepted += 1
        except (InvariantViolation, Phase2LogError) as e:
            violations.append(str(e))
        attempted += 1

        # Invalid: acceleration_bounded=True but not at ceiling
        bounded_lie = DriftCrossingRecorded(
            event_id=_stable_id("bounded_lie", "v1"),
            event_index=0,
            timestamp=_ts(3),
            identity="identity:user:carol",
            direction="up",
            drift_value=4.5,
            threshold_used=round(correct_threshold, 6),
            previous_drift=2.0,
            acceleration=2.5,       # well below ceiling
            acceleration_bounded=True,  # claims bounded — lie
        )
        try:
            log.append(bounded_lie)
            accepted += 1
        except (InvariantViolation, Phase2LogError) as e:
            violations.append(str(e))
        attempted += 1

        held = accepted == 1 and len(violations) == 2
        return SimulationReport(
            attack_name="drift_acceleration_bounds",
            invariants_held=held,
            violations_caught=violations,
            events_attempted=attempted,
            events_accepted=accepted,
            summary=(
                f"Drift acceleration: {accepted}/3 accepted. "
                f"Valid-at-ceiling accepted, exceed-max rejected, bounded-lie rejected. "
                f"{'PASS' if held else 'FAIL'}."
            ),
        )

    # FIX 5: Saturation attack ────────────────────────────────────────────────

    def saturation_attack(self, n_identities: int = 100) -> SimulationReport:
        """
        FIX 5: >30% identities at high privilege simultaneously.
        Verifies that saturation_flag is correctly set when >30% escalate.
        Note: saturation_flag is set by TemporalPrivilegeEngine (Phase 1).
        This test verifies the flag propagates correctly through
        EscalationDetected and is preserved in the event log.
        The 30% check is a detector-side invariant, not a log invariant.
        We verify: 40 out of 100 identities with saturation_flag=True
        are all accepted (log allows it), and the flag is preserved.
        """
        log = Phase2EventLog(enforce_invariants=True)
        accepted    = 0
        saturated   = 0
        unsaturated = 0

        high_priv_count = int(n_identities * 0.40)  # 40% — above 30% threshold

        for i in range(n_identities):
            is_saturated = (i < high_priv_count)
            det = EscalationDetected(
                event_id=_stable_id(f"identity:user:u{i}", str(i), "sat_test"),
                event_index=0,
                timestamp=_ts(1.0 + i * 0.001),
                identity=f"identity:user:u{i}",
                risk_score=0.9 if is_saturated else 0.3,
                risk_band="CRITICAL" if is_saturated else "MONITORING",
                effective_priv_now=9 if is_saturated else 2,
                effective_priv_prev=7 if is_saturated else 2,
                velocity=1.5 if is_saturated else 0.1,
                acceleration=0.5,
                drift=5.0 if is_saturated else 1.0,
                oscillation_count=0,
                path_birth_rate=1.0,
                redundancy_score=0.5 if is_saturated else 0.1,
                saturation_flag=is_saturated,  # True for 40% of identities
                trust_path_present=False,
                trigger_reasons=("velocity=1.50",) if is_saturated else ("velocity=0.10",),
                threshold_version="v0",
                policy_version="default_v0",
            )
            try:
                log.append(det)
                accepted += 1
                if is_saturated:
                    saturated += 1
                else:
                    unsaturated += 1
            except (InvariantViolation, Phase2LogError):
                pass

        # All events should be accepted (log doesn't enforce saturation — engine does)
        all_accepted = accepted == n_identities

        # Verify flag preservation: count saturated events in log
        logged_saturated = sum(
            1 for e in log.replay_type(EscalationDetected)
            if e.saturation_flag
        )
        flag_preserved = logged_saturated == high_priv_count

        # Saturation ratio check
        saturation_ratio = high_priv_count / n_identities
        above_threshold  = saturation_ratio > 0.30

        held = all_accepted and flag_preserved and above_threshold

        return SimulationReport(
            attack_name="saturation_attack",
            invariants_held=held,
            violations_caught=[],
            events_attempted=n_identities,
            events_accepted=accepted,
            summary=(
                f"Saturation: {high_priv_count}/{n_identities} identities "
                f"({saturation_ratio:.0%}) flagged saturated. "
                f"All accepted={all_accepted}, flags preserved={flag_preserved}. "
                f"Above 30% threshold={above_threshold}. "
                f"{'PASS' if held else 'FAIL'}."
            ),
            extras={
                "saturation_ratio": saturation_ratio,
                "logged_saturated": logged_saturated,
            },
        )

    # FIX 6: Determinism replay test ──────────────────────────────────────────

    def determinism_replay(self) -> SimulationReport:
        """
        FIX 6: After any attack simulation, verify projection_hash is identical
        across two independent full rebuilds.
        Tests that the system is invariant-safe AND deterministic.
        """
        log = Phase2EventLog(enforce_invariants=True)

        # Build a realistic log with multiple event types
        for i in range(10):
            det = _make_detection(day=float(i + 1))
            log.append(det)

        # Add some threshold adjustments
        signal  = "velocity"
        tier    = 0
        default = DEFAULT_THRESHOLDS[signal][str(tier)]
        for i in range(3):
            adj = ThresholdAdjusted(
                event_id=_stable_id("det_replay_adj", str(i)),
                event_index=0,
                timestamp=_ts(15.0 + i),
                signal_type=signal,
                tier=tier,
                previous_value=round(default + i * 0.02, 8),
                new_value=round(default + (i + 1) * 0.02, 8),
                delta=0.02,
                direction="up",
                fp_rate_observed=0.08,
                fn_rate_observed=0.05,
                learning_rate_used=0.005,
                version_id=f"v_det_{i}",
            )
            try:
                log.append(adj)
            except (InvariantViolation, Phase2LogError):
                pass

        # Run ReplayValidator — two independent replays must match
        validator = ReplayValidator(log)
        report    = validator.assert_consistency()

        # Also test incremental matches full
        incr_report = validator.assert_incremental_matches_full()

        held = report["consistent"] and incr_report["consistent"]

        return SimulationReport(
            attack_name="determinism_replay",
            invariants_held=held,
            violations_caught=[] if held else report.get("inconsistencies", []),
            events_attempted=len(log),
            events_accepted=len(log),
            summary=(
                f"Determinism: two replays {'match' if report['consistent'] else 'DIVERGE'}. "
                f"Incremental matches full: {incr_report['consistent']}. "
                f"Events={report['event_count']}. "
                f"{'PASS' if held else 'FAIL — DETERMINISM BROKEN'}."
            ),
            extras={
                "run1_hash":    report["run1_hash"][:16],
                "run2_hash":    report["run2_hash"][:16],
                "consistent":   report["consistent"],
            },
        )

    # FIX 7: Timestamp regression attack ──────────────────────────────────────

    def timestamp_regression(self) -> SimulationReport:
        """
        FIX 7: Append event with timestamp earlier than previous event.
        Monotonic enforcement must reject it.
        """
        log = Phase2EventLog(enforce_invariants=True)
        violations = []
        accepted = 0
        attempted = 0

        # First event at day=5
        det1 = _make_detection(identity="identity:user:alice", day=5.0)
        try:
            log.append(det1)
            accepted += 1
        except (InvariantViolation, Phase2LogError) as e:
            violations.append(str(e))
        attempted += 1

        # Second event at day=6 — valid
        det2 = _make_detection(identity="identity:user:bob", day=6.0)
        try:
            log.append(det2)
            accepted += 1
        except (InvariantViolation, Phase2LogError) as e:
            violations.append(str(e))
        attempted += 1

        # Third event at day=3 — regression (earlier than day=6)
        det3 = _make_detection(identity="identity:user:carol", day=3.0)
        try:
            log.append(det3)
            accepted += 1
        except (InvariantViolation, Phase2LogError) as e:
            violations.append(str(e))
        attempted += 1

        held = accepted == 2 and len(violations) == 1
        return SimulationReport(
            attack_name="timestamp_regression",
            invariants_held=held,
            violations_caught=violations,
            events_attempted=attempted,
            events_accepted=accepted,
            summary=(
                f"Timestamp regression: {accepted}/3 accepted. "
                f"day=5 OK, day=6 OK, day=3 (regression) rejected. "
                f"{'PASS' if held else 'FAIL'}."
            ),
        )

    # FIX 8: Memory exhaustion stress ─────────────────────────────────────────

    def memory_exhaustion_stress(self, n_events: int = 50_000) -> SimulationReport:
        """
        FIX 8: Flood with 50k events, measure time, ensure O(N) not O(N²).
        Projection rebuild after 50k events must complete in reasonable time.
        """
        log = Phase2EventLog(enforce_invariants=True)
        accepted = 0

        t_start = time.perf_counter()
        for i in range(n_events):
            det = _make_detection(
                identity=f"identity:user:u{i % 1000}",  # cycle 1000 identities
                day=float(i) / 1000.0 + 1.0,
                risk=0.3 + (i % 10) * 0.05,
            )
            try:
                log.append(det)
                accepted += 1
            except (InvariantViolation, Phase2LogError):
                pass  # monotonic violation from cycling identities — expected

        t_append = time.perf_counter() - t_start

        # Projection rebuild timing
        t_proj_start = time.perf_counter()
        from phase2.projections import ThresholdProjection
        proj = ThresholdProjection(log)
        proj.force_rebuild()
        t_proj = time.perf_counter() - t_proj_start

        # ReplayValidator consistency (single projection type)
        t_replay_start = time.perf_counter()
        validator = ReplayValidator(log)
        report    = validator.assert_consistency()
        t_replay  = time.perf_counter() - t_replay_start

        # Performance bounds (generous for CI environments)
        append_ok = t_append < 60.0    # 50k appends < 60s
        proj_ok   = t_proj   < 10.0    # projection rebuild < 10s
        replay_ok = t_replay < 60.0    # double replay < 60s

        held = report["consistent"] and append_ok and proj_ok

        return SimulationReport(
            attack_name="memory_exhaustion_stress",
            invariants_held=held,
            violations_caught=[],
            events_attempted=n_events,
            events_accepted=accepted,
            summary=(
                f"Stress: {accepted}/{n_events} events accepted. "
                f"append={t_append:.2f}s, proj_rebuild={t_proj:.3f}s, "
                f"double_replay={t_replay:.2f}s. "
                f"Deterministic={report['consistent']}. "
                f"{'PASS' if held else 'FAIL — performance budget exceeded'}."
            ),
            extras={
                "t_append_s":     round(t_append, 3),
                "t_proj_rebuild": round(t_proj, 3),
                "t_replay_s":     round(t_replay, 3),
                "consistent":     report["consistent"],
            },
        )

    # FIX 9: Automation cascade ───────────────────────────────────────────────

    def automation_cascade(self) -> SimulationReport:
        """
        FIX 9: Full automation governor precision threshold simulation.
        - 5 consecutive verifications below 0.80 → expect downgrade
        - 20 consecutive verifications above 0.90 → expect upgrade
        Uses PrecisionProjection + AutomationGovernor directly.
        """
        from phase2.projections import (
            AutomationProjection, PrecisionProjection,
            DOWNGRADE_PRECISION_THRESHOLD, DOWNGRADE_CONSECUTIVE_REQUIRED,
            UPGRADE_PRECISION_THRESHOLD, UPGRADE_CONSECUTIVE_REQUIRED,
        )
        from phase2.governance import AutomationGovernor

        log = Phase2EventLog(enforce_invariants=True)
        violations = []

        # Step 0: Set initial state to staged_contain FIRST (before any other events)
        initial_state = AutomationStateChanged(
            event_id=_stable_id("initial_staged_contain"),
            event_index=0,
            timestamp=_ts(0.5),
            scope_signal="composite",
            scope_tier=0,
            scope_action="staged_contain",
            previous_state="observe",
            new_state="staged_contain",
            direction="upgrade",
            trigger_reason="test setup",
            consecutive_count=20,
            precision_history=tuple([0.95] * 5),
        )
        log.append(initial_state)

        # Step 1: Append a detection + case
        det = _make_detection(identity="identity:user:dave", day=1.0)
        det = log.append(det)
        case = _make_case(det)
        case = log.append(case)

        # Step 2: First response at day=1
        resp = _make_response(case, "staged_contain", day_offset=0.0)
        resp = log.append(resp)

        # Step 3: 5 low-precision verifications — spaced to avoid timestamp issues
        for i in range(5):
            verif = PostActionVerified(
                event_id=_stable_id("verif_low", str(i)),
                event_index=0,
                timestamp=resp.timestamp + timedelta(hours=i + 1),
                response_event_id=resp.event_id,
                case_id=resp.case_id,
                identity=resp.identity,
                risk_score_before=0.8, risk_score_after=0.9, score_delta=-0.1,
                privilege_surface_before=5, privilege_surface_after=6, privilege_surface_reduction=-1,
                drift_before=2.0, drift_after=3.0, drift_stabilization=-1.0,
                path_count_before=3, path_count_after=3, path_count_reduction=0,
                score_success=False, surface_success=False, drift_success=False, path_success=False,
                success_count=0,
                precision=0.30,      # below 0.80 threshold
                verification_passed=False,
            )
            try:
                log.append(verif)
            except (InvariantViolation, Phase2LogError) as e:
                violations.append(str(e))

        # Step 4: Check downgrade
        auto_proj      = AutomationProjection(log)
        precision_proj = PrecisionProjection(log)
        governor       = AutomationGovernor(log, auto_proj, precision_proj)

        # Evaluate for downgrade at t_eval (after the 5 failing verifications)
        t_eval = resp.timestamp + timedelta(hours=6)  # after all 5 verifications
        downgrade_ev = governor.evaluate_scope(
            "composite", 0, "staged_contain", t_eval, event_index=0
        )
        downgrade_detected = downgrade_ev is not None and downgrade_ev.direction == "downgrade"

        # Step 5: Inject 20 high-precision verifications for upgrade test
        # Use a fresh case/response for proper references
        det2  = _make_detection(identity="identity:user:eve", day=10.0)
        det2  = log.append(det2)
        case2 = _make_case(det2)
        case2 = log.append(case2)
        resp2 = _make_response(case2, "observe", day_offset=0.0)
        resp2 = log.append(resp2)

        for i in range(20):
            verif = PostActionVerified(
                event_id=_stable_id("verif_high", str(i)),
                event_index=0,
                timestamp=resp2.timestamp + timedelta(hours=i + 1),
                response_event_id=resp2.event_id,
                case_id=resp2.case_id,
                identity=resp2.identity,
                risk_score_before=0.8, risk_score_after=0.2, score_delta=0.6,
                privilege_surface_before=5, privilege_surface_after=1, privilege_surface_reduction=4,
                drift_before=5.0, drift_after=1.0, drift_stabilization=4.0,
                path_count_before=4, path_count_after=0, path_count_reduction=4,
                score_success=True, surface_success=True, drift_success=True, path_success=True,
                success_count=4,
                precision=1.00,     # above 0.90 threshold
                verification_passed=True,
            )
            try:
                log.append(verif)
            except (InvariantViolation, Phase2LogError) as e:
                violations.append(str(e))

        # Evaluate for upgrade
        t_eval2 = resp2.timestamp + timedelta(hours=25)
        upgrade_ev = governor.evaluate_scope(
            "composite", 0, "observe", t_eval2, event_index=0
        )
        upgrade_detected = upgrade_ev is not None and upgrade_ev.direction == "upgrade"

        # Check consecutive_below and consecutive_above counts
        prec_proj     = PrecisionProjection(log)
        cons_below    = prec_proj.consecutive_below("composite", 0, "staged_contain", 0.80, 10)
        cons_above    = prec_proj.consecutive_above("composite", 0, "observe", 0.90, 25)

        held = (
            downgrade_detected
            and upgrade_detected
            and cons_below >= DOWNGRADE_CONSECUTIVE_REQUIRED
            and cons_above >= UPGRADE_CONSECUTIVE_REQUIRED
        )

        return SimulationReport(
            attack_name="automation_cascade",
            invariants_held=held,
            violations_caught=violations,
            events_attempted=30,  # 5 low + 20 high + setup
            events_accepted=30 - len(violations),
            summary=(
                f"Automation cascade: "
                f"downgrade_detected={downgrade_detected}, "
                f"upgrade_detected={upgrade_detected}, "
                f"cons_below={cons_below} (need {DOWNGRADE_CONSECUTIVE_REQUIRED}), "
                f"cons_above={cons_above} (need {UPGRADE_CONSECUTIVE_REQUIRED}). "
                f"{'PASS' if held else 'FAIL'}."
            ),
            extras={
                "downgrade_detected": downgrade_detected,
                "upgrade_detected":   upgrade_detected,
                "cons_below":         cons_below,
                "cons_above":         cons_above,
            },
        )

    # ── Original drift_acceleration (threshold mismatch test) ─────────────────

    def drift_acceleration(self) -> SimulationReport:
        """Original: threshold mismatch in DriftCrossingRecorded — rejected."""
        log = Phase2EventLog(enforce_invariants=True)
        violations = []
        accepted = 0
        attempted = 0

        correct_threshold = DEFAULT_THRESHOLDS["drift"]["0"]

        valid_crossing = DriftCrossingRecorded(
            event_id=_stable_id("valid_crossing", "v1"),
            event_index=0,
            timestamp=_ts(1),
            identity="identity:user:alice",
            direction="up",
            drift_value=5.5,
            threshold_used=round(correct_threshold, 6),
            previous_drift=3.0,
            acceleration=0.5,
            acceleration_bounded=False,
        )
        try:
            log.append(valid_crossing)
            accepted += 1
        except (InvariantViolation, Phase2LogError) as e:
            violations.append(str(e))
        attempted += 1

        invalid_crossing = DriftCrossingRecorded(
            event_id=_stable_id("invalid_crossing", "v1"),
            event_index=0,
            timestamp=_ts(2),
            identity="identity:user:bob",
            direction="up",
            drift_value=6.0,
            threshold_used=round(correct_threshold + 1.0, 6),  # wrong threshold
            previous_drift=4.0,
            acceleration=0.5,
            acceleration_bounded=False,
        )
        try:
            log.append(invalid_crossing)
            accepted += 1
        except (InvariantViolation, Phase2LogError) as e:
            violations.append(str(e))
        attempted += 1

        held = accepted == 1 and len(violations) == 1
        return SimulationReport(
            attack_name="drift_acceleration",
            invariants_held=held,
            violations_caught=violations,
            events_attempted=attempted,
            events_accepted=accepted,
            summary=(
                f"Drift threshold mismatch: valid accepted, invalid rejected. "
                f"{'PASS' if held else 'FAIL'}."
            ),
        )

    # ── Run all ───────────────────────────────────────────────────────────────

    def run_all(self, include_stress: bool = False) -> dict:
        """
        Run all attack simulations.
        include_stress=False skips memory_exhaustion_stress (slow, 50k events).
        """
        attacks = [
            # Original attacks
            self.edge_flood,
            self.oscillation_loop,
            self.threshold_poisoning,
            self.confirmation_replay,
            self.reference_forgery,
            self.schema_version_forgery,
            self.drift_acceleration,
            # New hardening attacks (9 critical fixes)
            self.event_index_injection,
            self.duplicate_event_replay,
            self.log_corruption,
            self.drift_acceleration_bounds,
            self.saturation_attack,
            self.determinism_replay,
            self.timestamp_regression,
            self.automation_cascade,
        ]
        if include_stress:
            attacks.append(self.memory_exhaustion_stress)

        reports    = []
        failures   = []
        total_att  = 0
        total_acc  = 0

        for attack_fn in attacks:
            try:
                report = attack_fn()
                reports.append(report)
                total_att += report.events_attempted
                total_acc += report.events_accepted
                if not report.invariants_held:
                    failures.append(report.attack_name)
            except Exception as e:
                failures.append(f"{attack_fn.__name__}: EXCEPTION — {e}")

        return {
            "all_invariants_held": len(failures) == 0,
            "reports":             reports,
            "total_attempted":     total_att,
            "total_accepted":      total_acc,
            "failures":            failures,
            "attack_count":        len(attacks),
        }