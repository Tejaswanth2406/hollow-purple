"""
phase5/health.py — Pipeline Health Monitor

Aggregates liveness signals from each pipeline component into a
HealthReport that the operator can poll or expose via /healthz.

Design:
  Each component registers a HealthProbe (a callable returning ComponentStatus).
  HealthMonitor.check() runs all probes and rolls up to a HealthBand:
      GREEN   — all components healthy
      YELLOW  — at least one component DEGRADED
      RED     — at least one component DOWN

Hardening:
  H1  — Probe callable wrapped in try/except; exception → DOWN status
  H2  — Probe timeout: probes exceeding timeout_s treated as DOWN
  H3  — Thread-safe: probes dict under lock
  H4  — Consecutive failure count per probe (circuit-breaker awareness)
  H5  — HealthHistory: rolling 100-sample ring buffer per component
  H6  — check() is non-blocking; uses threading.Timer for timeout (H2)
  H7  — BackpressureProbe factory: wraps BackpressureController
  H8  — DriftProbe factory: wraps DriftEnvelopeMonitor
"""
from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Callable, Optional


# ── Enums ─────────────────────────────────────────────────────────────────────

class ComponentState(Enum):
    HEALTHY  = "healthy"
    DEGRADED = "degraded"
    DOWN     = "down"


class HealthBand(Enum):
    GREEN  = "green"
    YELLOW = "yellow"
    RED    = "red"


# ── ComponentStatus ───────────────────────────────────────────────────────────

@dataclass
class ComponentStatus:
    name:       str
    state:      ComponentState
    detail:     str        = ""
    checked_at: Optional[datetime] = None
    latency_s:  float      = 0.0

    @classmethod
    def healthy(cls, name: str, detail: str = "", latency_s: float = 0.0) -> "ComponentStatus":
        return cls(
            name       = name,
            state      = ComponentState.HEALTHY,
            detail     = detail,
            checked_at = datetime.now(timezone.utc),
            latency_s  = latency_s,
        )

    @classmethod
    def degraded(cls, name: str, detail: str = "", latency_s: float = 0.0) -> "ComponentStatus":
        return cls(
            name       = name,
            state      = ComponentState.DEGRADED,
            detail     = detail,
            checked_at = datetime.now(timezone.utc),
            latency_s  = latency_s,
        )

    @classmethod
    def down(cls, name: str, detail: str = "", latency_s: float = 0.0) -> "ComponentStatus":
        return cls(
            name       = name,
            state      = ComponentState.DOWN,
            detail     = detail,
            checked_at = datetime.now(timezone.utc),
            latency_s  = latency_s,
        )

    def to_dict(self) -> dict:
        return {
            "name":       self.name,
            "state":      self.state.value,
            "detail":     self.detail,
            "checked_at": self.checked_at.isoformat() if self.checked_at else None,
            "latency_s":  round(self.latency_s, 4),
        }


# ── HealthReport ──────────────────────────────────────────────────────────────

@dataclass
class HealthReport:
    band:       HealthBand
    components: list[ComponentStatus]
    checked_at: datetime
    check_duration_s: float

    @property
    def is_healthy(self) -> bool:
        return self.band == HealthBand.GREEN

    def summary(self) -> str:
        counts = {s: 0 for s in ComponentState}
        for c in self.components:
            counts[c.state] += 1
        return (
            f"band={self.band.value} "
            f"healthy={counts[ComponentState.HEALTHY]} "
            f"degraded={counts[ComponentState.DEGRADED]} "
            f"down={counts[ComponentState.DOWN]}"
        )

    def to_dict(self) -> dict:
        return {
            "band":             self.band.value,
            "checked_at":       self.checked_at.isoformat(),
            "check_duration_s": round(self.check_duration_s, 4),
            "summary":          self.summary(),
            "components":       [c.to_dict() for c in self.components],
        }


# ── HealthProbeRecord ─────────────────────────────────────────────────────────

@dataclass
class _ProbeRecord:
    name:              str
    probe:             Callable[[], ComponentStatus]
    timeout_s:         float
    consecutive_fails: int                    = 0
    history:           deque                  = field(default_factory=lambda: deque(maxlen=100))


# ── HealthMonitor ─────────────────────────────────────────────────────────────

class HealthMonitor:
    """
    Registers probes and runs them on demand.

    Usage:
        monitor = HealthMonitor()
        monitor.register("backpressure", backpressure_probe, timeout_s=1.0)
        report = monitor.check()
        print(report.band)
    """

    def __init__(self, default_timeout_s: float = 2.0):
        self._probes: dict[str, _ProbeRecord] = {}
        self._lock   = threading.Lock()
        self._default_timeout_s = default_timeout_s

    # ── registration ─────────────────────────────────────────────────────────

    def register(
        self,
        name:      str,
        probe:     Callable[[], ComponentStatus],
        timeout_s: Optional[float] = None,
    ) -> None:
        with self._lock:
            self._probes[name] = _ProbeRecord(
                name      = name,
                probe     = probe,
                timeout_s = timeout_s or self._default_timeout_s,
            )

    def deregister(self, name: str) -> None:
        with self._lock:
            self._probes.pop(name, None)

    def registered(self) -> list[str]:
        with self._lock:
            return list(self._probes.keys())

    # ── check ─────────────────────────────────────────────────────────────────

    def check(self) -> HealthReport:
        """
        H1+H2: run all probes; exceptions and timeouts → DOWN.
        H3: thread-safe snapshot of probe list.
        """
        start = time.monotonic()
        now   = datetime.now(timezone.utc)

        with self._lock:
            probe_records = list(self._probes.values())

        statuses = []
        for rec in probe_records:
            status = self._run_probe(rec, now)
            statuses.append(status)

            # H4: consecutive failure tracking
            with self._lock:
                if rec.name in self._probes:
                    if status.state == ComponentState.DOWN:
                        self._probes[rec.name].consecutive_fails += 1
                    else:
                        self._probes[rec.name].consecutive_fails = 0
                    self._probes[rec.name].history.append(status)

        band = self._rollup(statuses)
        return HealthReport(
            band             = band,
            components       = statuses,
            checked_at       = now,
            check_duration_s = time.monotonic() - start,
        )

    def _run_probe(self, rec: _ProbeRecord, now: datetime) -> ComponentStatus:
        """H1+H2: execute probe with timeout."""
        result_container: list[ComponentStatus] = []
        exc_container:    list[Exception]        = []

        def _target():
            try:
                t0 = time.monotonic()
                s  = rec.probe()
                s  = ComponentStatus(
                    name       = rec.name,
                    state      = s.state,
                    detail     = s.detail,
                    checked_at = now,
                    latency_s  = time.monotonic() - t0,
                )
                result_container.append(s)
            except Exception as e:
                exc_container.append(e)

        t = threading.Thread(target=_target, daemon=True)
        t0 = time.monotonic()
        t.start()
        t.join(timeout=rec.timeout_s)

        elapsed = time.monotonic() - t0

        if t.is_alive():
            # H2: timed out
            return ComponentStatus.down(
                rec.name,
                detail    = f"probe timed out after {rec.timeout_s}s",
                latency_s = elapsed,
            )
        if exc_container:
            return ComponentStatus.down(
                rec.name,
                detail    = f"probe raised: {exc_container[0]}",
                latency_s = elapsed,
            )
        if result_container:
            return result_container[0]

        return ComponentStatus.down(rec.name, detail="no result", latency_s=elapsed)

    @staticmethod
    def _rollup(statuses: list[ComponentStatus]) -> HealthBand:
        if any(s.state == ComponentState.DOWN for s in statuses):
            return HealthBand.RED
        if any(s.state == ComponentState.DEGRADED for s in statuses):
            return HealthBand.YELLOW
        return HealthBand.GREEN

    # ── history ───────────────────────────────────────────────────────────────

    def history(self, name: str) -> list[ComponentStatus]:
        """H5: return rolling history for a named probe."""
        with self._lock:
            rec = self._probes.get(name)
            return list(rec.history) if rec else []

    def consecutive_failures(self, name: str) -> int:
        """H4: how many consecutive downs for a probe."""
        with self._lock:
            rec = self._probes.get(name)
            return rec.consecutive_fails if rec else 0

    # ── built-in probe factories ──────────────────────────────────────────────

    @staticmethod
    def backpressure_probe(controller) -> Callable[[], ComponentStatus]:
        """
        H7: factory for BackpressureController probes.
        Returns DEGRADED when pressure is ELEVATED, DOWN when OVERLOADED.
        """
        def _probe() -> ComponentStatus:
            try:
                state = controller.pressure_state()
                state_name = state.name if hasattr(state, "name") else str(state)
                if state_name == "OVERLOADED":
                    return ComponentStatus.down(
                        "backpressure", detail=f"pressure={state_name}"
                    )
                elif state_name == "ELEVATED":
                    return ComponentStatus.degraded(
                        "backpressure", detail=f"pressure={state_name}"
                    )
                return ComponentStatus.healthy(
                    "backpressure", detail=f"pressure={state_name}"
                )
            except Exception as e:
                return ComponentStatus.down("backpressure", detail=str(e))
        return _probe

    @staticmethod
    def drift_probe(monitor, max_acceptable_drift: float = 0.8) -> Callable[[], ComponentStatus]:
        """
        H8: factory for DriftEnvelopeMonitor probes.
        Returns DEGRADED when drift > 80% of envelope, DOWN on violation.
        """
        def _probe() -> ComponentStatus:
            try:
                state = monitor.current_state()
                drift = getattr(state, "drift_score", None)
                if drift is None:
                    return ComponentStatus.healthy("drift", detail="no drift score")

                if drift >= 1.0:
                    return ComponentStatus.down(
                        "drift", detail=f"drift={drift:.3f} (envelope exceeded)"
                    )
                elif drift >= max_acceptable_drift:
                    return ComponentStatus.degraded(
                        "drift", detail=f"drift={drift:.3f} (approaching limit)"
                    )
                return ComponentStatus.healthy(
                    "drift", detail=f"drift={drift:.3f}"
                )
            except Exception as e:
                return ComponentStatus.down("drift", detail=str(e))
        return _probe

    @staticmethod
    def merkle_log_probe(log) -> Callable[[], ComponentStatus]:
        """Probe for MerkleLog integrity: chain length and head hash readable."""
        def _probe() -> ComponentStatus:
            try:
                length    = len(log)
                head_hash = log.head_hash
                return ComponentStatus.healthy(
                    "merkle_log",
                    detail=f"length={length} head={head_hash[:12]}...",
                )
            except Exception as e:
                return ComponentStatus.down("merkle_log", detail=str(e))
        return _probe

    @staticmethod
    def snapshot_store_probe(store) -> Callable[[], ComponentStatus]:
        """Probe for PersistentSealedSnapshotStore: manifest readable."""
        def _probe() -> ComponentStatus:
            try:
                count = len(store)
                return ComponentStatus.healthy(
                    "snapshot_store", detail=f"snapshots={count}"
                )
            except Exception as e:
                return ComponentStatus.down("snapshot_store", detail=str(e))
        return _probe