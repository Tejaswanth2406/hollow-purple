"""
Formal Invariant Checker

System-level safety properties that must hold at all times.

Formal invariants are stricter than governance policies:
  - Governance policies evaluate discrete events
  - Invariants validate full system state snapshots

A violation of a formal invariant represents a dangerous or impossible
system state — something that should never exist under correct operation.
If an invariant fires, the system should halt, alert, and require human
review before resuming.

This design is inspired by formal methods in safety-critical systems
(avionics, nuclear control), adapted for enterprise security platforms.

Enterprise additions over the spec:
  - Invariant priority levels (safety-critical vs advisory)
  - Pre/post-condition pairs for transition validation
  - Violation callbacks (halt hooks, alerting)
  - Invariant coverage report: which state fields are covered?
  - Composable invariant combinators (all_of, any_of, not_)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple


class InvariantLevel(str, Enum):
    SAFETY    = "safety"     # Must hold at all times; violation = halt
    SECURITY  = "security"   # Must hold; violation = alert + investigate
    ADVISORY  = "advisory"   # Should hold; violation = log + monitor


@dataclass
class InvariantSpec:
    name: str
    predicate: Callable[[Any], bool]
    description: str
    level: InvariantLevel
    covers: List[str]               # which state fields this invariant covers
    _violation_count: int = field(default=0, repr=False, compare=False)

    def check(self, state: Any) -> bool:
        try:
            return bool(self.predicate(state))
        except Exception:
            return False   # broken invariant = conservative fail


@dataclass
class InvariantViolation:
    invariant_name: str
    level: InvariantLevel
    description: str
    state_snapshot: Any
    timestamp: float = field(default_factory=time.time)

    @property
    def is_safety_critical(self) -> bool:
        return self.level == InvariantLevel.SAFETY


@dataclass
class InvariantReport:
    violations: List[InvariantViolation]
    checked: int
    passed: int
    failed: int
    has_safety_violation: bool
    has_security_violation: bool
    coverage: Dict[str, List[str]]   # field -> [invariant names covering it]

    @property
    def safe(self) -> bool:
        return not self.has_safety_violation

    def summary(self) -> str:
        status = "SAFE" if self.safe else "UNSAFE"
        return (
            f"[{status}] {self.checked} invariants checked | "
            f"{self.passed} passed | {self.failed} failed"
        )


class FormalInvariantChecker:
    """
    Validates system state against a registered set of formal invariants.

    Supports:
      - Priority levels: SAFETY > SECURITY > ADVISORY
      - Halt hooks: callbacks fired on safety-critical violations
      - Pre/post transition checking
      - Coverage reporting: which state fields are under invariant protection
      - Combinators: all_of(), any_of(), not_() for composing invariants
    """

    def __init__(self, halt_on_safety: bool = False):
        """
        Args:
            halt_on_safety: If True, raise RuntimeError on SAFETY-level violations
        """
        self.halt_on_safety = halt_on_safety
        self._invariants: Dict[str, InvariantSpec] = {}
        self._halt_hooks: List[Callable[[InvariantViolation], None]] = []
        self._violation_log: List[InvariantViolation] = []

    # ─── Registration ────────────────────────────────────────────────────────

    def register(
        self,
        name: str,
        predicate: Callable[[Any], bool],
        description: str = "",
        level: InvariantLevel = InvariantLevel.SECURITY,
        covers: Optional[List[str]] = None,
    ):
        """
        Register a named invariant.

        Args:
            name:        Unique invariant identifier
            predicate:   Callable(state) -> bool; False = violation
            description: Human-readable description
            level:       InvariantLevel.SAFETY | SECURITY | ADVISORY
            covers:      List of state field names this invariant monitors
        """
        self._invariants[name] = InvariantSpec(
            name=name,
            predicate=predicate,
            description=description,
            level=level,
            covers=covers or [],
        )

    def unregister(self, name: str):
        self._invariants.pop(name, None)

    def add_halt_hook(self, callback: Callable[[InvariantViolation], None]):
        """Register a callback fired on any SAFETY-level violation."""
        self._halt_hooks.append(callback)

    # ─── Validation ──────────────────────────────────────────────────────────

    def validate(self, state: Any) -> InvariantReport:
        """
        Check all invariants against the current state.

        Returns:
            InvariantReport with full violation breakdown and coverage map
        """
        violations: List[InvariantViolation] = []
        has_safety = False
        has_security = False

        for spec in self._invariants.values():
            if not spec.check(state):
                spec._violation_count += 1
                v = InvariantViolation(
                    invariant_name=spec.name,
                    level=spec.level,
                    description=spec.description,
                    state_snapshot=state,
                )
                violations.append(v)
                self._violation_log.append(v)

                if spec.level == InvariantLevel.SAFETY:
                    has_safety = True
                    for hook in self._halt_hooks:
                        try:
                            hook(v)
                        except Exception:
                            pass
                elif spec.level == InvariantLevel.SECURITY:
                    has_security = True

        if self.halt_on_safety and has_safety:
            names = [v.invariant_name for v in violations if v.is_safety_critical]
            raise RuntimeError(f"SAFETY invariant violations: {names}")

        coverage = self._build_coverage_map()

        return InvariantReport(
            violations=violations,
            checked=len(self._invariants),
            passed=len(self._invariants) - len(violations),
            failed=len(violations),
            has_safety_violation=has_safety,
            has_security_violation=has_security,
            coverage=coverage,
        )

    def check_transition(
        self,
        pre_state: Any,
        post_state: Any,
        transition_invariants: Optional[List[str]] = None,
    ) -> Tuple[InvariantReport, InvariantReport]:
        """
        Validate both the pre-state and post-state of a state transition.

        Args:
            pre_state:             State before the transition
            post_state:            State after the transition
            transition_invariants: If set, check only these invariants

        Returns:
            (pre_report, post_report)
        """
        if transition_invariants:
            # Temporarily restrict to named invariants
            all_inv = dict(self._invariants)
            self._invariants = {
                k: v for k, v in all_inv.items() if k in transition_invariants
            }
            pre = self.validate(pre_state)
            post = self.validate(post_state)
            self._invariants = all_inv
        else:
            pre = self.validate(pre_state)
            post = self.validate(post_state)

        return pre, post

    # ─── Combinators ─────────────────────────────────────────────────────────

    @staticmethod
    def all_of(*predicates: Callable[[Any], bool]) -> Callable[[Any], bool]:
        """Compose: all predicates must return True."""
        def combined(state: Any) -> bool:
            return all(p(state) for p in predicates)
        combined.__name__ = "all_of(" + ", ".join(
            getattr(p, "__name__", "?") for p in predicates
        ) + ")"
        return combined

    @staticmethod
    def any_of(*predicates: Callable[[Any], bool]) -> Callable[[Any], bool]:
        """Compose: at least one predicate must return True."""
        def combined(state: Any) -> bool:
            return any(p(state) for p in predicates)
        combined.__name__ = "any_of"
        return combined

    @staticmethod
    def not_(predicate: Callable[[Any], bool]) -> Callable[[Any], bool]:
        """Negate a predicate."""
        def negated(state: Any) -> bool:
            return not predicate(state)
        negated.__name__ = f"not_({getattr(predicate, '__name__', '?')})"
        return negated

    # ─── Reporting ───────────────────────────────────────────────────────────

    def violation_history(
        self,
        level: Optional[InvariantLevel] = None,
    ) -> List[InvariantViolation]:
        if level:
            return [v for v in self._violation_log if v.level == level]
        return list(self._violation_log)

    def coverage_report(self) -> dict:
        return {
            "total_invariants": len(self._invariants),
            "fields_covered": self._build_coverage_map(),
            "uncovered_hint": "Fields not in any 'covers' list have no invariant protection",
        }

    def _build_coverage_map(self) -> Dict[str, List[str]]:
        coverage: Dict[str, List[str]] = {}
        for spec in self._invariants.values():
            for field_name in spec.covers:
                coverage.setdefault(field_name, []).append(spec.name)
        return coverage


# ─── Built-in formal invariants ───────────────────────────────────────────────

def inv_no_unlimited_privileges(state: dict) -> bool:
    """No identity may hold wildcard (*) privileges."""
    return all(
        "*" not in identity.get("privileges", [])
        for identity in state.get("identities", [])
    )


def inv_no_orphaned_sessions(state: dict) -> bool:
    """All active sessions must map to a known identity."""
    known_ids = {i["id"] for i in state.get("identities", [])}
    return all(
        s.get("identity_id") in known_ids
        for s in state.get("sessions", [])
    )


def inv_admin_count_bounded(state: dict, max_admins: int = 5) -> bool:
    """The number of admin-role identities must not exceed the limit."""
    admins = [
        i for i in state.get("identities", [])
        if "admin" in i.get("roles", [])
    ]
    return len(admins) <= max_admins


def inv_audit_log_monotonic(state: dict) -> bool:
    """Audit log entries must be strictly ordered by timestamp."""
    entries = state.get("audit_log", [])
    timestamps = [e.get("timestamp", "") for e in entries]
    return timestamps == sorted(timestamps)