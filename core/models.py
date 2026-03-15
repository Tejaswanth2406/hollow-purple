"""
core/models.py — Hollow Purple Core Data Models (Advanced Production Grade)

Defines all shared data structures used across all phases:
  - Enums:  IdentityType, ResourceType, EdgeType, RiskTier, AnomalyClass
  - Nodes:  IdentityNode, RoleNode, ResourceNode
  - Edges:  PermissionEdge, TrustEdge, InheritsEdge, AccessedEdge
  - Events: BehaviorEvent, AuditRecord
  - Results: RiskSignal, AnomalyResult, ValidationResult

Design principles:
  - All nodes carry privilege_level + effective_privilege (post-closure)
  - All edges carry full lifecycle metadata (born_at, last_seen, is_active, revoked_at)
  - BehaviorEvent is timezone-safe and self-validating via __post_init__
  - All models are dataclass-based with validation
  - node_key / edge_key properties are canonical and collision-resistant
  - RiskSignal supports multi-phase aggregation and confidence scoring
  - AuditRecord carries a SHA-256 content hash for Merkle tree integration
"""
from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class IdentityType(str, Enum):
    USER            = "user"
    SERVICE_ACCOUNT = "service_account"
    GROUP           = "group"
    DOMAIN          = "domain"
    FEDERATED       = "federated"
    WORKLOAD        = "workload"
    UNKNOWN         = "unknown"


class ResourceType(str, Enum):
    BUCKET          = "bucket"
    DATASET         = "dataset"
    SECRET          = "secret"
    FUNCTION        = "function"
    VM              = "vm"
    TOPIC           = "topic"
    SUBSCRIPTION    = "subscription"
    PROJECT         = "project"
    KEY_RING        = "key_ring"
    CRYPTO_KEY      = "crypto_key"
    SERVICE_ACCOUNT = "service_account_resource"
    CLUSTER         = "cluster"
    ARTIFACT        = "artifact"
    UNKNOWN         = "unknown"


class EdgeType(str, Enum):
    PERMISSION = "permission"
    TRUST      = "trust"
    ACCESSED   = "accessed"
    INHERITS   = "inherits"
    DELEGATED  = "delegated"
    FEDERATED  = "federated"


class RiskTier(str, Enum):
    CRITICAL = "critical"   # score >= 0.85
    HIGH     = "high"       # score >= 0.65
    ELEVATED = "elevated"   # score >= 0.40
    MODERATE = "moderate"   # score >= 0.20
    LOW      = "low"        # score <  0.20


class AnomalyClass(str, Enum):
    PRIVILEGE_ESCALATION  = "privilege_escalation"
    LATERAL_MOVEMENT      = "lateral_movement"
    TRUST_CHAIN_ABUSE     = "trust_chain_abuse"
    ROLE_EXPLOSION        = "role_explosion"
    CREDENTIAL_COMPROMISE = "credential_compromise"
    SATURATION_BREACH     = "saturation_breach"
    DRIFT_DETECTED        = "drift_detected"
    INVARIANT_VIOLATION   = "invariant_violation"
    SHADOW_IDENTITY       = "shadow_identity"
    MERKLE_INCONSISTENCY  = "merkle_inconsistency"
    BACKPRESSURE_EXCEEDED = "backpressure_exceeded"
    CONSENSUS_FAILURE     = "consensus_failure"
    UNKNOWN               = "unknown"


class EventSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


# ---------------------------------------------------------------------------
# Privilege resolution helpers
# ---------------------------------------------------------------------------

PRIVILEGE_TIERS: dict[str, int] = {
    "owner":                      10,
    "projectiamadmin":            9,
    "roleadmin":                  9,
    "securityadmin":              9,
    "admin":                      8,
    "serviceaccountadmin":        8,
    "serviceaccounttokencreator": 8,
    "editor":                     6,
    "deployer":                   5,
    "developer":                  5,
    "serviceaccountuser":         4,
    "viewer":                     2,
    "reader":                     2,
    "browser":                    1,
}


def privilege_tier_from_role(role: str) -> int:
    """Resolve privilege tier from a role string via keyword matching."""
    r = role.lower().replace("roles/", "").replace(".", "").replace("_", "")
    for keyword, tier in sorted(PRIVILEGE_TIERS.items(), key=lambda x: -x[1]):
        if keyword in r:
            return tier
    return 3


def risk_tier_from_score(score: float) -> RiskTier:
    """Map a float score [0,1] to a RiskTier."""
    if score >= 0.85: return RiskTier.CRITICAL
    if score >= 0.65: return RiskTier.HIGH
    if score >= 0.40: return RiskTier.ELEVATED
    if score >= 0.20: return RiskTier.MODERATE
    return RiskTier.LOW


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


# ---------------------------------------------------------------------------
# Node models
# ---------------------------------------------------------------------------

@dataclass
class IdentityNode:
    """
    Represents a principal: user, service account, group, domain, or workload.

    node_key            — canonical graph key:  "identity:{principal}"
    privilege_level     — highest role privilege directly assigned
    effective_privilege — post-closure value (includes trust chain propagation)
    risk_score          — aggregated risk signal [0.0, 1.0]
    anomaly_flags       — AnomalyClass values detected on this identity
    """
    identity:             str
    identity_type:        IdentityType
    first_seen:           datetime
    last_seen:            datetime
    privilege_level:      int                = 0
    effective_privilege:  int                = 0
    risk_score:           float              = 0.0
    anomaly_flags:        list[AnomalyClass] = field(default_factory=list)
    project:              Optional[str]      = None
    display_name:         Optional[str]      = None
    metadata:             dict[str, Any]     = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.identity:
            raise ValueError("IdentityNode.identity must not be empty")
        if not (0.0 <= self.risk_score <= 1.0):
            raise ValueError(f"risk_score must be in [0,1], got {self.risk_score}")
        self.first_seen = _ensure_utc(self.first_seen)
        self.last_seen  = _ensure_utc(self.last_seen)

    @property
    def node_key(self) -> str:
        return f"identity:{self.identity}"

    @property
    def risk_tier(self) -> RiskTier:
        return risk_tier_from_score(self.risk_score)

    @property
    def is_high_privilege(self) -> bool:
        return self.effective_privilege >= 7

    @property
    def is_service_account(self) -> bool:
        return self.identity_type == IdentityType.SERVICE_ACCOUNT

    def touch(self, ts: datetime) -> None:
        ts = _ensure_utc(ts)
        if ts > self.last_seen:
            self.last_seen = ts

    def flag_anomaly(self, anomaly: AnomalyClass) -> None:
        if anomaly not in self.anomaly_flags:
            self.anomaly_flags.append(anomaly)

    def __repr__(self) -> str:
        return (
            f"IdentityNode({self.identity!r}, type={self.identity_type.value}, "
            f"priv={self.privilege_level}, eff={self.effective_privilege}, "
            f"risk={self.risk_score:.2f})"
        )


@dataclass
class RoleNode:
    """
    Represents an IAM role (predefined or custom).

    node_key  — canonical graph key: "role:{role}"
    """
    role:            str
    privilege_level: int            = 3
    is_custom:       bool           = False
    description:     Optional[str]  = None
    metadata:        dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.role:
            raise ValueError("RoleNode.role must not be empty")
        if not (0 <= self.privilege_level <= 10):
            raise ValueError(f"privilege_level must be in [0,10], got {self.privilege_level}")

    @property
    def node_key(self) -> str:
        return f"role:{self.role}"

    @property
    def is_predefined(self) -> bool:
        return self.role.startswith("roles/")

    @property
    def short_name(self) -> str:
        return self.role.split("/")[-1] if "/" in self.role else self.role

    def __repr__(self) -> str:
        return (
            f"RoleNode({self.role!r}, priv={self.privilege_level}, "
            f"custom={self.is_custom})"
        )


@dataclass
class ResourceNode:
    """
    Represents a cloud resource (bucket, secret, VM, dataset, etc.).

    node_key     — canonical graph key: "resource:{resource_name}"
    is_sensitive — auto-flagged True for SECRET, CRYPTO_KEY, KEY_RING, SERVICE_ACCOUNT
    """
    resource_name:   str
    resource_type:   ResourceType
    project:         str
    privilege_level: int            = 2
    region:          Optional[str]  = None
    is_sensitive:    bool           = False
    metadata:        dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.resource_name:
            raise ValueError("ResourceNode.resource_name must not be empty")
        if self.resource_type in (
            ResourceType.SECRET, ResourceType.CRYPTO_KEY,
            ResourceType.KEY_RING, ResourceType.SERVICE_ACCOUNT,
        ):
            self.is_sensitive = True

    @property
    def node_key(self) -> str:
        return f"resource:{self.resource_name}"

    @property
    def short_name(self) -> str:
        return self.resource_name.split("/")[-1]

    def __repr__(self) -> str:
        return (
            f"ResourceNode({self.resource_name!r}, "
            f"type={self.resource_type.value}, project={self.project!r}, "
            f"sensitive={self.is_sensitive})"
        )


# ---------------------------------------------------------------------------
# Edge models
# ---------------------------------------------------------------------------

@dataclass
class _BaseEdge:
    """Shared lifecycle fields for all edge types."""
    source_key:        str
    target_key:        str
    observed_at:       datetime
    metadata:          dict[str, Any]      = field(default_factory=dict)
    edge_id:           str                 = field(default_factory=lambda: str(uuid.uuid4()))
    born_at:           Optional[datetime]  = None
    last_seen:         Optional[datetime]  = None
    is_active:         bool                = True
    revoked_at:        Optional[datetime]  = None
    observation_count: int                 = 1

    def __post_init__(self) -> None:
        self.observed_at = _ensure_utc(self.observed_at)
        if self.born_at   is None: self.born_at   = self.observed_at
        if self.last_seen is None: self.last_seen = self.observed_at

    @property
    def age_seconds(self) -> float:
        if self.born_at:
            return (datetime.now(timezone.utc) - self.born_at).total_seconds()
        return 0.0

    @property
    def edge_type(self) -> str:
        raise NotImplementedError

    @property
    def edge_key(self) -> tuple[str, str, str]:
        return (self.source_key, self.target_key, self.edge_type)


@dataclass
class PermissionEdge(_BaseEdge):
    """
    Permission assignment:
      identity -> role      (role field set)
      role     -> resource  (role field set)
      identity -> resource  (direct access, role=None)
    """
    role:         Optional[str] = None
    action:       Optional[str] = None
    is_inherited: bool          = False

    @property
    def edge_type(self) -> str:
        return EdgeType.PERMISSION.value

    def __repr__(self) -> str:
        return (
            f"PermissionEdge({self.source_key!r} -> {self.target_key!r}, "
            f"role={self.role!r}, active={self.is_active})"
        )


@dataclass
class TrustEdge(_BaseEdge):
    """
    Trust / impersonation:
      identity -> identity  (ActAs, AssumeRole, GenerateAccessToken, etc.)
    """
    trust_mechanism: str  = "unknown"
    trust_depth:     int  = 1
    is_transitive:   bool = False

    @property
    def edge_type(self) -> str:
        return EdgeType.TRUST.value

    def __repr__(self) -> str:
        return (
            f"TrustEdge({self.source_key!r} -> {self.target_key!r}, "
            f"mechanism={self.trust_mechanism!r}, depth={self.trust_depth})"
        )


@dataclass
class InheritsEdge(_BaseEdge):
    """Role inheritance: role -> role."""
    parent_role: str = ""
    child_role:  str = ""

    @property
    def edge_type(self) -> str:
        return EdgeType.INHERITS.value

    def __repr__(self) -> str:
        return f"InheritsEdge({self.parent_role!r} -> {self.child_role!r})"


@dataclass
class AccessedEdge(_BaseEdge):
    """Direct resource access (no role intermediary): identity -> resource."""
    action:       Optional[str] = None
    access_count: int           = 1

    @property
    def edge_type(self) -> str:
        return EdgeType.ACCESSED.value

    def __repr__(self) -> str:
        return (
            f"AccessedEdge({self.source_key!r} -> {self.target_key!r}, "
            f"action={self.action!r}, count={self.access_count})"
        )


# ---------------------------------------------------------------------------
# Event model
# ---------------------------------------------------------------------------

@dataclass
class BehaviorEvent:
    """
    A single observed IAM / audit log event.

    Fields
    ------
    event_id   : unique identifier (auto-generated UUID4)
    timestamp  : when the event occurred — auto-normalised to UTC
    principal  : who performed the action  e.g. "user:alice@example.com"
    action     : full action string        e.g. "storage.buckets.get"
    resource   : full resource path
    project    : GCP/AWS project or account ID
    role       : IAM role involved (optional)
    success    : whether the action succeeded (False events skipped by GraphBuilder)
    source_ip  : originating IP (optional)
    severity   : event severity classification
    metadata   : arbitrary extra fields from the log source
    """
    timestamp:  datetime
    principal:  str
    action:     str
    resource:   str
    project:    str
    success:    bool            = True
    role:       Optional[str]   = None
    source_ip:  Optional[str]   = None
    severity:   EventSeverity   = EventSeverity.INFO
    metadata:   dict[str, Any]  = field(default_factory=dict)
    event_id:   str             = field(default_factory=lambda: str(uuid.uuid4()))

    def __post_init__(self) -> None:
        self.timestamp = _ensure_utc(self.timestamp)
        if not self.principal:
            raise ValueError("BehaviorEvent.principal must not be empty")
        if not self.action:
            raise ValueError("BehaviorEvent.action must not be empty")
        if not self.resource:
            raise ValueError("BehaviorEvent.resource must not be empty")

    @property
    def action_short(self) -> str:
        return self.action.split(".")[-1].split("/")[-1]

    @property
    def principal_type(self) -> str:
        return self.principal.split(":")[0] if ":" in self.principal else "user"

    @property
    def fingerprint(self) -> str:
        """Stable SHA-256 hash for deduplication."""
        raw = f"{self.principal}|{self.action}|{self.resource}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id":  self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "principal": self.principal,
            "action":    self.action,
            "resource":  self.resource,
            "project":   self.project,
            "role":      self.role,
            "success":   self.success,
            "source_ip": self.source_ip,
            "severity":  self.severity.value,
            "metadata":  self.metadata,
        }

    def __repr__(self) -> str:
        return (
            f"BehaviorEvent({self.principal!r} -> {self.action!r} "
            f"on {self.resource!r} @ {self.timestamp.isoformat()} "
            f"[{'OK' if self.success else 'FAIL'}])"
        )


# ---------------------------------------------------------------------------
# Result / signal models
# ---------------------------------------------------------------------------

@dataclass
class RiskSignal:
    """
    A scored risk signal emitted by any pipeline phase.
    Supports multi-phase aggregation via weighted_score (score * confidence).
    """
    signal_id:           str              = field(default_factory=lambda: str(uuid.uuid4()))
    source_phase:        str              = "unknown"
    anomaly_class:       AnomalyClass     = AnomalyClass.UNKNOWN
    score:               float            = 0.0
    confidence:          float            = 1.0
    affected_identity:   Optional[str]    = None
    affected_resource:   Optional[str]    = None
    description:         str              = ""
    evidence:            dict[str, Any]   = field(default_factory=dict)
    emitted_at:          datetime         = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def __post_init__(self) -> None:
        if not (0.0 <= self.score <= 1.0):
            raise ValueError(f"RiskSignal.score must be in [0,1], got {self.score}")
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"RiskSignal.confidence must be in [0,1], got {self.confidence}")

    @property
    def weighted_score(self) -> float:
        return round(self.score * self.confidence, 4)

    @property
    def risk_tier(self) -> RiskTier:
        return risk_tier_from_score(self.weighted_score)

    def to_dict(self) -> dict[str, Any]:
        return {
            "signal_id":         self.signal_id,
            "source_phase":      self.source_phase,
            "anomaly_class":     self.anomaly_class.value,
            "score":             self.score,
            "confidence":        self.confidence,
            "weighted_score":    self.weighted_score,
            "risk_tier":         self.risk_tier.value,
            "affected_identity": self.affected_identity,
            "affected_resource": self.affected_resource,
            "description":       self.description,
            "evidence":          self.evidence,
            "emitted_at":        self.emitted_at.isoformat(),
        }

    def __repr__(self) -> str:
        return (
            f"RiskSignal({self.anomaly_class.value}, score={self.score:.2f}, "
            f"conf={self.confidence:.2f}, tier={self.risk_tier.value}, "
            f"phase={self.source_phase})"
        )


@dataclass
class AnomalyResult:
    """
    Aggregated anomaly result combining one or more RiskSignals.
    Produced by pipeline stages and consumed by alert_router.
    Score is computed as confidence-weighted mean of all signals.
    """
    result_id:           str                  = field(default_factory=lambda: str(uuid.uuid4()))
    signals:             list[RiskSignal]      = field(default_factory=list)
    final_score:         float                 = 0.0
    risk_tier:           RiskTier              = RiskTier.LOW
    anomaly_classes:     list[AnomalyClass]    = field(default_factory=list)
    affected_identities: list[str]             = field(default_factory=list)
    affected_resources:  list[str]             = field(default_factory=list)
    summary:             str                   = ""
    generated_at:        datetime              = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def add_signal(self, signal: RiskSignal) -> None:
        self.signals.append(signal)
        if signal.anomaly_class not in self.anomaly_classes:
            self.anomaly_classes.append(signal.anomaly_class)
        if signal.affected_identity and signal.affected_identity not in self.affected_identities:
            self.affected_identities.append(signal.affected_identity)
        if signal.affected_resource and signal.affected_resource not in self.affected_resources:
            self.affected_resources.append(signal.affected_resource)
        self._recompute_score()

    def _recompute_score(self) -> None:
        if not self.signals:
            self.final_score = 0.0
        else:
            total_weight = sum(s.confidence for s in self.signals)
            self.final_score = (
                min(1.0, sum(s.score * s.confidence for s in self.signals) / total_weight)
                if total_weight > 0 else 0.0
            )
        self.risk_tier = risk_tier_from_score(self.final_score)

    def to_dict(self) -> dict[str, Any]:
        return {
            "result_id":            self.result_id,
            "final_score":          round(self.final_score, 4),
            "risk_tier":            self.risk_tier.value,
            "anomaly_classes":      [a.value for a in self.anomaly_classes],
            "affected_identities":  self.affected_identities,
            "affected_resources":   self.affected_resources,
            "summary":              self.summary,
            "signal_count":         len(self.signals),
            "signals":              [s.to_dict() for s in self.signals],
            "generated_at":         self.generated_at.isoformat(),
        }


@dataclass
class ValidationResult:
    """
    Result of a formal invariant or schema validation check.
    Used by Invariants.py, P3_formal_invariants.py, Reply_Validator.py.
    """
    check_name:  str
    passed:      bool
    severity:    EventSeverity      = EventSeverity.INFO
    violations:  list[str]          = field(default_factory=list)
    context:     dict[str, Any]     = field(default_factory=dict)
    checked_at:  datetime           = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @property
    def violation_count(self) -> int:
        return len(self.violations)

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_name":      self.check_name,
            "passed":          self.passed,
            "severity":        self.severity.value,
            "violations":      self.violations,
            "violation_count": self.violation_count,
            "context":         self.context,
            "checked_at":      self.checked_at.isoformat(),
        }

    def __repr__(self) -> str:
        status = "PASS" if self.passed else f"FAIL({self.violation_count} violations)"
        return f"ValidationResult({self.check_name!r}, {status})"


# ---------------------------------------------------------------------------
# Audit record — Merkle-ready
# ---------------------------------------------------------------------------

@dataclass
class AuditRecord:
    """
    Immutable audit trail entry written by audit_log.py.
    content_hash is SHA-256 over canonical fields for Merkle tree integration (Phase 3).
    """
    record_id:    str                      = field(default_factory=lambda: str(uuid.uuid4()))
    event:        Optional[BehaviorEvent]  = None
    signal:       Optional[RiskSignal]     = None
    action_taken: str                      = ""
    actor:        str                      = "system"
    timestamp:    datetime                 = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    metadata:     dict[str, Any]           = field(default_factory=dict)

    @property
    def content_hash(self) -> str:
        parts = [self.record_id, self.timestamp.isoformat(),
                 self.action_taken, self.actor]
        if self.event:   parts.append(self.event.fingerprint)
        if self.signal:  parts.append(self.signal.signal_id)
        return hashlib.sha256("|".join(parts).encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_id":    self.record_id,
            "timestamp":    self.timestamp.isoformat(),
            "action_taken": self.action_taken,
            "actor":        self.actor,
            "content_hash": self.content_hash,
            "event":        self.event.to_dict() if self.event else None,
            "signal":       self.signal.to_dict() if self.signal else None,
            "metadata":     self.metadata,
        }