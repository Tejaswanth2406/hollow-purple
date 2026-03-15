"""
api/schemas.py — Request / Response schemas for Hollow Purple API
All models use strict Pydantic validation.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field, validator


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Provider(str, Enum):
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    OKTA = "okta"
    GITHUB = "github"
    CUSTOM = "custom"


class PipelineStatus(str, Enum):
    OK = "ok"
    DEGRADED = "degraded"
    DOWN = "down"


# ---------------------------------------------------------------------------
# Event Ingestion
# ---------------------------------------------------------------------------

class EventIngestRequest(BaseModel):
    event_id: str = Field(..., min_length=1, max_length=128)
    timestamp: datetime
    actor: str = Field(..., description="Identity performing the action")
    action: str = Field(..., description="Action performed (e.g. AssumeRole)")
    resource: str = Field(..., description="Target resource")
    provider: Provider
    region: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

    @validator("event_id")
    def event_id_no_spaces(cls, v: str) -> str:
        if " " in v:
            raise ValueError("event_id must not contain spaces")
        return v


class EventIngestResponse(BaseModel):
    accepted: bool
    event_id: str
    message: str
    queued_at: datetime = Field(default_factory=datetime.utcnow)


class BulkIngestRequest(BaseModel):
    events: List[EventIngestRequest] = Field(..., min_items=1, max_items=500)


class BulkIngestResponse(BaseModel):
    accepted: int
    rejected: int
    errors: List[Dict[str, str]] = []


# ---------------------------------------------------------------------------
# Risk Graph
# ---------------------------------------------------------------------------

class RiskQueryRequest(BaseModel):
    identity: str = Field(..., description="Identity (user/role/service) to evaluate")
    window_hours: int = Field(default=24, ge=1, le=720)
    include_paths: bool = Field(default=True)
    max_depth: int = Field(default=5, ge=1, le=10)


class RiskPath(BaseModel):
    source: str
    target: str
    privilege: str
    hops: int
    weight: float = Field(..., ge=0.0, le=1.0)


class RiskQueryResponse(BaseModel):
    identity: str
    risk_score: float = Field(..., ge=0.0, le=1.0)
    risk_level: Severity
    exposure_paths: List[RiskPath]
    evaluated_at: datetime = Field(default_factory=datetime.utcnow)
    window_hours: int


class GraphNodeRequest(BaseModel):
    node_id: str
    depth: int = Field(default=2, ge=1, le=5)


class GraphNodeResponse(BaseModel):
    node_id: str
    node_type: str
    edges: List[Dict[str, Any]]
    risk_score: float


# ---------------------------------------------------------------------------
# Replay Verification
# ---------------------------------------------------------------------------

class ReplayRequest(BaseModel):
    start_time: datetime
    end_time: datetime
    identity_filter: Optional[str] = None
    action_filter: Optional[str] = None

    @validator("end_time")
    def end_after_start(cls, v: datetime, values: dict) -> datetime:
        if "start_time" in values and v <= values["start_time"]:
            raise ValueError("end_time must be after start_time")
        return v


class ReplayResponse(BaseModel):
    verified: bool
    events_replayed: int
    divergence_detected: bool
    divergence_count: int = 0
    merkle_root: Optional[str] = None
    replay_duration_ms: float
    verified_at: datetime = Field(default_factory=datetime.utcnow)


# ---------------------------------------------------------------------------
# Health Telemetry
# ---------------------------------------------------------------------------

class ComponentHealth(BaseModel):
    status: PipelineStatus
    latency_ms: Optional[float] = None
    last_event: Optional[datetime] = None
    error: Optional[str] = None


class HealthResponse(BaseModel):
    status: PipelineStatus
    event_pipeline: ComponentHealth
    graph_engine: ComponentHealth
    mahoragha_verifier: ComponentHealth
    event_store: ComponentHealth
    pattern_detector: ComponentHealth
    uptime_seconds: float
    version: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

class Alert(BaseModel):
    alert_id: str
    severity: Severity
    category: str
    message: str
    identity: Optional[str] = None
    resource: Optional[str] = None
    provider: Optional[Provider] = None
    timestamp: datetime
    acknowledged: bool = False
    metadata: Dict[str, Any] = {}


class AlertListResponse(BaseModel):
    alerts: List[Alert]
    total: int
    unacknowledged: int


class AlertAckRequest(BaseModel):
    alert_id: str
    acknowledged_by: str
    note: Optional[str] = None


class AlertAckResponse(BaseModel):
    alert_id: str
    acknowledged: bool
    acknowledged_by: str
    acknowledged_at: datetime = Field(default_factory=datetime.utcnow)


# ---------------------------------------------------------------------------
# Governance
# ---------------------------------------------------------------------------

class PolicyRule(BaseModel):
    rule_id: str
    name: str
    description: str
    condition: str
    action: str
    severity: Severity
    enabled: bool = True


class PolicyCreateRequest(BaseModel):
    name: str
    description: str
    condition: str = Field(..., description="CEL expression for rule evaluation")
    action: str = Field(..., description="Action: block | alert | log")
    severity: Severity
    enabled: bool = True


class PolicyCreateResponse(BaseModel):
    rule_id: str
    name: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    enabled: bool


class PolicyListResponse(BaseModel):
    rules: List[PolicyRule]
    total: int


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

class TokenRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None
    request_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)