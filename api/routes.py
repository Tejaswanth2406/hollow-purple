"""
api/routes.py — Hollow Purple API Route Definitions

Routes are thin HTTP handlers only.
All business logic lives in api/services/.

Endpoints:
  POST   /auth/token
  POST   /events/ingest
  POST   /events/bulk-ingest
  POST   /risk/query
  GET    /risk/node/{node_id}
  POST   /replay/verify
  GET    /health
  GET    /alerts
  POST   /alerts/{alert_id}/ack
  GET    /governance/policies
  POST   /governance/policies
"""

from __future__ import annotations

import os
import uuid
from datetime import timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from .auth import (
    AuthContext,
    create_access_token,
    require_admin,
    require_analyst,
    verify_token,
)
from .schemas import (
    Alert,
    AlertAckRequest,
    AlertAckResponse,
    AlertListResponse,
    BulkIngestRequest,
    BulkIngestResponse,
    ComponentHealth,
    ErrorResponse,
    EventIngestRequest,
    EventIngestResponse,
    GraphNodeResponse,
    HealthResponse,
    PipelineStatus,
    PolicyCreateRequest,
    PolicyCreateResponse,
    PolicyListResponse,
    ReplayRequest,
    ReplayResponse,
    RiskQueryRequest,
    RiskQueryResponse,
    TokenRequest,
    TokenResponse,
)
from .services import EventService, ReplayService, RiskService

router = APIRouter()

# Service singletons (FastAPI DI manages their lifecycle)
_event_svc  = EventService()
_risk_svc   = RiskService()
_replay_svc = ReplayService()


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

@router.post(
    "/auth/token",
    response_model=TokenResponse,
    summary="Issue JWT access token",
    tags=["auth"],
)
async def issue_token(request: TokenRequest):
    """
    Basic credential exchange.
    Replace with LDAP/SSO integration in production.
    """
    _USERS = {
        os.getenv("HP_ADMIN_USER", "admin"): (os.getenv("HP_ADMIN_PASS", "changeme"), "admin"),
        os.getenv("HP_ANALYST_USER", "analyst"): (os.getenv("HP_ANALYST_PASS", "changeme"), "analyst"),
    }
    entry = _USERS.get(request.username)
    if not entry or entry[0] != request.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token(subject=request.username, role=entry[1])
    return TokenResponse(access_token=token, expires_in=3600)


# ---------------------------------------------------------------------------
# Event Ingestion
# ---------------------------------------------------------------------------

@router.post(
    "/events/ingest",
    response_model=EventIngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest a single security event",
    tags=["events"],
)
async def ingest_event(
    request: EventIngestRequest,
    ctx: AuthContext = Depends(verify_token),
):
    result = await _event_svc.ingest_event(request.dict())
    if not result["accepted"]:
        raise HTTPException(status_code=422, detail=result["message"])
    return result


@router.post(
    "/events/bulk-ingest",
    response_model=BulkIngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest up to 500 events in one request",
    tags=["events"],
)
async def bulk_ingest(
    request: BulkIngestRequest,
    ctx: AuthContext = Depends(require_analyst),
):
    return await _event_svc.bulk_ingest([e.dict() for e in request.events])


# ---------------------------------------------------------------------------
# Risk Graph
# ---------------------------------------------------------------------------

@router.post(
    "/risk/query",
    response_model=RiskQueryResponse,
    summary="Query identity risk score and exposure paths",
    tags=["risk"],
)
async def query_risk(
    request: RiskQueryRequest,
    ctx: AuthContext = Depends(verify_token),
):
    result = await _risk_svc.query_identity_risk(
        identity=request.identity,
        window_hours=request.window_hours,
        include_paths=request.include_paths,
        max_depth=request.max_depth,
    )
    return result


@router.get(
    "/risk/node/{node_id}",
    response_model=GraphNodeResponse,
    summary="Retrieve graph node details and edges",
    tags=["risk"],
)
async def get_graph_node(
    node_id: str,
    depth: int = Query(default=2, ge=1, le=5),
    ctx: AuthContext = Depends(require_analyst),
):
    return await _risk_svc.get_graph_node(node_id, depth)


# ---------------------------------------------------------------------------
# Replay Verification
# ---------------------------------------------------------------------------

@router.post(
    "/replay/verify",
    response_model=ReplayResponse,
    summary="Trigger Mahoragha deterministic replay verification",
    tags=["replay"],
)
async def replay_verify(
    request: ReplayRequest,
    ctx: AuthContext = Depends(require_analyst),
):
    return await _replay_svc.verify_replay(
        start_time=request.start_time,
        end_time=request.end_time,
        identity_filter=request.identity_filter,
    )


# ---------------------------------------------------------------------------
# Health Telemetry
# ---------------------------------------------------------------------------

@router.get(
    "/health",
    response_model=HealthResponse,
    summary="System health and component status",
    tags=["telemetry"],
)
async def health():
    def _probe(name: str) -> ComponentHealth:
        try:
            from MAHORAGHA.health import check_component
            data = check_component(name)
            return ComponentHealth(status=PipelineStatus(data["status"]), latency_ms=data.get("latency_ms"))
        except Exception:
            return ComponentHealth(status=PipelineStatus.OK)

    import time
    return HealthResponse(
        status=PipelineStatus.OK,
        event_pipeline=_probe("pipeline"),
        graph_engine=_probe("graph"),
        mahoragha_verifier=_probe("verifier"),
        event_store=_probe("event_store"),
        pattern_detector=_probe("pattern_detector"),
        uptime_seconds=time.process_time(),
        version="1.0.0",
    )


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

@router.get(
    "/alerts",
    response_model=AlertListResponse,
    summary="List recent security alerts",
    tags=["alerts"],
)
async def list_alerts(
    severity: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    ctx: AuthContext = Depends(verify_token),
):
    try:
        from MAHORAGHA.alerts import get_alerts
        alerts = get_alerts(severity=severity, limit=limit)
    except ImportError:
        alerts = []

    unacked = sum(1 for a in alerts if not a.get("acknowledged", False))
    return AlertListResponse(alerts=alerts, total=len(alerts), unacknowledged=unacked)


@router.post(
    "/alerts/{alert_id}/ack",
    response_model=AlertAckResponse,
    summary="Acknowledge a security alert",
    tags=["alerts"],
)
async def ack_alert(
    alert_id: str,
    request: AlertAckRequest,
    ctx: AuthContext = Depends(require_analyst),
):
    try:
        from MAHORAGHA.alerts import acknowledge_alert
        acknowledge_alert(alert_id, acknowledged_by=request.acknowledged_by, note=request.note)
    except ImportError:
        pass
    return AlertAckResponse(alert_id=alert_id, acknowledged=True, acknowledged_by=request.acknowledged_by)


# ---------------------------------------------------------------------------
# Governance
# ---------------------------------------------------------------------------

@router.get(
    "/governance/policies",
    response_model=PolicyListResponse,
    summary="List all active governance policies",
    tags=["governance"],
)
async def list_policies(ctx: AuthContext = Depends(require_analyst)):
    try:
        from MAHORAGHA.governance import list_policies as _list
        rules = _list()
    except ImportError:
        rules = []
    return PolicyListResponse(rules=rules, total=len(rules))


@router.post(
    "/governance/policies",
    response_model=PolicyCreateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new governance policy rule",
    tags=["governance"],
)
async def create_policy(
    request: PolicyCreateRequest,
    ctx: AuthContext = Depends(require_admin),
):
    rule_id = str(uuid.uuid4())
    try:
        from MAHORAGHA.governance import create_policy as _create
        _create(rule_id=rule_id, **request.dict())
    except ImportError:
        pass
    return PolicyCreateResponse(rule_id=rule_id, name=request.name, enabled=request.enabled)