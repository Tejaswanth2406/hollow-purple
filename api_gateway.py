"""
API Gateway

The API Gateway provides the REST API interface for Hollow Purple,
serving as the primary interface between analysts/SOC operators and
the underlying control and data planes.

This gateway:
1. Handles authentication and authorization
2. Routes requests to appropriate components
3. Provides unified API responses
4. Implements rate limiting and security controls
5. Offers real-time streaming capabilities
"""

import asyncio
import logging
import os
from collections import defaultdict
from typing import Dict, List, Tuple, Optional, Any, Union, Set
from dataclasses import dataclass
from datetime import datetime, timedelta
import json
import uuid
from enum import Enum
import hashlib
import hmac
import base64
from fastapi import FastAPI, HTTPException, Depends, WebSocket, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
import uvicorn

logger = logging.getLogger(__name__)

class APIEndpoint(Enum):
    """API endpoint categories"""
    THREATS = "threats"
    INCIDENTS = "incidents"
    INVESTIGATIONS = "investigations"
    SIMULATIONS = "simulations"
    POLICIES = "policies"
    REPORTS = "reports"
    SYSTEM = "system"
    STREAMING = "streaming"

class UserRole(Enum):
    """User role levels"""
    ANALYST = "analyst"
    ADMIN = "admin"
    SOC = "soc"
    AUDITOR = "auditor"
    API = "api"

@dataclass
class APIUser:
    """API user configuration"""
    user_id: str
    username: str
    role: UserRole
    permissions: Set[str]
    api_key: str
    active: bool
    created_at: datetime
    last_login: Optional[datetime]

@dataclass
class APIRequest:
    """API request context"""
    request_id: str
    user: APIUser
    endpoint: str
    method: str
    params: Dict[str, Any]
    timestamp: datetime

@dataclass
class APIResponse:
    """API response structure"""
    request_id: str
    status: str
    data: Any
    metadata: Dict[str, Any]
    timestamp: datetime

class APIGateway:
    """
    API Gateway for Hollow Purple

    Provides secure, scalable API access to all system components
    with authentication, authorization, rate limiting, and monitoring.
    """

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or self._default_config()

        # User management
        self.users: Dict[str, APIUser] = {}
        self.api_keys: Dict[str, str] = {}  # api_key -> user_id

        # Rate limiting
        self.rate_limits: Dict[str, Dict[str, Any]] = {}
        self.request_counts: Dict[str, int] = {}

        # Active connections
        self.websocket_connections: Dict[str, WebSocket] = {}
        self.streaming_subscriptions: Dict[str, Set[str]] = defaultdict(set)

        # Request/response tracking
        self.request_log: List[APIRequest] = []
        self.response_cache: Dict[str, APIResponse] = {}

        # Security
        self.security_token = self._generate_security_token()

        # Initialize default users
        self._create_default_users()

        # Create FastAPI app
        self.app = self._create_fastapi_app()

        logger.info("API Gateway initialized")

    def _default_config(self) -> Dict[str, Any]:
        """Default configuration"""
        return {
            'host': '0.0.0.0',
            'port': 8000,
            'cors_origins': ['*'],  # Configure appropriately for production
            'rate_limit_requests': 1000,  # per minute
            'rate_limit_window': 60,  # seconds
            'request_timeout': 30,  # seconds
            'cache_ttl': 300,  # 5 minutes
            'enable_websockets': True,
            'enable_streaming': True,
            'log_requests': True
        }

    def _generate_security_token(self) -> str:
        """Generate security token for internal communication"""
        return base64.b64encode(uuid.uuid4().bytes).decode()

    def _create_default_users(self):
        """Create default API users"""
        default_users = [
            APIUser(
                user_id="admin_user",
                username="admin",
                role=UserRole.ADMIN,
                permissions={"*"},  # All permissions
                api_key=self._generate_api_key(),
                active=True,
                created_at=datetime.now(),
                last_login=None
            ),
            APIUser(
                user_id="soc_user",
                username="soc_analyst",
                role=UserRole.SOC,
                permissions={
                    "threats:read", "incidents:read", "investigations:*",
                    "simulations:read", "reports:read", "streaming:read"
                },
                api_key=self._generate_api_key(),
                active=True,
                created_at=datetime.now(),
                last_login=None
            ),
            APIUser(
                user_id="analyst_user",
                username="analyst",
                role=UserRole.ANALYST,
                permissions={
                    "threats:read", "incidents:read", "investigations:read",
                    "reports:read", "streaming:read"
                },
                api_key=self._generate_api_key(),
                active=True,
                created_at=datetime.now(),
                last_login=None
            )
        ]

        for user in default_users:
            self.users[user.user_id] = user
            self.api_keys[user.api_key] = user.user_id

            print(f"Created user: {user.username} (API Key: {user.api_key[:8]}...)")

    def _generate_api_key(self) -> str:
        """Generate a secure API key"""
        return base64.b64encode(uuid.uuid4().bytes + uuid.uuid4().bytes).decode()[:32]

    def _create_fastapi_app(self) -> FastAPI:
        """Create and configure FastAPI application"""
        app = FastAPI(
            title="Hollow Purple API",
            description="Enterprise Autonomous Cyber Defense Platform",
            version="2.0.0",
            docs_url="/docs",
            redoc_url="/redoc"
        )

        # CORS middleware
        app.add_middleware(
            CORSMiddleware,
            allow_origins=self.config['cors_origins'],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

        # Security scheme
        security = HTTPBearer()

        # Dependency for authentication
        async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> APIUser:
            return self._authenticate_user(credentials.credentials)

        # Routes
        @app.get("/")
        async def root():
            return {"message": "Hollow Purple API Gateway", "version": "2.0.0"}

        @app.get("/health")
        async def health_check():
            return {"status": "healthy", "timestamp": datetime.now().isoformat()}

        @app.get("/threats")
        async def get_threats(current_user: APIUser = Depends(get_current_user)):
            return await self._handle_request("GET", "/threats", {}, current_user)

        @app.get("/threats/{threat_id}")
        async def get_threat(threat_id: str, current_user: APIUser = Depends(get_current_user)):
            return await self._handle_request("GET", f"/threats/{threat_id}", {"threat_id": threat_id}, current_user)

        @app.get("/incidents")
        async def get_incidents(current_user: APIUser = Depends(get_current_user)):
            return await self._handle_request("GET", "/incidents", {}, current_user)

        @app.post("/incidents/{incident_id}/investigate")
        async def investigate_incident(incident_id: str, current_user: APIUser = Depends(get_current_user)):
            return await self._handle_request("POST", f"/incidents/{incident_id}/investigate", {"incident_id": incident_id}, current_user)

        @app.get("/simulations")
        async def get_simulations(current_user: APIUser = Depends(get_current_user)):
            return await self._handle_request("GET", "/simulations", {}, current_user)

        @app.post("/simulations")
        async def start_simulation(simulation_config: Dict[str, Any], current_user: APIUser = Depends(get_current_user)):
            return await self._handle_request("POST", "/simulations", simulation_config, current_user)

        @app.get("/policies")
        async def get_policies(current_user: APIUser = Depends(get_current_user)):
            return await self._handle_request("GET", "/policies", {}, current_user)

        @app.post("/policies")
        async def create_policy(policy_config: Dict[str, Any], current_user: APIUser = Depends(get_current_user)):
            return await self._handle_request("POST", "/policies", policy_config, current_user)

        @app.get("/reports/{report_type}")
        async def get_report(report_type: str, current_user: APIUser = Depends(get_current_user)):
            return await self._handle_request("GET", f"/reports/{report_type}", {"report_type": report_type}, current_user)

        @app.get("/system/status")
        async def get_system_status(current_user: APIUser = Depends(get_current_user)):
            return await self._handle_request("GET", "/system/status", {}, current_user)

        @app.get("/system/metrics")
        async def get_system_metrics(current_user: APIUser = Depends(get_current_user)):
            return await self._handle_request("GET", "/system/metrics", {}, current_user)

        # WebSocket endpoint for real-time streaming
        @app.websocket("/ws")
        async def websocket_endpoint(websocket: WebSocket, token: str):
            await websocket.accept()

            # Authenticate WebSocket connection
            user = self._authenticate_websocket(token)
            if not user:
                await websocket.close(code=1008)  # Policy violation
                return

            connection_id = str(uuid.uuid4())
            self.websocket_connections[connection_id] = websocket

            try:
                while True:
                    # Keep connection alive and handle subscriptions
                    data = await websocket.receive_text()
                    await self._handle_websocket_message(connection_id, data, user)
            except Exception as e:
                logger.error(f"WebSocket error: {e}")
            finally:
                if connection_id in self.websocket_connections:
                    del self.websocket_connections[connection_id]

        # Streaming endpoints
        @app.get("/stream/threats")
        async def stream_threats(current_user: APIUser = Depends(get_current_user)):
            return StreamingResponse(
                self._stream_threats(current_user),
                media_type="text/plain"
            )

        @app.get("/stream/incidents")
        async def stream_incidents(current_user: APIUser = Depends(get_current_user)):
            return StreamingResponse(
                self._stream_incidents(current_user),
                media_type="text/plain"
            )

        return app

    def _authenticate_user(self, api_key: str) -> APIUser:
        """Authenticate user by API key"""
        if api_key not in self.api_keys:
            raise HTTPException(status_code=401, detail="Invalid API key")

        user_id = self.api_keys[api_key]
        user = self.users[user_id]

        if not user.active:
            raise HTTPException(status_code=401, detail="User account disabled")

        # Update last login
        user.last_login = datetime.now()

        # Check rate limiting
        if not self._check_rate_limit(user.user_id):
            raise HTTPException(status_code=429, detail="Rate limit exceeded")

        return user

    def _authenticate_websocket(self, token: str) -> Optional[APIUser]:
        """Authenticate WebSocket connection"""
        try:
            return self._authenticate_user(token)
        except:
            return None

    def _check_rate_limit(self, user_id: str) -> bool:
        """Check if user is within rate limits"""
        now = datetime.now()
        window_key = f"{user_id}_{now.minute}"

        if window_key not in self.rate_limits:
            self.rate_limits[window_key] = {
                'count': 0,
                'reset_time': now + timedelta(seconds=self.config['rate_limit_window'])
            }

        limit_data = self.rate_limits[window_key]

        # Reset if window expired
        if now >= limit_data['reset_time']:
            limit_data['count'] = 0
            limit_data['reset_time'] = now + timedelta(seconds=self.config['rate_limit_window'])

        # Check limit
        if limit_data['count'] >= self.config['rate_limit_requests']:
            return False

        limit_data['count'] += 1
        return True

    def _check_permissions(self, user: APIUser, endpoint: str, method: str) -> bool:
        """Check if user has permission for the endpoint"""
        if "*" in user.permissions:
            return True

        required_permission = f"{endpoint}:{method.lower()}"
        return required_permission in user.permissions

    async def _handle_request(self, method: str, endpoint: str, params: Dict[str, Any], user: APIUser) -> Dict[str, Any]:
        """Handle API request"""
        request_id = str(uuid.uuid4())

        # Check permissions
        if not self._check_permissions(user, endpoint.split('/')[1], method):
            raise HTTPException(status_code=403, detail="Insufficient permissions")

        # Create request context
        request = APIRequest(
            request_id=request_id,
            user=user,
            endpoint=endpoint,
            method=method,
            params=params,
            timestamp=datetime.now()
        )

        if self.config['log_requests']:
            self.request_log.append(request)

        try:
            # Route to appropriate handler
            response_data = await self._route_request(request)

            response = APIResponse(
                request_id=request_id,
                status="success",
                data=response_data,
                metadata={"user": user.username, "endpoint": endpoint},
                timestamp=datetime.now()
            )

            # Cache response
            self.response_cache[request_id] = response

            return response.data

        except Exception as e:
            logger.error(f"Request handling failed: {e}")

            response = APIResponse(
                request_id=request_id,
                status="error",
                data={"error": str(e)},
                metadata={"user": user.username, "endpoint": endpoint},
                timestamp=datetime.now()
            )

            return response.data

    async def _route_request(self, request: APIRequest) -> Any:
        """Route request to appropriate component"""
        endpoint_parts = request.endpoint.strip('/').split('/')

        if endpoint_parts[0] == 'threats':
            return await self._handle_threats_request(request)
        elif endpoint_parts[0] == 'incidents':
            return await self._handle_incidents_request(request)
        elif endpoint_parts[0] == 'simulations':
            return await self._handle_simulations_request(request)
        elif endpoint_parts[0] == 'policies':
            return await self._handle_policies_request(request)
        elif endpoint_parts[0] == 'reports':
            return await self._handle_reports_request(request)
        elif endpoint_parts[0] == 'system':
            return await self._handle_system_request(request)
        else:
            raise HTTPException(status_code=404, detail="Endpoint not found")

    async def _handle_threats_request(self, request: APIRequest) -> Any:
        """Handle threats-related requests"""
        # Route to data plane for threat intelligence
        from ingestion.orchestrator import ingestion_orchestrator

        if request.method == "GET":
            if len(request.endpoint.split('/')) == 2:  # /threats
                # Get all threats
                return await ingestion_orchestrator.get_recent_threats()
            else:  # /threats/{id}
                threat_id = request.params.get('threat_id')
                return await ingestion_orchestrator.get_threat_details(threat_id)

        return {"message": "Threats endpoint"}

    async def _handle_incidents_request(self, request: APIRequest) -> Any:
        """Handle incidents-related requests"""
        from engine.orchestrator import engine_orchestrator

        if request.method == "GET":
            return await engine_orchestrator.get_active_incidents()
        elif request.method == "POST" and "investigate" in request.endpoint:
            incident_id = request.params.get('incident_id')
            return await engine_orchestrator.investigate_incident(incident_id, request.user.user_id)

        return {"message": "Incidents endpoint"}

    async def _handle_simulations_request(self, request: APIRequest) -> Any:
        """Handle simulation-related requests"""
        from control_plane.simulation_orchestrator import simulation_orchestrator

        if request.method == "GET":
            return simulation_orchestrator.get_simulation_metrics()
        elif request.method == "POST":
            scenario_id = request.params.get('scenario_id', 'phishing_attack_chain')
            return await simulation_orchestrator.start_simulation(scenario_id, request.params)

        return {"message": "Simulations endpoint"}

    async def _handle_policies_request(self, request: APIRequest) -> Any:
        """Handle policy-related requests"""
        from control_plane.policy_enforcement import policy_engine

        if request.method == "GET":
            return policy_engine.get_policy_metrics()
        elif request.method == "POST":
            return policy_engine.add_policy(request.params)

        return {"message": "Policies endpoint"}

    async def _handle_reports_request(self, request: APIRequest) -> Any:
        """Handle reports-related requests"""
        from control_plane.ai_reasoning import AIReasoningLayer

        reasoning = AIReasoningLayer()
        report_type = request.params.get('report_type', 'threat_summary')

        if report_type == 'threat_summary':
            return await reasoning.generate_threat_summary()
        elif report_type == 'system_health':
            return await reasoning.assess_system_health()
        elif report_type == 'compliance':
            return await reasoning.generate_compliance_report()

        return {"message": "Reports endpoint"}

    async def _handle_system_request(self, request: APIRequest) -> Any:
        """Handle system-related requests"""
        if "status" in request.endpoint:
            # Get overall system status
            return await self._get_system_status()
        elif "metrics" in request.endpoint:
            # Get system metrics
            return await self._get_system_metrics()

        return {"message": "System endpoint"}

    async def _get_system_status(self) -> Dict[str, Any]:
        """Get overall system status"""
        # Aggregate status from all components
        status = {
            "overall_health": "healthy",
            "components": {},
            "timestamp": datetime.now().isoformat()
        }

        # Check control plane
        try:
            from control_plane.orchestrator import orchestrator
            status["components"]["control_plane"] = "healthy"
        except:
            status["components"]["control_plane"] = "unavailable"

        # Check data plane
        try:
            from ingestion.orchestrator import ingestion_orchestrator
            status["components"]["data_plane"] = "healthy"
        except:
            status["components"]["data_plane"] = "unavailable"

        return status

    async def _get_system_metrics(self) -> Dict[str, Any]:
        """Get system-wide metrics"""
        metrics = {
            "control_plane": {},
            "data_plane": {},
            "overall": {}
        }

        # Control plane metrics
        try:
            from control_plane.orchestrator import orchestrator
            metrics["control_plane"] = orchestrator.get_metrics()
        except:
            metrics["control_plane"] = {"status": "unavailable"}

        # Data plane metrics
        try:
            from ingestion.orchestrator import ingestion_orchestrator
            metrics["data_plane"] = await ingestion_orchestrator.get_metrics()
        except:
            metrics["data_plane"] = {"status": "unavailable"}

        return metrics

    async def _handle_websocket_message(self, connection_id: str, message: str, user: APIUser):
        """Handle WebSocket message"""
        try:
            data = json.loads(message)

            if data.get('type') == 'subscribe':
                stream_type = data.get('stream')
                self.streaming_subscriptions[stream_type].add(connection_id)

            elif data.get('type') == 'unsubscribe':
                stream_type = data.get('stream')
                self.streaming_subscriptions[stream_type].discard(connection_id)

        except Exception as e:
            logger.error(f"WebSocket message handling failed: {e}")

    async def _stream_threats(self, user: APIUser):
        """Stream real-time threat data"""
        # Simplified streaming - would integrate with actual event streams
        while True:
            threat_data = {
                "timestamp": datetime.now().isoformat(),
                "threats_detected": 0,
                "high_priority": 0
            }

            yield f"data: {json.dumps(threat_data)}\n\n"
            await asyncio.sleep(5)  # Update every 5 seconds

    async def _stream_incidents(self, user: APIUser):
        """Stream real-time incident data"""
        while True:
            incident_data = {
                "timestamp": datetime.now().isoformat(),
                "active_incidents": 0,
                "new_incidents": 0
            }

            yield f"data: {json.dumps(incident_data)}\n\n"
            await asyncio.sleep(10)  # Update every 10 seconds

    async def broadcast_to_subscribers(self, stream_type: str, data: Dict[str, Any]):
        """Broadcast data to WebSocket subscribers"""
        if stream_type in self.streaming_subscriptions:
            message = json.dumps({
                "type": "update",
                "stream": stream_type,
                "data": data,
                "timestamp": datetime.now().isoformat()
            })

            disconnected = []
            for connection_id in self.streaming_subscriptions[stream_type]:
                if connection_id in self.websocket_connections:
                    try:
                        await self.websocket_connections[connection_id].send_text(message)
                    except:
                        disconnected.append(connection_id)

            # Clean up disconnected clients
            for conn_id in disconnected:
                self.streaming_subscriptions[stream_type].discard(conn_id)
                if conn_id in self.websocket_connections:
                    del self.websocket_connections[conn_id]

    def create_user(self, username: str, role: UserRole, permissions: Set[str]) -> str:
        """Create a new API user"""
        user_id = str(uuid.uuid4())
        api_key = self._generate_api_key()

        user = APIUser(
            user_id=user_id,
            username=username,
            role=role,
            permissions=permissions,
            api_key=api_key,
            active=True,
            created_at=datetime.now(),
            last_login=None
        )

        self.users[user_id] = user
        self.api_keys[api_key] = user_id

        logger.info(f"Created API user: {username} ({user_id})")
        return api_key

    def get_api_metrics(self) -> Dict[str, Any]:
        """Get API gateway metrics"""
        return {
            "total_requests": len(self.request_log),
            "active_connections": len(self.websocket_connections),
            "active_users": sum(1 for user in self.users.values() if user.active),
            "rate_limit_violations": sum(1 for limit in self.rate_limits.values() if limit['count'] >= self.config['rate_limit_requests']),
            "cached_responses": len(self.response_cache)
        }

    async def start_server(self):
        """Start the API server"""
        logger.info(f"Starting API Gateway on {self.config['host']}:{self.config['port']}")

        config = uvicorn.Config(
            self.app,
            host=self.config['host'],
            port=self.config['port'],
            log_level="info"
        )

        server = uvicorn.Server(config)
        await server.serve()

# Global API gateway instance
api_gateway = APIGateway()

# Convenience functions
def get_api_key_for_user(username: str) -> Optional[str]:
    """Get API key for a username"""
    for user in api_gateway.users.values():
        if user.username == username:
            return user.api_key
    return None

async def start_api_gateway():
    """Start the API gateway server"""
    await api_gateway.start_server()

# Export the API gateway app for ASGI deployment.
app = api_gateway.app

if __name__ == "__main__":
    host = os.getenv("HP_API_HOST", "0.0.0.0")
    port = int(os.getenv("HP_API_PORT", 8000))
    uvicorn.run(app, host=host, port=port, log_level="info")
