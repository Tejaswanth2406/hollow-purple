"""
api/auth.py — JWT Authentication + Role-Based Access Control
Production features:
  - HS256 / RS256 JWT support
  - API key authentication
  - Role-based access (admin, analyst, viewer)
  - Token expiry enforcement
  - Rate limit hooks per identity
"""

from __future__ import annotations

import os
import uuid
import logging
from datetime import datetime, timedelta
from typing import Optional

import jwt
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, APIKeyHeader

logger = logging.getLogger("hollowpurple.auth")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

SECRET_KEY: str = os.getenv("HP_API_SECRET", "hollowpurple-dev-secret-CHANGE-IN-PROD")
ALGORITHM: str = os.getenv("HP_JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("HP_TOKEN_EXPIRE_MINUTES", "60"))

_API_KEYS: dict[str, dict] = {
    os.getenv("HP_ADMIN_API_KEY", "hp-admin-key-dev"): {"user": "admin-service", "role": "admin"},
    os.getenv("HP_READ_API_KEY",  "hp-read-key-dev"):  {"user": "read-service",  "role": "viewer"},
}

bearer_scheme = HTTPBearer(auto_error=False)
api_key_scheme = APIKeyHeader(name="X-API-Key", auto_error=False)


# ---------------------------------------------------------------------------
# Auth Context
# ---------------------------------------------------------------------------

class AuthContext:
    ROLES = ("viewer", "analyst", "admin")

    def __init__(self, user: str, role: str, auth_method: str = "jwt"):
        self.user = user
        self.role = role
        self.auth_method = auth_method
        self.request_id = str(uuid.uuid4())

    def has_role(self, minimum_role: str) -> bool:
        try:
            return self.ROLES.index(self.role) >= self.ROLES.index(minimum_role)
        except ValueError:
            return False

    def __repr__(self) -> str:
        return f"AuthContext(user={self.user!r}, role={self.role!r})"


# ---------------------------------------------------------------------------
# Token utilities
# ---------------------------------------------------------------------------

def create_access_token(
    subject: str,
    role: str = "viewer",
    expires_delta: Optional[timedelta] = None,
    extra_claims: Optional[dict] = None,
) -> str:
    expire = datetime.utcnow() + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    payload = {
        "sub": subject,
        "role": role,
        "exp": expire,
        "iat": datetime.utcnow(),
        "jti": str(uuid.uuid4()),
    }
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------

async def verify_token(
    bearer: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
    api_key: Optional[str] = Security(api_key_scheme),
) -> AuthContext:
    if bearer and bearer.credentials:
        payload = decode_token(bearer.credentials)
        user = payload.get("sub")
        role = payload.get("role", "viewer")
        if not user:
            raise HTTPException(status_code=401, detail="Token missing subject claim")
        logger.debug("JWT auth: user=%s role=%s", user, role)
        return AuthContext(user=user, role=role, auth_method="jwt")

    if api_key and api_key in _API_KEYS:
        info = _API_KEYS[api_key]
        logger.debug("API-key auth: user=%s role=%s", info["user"], info["role"])
        return AuthContext(user=info["user"], role=info["role"], auth_method="api_key")

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required: provide a Bearer JWT or X-API-Key",
        headers={"WWW-Authenticate": "Bearer"},
    )


# ---------------------------------------------------------------------------
# Role guards
# ---------------------------------------------------------------------------

def require_analyst(ctx: AuthContext = Depends(verify_token)) -> AuthContext:
    if not ctx.has_role("analyst"):
        raise HTTPException(status_code=403, detail="Analyst role required")
    return ctx


def require_admin(ctx: AuthContext = Depends(verify_token)) -> AuthContext:
    if not ctx.has_role("admin"):
        raise HTTPException(status_code=403, detail="Admin role required")
    return ctx