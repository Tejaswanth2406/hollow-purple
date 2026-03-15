"""
api/server.py — Hollow Purple API Server

Full middleware stack + router registration + lifecycle hooks.

Request flow:
    Client
      ↓ RateLimitMiddleware
      ↓ AttackDetectionMiddleware
      ↓ RequestLoggerMiddleware
      ↓ AuditTrailMiddleware
      ↓ CORSMiddleware
      ↓ Authentication (FastAPI Depends)
      ↓ Route Handler
      ↓ Service Layer
      ↓ Core Engine (graph / replay / pipeline)
"""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .middleware import (
    AttackDetectionMiddleware,
    AuditTrailMiddleware,
    RateLimitMiddleware,
    RequestLoggerMiddleware,
)
from .routes import router
from .streaming.event_stream import router as event_router
from .streaming.alert_stream import router as alert_router
from .streaming.graph_updates import router as graph_router

logger = logging.getLogger("hollowpurple.api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle."""
    logger.info("hollow_purple_api_starting")

    # Startup hooks (uncomment when engine is available):
    # await warm_graph_cache()
    # await verify_merkle_tree_head()
    # await connect_event_store()
    # await workers.replay_worker.start()
    # await workers.graph_worker.start()
    # await workers.ingestion_worker.start()
    # await workers.scheduler.start()

    yield

    logger.info("hollow_purple_api_shutdown")


def create_app(
    cors_origins: list[str] | None = None,
    rate_per_sec: int = 10,
    rate_burst: int = 30,
) -> FastAPI:
    """
    Build and configure the FastAPI application.

    Parameters
    ----------
    cors_origins : allowed CORS origins (default: all — tighten in production)
    rate_per_sec : sustained rate limit per IP
    rate_burst   : burst capacity
    """

    app = FastAPI(
        title="Hollow Purple Security Engine",
        version="1.0.0",
        description=(
            "Graph-based cloud identity risk detection engine with "
            "Mahoragha deterministic replay verification."
        ),
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # ------------------------------------------------------------------
    # Security headers
    # ------------------------------------------------------------------
    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"]  = "nosniff"
        response.headers["X-Frame-Options"]         = "DENY"
        response.headers["X-XSS-Protection"]        = "1; mode=block"
        response.headers["Referrer-Policy"]         = "strict-origin-when-cross-origin"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    # ------------------------------------------------------------------
    # Middleware stack (innermost registered last = executes first)
    # ------------------------------------------------------------------
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins or ["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(AuditTrailMiddleware)
    app.add_middleware(RequestLoggerMiddleware)
    app.add_middleware(AttackDetectionMiddleware)
    app.add_middleware(RateLimitMiddleware, rate=rate_per_sec, burst=rate_burst)

    # ------------------------------------------------------------------
    # Global error handler
    # ------------------------------------------------------------------
    @app.exception_handler(Exception)
    async def unhandled_exception(request: Request, exc: Exception):
        logger.exception("unhandled_exception", extra={"path": request.url.path})
        return JSONResponse(
            status_code=500,
            content={"error": "internal_server_error", "detail": str(exc)},
        )

    # ------------------------------------------------------------------
    # REST + WebSocket routers
    # ------------------------------------------------------------------
    app.include_router(router,       prefix="/api/v1")
    app.include_router(event_router, prefix="/stream")
    app.include_router(alert_router, prefix="/stream")
    app.include_router(graph_router, prefix="/stream")

    return app


# Entry point for uvicorn: uvicorn api.server:app --reload
app = create_app()