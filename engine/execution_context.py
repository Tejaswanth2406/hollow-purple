"""
engine/execution_context.py
============================
Enterprise-grade execution context propagation layer.

Features
--------
- Async-safe ContextVar propagation across coroutines and tasks
- Full request lifecycle tracking (request_id, trace_id, span_id)
- Multi-tenant isolation
- Structured metadata for logging, tracing, and auditing
- OpenTelemetry-compatible trace/span IDs
- Context serialization for deterministic replay
- Middleware integration hook for ASGI/WSGI frameworks
"""

from __future__ import annotations

import uuid
import time
import logging
import contextvars
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, Optional


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# ContextVars — async-safe, task-local storage
# ---------------------------------------------------------------------------

_ctx_request_id: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "request_id", default=None
)
_ctx_trace_id: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "trace_id", default=None
)
_ctx_span_id: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "span_id", default=None
)
_ctx_tenant_id: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "tenant_id", default=None
)
_ctx_user_id: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "user_id", default=None
)
_ctx_correlation_id: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "correlation_id", default=None
)
_ctx_instance: contextvars.ContextVar[Optional["ExecutionContext"]] = (
    contextvars.ContextVar("execution_context", default=None)
)


# ---------------------------------------------------------------------------
# Public accessor — retrieve current context from any coroutine
# ---------------------------------------------------------------------------


def get_current_context() -> Optional["ExecutionContext"]:
    """Return the active ExecutionContext for the current async task, or None."""
    return _ctx_instance.get()


# ---------------------------------------------------------------------------
# Core dataclass
# ---------------------------------------------------------------------------


@dataclass
class ExecutionContext:
    """
    Immutable-by-convention context record propagated across async boundaries.

    Lifecycle
    ---------
    1. Construct via ``ExecutionContext.create(...)``
    2. Call ``ctx.activate()`` — binds to ContextVars for the current task
    3. Use as async context manager for automatic bind/unbind + timing

    All IDs follow UUID4 format for uniqueness and observability compatibility.
    Trace/Span IDs are also formatted as 32-char hex strings to match
    OpenTelemetry W3C trace-context headers.
    """

    request_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    trace_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    span_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    tenant_id: Optional[str] = field(default=None)
    user_id: Optional[str] = field(default=None)
    correlation_id: Optional[str] = field(default=None)
    environment: str = field(default="production")
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Internal timing — set on activation
    _start_ns: int = field(default=0, repr=False, compare=False)
    _start_utc: str = field(default="", repr=False, compare=False)

    # ---------------------------------------------------------------------------
    # Factories
    # ---------------------------------------------------------------------------

    @classmethod
    def create(
        cls,
        *,
        tenant_id: Optional[str] = None,
        user_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        environment: str = "production",
        metadata: Optional[Dict[str, Any]] = None,
        trace_id: Optional[str] = None,
    ) -> "ExecutionContext":
        """
        Named constructor — preferred over direct instantiation.

        Parameters
        ----------
        tenant_id       : Tenant/org identifier for multi-tenant systems.
        user_id         : Authenticated user performing the operation.
        correlation_id  : External request ID (e.g. from upstream gateway).
        environment     : Runtime environment label (production/staging/dev).
        metadata        : Arbitrary key-value annotations.
        trace_id        : Provide an existing trace ID to continue a trace chain.
        """
        return cls(
            tenant_id=tenant_id,
            user_id=user_id,
            correlation_id=correlation_id,
            environment=environment,
            metadata=metadata or {},
            trace_id=trace_id or uuid.uuid4().hex,
        )

    @classmethod
    def from_headers(cls, headers: Dict[str, str]) -> "ExecutionContext":
        """
        Reconstruct context from HTTP/gRPC headers.
        Supports W3C traceparent header and custom X- headers.

        Expected headers (case-insensitive)
        ------------------------------------
        traceparent          : W3C trace-context (00-{trace_id}-{span_id}-{flags})
        x-request-id         : Upstream request identifier
        x-tenant-id          : Tenant identifier
        x-user-id            : Authenticated user
        x-correlation-id     : External correlation handle
        """
        headers_lower = {k.lower(): v for k, v in headers.items()}

        trace_id = None
        span_id = None
        traceparent = headers_lower.get("traceparent", "")
        if traceparent:
            parts = traceparent.split("-")
            if len(parts) == 4:
                trace_id = parts[1]
                span_id = parts[2]

        ctx = cls.create(
            tenant_id=headers_lower.get("x-tenant-id"),
            user_id=headers_lower.get("x-user-id"),
            correlation_id=headers_lower.get("x-correlation-id")
            or headers_lower.get("x-request-id"),
            trace_id=trace_id,
        )
        if span_id:
            object.__setattr__(ctx, "span_id", span_id)
        return ctx

    # ---------------------------------------------------------------------------
    # Activation
    # ---------------------------------------------------------------------------

    def activate(self) -> "ExecutionContext":
        """
        Bind this context to the current async task via ContextVars.
        Returns self for chaining.
        """
        now = datetime.now(timezone.utc)
        object.__setattr__(self, "_start_ns", time.perf_counter_ns())
        object.__setattr__(self, "_start_utc", now.isoformat())

        _ctx_request_id.set(self.request_id)
        _ctx_trace_id.set(self.trace_id)
        _ctx_span_id.set(self.span_id)
        _ctx_tenant_id.set(self.tenant_id)
        _ctx_user_id.set(self.user_id)
        _ctx_correlation_id.set(self.correlation_id)
        _ctx_instance.set(self)

        logger.debug(
            "ExecutionContext activated",
            extra={
                "request_id": self.request_id,
                "trace_id": self.trace_id,
                "tenant_id": self.tenant_id,
                "environment": self.environment,
            },
        )
        return self

    def deactivate(self) -> None:
        """Clear context bindings from ContextVars."""
        for var in (
            _ctx_request_id,
            _ctx_trace_id,
            _ctx_span_id,
            _ctx_tenant_id,
            _ctx_user_id,
            _ctx_correlation_id,
            _ctx_instance,
        ):
            var.set(None)  # type: ignore[arg-type]

    # ---------------------------------------------------------------------------
    # Context managers
    # ---------------------------------------------------------------------------

    @asynccontextmanager
    async def scope(self):
        """
        Async context manager that activates and deactivates the context,
        and logs total elapsed time on exit.

        Usage::

            async with ctx.scope():
                await do_work()
        """
        self.activate()
        try:
            yield self
        finally:
            elapsed_ms = (time.perf_counter_ns() - self._start_ns) / 1_000_000
            logger.info(
                "ExecutionContext scope completed",
                extra={
                    "request_id": self.request_id,
                    "trace_id": self.trace_id,
                    "elapsed_ms": round(elapsed_ms, 3),
                },
            )
            self.deactivate()

    @contextmanager
    def sync_scope(self):
        """Synchronous variant of ``scope()`` for non-async call sites."""
        self.activate()
        try:
            yield self
        finally:
            self.deactivate()

    # ---------------------------------------------------------------------------
    # Child span creation
    # ---------------------------------------------------------------------------

    def child_span(self, *, metadata: Optional[Dict[str, Any]] = None) -> "ExecutionContext":
        """
        Derive a child context with a new span_id, inheriting the trace chain.
        Use this when spawning sub-operations that should share the same trace.
        """
        child = ExecutionContext.create(
            tenant_id=self.tenant_id,
            user_id=self.user_id,
            correlation_id=self.correlation_id,
            environment=self.environment,
            metadata={**self.metadata, **(metadata or {})},
            trace_id=self.trace_id,  # same trace
        )
        return child

    # ---------------------------------------------------------------------------
    # Serialization
    # ---------------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """
        Serialize context to a plain dict suitable for structured logging,
        audit trails, or deterministic replay payloads.
        """
        return {
            "request_id": self.request_id,
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "tenant_id": self.tenant_id,
            "user_id": self.user_id,
            "correlation_id": self.correlation_id,
            "environment": self.environment,
            "start_utc": self._start_utc,
            "metadata": self.metadata,
        }

    def to_headers(self) -> Dict[str, str]:
        """
        Emit propagation headers for outbound HTTP/gRPC calls.
        Compatible with W3C Trace Context spec.
        """
        headers: Dict[str, str] = {
            "traceparent": f"00-{self.trace_id}-{self.span_id}-01",
            "x-request-id": self.request_id,
        }
        if self.tenant_id:
            headers["x-tenant-id"] = self.tenant_id
        if self.user_id:
            headers["x-user-id"] = self.user_id
        if self.correlation_id:
            headers["x-correlation-id"] = self.correlation_id
        return headers

    # ---------------------------------------------------------------------------
    # Static accessors — read current context without holding a reference
    # ---------------------------------------------------------------------------

    @staticmethod
    def current_request_id() -> Optional[str]:
        return _ctx_request_id.get()

    @staticmethod
    def current_trace_id() -> Optional[str]:
        return _ctx_trace_id.get()

    @staticmethod
    def current_span_id() -> Optional[str]:
        return _ctx_span_id.get()

    @staticmethod
    def current_tenant_id() -> Optional[str]:
        return _ctx_tenant_id.get()

    @staticmethod
    def current_user_id() -> Optional[str]:
        return _ctx_user_id.get()


# ---------------------------------------------------------------------------
# ASGI Middleware helper
# ---------------------------------------------------------------------------


class ExecutionContextMiddleware:
    """
    Lightweight ASGI middleware that creates and activates an ExecutionContext
    for each incoming request, then propagates it via ContextVars.

    Compatible with Starlette, FastAPI, and any ASGI-compliant framework.

    Usage (FastAPI)::

        from fastapi import FastAPI
        from engine.execution_context import ExecutionContextMiddleware

        app = FastAPI()
        app.add_middleware(ExecutionContextMiddleware, environment="production")
    """

    def __init__(self, app, *, environment: str = "production"):
        self.app = app
        self.environment = environment

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            headers = dict(scope.get("headers", []))
            decoded = {k.decode(): v.decode() for k, v in headers.items()}
            ctx = ExecutionContext.from_headers(decoded)
            ctx.environment = self.environment
            async with ctx.scope():
                await self.app(scope, receive, send)
        else:
            await self.app(scope, receive, send)