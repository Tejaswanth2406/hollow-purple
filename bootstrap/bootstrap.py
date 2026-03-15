"""
bootstrap/bootstrap.py
======================

Ultra-advanced runtime bootstrap controller for Hollow Purple.

Responsibilities
----------------
• Environment bootstrap (scripts.bootstrap_env)
• Service supervision
• Dependency ordering
• Crash recovery
• Runtime lifecycle control
• Signal handling
• Platform readiness

Acts as the **distributed runtime controller**.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import time
from dataclasses import dataclass, field
from typing import Callable, Awaitable, Dict, Optional

from scripts.bootstrap_env import bootstrap, ApplicationContext

from api.server import start_api_server
from ingestion.orchestrator import start_ingestion_pipeline
from MAHORAGHA.health import start_health_monitor


log = logging.getLogger("hp.runtime")


# -----------------------------------------------------
# SERVICE MODEL
# -----------------------------------------------------

@dataclass
class RuntimeService:

    name: str
    start: Callable[[], Awaitable]

    dependencies: list[str] = field(default_factory=list)

    critical: bool = True

    restart: bool = True

    backoff_seconds: float = 2.0


# -----------------------------------------------------
# SERVICE SUPERVISOR
# -----------------------------------------------------

class ServiceSupervisor:

    def __init__(self):

        self.services: Dict[str, RuntimeService] = {}
        self.tasks: Dict[str, asyncio.Task] = {}
        self.running = True

    def register(self, service: RuntimeService):

        log.info("Register service %s", service.name)

        self.services[service.name] = service

    async def start_all(self):

        order = self._resolve_dependencies()

        log.info("Startup order %s", order)

        for name in order:

            service = self.services[name]

            task = asyncio.create_task(
                self._run(service),
                name=f"service:{service.name}",
            )

            self.tasks[name] = task

    async def _run(self, service: RuntimeService):

        backoff = service.backoff_seconds

        while self.running:

            try:

                log.info("Starting %s", service.name)

                await service.start()

                if not service.restart:
                    break

                log.warning("%s exited, restarting", service.name)

            except Exception:

                log.exception("Service crashed %s", service.name)

                if not service.restart:
                    break

                await asyncio.sleep(backoff)

                backoff = min(backoff * 2, 30)

    def _resolve_dependencies(self):

        resolved = []
        unresolved = set(self.services.keys())

        while unresolved:

            progress = False

            for name in list(unresolved):

                deps = self.services[name].dependencies

                if all(d in resolved for d in deps):

                    resolved.append(name)
                    unresolved.remove(name)
                    progress = True

            if not progress:
                raise RuntimeError("Circular service dependency detected")

        return resolved

    async def shutdown(self):

        log.info("Stopping services")

        self.running = False

        for task in self.tasks.values():
            task.cancel()

        await asyncio.gather(*self.tasks.values(), return_exceptions=True)

        log.info("All services stopped")


# -----------------------------------------------------
# HEALTH REGISTRY
# -----------------------------------------------------

class HealthRegistry:

    def __init__(self):

        self.states: Dict[str, str] = {}

    def set(self, service: str, state: str):

        self.states[service] = state

    def snapshot(self):

        return dict(self.states)


health = HealthRegistry()


# -----------------------------------------------------
# METRICS SERVICE
# -----------------------------------------------------

async def start_metrics():

    port = int(os.getenv("HP_METRICS_PORT", 9100))

    log.info("Metrics server started on %s", port)

    while True:
        await asyncio.sleep(60)


# -----------------------------------------------------
# RUNTIME BOOTSTRAP
# -----------------------------------------------------

class RuntimeBootstrap:

    def __init__(self):

        self.ctx: Optional[ApplicationContext] = None

        self.supervisor = ServiceSupervisor()

        self._shutdown_event = asyncio.Event()

        self.started_at = time.time()

    # -------------------------------------------------

    async def initialize(self):

        log.info("Bootstrapping environment")

        self.ctx = await bootstrap()

        log.info(
            "Bootstrap manifest",
            extra={"manifest": self.ctx.manifest()},
        )

        self._register_services()

    # -------------------------------------------------

    def _register_services(self):

        assert self.ctx is not None

        # Metrics
        self.supervisor.register(
            RuntimeService(
                name="metrics",
                start=start_metrics,
                critical=False,
            )
        )

        # Graph engine
        self.supervisor.register(
            RuntimeService(
                name="graph",
                start=self.ctx.graph.start,
            )
        )

        # Detection engine
        self.supervisor.register(
            RuntimeService(
                name="engine",
                start=self.ctx.engine.start,
                dependencies=["graph"],
            )
        )

        # Ingestion pipeline
        self.supervisor.register(
            RuntimeService(
                name="ingestion",
                start=start_ingestion_pipeline,
            )
        )

        # Worker scheduler
        self.supervisor.register(
            RuntimeService(
                name="scheduler",
                start=self.ctx.scheduler.start,
                dependencies=["engine"],
            )
        )

        # Health monitor
        self.supervisor.register(
            RuntimeService(
                name="health",
                start=start_health_monitor,
                critical=False,
            )
        )

        # API
        self.supervisor.register(
            RuntimeService(
                name="api",
                start=self._start_api,
                dependencies=["engine", "ingestion"],
            )
        )

    # -------------------------------------------------

    async def _start_api(self):

        host = os.getenv("HP_API_HOST", "0.0.0.0")
        port = int(os.getenv("HP_API_PORT", 8080))

        await start_api_server(host=host, port=port)

    # -------------------------------------------------

    async def start(self):

        log.info("Starting platform services")

        await self.supervisor.start_all()

        log.info("Hollow Purple runtime ready")

    # -------------------------------------------------

    async def shutdown(self):

        uptime = time.time() - self.started_at

        log.warning("Runtime shutdown after %s seconds", uptime)

        await self.supervisor.shutdown()

        self._shutdown_event.set()

    # -------------------------------------------------

    async def run_forever(self):

        await self._shutdown_event.wait()

    # -------------------------------------------------

    def register_signal_handlers(self):

        loop = asyncio.get_event_loop()

        for sig in (signal.SIGINT, signal.SIGTERM):

            loop.add_signal_handler(
                sig,
                lambda s=sig: asyncio.create_task(self.shutdown()),
            )

        log.info("Signal handlers registered")


# -----------------------------------------------------
# PUBLIC ENTRYPOINT
# -----------------------------------------------------

async def start_runtime() -> RuntimeBootstrap:

    runtime = RuntimeBootstrap()

    runtime.register_signal_handlers()

    await runtime.initialize()

    await runtime.start()

    return runtime