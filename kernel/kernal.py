"""
HOLLOW PURPLE PLATFORM KERNEL
Core system orchestration layer
"""

import asyncio
import logging
import os
from dataclasses import dataclass, field
from typing import Callable, Awaitable, Dict, List

from configs.config_loader import ConfigLoader

from api.server import start_api_server
from ingestion.orchestrator import start_ingestion_pipeline
from graph.builder import GraphBuilder
from engine.orchestrator import EngineOrchestrator
from api.workers.scheduler import WorkerScheduler
from MAHORAGHA.health import start_health_monitor


logger = logging.getLogger("hp.kernel")


# ------------------------------------------------
# SERVICE MODEL
# ------------------------------------------------

@dataclass
class Service:

    name: str
    start: Callable[[], Awaitable]

    dependencies: List[str] = field(default_factory=list)

    critical: bool = True

    restart: bool = True

    backoff: int = 3


# ------------------------------------------------
# SERVICE REGISTRY
# ------------------------------------------------

class ServiceRegistry:

    def __init__(self):

        self.services: Dict[str, Service] = {}
        self.tasks: Dict[str, asyncio.Task] = {}
        self.running = True

    def register(self, service: Service):

        logger.info("Register service: %s", service.name)

        self.services[service.name] = service

    async def start_services(self):

        ordered = self._resolve_dependencies()

        logger.info("Startup order: %s", ordered)

        for name in ordered:

            service = self.services[name]

            task = asyncio.create_task(self._run(service))

            self.tasks[service.name] = task

    async def _run(self, service: Service):

        backoff = service.backoff

        while self.running:

            try:

                logger.info("Starting service %s", service.name)

                await service.start()

            except Exception:

                logger.exception("Service crashed: %s", service.name)

                if not service.restart:
                    return

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
                raise RuntimeError("Circular dependency detected")

        return resolved

    async def shutdown(self):

        logger.info("Stopping all services")

        self.running = False

        for task in self.tasks.values():
            task.cancel()

        await asyncio.gather(*self.tasks.values(), return_exceptions=True)


# ------------------------------------------------
# METRICS SERVER
# ------------------------------------------------

async def start_metrics():

    port = int(os.getenv("HP_METRICS_PORT", 9100))

    logger.info("Metrics server started on %s", port)

    while True:
        await asyncio.sleep(60)


# ------------------------------------------------
# HOLLOW PURPLE KERNEL
# ------------------------------------------------

class HollowPurpleKernel:

    def __init__(self):

        self.registry = ServiceRegistry()
        self.config_loader = ConfigLoader("configs")

        self.graph = None
        self.engine = None
        self.scheduler = None

    async def initialize(self):

        logger.info("Loading configuration")

        config = self.config_loader.load()

        logger.info("Config checksum %s", config.checksum())

        asyncio.create_task(self.config_loader.watch())

        logger.info("Initializing engines")

        self.graph = GraphBuilder()

        self.engine = EngineOrchestrator(self.graph)

        self.scheduler = WorkerScheduler()

        self._register_services()

    def _register_services(self):

        self.registry.register(
            Service(
                name="metrics",
                start=start_metrics,
                critical=False
            )
        )

        self.registry.register(
            Service(
                name="graph_engine",
                start=self.graph.start
            )
        )

        self.registry.register(
            Service(
                name="engine",
                start=self.engine.start,
                dependencies=["graph_engine"]
            )
        )

        self.registry.register(
            Service(
                name="ingestion",
                start=start_ingestion_pipeline
            )
        )

        self.registry.register(
            Service(
                name="workers",
                start=self.scheduler.start,
                dependencies=["engine"]
            )
        )

        self.registry.register(
            Service(
                name="health_monitor",
                start=start_health_monitor,
                critical=False
            )
        )

        self.registry.register(
            Service(
                name="api",
                start=self._start_api,
                dependencies=["engine", "ingestion"]
            )
        )

    async def _start_api(self):

        host = os.getenv("HP_API_HOST", "0.0.0.0")
        port = int(os.getenv("HP_API_PORT", 8080))

        await start_api_server(host=host, port=port)

    async def start(self):

        await self.initialize()

        await self.registry.start_services()

        logger.info("HOLLOW PURPLE KERNEL READY")

    async def shutdown(self):

        logger.warning("System shutdown initiated")

        await self.registry.shutdown()