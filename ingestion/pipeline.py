"""
ingestion/pipeline.py — Composable Async Pipeline Abstraction

Supports:
  - Linear stage composition
  - Conditional stage branching
  - Per-stage timeout enforcement
  - Stage skip on None (dropped events propagate cleanly)
  - Named stage tagging for trace/metrics
"""

import asyncio
import logging
import time
from typing import Any, Callable, Awaitable

logger = logging.getLogger("hollow_purple.pipeline")

StageFunc = Callable[[Any], Awaitable[Any]]


class Stage:
    """Wraps a single pipeline stage with timeout and name."""

    def __init__(self, fn: StageFunc, name: str = "", timeout: float = 5.0):
        self.fn      = fn
        self.name    = name or fn.__name__
        self.timeout = timeout

    async def run(self, event: Any) -> Any:
        if event is None:
            return None
        start = time.perf_counter()
        try:
            result = await asyncio.wait_for(self.fn(event), timeout=self.timeout)
            elapsed = (time.perf_counter() - start) * 1000
            logger.debug("Stage '%s' completed in %.2fms", self.name, elapsed)
            return result
        except asyncio.TimeoutError:
            logger.error("Stage '%s' timed out after %.1fs", self.name, self.timeout)
            raise
        except Exception as exc:
            logger.error("Stage '%s' raised: %s", self.name, exc)
            raise


class IngestionPipeline:
    """
    Linear async pipeline. Each stage receives the output of the previous.

    Usage:
        pipeline = IngestionPipeline([
            Stage(parser.parse,         name="parse",      timeout=2.0),
            Stage(validator.validate,   name="validate",   timeout=1.0),
            Stage(normalizer.normalize, name="normalize",  timeout=1.0),
            Stage(deduplicator.process, name="deduplicate",timeout=1.0),
            Stage(enricher.enrich,      name="enrich",     timeout=3.0),
        ])
        result = await pipeline.run(raw_event)
    """

    def __init__(self, stages: list[Stage]):
        self.stages = stages
        logger.info("Pipeline built with %d stages: %s",
                    len(stages), [s.name for s in stages])

    async def run(self, event: Any) -> Any:
        current = event
        for stage in self.stages:
            current = await stage.run(current)
            if current is None:
                logger.debug("Pipeline short-circuited at stage '%s' (None returned)", stage.name)
                return None
        return current

    def insert_stage(self, index: int, stage: Stage):
        """Dynamically insert a stage (e.g. geo-enrichment, threat intel lookup)."""
        self.stages.insert(index, stage)
        logger.info("Inserted stage '%s' at position %d", stage.name, index)

    def remove_stage(self, name: str):
        self.stages = [s for s in self.stages if s.name != name]
        logger.info("Removed stage '%s'", name)

    @property
    def stage_names(self) -> list[str]:
        return [s.name for s in self.stages]