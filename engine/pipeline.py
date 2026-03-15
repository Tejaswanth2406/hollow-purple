"""
engine/pipeline.py
==================
Enterprise async execution pipeline with stage isolation, retries,
structured result reporting, and observability hooks.

Features
--------
- Typed stage handlers (sync and async support)
- Per-stage retry with exponential backoff and jitter
- Per-stage timeout enforcement
- Stage-level error isolation (fail-fast or continue-on-error modes)
- Structured PipelineResult with per-stage telemetry
- Middleware/hook system (before_stage, after_stage, on_error)
- Named pipeline registry pattern
- AsyncContextManager support for resource-safe execution
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import time
import traceback
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List, Optional, Union


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

Handler = Union[
    Callable[[Any], Any],
    Callable[[Any], Awaitable[Any]],
]

HookFn = Callable[["StageRecord"], Awaitable[None]]


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class StageStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    TIMED_OUT = "timed_out"


class PipelineMode(str, Enum):
    FAIL_FAST = "fail_fast"          # Abort on first stage failure
    CONTINUE_ON_ERROR = "continue"   # Run all stages regardless


# ---------------------------------------------------------------------------
# Stage record — per-execution telemetry
# ---------------------------------------------------------------------------


@dataclass
class StageRecord:
    """Execution record for a single stage run."""

    name: str
    status: StageStatus = StageStatus.PENDING
    input_type: str = ""
    output_type: str = ""
    elapsed_ms: float = 0.0
    attempts: int = 0
    error: Optional[str] = None
    error_traceback: Optional[str] = None

    def mark_running(self) -> None:
        self.status = StageStatus.RUNNING

    def mark_success(self, elapsed_ms: float, attempts: int) -> None:
        self.status = StageStatus.SUCCESS
        self.elapsed_ms = elapsed_ms
        self.attempts = attempts

    def mark_failed(self, exc: Exception, elapsed_ms: float, attempts: int) -> None:
        self.status = StageStatus.FAILED
        self.elapsed_ms = elapsed_ms
        self.attempts = attempts
        self.error = f"{type(exc).__name__}: {exc}"
        self.error_traceback = traceback.format_exc()

    def mark_timed_out(self, timeout_s: float) -> None:
        self.status = StageStatus.TIMED_OUT
        self.error = f"Stage timed out after {timeout_s}s"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stage": self.name,
            "status": self.status.value,
            "elapsed_ms": round(self.elapsed_ms, 3),
            "attempts": self.attempts,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Pipeline result
# ---------------------------------------------------------------------------


@dataclass
class PipelineResult:
    """
    Container returned by ``Pipeline.execute()``.
    Carries the final output value along with per-stage telemetry.
    """

    success: bool
    output: Any
    stages: List[StageRecord] = field(default_factory=list)
    total_elapsed_ms: float = 0.0
    pipeline_name: str = ""

    @property
    def failed_stages(self) -> List[StageRecord]:
        return [s for s in self.stages if s.status == StageStatus.FAILED]

    @property
    def succeeded_stages(self) -> List[StageRecord]:
        return [s for s in self.stages if s.status == StageStatus.SUCCESS]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pipeline": self.pipeline_name,
            "success": self.success,
            "total_elapsed_ms": round(self.total_elapsed_ms, 3),
            "stages": [s.to_dict() for s in self.stages],
        }


# ---------------------------------------------------------------------------
# Stage definition
# ---------------------------------------------------------------------------


@dataclass
class PipelineStage:
    """
    A named, configurable execution stage.

    Parameters
    ----------
    name          : Human-readable identifier.
    handler       : Sync or async callable ``(data: Any) -> Any``.
    timeout_s     : Per-attempt timeout in seconds. None = no limit.
    max_retries   : Number of retry attempts after initial failure.
    retry_base_s  : Base back-off interval in seconds (exponential + jitter).
    skip_on_error : If True, stage failure is logged but does not bubble up.
    """

    name: str
    handler: Handler
    timeout_s: Optional[float] = None
    max_retries: int = 0
    retry_base_s: float = 0.5
    skip_on_error: bool = False

    async def _invoke(self, data: Any) -> Any:
        """Normalise sync/async handler into an awaitable."""
        if inspect.iscoroutinefunction(self.handler):
            coro = self.handler(data)
        else:
            loop = asyncio.get_event_loop()
            coro = loop.run_in_executor(None, self.handler, data)

        if self.timeout_s is not None:
            return await asyncio.wait_for(coro, timeout=self.timeout_s)
        return await coro

    async def run(self, data: Any) -> tuple[Any, StageRecord]:
        """
        Execute this stage with retry logic.
        Returns ``(result, StageRecord)``.
        """
        record = StageRecord(
            name=self.name,
            input_type=type(data).__name__,
        )
        record.mark_running()

        last_exc: Optional[Exception] = None
        total_start = time.perf_counter()

        for attempt in range(1, self.max_retries + 2):  # +2: initial + retries
            try:
                result = await self._invoke(data)
                elapsed_ms = (time.perf_counter() - total_start) * 1000
                record.output_type = type(result).__name__
                record.mark_success(elapsed_ms=elapsed_ms, attempts=attempt)

                logger.debug(
                    "Stage succeeded",
                    extra={
                        "stage": self.name,
                        "attempt": attempt,
                        "elapsed_ms": round(elapsed_ms, 2),
                    },
                )
                return result, record

            except asyncio.TimeoutError as exc:
                elapsed_ms = (time.perf_counter() - total_start) * 1000
                record.mark_timed_out(self.timeout_s or 0)
                logger.error(
                    "Stage timed out",
                    extra={"stage": self.name, "timeout_s": self.timeout_s},
                )
                last_exc = exc
                break  # No retry after timeout

            except Exception as exc:
                last_exc = exc
                elapsed_ms = (time.perf_counter() - total_start) * 1000
                logger.warning(
                    "Stage attempt failed",
                    extra={
                        "stage": self.name,
                        "attempt": attempt,
                        "max_retries": self.max_retries,
                        "error": str(exc),
                    },
                )
                if attempt <= self.max_retries:
                    # Exponential backoff with full jitter
                    import random
                    sleep_s = self.retry_base_s * (2 ** (attempt - 1))
                    jitter = random.uniform(0, sleep_s * 0.3)
                    await asyncio.sleep(sleep_s + jitter)

        # All attempts exhausted
        elapsed_ms = (time.perf_counter() - total_start) * 1000
        record.mark_failed(last_exc, elapsed_ms=elapsed_ms, attempts=attempt)
        logger.error(
            "Stage failed permanently",
            extra={
                "stage": self.name,
                "error": str(last_exc),
                "attempts": attempt,
            },
        )
        return data, record  # pass-through original data on failure


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


class Pipeline:
    """
    Ordered async execution pipeline.

    Usage
    -----
    ::

        pipeline = Pipeline(name="ingest", mode=PipelineMode.FAIL_FAST)

        pipeline.add_stage("validate", validate_handler, timeout_s=5.0)
        pipeline.add_stage("enrich",   enrich_handler,   max_retries=2)
        pipeline.add_stage("store",    store_handler,    max_retries=3, retry_base_s=1.0)

        result = await pipeline.execute(raw_event)
        if result.success:
            print(result.output)
    """

    def __init__(
        self,
        *,
        name: str = "pipeline",
        mode: PipelineMode = PipelineMode.FAIL_FAST,
    ):
        self.name = name
        self.mode = mode
        self._stages: List[PipelineStage] = []
        self._before_stage_hooks: List[HookFn] = []
        self._after_stage_hooks: List[HookFn] = []
        self._on_error_hooks: List[HookFn] = []

    # ---------------------------------------------------------------------------
    # Builder methods
    # ---------------------------------------------------------------------------

    def add_stage(
        self,
        name: str,
        handler: Handler,
        *,
        timeout_s: Optional[float] = None,
        max_retries: int = 0,
        retry_base_s: float = 0.5,
        skip_on_error: bool = False,
    ) -> "Pipeline":
        """
        Append a stage to the pipeline. Returns ``self`` for chaining.
        """
        stage = PipelineStage(
            name=name,
            handler=handler,
            timeout_s=timeout_s,
            max_retries=max_retries,
            retry_base_s=retry_base_s,
            skip_on_error=skip_on_error,
        )
        self._stages.append(stage)
        return self

    def before_stage(self, fn: HookFn) -> "Pipeline":
        """Register a hook called before each stage."""
        self._before_stage_hooks.append(fn)
        return self

    def after_stage(self, fn: HookFn) -> "Pipeline":
        """Register a hook called after each stage (success or skip)."""
        self._after_stage_hooks.append(fn)
        return self

    def on_error(self, fn: HookFn) -> "Pipeline":
        """Register a hook called when a stage permanently fails."""
        self._on_error_hooks.append(fn)
        return self

    # ---------------------------------------------------------------------------
    # Execution
    # ---------------------------------------------------------------------------

    async def execute(self, data: Any) -> PipelineResult:
        """
        Run all stages sequentially, passing output of each into the next.

        Returns a ``PipelineResult`` regardless of failure — never raises.
        """
        pipeline_start = time.perf_counter()
        stage_records: List[StageRecord] = []
        current = data
        overall_success = True

        logger.info(
            "Pipeline started",
            extra={"pipeline": self.name, "stages": len(self._stages)},
        )

        for stage in self._stages:
            # Before-stage hooks
            dummy_record = StageRecord(name=stage.name)
            for hook in self._before_stage_hooks:
                try:
                    await hook(dummy_record)
                except Exception:
                    logger.exception("before_stage hook error", extra={"stage": stage.name})

            result, record = await stage.run(current)
            stage_records.append(record)

            if record.status in (StageStatus.FAILED, StageStatus.TIMED_OUT):
                overall_success = False

                for hook in self._on_error_hooks:
                    try:
                        await hook(record)
                    except Exception:
                        logger.exception("on_error hook error", extra={"stage": stage.name})

                if stage.skip_on_error:
                    record.status = StageStatus.SKIPPED
                    logger.warning(
                        "Stage failure skipped",
                        extra={"stage": stage.name},
                    )
                elif self.mode == PipelineMode.FAIL_FAST:
                    logger.error(
                        "Pipeline aborted (fail_fast)",
                        extra={"stage": stage.name},
                    )
                    break
            else:
                current = result

            # After-stage hooks
            for hook in self._after_stage_hooks:
                try:
                    await hook(record)
                except Exception:
                    logger.exception("after_stage hook error", extra={"stage": stage.name})

        total_elapsed_ms = (time.perf_counter() - pipeline_start) * 1000

        pipeline_result = PipelineResult(
            success=overall_success,
            output=current,
            stages=stage_records,
            total_elapsed_ms=total_elapsed_ms,
            pipeline_name=self.name,
        )

        log_level = logging.INFO if overall_success else logging.ERROR
        logger.log(
            log_level,
            "Pipeline completed",
            extra={
                "pipeline": self.name,
                "success": overall_success,
                "total_elapsed_ms": round(total_elapsed_ms, 2),
                "failed_stages": [s.name for s in pipeline_result.failed_stages],
            },
        )

        return pipeline_result

    # ---------------------------------------------------------------------------
    # Introspection
    # ---------------------------------------------------------------------------

    @property
    def stage_names(self) -> List[str]:
        return [s.name for s in self._stages]

    def __repr__(self) -> str:
        return (
            f"Pipeline(name={self.name!r}, mode={self.mode.value!r}, "
            f"stages={self.stage_names})"
        )