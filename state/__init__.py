"""
HOLLOW_PURPLE — State Management System v2.0

Event-sourced, CQRS-compliant deterministic state engine.
Supports full ledger replay, snapshot acceleration,
time-travel queries, and streaming projections.
"""

from state.state_machine import StateMachine
from state.reducers import ReducerRegistry
from state.snapshot_manager import SnapshotManager
from state.projections import ProjectionRegistry

__all__ = [
    "StateMachine",
    "ReducerRegistry",
    "SnapshotManager",
    "ProjectionRegistry",
]

__version__ = "2.0.0"