"""
Hollow Purple / Mahoraga — Storage Layer
=========================================
Enterprise persistent data management layer.

Components
----------
EventStore       — Append-only tamper-evident event ledger
BaselineStore    — Behavioral baseline model persistence
GraphStore       — Relationship graph (nodes, edges, traversal)
IntegrityStore   — Cryptographic chain verification + audit
SnapshotStore    — Deterministic replay checkpoint management
"""

from .event_store import EventStore, EventRecord, ChainVerificationError
from .baseline_store import BaselineStore, BaselineRecord, BaselineNotFoundError
from .graph_store import (
    GraphStore,
    NodeRecord,
    EdgeRecord,
    TraversalResult,
    GraphCycleError,
)
from .integrity_store import IntegrityStore, IntegrityReport, TamperDetectedError
from .snapshot_store import SnapshotStore, Snapshot, SnapshotNotFoundError

__all__ = [
    # Event Store
    "EventStore",
    "EventRecord",
    "ChainVerificationError",
    # Baseline Store
    "BaselineStore",
    "BaselineRecord",
    "BaselineNotFoundError",
    # Graph Store
    "GraphStore",
    "NodeRecord",
    "EdgeRecord",
    "TraversalResult",
    "GraphCycleError",
    # Integrity Store
    "IntegrityStore",
    "IntegrityReport",
    "TamperDetectedError",
    # Snapshot Store
    "SnapshotStore",
    "Snapshot",
    "SnapshotNotFoundError",
]

__version__ = "1.0.0"
__author__ = "Hollow Purple Core Team"