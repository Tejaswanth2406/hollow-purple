"""
Hollow Purple / Mahoraga — Engine Package
==========================================
Core runtime orchestration layer for the Hollow Purple event-sourced platform.

Components
----------
BaselineRuntimeEngine   — Runtime controller: feature extraction → drift detection
                          → baseline update → anomaly result, per-event and
                          per-batch. Fully deterministic and replay-safe.

ReplayEngine            — Deterministic state-reconstruction engine. Replays the
                          append-only event log to rebuild identity, resource, and
                          baseline state. Supports full / targeted / range replay,
                          checkpoint creation, and integrity verification.

GraphEngine             — Directed interaction graph over identities and resources.
                          Incremental updates, BFS path finding, unusual-relationship
                          detection, and degree-centrality computation.

Supporting types
----------------
Protocols (injection contracts)
    FeatureExtractorProtocol, BaselineEngineProtocol,
    BaselineStoreProtocol, DriftDetectorProtocol,
    FeatureVector, IdentityBaselineProtocol

Result / value objects
    BaselineProcessingResult, BatchProcessingResult
    ReplaySnapshot, ReconstructedState, EngineCheckpoint
    Node, Edge, InteractionGraph, NodeNeighbors,
    UnusualRelationshipResult, InteractionPath, DegreeCentrality

Enumerations
    NodeType, EdgeType

Design principles
-----------------
* All operations are deterministic and replay-safe.
* No global mutable state; every component is dependency-injected.
* Identical event logs always produce identical outputs.
* Nondeterministic entropy sources (random, os.urandom) are never used
  inside any engine component.

Usage example
-------------
    from hollow_purple.engine import (
        BaselineRuntimeEngine,
        ReplayEngine,
        GraphEngine,
    )

    # Inject policy_engine dependencies into the baseline runtime
    runtime = BaselineRuntimeEngine(
        feature_extractor=my_extractor,
        baseline_engine=my_baseline_engine,
        baseline_store=my_store,
        drift_detector=my_detector,
        node_id="node-prod-01",
    )

    # Reconstruct full system state from the event log
    replay = ReplayEngine(event_log=log, baseline_engine=runtime)
    snapshot = replay.replay_all_events()

    # Build the interaction graph from the same log
    graph = GraphEngine(node_id="node-prod-01")
    graph.build_graph(list(log.load_events()))
"""

# ---------------------------------------------------------------------------
# Baseline runtime — behavioral modeling coordinator
# ---------------------------------------------------------------------------
from .baseline import (
    # Engine
    BaselineRuntimeEngine,
    # Result types
    BaselineProcessingResult,
    BatchProcessingResult,
    # Injection-contract protocols
    FeatureExtractorProtocol,
    BaselineEngineProtocol,
    BaselineStoreProtocol,
    DriftDetectorProtocol,
    FeatureVector,
    IdentityBaselineProtocol,
)

# ---------------------------------------------------------------------------
# Replay engine — deterministic state reconstruction
# ---------------------------------------------------------------------------
from .replay_engine import (
    # Engine
    ReplayEngine,
    # Value / result objects
    ReplaySnapshot,
    ReconstructedState,
    EngineCheckpoint,
)

# ---------------------------------------------------------------------------
# Graph engine — relationship graph and security analysis
# ---------------------------------------------------------------------------
# Note: GraphEngine is not yet implemented in this version.

# ---------------------------------------------------------------------------
# Package metadata
# ---------------------------------------------------------------------------
__version__ = "1.0.0"
__author__ = "Hollow Purple Core Team"

# ---------------------------------------------------------------------------
# Public API surface
# ---------------------------------------------------------------------------
__all__ = [
    # ------------------------------------------------------------------ #
    # Baseline runtime                                                     #
    # ------------------------------------------------------------------ #
    "BaselineRuntimeEngine",
    "BaselineProcessingResult",
    "BatchProcessingResult",
    # Protocols
    "FeatureExtractorProtocol",
    "BaselineEngineProtocol",
    "BaselineStoreProtocol",
    "DriftDetectorProtocol",
    "FeatureVector",
    "IdentityBaselineProtocol",
    # ------------------------------------------------------------------ #
    # Replay engine                                                        #
    # ------------------------------------------------------------------ #
    "ReplayEngine",
    "ReplaySnapshot",
    "ReconstructedState",
    "EngineCheckpoint",
    # ------------------------------------------------------------------ #
    # Metadata                                                             #
    # ------------------------------------------------------------------ #
    "__version__",
    "__author__",
]