"""
Hollow Purple / Mahoraga — Phase 4
====================================
Deterministic Replay & State Reconstruction Engine

This layer provides cryptographically verifiable, forensic-grade
reconstruction of the exact system state at any point in history.

Inspired by
-----------
- Event sourcing patterns (Netflix, Uber, Stripe)
- Google Certificate Transparency (Merkle audit logs)
- Lamport logical clocks for distributed replay ordering
- CQRS read-model rebuilding patterns

Architecture position
---------------------
    Ingestion → Storage → Engine → Projections
        → Phase 3 Verifiable Logs
            → Phase 4 Deterministic Replay   ← this layer
                → Mahoraga Defense Engine

Components
----------
DeterministicReplay   — Pure event-driven state machine replay engine
ReplayValidator       — Checkpoint-anchored state hash verification
StateReconstructor    — Snapshot + delta replay with gap detection
ReplayPipeline        — Full orchestrated replay workflow
AuditVerifier         — Merkle-tree forensic log integrity proof
"""

from .deterministic_replay import (
    DeterministicReplay,
    StateMachine,
    ReplayResult,
    ReplayMode,
)
from .replay_validator import (
    ReplayValidator,
    Checkpoint,
    ValidationResult,
    CheckpointMismatchError,
)
from .state_reconstructor import (
    StateReconstructor,
    ReconstructionResult,
    ReconstructionStrategy,
    GapDetectedError,
)
from .pipeline import (
    ReplayPipeline,
    ReplayPipelineConfig,
    ReplayPipelineResult,
)
from .audit_verifier import (
    AuditVerifier,
    MerkleTree,
    AuditProof,
    AuditReport,
    TamperEvidenceError,
)

__all__ = [
    # Deterministic Replay
    "DeterministicReplay",
    "StateMachine",
    "ReplayResult",
    "ReplayMode",
    # Validator
    "ReplayValidator",
    "Checkpoint",
    "ValidationResult",
    "CheckpointMismatchError",
    # Reconstructor
    "StateReconstructor",
    "ReconstructionResult",
    "ReconstructionStrategy",
    "GapDetectedError",
    # Pipeline
    "ReplayPipeline",
    "ReplayPipelineConfig",
    "ReplayPipelineResult",
    # Audit
    "AuditVerifier",
    "MerkleTree",
    "AuditProof",
    "AuditReport",
    "TamperEvidenceError",
]

__version__ = "1.0.0"
__author__ = "Hollow Purple Core Team"