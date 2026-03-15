"""
MAHORAGHA.phase3 — Phase 3 Adversarial Hardening Layer

Phase 3 is the adversarial-hardened core of Hollow Purple. It sits between
the raw graph construction layer (graph.builder) and the Phase 4 pipeline
orchestrator. Its responsibilities:

  Merkle Integrity
    P3_merkle_log            — append-only Merkle tree over audit events
    signed_tree_head_hardened — hardened Signed Tree Head (STH) verification

  Adversarial Simulation
    P3_adversarial           — multi-vector attack simulation against the IAM graph
    P3_shadow_rebuild        — reconstruct shadow identities from audit residue

  Invariant Enforcement
    P3_formal_invariants     — formal safety / liveness invariant checker

  Temporal Analysis
    P3_snapshot              — point-in-time IAM graph snapshotting
    p3_drift_envelope        — drift envelope computation and alerting

  Flow Control
    p3_backpressure          — adaptive backpressure and rate-limiting

Module dependency order (import-safe)
--------------------------------------
  utils (no deps)
  → P3_merkle_log
  → signed_tree_head_hardened
  → P3_formal_invariants
  → P3_snapshot
  → p3_drift_envelope
  → p3_backpressure
  → P3_shadow_rebuild
  → P3_adversarial
"""
from __future__ import annotations

__phase__   = 3
__version__ = "3.0.0"

# Public surface — import lazily to avoid circular deps at package init time
def get_merkle_log():
    from MAHORAGHA.phase3.P3_merkle_log import MerkleLog
    return MerkleLog

def get_adversarial_simulator():
    from MAHORAGHA.phase3.P3_adversarial import Phase3AdversarialSimulator
    return Phase3AdversarialSimulator

def get_snapshot_engine():
    from MAHORAGHA.phase3.P3_snapshot import Phase3Snapshot
    return Phase3Snapshot

def get_drift_envelope():
    from MAHORAGHA.phase3.p3_drift_envelope import DriftEnvelope
    return DriftEnvelope

def get_backpressure():
    from MAHORAGHA.phase3.p3_backpressure import BackpressureController
    return BackpressureController

def get_formal_invariants():
    from MAHORAGHA.phase3.P3_formal_invariants import FormalInvariantChecker
    return FormalInvariantChecker

def get_shadow_rebuild():
    from MAHORAGHA.phase3.P3_shadow_rebuild import ShadowRebuildEngine
    return ShadowRebuildEngine

def get_signed_tree_head():
    from MAHORAGHA.phase3.signed_tree_head_hardened import SignedTreeHead
    return SignedTreeHead


# Module manifest for test_architecture.py and health checks
PHASE3_MANIFEST = {
    "P3_merkle_log":            "MerkleLog",
    "P3_adversarial":           "Phase3AdversarialSimulator",
    "P3_snapshot":              "Phase3Snapshot",
    "p3_drift_envelope":        "DriftEnvelope",
    "p3_backpressure":          "BackpressureController",
    "P3_formal_invariants":     "FormalInvariantChecker",
    "P3_shadow_rebuild":        "ShadowRebuildEngine",
    "signed_tree_head_hardened": "SignedTreeHead",
}


def health_check() -> dict[str, bool]:
    """Import-check every Phase 3 module. Returns module -> success map."""
    import importlib
    results: dict[str, bool] = {}
    for module_name in PHASE3_MANIFEST:
        full_path = f"MAHORAGHA.phase3.{module_name}"
        try:
            importlib.import_module(full_path)
            results[full_path] = True
        except ImportError:
            results[full_path] = False
    return results


__all__ = [
    "PHASE3_MANIFEST",
    "health_check",
    "get_merkle_log",
    "get_adversarial_simulator",
    "get_snapshot_engine",
    "get_drift_envelope",
    "get_backpressure",
    "get_formal_invariants",
    "get_shadow_rebuild",
    "get_signed_tree_head",
]