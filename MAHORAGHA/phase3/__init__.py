"""
MAHORAGHA — Hollow Purple Multi-Phase IAM Threat Analysis Engine

Architecture
------------
Phase 3  (MAHORAGHA/phase3/)
  Adversarial hardening, Merkle integrity, shadow rebuild,
  drift envelope, backpressure, formal invariants, snapshot

Phase 4  (phase4_pipeline.py)
  Orchestration pipeline connecting phase3 outputs to phase5 consensus

Phase 5  (p5_consensus.py)
  Distributed consensus over risk signals across analysis nodes

Core modules
------------
  Adversarial_simulator — end-to-end adversarial attack simulation
  alert_router          — risk signal routing and escalation
  audit_log             — append-only Merkle-ready audit log
  Event_log             — structured event ingestion log
  events                — event bus and subscription model
  Governance            — policy enforcement and governance checks
  health                — system health probe and liveness checks
  Invariants            — cross-phase formal invariant checker
  p5_consensus          — Phase 5 BFT consensus engine
  phase4_pipeline       — Phase 4 orchestration pipeline
  Projections           — temporal risk projection and forecasting
  Reply_Validator       — response validation and schema enforcement
  retention             — event and signal retention policy engine
  utils                 — shared utilities (hashing, timing, formatting)

Package metadata
----------------
"""
from __future__ import annotations

__version__     = "3.0.0"
__codename__    = "HOLLOW_PURPLE"
__phase_range__ = (3, 5)

# Phase registry — used by pipeline.py and test_architecture.py
PHASE_REGISTRY: dict[int, str] = {
    3: "MAHORAGHA.phase3",
    4: "MAHORAGHA.phase4_pipeline",
    5: "MAHORAGHA.p5_consensus",
}

# Module inventory for health checks
CORE_MODULES = [
    "MAHORAGHA.Adversarial_simulator",
    "MAHORAGHA.alert_router",
    "MAHORAGHA.audit_log",
    "MAHORAGHA.Event_log",
    "MAHORAGHA.events",
    "MAHORAGHA.Governance",
    "MAHORAGHA.health",
    "MAHORAGHA.Invariants",
    "MAHORAGHA.p5_consensus",
    "MAHORAGHA.phase4_pipeline",
    "MAHORAGHA.Projections",
    "MAHORAGHA.Reply_Validator",
    "MAHORAGHA.retention",
    "MAHORAGHA.utils",
]

PHASE3_MODULES = [
    "MAHORAGHA.phase3.P3_adversarial",
    "MAHORAGHA.phase3.p3_backpressure",
    "MAHORAGHA.phase3.p3_drift_envelope",
    "MAHORAGHA.phase3.P3_formal_invariants",
    "MAHORAGHA.phase3.P3_merkle_log",
    "MAHORAGHA.phase3.P3_shadow_rebuild",
    "MAHORAGHA.phase3.P3_snapshot",
    "MAHORAGHA.phase3.signed_tree_head_hardened",
]


def health_check() -> dict[str, bool]:
    """
    Attempt to import all registered modules.
    Returns a dict of module_name -> import_success.
    Used by health.py and test_architecture.py.
    """
    import importlib
    results: dict[str, bool] = {}
    for module_path in CORE_MODULES + PHASE3_MODULES:
        try:
            importlib.import_module(module_path)
            results[module_path] = True
        except ImportError as exc:
            results[module_path] = False
    return results


def version_info() -> dict[str, str]:
    return {
        "version":     __version__,
        "codename":    __codename__,
        "phase_range": f"{__phase_range__[0]}-{__phase_range__[1]}",
    }


__all__ = [
    "PHASE_REGISTRY",
    "CORE_MODULES",
    "PHASE3_MODULES",
    "health_check",
    "version_info",
    "__version__",
    "__codename__",
]