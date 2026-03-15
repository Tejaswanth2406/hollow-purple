"""
Hollow Purple / Mahoraga — Projection Layer
============================================
Transforms raw graph and event state into materialized security
intelligence views consumed by analysts and the Mahoraga defense engine.

Pipeline position
-----------------
    Event Ledger → Graph Engine → Projection Layer → Mahoraga Decision Engine

Components
----------
GraphProjection      — Query-optimized attack graph view with path analysis
IdentityProjection   — Identity behavior fingerprinting and access mapping
ExposureProjection   — Internet/lateral exposure surface computation
RiskProjection       — Multi-factor risk scoring for identities and assets
"""

from .graph_projection import GraphProjection, GraphProjectionResult
from .identity_projection import (
    IdentityProjection,
    IdentityProfile,
    IdentityAnomalyFlag,
)
from .exposure_projection import (
    ExposureProjection,
    ExposureRecord,
    ExposureSeverity,
)
from .risk_projection import (
    RiskProjection,
    RiskScore,
    RiskTier,
    RiskReport,
)

__all__ = [
    # Graph
    "GraphProjection",
    "GraphProjectionResult",
    # Identity
    "IdentityProjection",
    "IdentityProfile",
    "IdentityAnomalyFlag",
    # Exposure
    "ExposureProjection",
    "ExposureRecord",
    "ExposureSeverity",
    # Risk
    "RiskProjection",
    "RiskScore",
    "RiskTier",
    "RiskReport",
]

__version__ = "1.0.0"
__author__ = "Hollow Purple Core Team"