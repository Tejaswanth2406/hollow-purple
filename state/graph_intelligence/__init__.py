"""
HOLLOW_PURPLE — Graph Intelligence Engine v2.0

Graph-based cyber attack detection and risk analysis layer.
Operates on the live identity/resource relationship graph.

Modules:
  - AttackPathEngine           : BFS/DFS multi-path attack chain discovery
  - BlastRadiusEngine          : Compromise impact propagation analysis
  - LateralMovementDetector    : Behavioral lateral movement detection
  - PrivilegeEscalationDetector: Graph-aware privilege escalation analysis
  - CrownJewelAnalyzer         : Critical asset exposure and access risk scoring
"""

from graph_intelligence.attack_path_engine import AttackPathEngine
from graph_intelligence.blast_radius_engine import BlastRadiusEngine
from graph_intelligence.lateral_movement_detector import LateralMovementDetector
from graph_intelligence.privilege_escalation_detector import PrivilegeEscalationDetector
from graph_intelligence.crown_jewel_analyzer import CrownJewelAnalyzer

__all__ = [
    "AttackPathEngine",
    "BlastRadiusEngine",
    "LateralMovementDetector",
    "PrivilegeEscalationDetector",
    "CrownJewelAnalyzer",
]

__version__ = "2.0.0"