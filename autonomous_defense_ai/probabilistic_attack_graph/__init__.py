"""
Probabilistic Attack Graph Module

This module provides advanced probabilistic modeling for cyber attack graphs,
including Bayesian networks, risk propagation, temporal risk modeling, and
uncertainty quantification for autonomous cyber defense.
"""

from .attack_graph_builder import (
    BayesianAttackGraph,
    ProbabilisticNode,
    ProbabilisticEdge,
    RiskPropagationEngine as BasicRiskPropagationEngine
)

from .probability_engine import (
    ProbabilityEngine,
    UncertaintyQuantifier,
    MonteCarloSimulator
)

from .bayesian_update import (
    BayesianUpdateEngine,
    EvidenceProcessor,
    BeliefPropagation
)

from .risk_propagation import (
    RiskPropagationEngine,
    RiskVector,
    RiskPropagationResult
)

from .temporal_risk_model import (
    TemporalRiskModel,
    TemporalRiskPoint,
    RiskTimeSeries,
    TemporalRiskForecast
)

__all__ = [
    # Core attack graph components
    'BayesianAttackGraph',
    'ProbabilisticNode',
    'ProbabilisticEdge',

    # Probability and uncertainty
    'ProbabilityEngine',
    'UncertaintyQuantifier',
    'MonteCarloSimulator',

    # Bayesian inference
    'BayesianUpdateEngine',
    'EvidenceProcessor',
    'BeliefPropagation',

    # Risk propagation
    'RiskPropagationEngine',
    'RiskVector',
    'RiskPropagationResult',

    # Temporal modeling
    'TemporalRiskModel',
    'TemporalRiskPoint',
    'RiskTimeSeries',
    'TemporalRiskForecast',

    # Legacy alias
    'BasicRiskPropagationEngine'
]

# Module version
__version__ = "1.0.0"

# Module description
__doc__ = """
Probabilistic Attack Graph Module for Hollow Purple

This module implements enterprise-grade probabilistic reasoning for cyber attack graphs,
enabling autonomous defense systems to model attack progression, quantify uncertainty,
and predict threat evolution with mathematical rigor.

Key Features:
- Bayesian attack graph construction with belief propagation
- Monte Carlo simulation for uncertainty quantification
- Advanced risk propagation with multi-dimensional risk vectors
- Temporal risk modeling with forecasting capabilities
- Real-time Bayesian updates based on evidence
- Integration with graph neural networks for pattern learning

Usage:
    from autonomous_defense_ai.probabilistic_attack_graph import (
        BayesianAttackGraph,
        ProbabilityEngine,
        RiskPropagationEngine
    )

    # Create attack graph
    graph = BayesianAttackGraph()

    # Add probabilistic nodes and edges
    # ... (see individual module docs for details)

    # Perform risk propagation
    risk_engine = RiskPropagationEngine()
    propagation_result = risk_engine.propagate_risk(graph)

    # Forecast risk evolution
    temporal_model = TemporalRiskModel()
    forecast = temporal_model.forecast_risk_evolution(risk_series)
"""