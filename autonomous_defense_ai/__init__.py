"""
Autonomous Defense AI Module

This module provides enterprise-grade AI capabilities for autonomous cyber defense,
combining graph neural networks, probabilistic reasoning, and reinforcement learning
for comprehensive threat detection and mitigation.
"""

from .graph_neural_network import (
    GraphNeuralNetwork,
    ThreatPredictor,
    AdvancedGraphFeatureBuilder,
    GNNModelTrainer,
    TemporalAttackPredictor
)

from .probabilistic_attack_graph import (
    BayesianAttackGraph,
    ProbabilisticNode,
    ProbabilisticEdge,
    ProbabilityEngine,
    BayesianUpdateEngine,
    RiskPropagationEngine,
    TemporalRiskModel
)

from .reinforcement_defense import (
    DefenseEnvironment,
    DefenseAgent,
    RewardModel,
    DefensePolicyNetwork
)

__all__ = [
    # Graph Neural Networks
    'GraphNeuralNetwork',
    'ThreatPredictor',
    'AdvancedGraphFeatureBuilder',
    'GNNModelTrainer',
    'TemporalAttackPredictor',

    # Probabilistic Attack Graphs
    'BayesianAttackGraph',
    'ProbabilisticNode',
    'ProbabilisticEdge',
    'ProbabilityEngine',
    'BayesianUpdateEngine',
    'RiskPropagationEngine',
    'TemporalRiskModel',

    # Reinforcement Defense
    'DefenseEnvironment',
    'DefenseAgent',
    'RewardModel',
    'DefensePolicyNetwork'
]

# Module version
__version__ = "1.0.0"

# Module description
__doc__ = """
Autonomous Defense AI Module for Hollow Purple

This module implements DARPA/Palantir-style autonomous cyber defense capabilities,
providing advanced AI for threat detection, risk assessment, and autonomous mitigation.

Architecture:
- Graph Neural Networks: Learn attack patterns and predict attacker movements
- Probabilistic Attack Graphs: Bayesian reasoning for uncertainty quantification
- Reinforcement Learning: Adaptive defense strategies and optimal action selection

Key Capabilities:
- Real-time threat prediction with temporal analysis
- Probabilistic risk propagation through attack graphs
- Autonomous defense action selection and execution
- Continuous learning from threat intelligence and outcomes
- Multi-objective optimization for defense effectiveness vs. operational impact

Usage:
    from autonomous_defense_ai import (
        GraphNeuralNetwork,
        BayesianAttackGraph,
        DefenseAgent
    )

    # Create AI components
    gnn = GraphNeuralNetwork(...)
    attack_graph = BayesianAttackGraph()
    agent = DefenseAgent(environment)

    # Integrate into defense pipeline
    # ... (see individual module docs for detailed usage)

Enterprise Features:
- Production-ready with comprehensive error handling
- Scalable architecture for planet-scale deployments
- Integration with existing security infrastructure
- Advanced monitoring and telemetry
- Self-healing and adaptive capabilities

This represents the core AI brain of Hollow Purple, enabling autonomous,
intelligent cyber defense at enterprise scale.
"""