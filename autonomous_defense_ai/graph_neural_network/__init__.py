"""
Graph Neural Network Module for Cyber Threat Prediction

This module provides advanced graph neural network capabilities for:
- Real-time threat detection in cyber defense graphs
- Attack path prediction and analysis
- Temporal graph analysis for evolving threats
- Feature engineering for cyber security data
- Model training and evaluation pipelines

Key Components:
- GNNModel: Core graph neural network architecture
- AttackPredictionEngine: Engine for predicting attacker movements
- GraphFeatureBuilder: Advanced feature engineering for graphs
- TemporalAttackPredictor: Time-aware attack prediction
- GNNModelTrainer: Comprehensive training infrastructure

Usage:
    from autonomous_defense_ai.graph_neural_network import (
        ThreatPredictor,
        GNNModelTrainer,
        TemporalAttackPredictor
    )

    # Initialize threat predictor
    predictor = ThreatPredictor()

    # Analyze threat landscape
    analysis = predictor.analyze_threat_landscape(nodes, edges)
"""

from .gnn_model import (
    GraphNeuralNetwork,
    AttackPredictionEngine,
    ThreatPredictor,
    GraphFeatureBuilder
)

from .attack_prediction import (
    TemporalAttackPredictor,
    AttackPath,
    AttackerProfile
)

from .graph_feature_builder import (
    AdvancedGraphFeatureBuilder
)

from .model_trainer import (
    GNNModelTrainer,
    TrainingConfig,
    TrainingMetrics,
    AdversarialTrainingMixin,
    CurriculumLearningTrainer
)

__all__ = [
    # Core GNN components
    'GraphNeuralNetwork',
    'AttackPredictionEngine',
    'ThreatPredictor',
    'GraphFeatureBuilder',

    # Advanced prediction
    'TemporalAttackPredictor',
    'AttackPath',
    'AttackerProfile',

    # Feature engineering
    'AdvancedGraphFeatureBuilder',

    # Training infrastructure
    'GNNModelTrainer',
    'TrainingConfig',
    'TrainingMetrics',
    'AdversarialTrainingMixin',
    'CurriculumLearningTrainer'
]