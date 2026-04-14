"""
Reinforcement Defense Module

This module provides reinforcement learning capabilities for autonomous cyber defense,
including policy networks, reward modeling, and adaptive defense agents.
"""

from .defense_environment import (
    DefenseEnvironment,
    DefenseAction,
    DefenseState,
    DefenseReward
)

from .reward_model import (
    RewardModel,
    RewardComponents,
    RewardHistory
)

from .policy_network import (
    DefensePolicyNetwork,
    ActorCriticNetwork,
    AttentionPolicyNetwork,
    MultiHeadPolicyNetwork,
    PolicyOutput,
    PolicyLoss
)

from .defense_agent import (
    DefenseAgent,
    AgentConfig,
    AgentMetrics,
    AgentExperience
)

__all__ = [
    # Environment components
    'DefenseEnvironment',
    'DefenseAction',
    'DefenseState',
    'DefenseReward',

    # Reward modeling
    'RewardModel',
    'RewardComponents',
    'RewardHistory',

    # Policy networks
    'DefensePolicyNetwork',
    'ActorCriticNetwork',
    'AttentionPolicyNetwork',
    'MultiHeadPolicyNetwork',
    'PolicyOutput',
    'PolicyLoss',

    # Defense agent
    'DefenseAgent',
    'AgentConfig',
    'AgentMetrics',
    'AgentExperience'
]

# Module version
__version__ = "1.0.0"

# Module description
__doc__ = """
Reinforcement Defense Module for Hollow Purple

This module implements advanced reinforcement learning for autonomous cyber defense,
enabling AI agents to learn optimal defense strategies through interaction with
cyber threat environments.

Key Features:
- Actor-Critic policy networks with PPO optimization
- Multi-objective reward modeling for complex defense scenarios
- Attention-based networks for focusing on relevant threat indicators
- Adaptive agents that learn from experience and adapt to new threats
- Comprehensive evaluation and monitoring capabilities

Usage:
    from autonomous_defense_ai.reinforcement_defense import (
        DefenseEnvironment,
        DefenseAgent,
        RewardModel
    )

    # Create environment and agent
    env = DefenseEnvironment(attack_graph)
    agent = DefenseAgent(env)

    # Train agent
    agent.start_continuous_training()

    # Evaluate performance
    results = agent.evaluate_policy(num_episodes=10)

Integration with Other Modules:
- Works with probabilistic_attack_graph for threat modeling
- Integrates with graph_neural_network for state representation
- Connects to broader autonomous_defense_ai system for end-to-end defense
"""