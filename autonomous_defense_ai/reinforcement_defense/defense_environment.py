"""
Defense Environment for Reinforcement Learning

This module implements the reinforcement learning environment for autonomous cyber defense,
providing the interface between attack graphs, defense actions, and reward modeling.
"""

import numpy as np
from typing import Dict, List, Tuple, Optional, Any, Union, Set
from dataclasses import dataclass
from datetime import datetime, timedelta
import logging
from collections import defaultdict, deque
import gym
from gym import spaces
import networkx as nx

logger = logging.getLogger(__name__)

@dataclass
class DefenseAction:
    """A defense action that can be taken"""
    action_type: str  # 'block', 'monitor', 'isolate', 'patch', 'honeypot', etc.
    target_node: str
    parameters: Dict[str, Any]
    cost: float
    effectiveness: float
    duration: timedelta
    timestamp: datetime

@dataclass
class DefenseState:
    """Current state of the defense environment"""
    attack_graph: Any  # Reference to current attack graph
    active_defenses: List[DefenseAction]
    system_health: float  # 0-1 scale
    risk_levels: Dict[str, float]
    resource_utilization: Dict[str, float]
    threat_indicators: Dict[str, float]
    timestamp: datetime

@dataclass
class DefenseReward:
    """Reward structure for defense actions"""
    immediate_reward: float
    risk_reduction: float
    resource_cost: float
    system_impact: float
    long_term_benefit: float
    total_reward: float

class DefenseEnvironment(gym.Env):
    """
    Reinforcement Learning Environment for Cyber Defense

    This environment models the cyber defense problem as a Markov Decision Process,
    where an agent must choose optimal defense actions to mitigate cyber threats.
    """

    def __init__(self, attack_graph: Any, max_steps: int = 1000,
                 time_step: timedelta = timedelta(minutes=5)):
        self.attack_graph = attack_graph
        self.max_steps = max_steps
        self.time_step = time_step

        # Environment state
        self.current_step = 0
        self.current_state = None
        self.defense_history = []
        self.reward_history = []

        # Defense action space
        self.action_types = [
            'block_ip', 'isolate_host', 'patch_vulnerability',
            'deploy_honeypot', 'increase_monitoring', 'quarantine_user',
            'update_firewall', 'enable_2fa', 'rotate_credentials'
        ]

        # Resource constraints
        self.resource_limits = {
            'bandwidth': 100.0,
            'cpu': 80.0,
            'memory': 90.0,
            'storage': 95.0
        }

        # Action costs and effectiveness
        self.action_profiles = self._initialize_action_profiles()

        # Define observation and action spaces
        self._define_spaces()

        # Initialize environment
        self.reset()

    def _define_spaces(self):
        """Define the observation and action spaces for RL"""
        # Observation space: state vector representing system status
        # [system_health, risk_levels, resource_utilization, threat_indicators, active_defenses]
        obs_dim = 1 + len(self.attack_graph.nodes) + len(self.resource_limits) + 10 + len(self.action_types)
        self.observation_space = spaces.Box(
            low=0.0, high=1.0, shape=(obs_dim,), dtype=np.float32
        )

        # Action space: discrete actions for each node and action type
        n_nodes = len(self.attack_graph.nodes)
        n_actions = len(self.action_types)
        self.action_space = spaces.MultiDiscrete([n_nodes, n_actions])

    def _initialize_action_profiles(self) -> Dict[str, Dict[str, Any]]:
        """Initialize defense action profiles with costs and effectiveness"""
        return {
            'block_ip': {
                'cost': 0.1,
                'effectiveness': 0.9,
                'duration_hours': 24,
                'resource_impact': {'bandwidth': 0.05},
                'risk_reduction': 0.8
            },
            'isolate_host': {
                'cost': 0.3,
                'effectiveness': 0.95,
                'duration_hours': 48,
                'resource_impact': {'cpu': 0.1, 'bandwidth': 0.1},
                'risk_reduction': 0.9
            },
            'patch_vulnerability': {
                'cost': 0.2,
                'effectiveness': 0.85,
                'duration_hours': 168,  # 1 week
                'resource_impact': {'cpu': 0.05},
                'risk_reduction': 0.7
            },
            'deploy_honeypot': {
                'cost': 0.15,
                'effectiveness': 0.6,
                'duration_hours': 720,  # 30 days
                'resource_impact': {'cpu': 0.02, 'memory': 0.05},
                'risk_reduction': 0.4
            },
            'increase_monitoring': {
                'cost': 0.05,
                'effectiveness': 0.7,
                'duration_hours': 24,
                'resource_impact': {'cpu': 0.03, 'memory': 0.02},
                'risk_reduction': 0.3
            },
            'quarantine_user': {
                'cost': 0.25,
                'effectiveness': 0.8,
                'duration_hours': 48,
                'resource_impact': {'bandwidth': 0.05},
                'risk_reduction': 0.6
            },
            'update_firewall': {
                'cost': 0.1,
                'effectiveness': 0.75,
                'duration_hours': 12,
                'resource_impact': {'cpu': 0.01},
                'risk_reduction': 0.5
            },
            'enable_2fa': {
                'cost': 0.05,
                'effectiveness': 0.8,
                'duration_hours': 168,  # 1 week
                'resource_impact': {},
                'risk_reduction': 0.4
            },
            'rotate_credentials': {
                'cost': 0.1,
                'effectiveness': 0.9,
                'duration_hours': 24,
                'resource_impact': {'cpu': 0.02},
                'risk_reduction': 0.7
            }
        }

    def reset(self) -> np.ndarray:
        """Reset the environment to initial state"""
        self.current_step = 0
        self.defense_history = []
        self.reward_history = []

        # Initialize with baseline state
        self.current_state = DefenseState(
            attack_graph=self.attack_graph,
            active_defenses=[],
            system_health=0.8,  # Start with good health
            risk_levels={node_id: 0.1 for node_id in self.attack_graph.nodes.keys()},
            resource_utilization={res: 0.2 for res in self.resource_limits.keys()},
            threat_indicators=self._initialize_threat_indicators(),
            timestamp=datetime.now()
        )

        return self._get_observation()

    def step(self, action: Tuple[int, int]) -> Tuple[np.ndarray, float, bool, Dict[str, Any]]:
        """
        Execute one step in the environment

        Args:
            action: (node_index, action_index) tuple

        Returns:
            observation, reward, done, info
        """
        node_index, action_index = action

        # Get node ID and action type
        node_ids = list(self.attack_graph.nodes.keys())
        if node_index >= len(node_ids):
            logger.warning(f"Invalid node index: {node_index}")
            return self._get_observation(), -1.0, False, {'error': 'invalid_node'}

        target_node = node_ids[node_index]
        action_type = self.action_types[action_index]

        # Execute defense action
        defense_action = self._execute_defense_action(target_node, action_type)

        if defense_action:
            self.defense_history.append(defense_action)

            # Update environment state
            self._update_environment_state(defense_action)

            # Calculate reward
            reward = self._calculate_reward(defense_action)

            self.reward_history.append(reward)
        else:
            # Invalid action
            reward = DefenseReward(
                immediate_reward=-1.0,
                risk_reduction=0.0,
                resource_cost=0.0,
                system_impact=-0.1,
                long_term_benefit=0.0,
                total_reward=-1.1
            )

        # Advance time
        self.current_step += 1
        self.current_state.timestamp += self.time_step

        # Simulate attack progression
        self._simulate_attack_progression()

        # Check if episode is done
        done = self._is_episode_done()

        # Get observation
        observation = self._get_observation()

        info = {
            'step': self.current_step,
            'defense_action': defense_action,
            'system_health': self.current_state.system_health,
            'total_risk': sum(self.current_state.risk_levels.values())
        }

        return observation, reward.total_reward, done, info

    def _execute_defense_action(self, target_node: str, action_type: str) -> Optional[DefenseAction]:
        """Execute a defense action and return the action object"""
        if action_type not in self.action_profiles:
            return None

        profile = self.action_profiles[action_type]

        # Check resource constraints
        if not self._check_resource_constraints(profile):
            return None

        # Create defense action
        defense_action = DefenseAction(
            action_type=action_type,
            target_node=target_node,
            parameters={},
            cost=profile['cost'],
            effectiveness=profile['effectiveness'],
            duration=timedelta(hours=profile['duration_hours']),
            timestamp=self.current_state.timestamp
        )

        # Apply immediate effects
        self._apply_defense_effects(defense_action)

        return defense_action

    def _check_resource_constraints(self, action_profile: Dict[str, Any]) -> bool:
        """Check if action can be executed given resource constraints"""
        resource_impact = action_profile.get('resource_impact', {})

        for resource, impact in resource_impact.items():
            current_usage = self.current_state.resource_utilization.get(resource, 0.0)
            limit = self.resource_limits.get(resource, 1.0)

            if current_usage + impact > limit:
                return False

        return True

    def _apply_defense_effects(self, defense_action: DefenseAction):
        """Apply the effects of a defense action to the environment"""
        profile = self.action_profiles[defense_action.action_type]

        # Update resource utilization
        for resource, impact in profile.get('resource_impact', {}).items():
            self.current_state.resource_utilization[resource] += impact
            # Ensure bounds
            self.current_state.resource_utilization[resource] = min(
                1.0, self.current_state.resource_utilization[resource]
            )

        # Reduce risk for target node
        risk_reduction = profile['risk_reduction'] * defense_action.effectiveness
        if defense_action.target_node in self.current_state.risk_levels:
            self.current_state.risk_levels[defense_action.target_node] *= (1 - risk_reduction)
            self.current_state.risk_levels[defense_action.target_node] = max(
                0.0, self.current_state.risk_levels[defense_action.target_node]
            )

        # Update threat indicators
        self._update_threat_indicators(defense_action)

    def _update_environment_state(self, defense_action: DefenseAction):
        """Update the overall environment state after an action"""
        # Add to active defenses
        self.current_state.active_defenses.append(defense_action)

        # Remove expired defenses
        current_time = self.current_state.timestamp
        self.current_state.active_defenses = [
            d for d in self.current_state.active_defenses
            if current_time < d.timestamp + d.duration
        ]

        # Update system health based on risk levels and defenses
        total_risk = sum(self.current_state.risk_levels.values())
        n_nodes = len(self.current_state.risk_levels)

        if n_nodes > 0:
            avg_risk = total_risk / n_nodes
            # System health decreases with average risk
            health_impact = avg_risk * 0.5
            self.current_state.system_health = max(0.0, self.current_state.system_health - health_impact)

            # Defense actions can improve health
            defense_benefit = len(self.current_state.active_defenses) * 0.01
            self.current_state.system_health = min(1.0, self.current_state.system_health + defense_benefit)

    def _calculate_reward(self, defense_action: DefenseAction) -> DefenseReward:
        """Calculate the reward for a defense action"""
        profile = self.action_profiles[defense_action.action_type]

        # Immediate reward based on effectiveness vs cost
        effectiveness = defense_action.effectiveness
        cost = defense_action.cost
        immediate_reward = effectiveness * 2.0 - cost * 1.5

        # Risk reduction reward
        old_risk = self.current_state.risk_levels.get(defense_action.target_node, 0.0)
        # Calculate what risk was before this action (approximate)
        estimated_old_risk = old_risk / (1 - profile['risk_reduction'] * effectiveness)
        risk_reduction = max(0.0, estimated_old_risk - old_risk)
        risk_reduction_reward = risk_reduction * 3.0

        # Resource cost penalty
        resource_penalty = cost * 0.5

        # System impact (negative for disruptive actions)
        system_impact = -cost * 0.2

        # Long-term benefit (based on duration and effectiveness)
        duration_factor = defense_action.duration.total_seconds() / 3600 / 24  # Days
        long_term_benefit = effectiveness * duration_factor * 0.1

        # Total reward
        total_reward = (immediate_reward + risk_reduction_reward -
                       resource_penalty + system_impact + long_term_benefit)

        return DefenseReward(
            immediate_reward=immediate_reward,
            risk_reduction=risk_reduction_reward,
            resource_cost=-resource_penalty,
            system_impact=system_impact,
            long_term_benefit=long_term_benefit,
            total_reward=total_reward
        )

    def _simulate_attack_progression(self):
        """Simulate how the attack progresses over time"""
        # Increase risk levels slightly over time (attack progression)
        attack_progression_rate = 0.02  # 2% increase per step

        for node_id in self.current_state.risk_levels:
            # Base progression
            self.current_state.risk_levels[node_id] += attack_progression_rate

            # Node-specific factors
            node = self.attack_graph.nodes.get(node_id)
            if node:
                # Higher vulnerability leads to faster risk increase
                vulnerability_factor = node.base_vulnerability * 0.1
                self.current_state.risk_levels[node_id] += vulnerability_factor

            # Bound risk to [0, 1]
            self.current_state.risk_levels[node_id] = min(1.0, self.current_state.risk_levels[node_id])

        # Update threat indicators based on risk levels
        max_risk = max(self.current_state.risk_levels.values())
        self.current_state.threat_indicators['max_risk_level'] = max_risk
        self.current_state.threat_indicators['high_risk_nodes'] = sum(
            1 for risk in self.current_state.risk_levels.values() if risk > 0.7
        )

    def _initialize_threat_indicators(self) -> Dict[str, float]:
        """Initialize threat indicators"""
        return {
            'active_attacks': 0.0,
            'suspicious_connections': 0.0,
            'failed_logins': 0.0,
            'anomalous_traffic': 0.0,
            'max_risk_level': 0.0,
            'high_risk_nodes': 0.0,
            'defense_coverage': 0.0,
            'threat_intelligence_alerts': 0.0,
            'zero_day_indicators': 0.0,
            'insider_threat_signals': 0.0
        }

    def _update_threat_indicators(self, defense_action: DefenseAction):
        """Update threat indicators based on defense action"""
        # Defense actions can reduce certain threat indicators
        action_type = defense_action.action_type

        if action_type == 'block_ip':
            self.current_state.threat_indicators['suspicious_connections'] *= 0.7
            self.current_state.threat_indicators['anomalous_traffic'] *= 0.8
        elif action_type == 'isolate_host':
            self.current_state.threat_indicators['active_attacks'] *= 0.5
        elif action_type == 'increase_monitoring':
            self.current_state.threat_indicators['threat_intelligence_alerts'] *= 0.9
        elif action_type == 'quarantine_user':
            self.current_state.threat_indicators['insider_threat_signals'] *= 0.6

    def _get_observation(self) -> np.ndarray:
        """Get the current observation vector"""
        obs = []

        # System health
        obs.append(self.current_state.system_health)

        # Risk levels for all nodes
        node_ids = sorted(self.current_state.risk_levels.keys())
        for node_id in node_ids:
            obs.append(self.current_state.risk_levels[node_id])

        # Resource utilization
        for resource in sorted(self.resource_limits.keys()):
            obs.append(self.current_state.resource_utilization[resource])

        # Threat indicators
        for indicator in sorted(self.current_state.threat_indicators.keys()):
            obs.append(self.current_state.threat_indicators[indicator])

        # Active defenses (one-hot encoded by action type)
        active_action_counts = defaultdict(int)
        for defense in self.current_state.active_defenses:
            active_action_counts[defense.action_type] += 1

        for action_type in self.action_types:
            obs.append(min(1.0, active_action_counts[action_type] * 0.1))  # Scale by 0.1

        return np.array(obs, dtype=np.float32)

    def _is_episode_done(self) -> bool:
        """Check if the episode should end"""
        # End if max steps reached
        if self.current_step >= self.max_steps:
            return True

        # End if system health is too low
        if self.current_state.system_health < 0.1:
            return True

        # End if all nodes have very high risk
        high_risk_count = sum(1 for risk in self.current_state.risk_levels.values() if risk > 0.9)
        if high_risk_count >= len(self.current_state.risk_levels) * 0.8:
            return True

        return False

    def render(self, mode='human'):
        """Render the current environment state"""
        print(f"Step: {self.current_step}")
        print(f"System Health: {self.current_state.system_health:.3f}")
        print(f"Active Defenses: {len(self.current_state.active_defenses)}")
        print(f"Average Risk: {np.mean(list(self.current_state.risk_levels.values())):.3f}")
        print(f"Resource Usage: {self.current_state.resource_utilization}")
        print("---")

    def get_state_summary(self) -> Dict[str, Any]:
        """Get a summary of the current environment state"""
        return {
            'step': self.current_step,
            'system_health': self.current_state.system_health,
            'total_risk': sum(self.current_state.risk_levels.values()),
            'active_defenses': len(self.current_state.active_defenses),
            'resource_utilization': self.current_state.resource_utilization.copy(),
            'high_risk_nodes': sum(1 for r in self.current_state.risk_levels.values() if r > 0.7),
            'threat_indicators': self.current_state.threat_indicators.copy()
        }

# Example usage
if __name__ == "__main__":
    from ..probabilistic_attack_graph import BayesianAttackGraph, ProbabilisticNode, ProbabilisticEdge

    # Create sample attack graph
    graph = BayesianAttackGraph()

    # Add nodes
    nodes = [
        ProbabilisticNode("web_server", "server", 0.3),
        ProbabilisticNode("app_server", "server", 0.4),
        ProbabilisticNode("database", "database", 0.8)
    ]

    for node in nodes:
        graph.add_node(node)

    # Add edges
    edges = [
        ProbabilisticEdge("web_server", "app_server", "service_call", 0.8, 0.3, 2.0),
        ProbabilisticEdge("app_server", "database", "database_query", 0.9, 0.1, 3.0)
    ]

    for edge in edges:
        graph.add_edge(edge)

    # Create defense environment
    env = DefenseEnvironment(graph)

    print("Initial state:")
    env.render()

    # Take some actions
    for step in range(5):
        # Random action
        action = env.action_space.sample()
        obs, reward, done, info = env.step(action)

        print(f"Step {step + 1}:")
        print(f"Action: {action}")
        print(f"Reward: {reward:.3f}")
        print(f"System Health: {info['system_health']:.3f}")
        print(f"Total Risk: {info['total_risk']:.3f}")

        if done:
            break

    print("Final state:")
    env.render()