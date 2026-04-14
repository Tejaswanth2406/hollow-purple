"""
Reward Model for Defense Actions

This module implements advanced reward modeling for cyber defense reinforcement learning,
including multi-objective rewards, risk-based incentives, and long-term value estimation.
"""

import numpy as np
from typing import Dict, List, Tuple, Optional, Any, Union, Set
from dataclasses import dataclass
from datetime import datetime, timedelta
import logging
from collections import defaultdict, deque
import pandas as pd
from scipy.optimize import minimize_scalar
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestRegressor
import warnings

logger = logging.getLogger(__name__)

@dataclass
class RewardComponents:
    """Components that make up the total reward"""
    risk_mitigation: float      # Reward for reducing risk
    resource_efficiency: float  # Reward for efficient resource use
    system_stability: float     # Reward for maintaining system stability
    action_effectiveness: float # Reward for action effectiveness
    long_term_value: float      # Reward for long-term benefits
    penalty_avoidance: float    # Reward for avoiding penalties
    total_reward: float         # Combined total reward

@dataclass
class RewardHistory:
    """History of rewards for learning"""
    timestamp: datetime
    action: Any
    state_before: Any
    state_after: Any
    reward_components: RewardComponents
    context_factors: Dict[str, float]

class RewardModel:
    """
    Advanced reward model for cyber defense reinforcement learning

    This model provides sophisticated reward calculations that balance multiple objectives:
    - Risk reduction
    - Resource efficiency
    - System stability
    - Long-term strategic value
    """

    def __init__(self, alpha: float = 0.1, gamma: float = 0.99,
                 reward_horizon: int = 10):
        self.alpha = alpha  # Learning rate for reward adaptation
        self.gamma = gamma  # Discount factor for long-term rewards
        self.reward_horizon = reward_horizon  # Look-ahead horizon

        # Reward weights for different components
        self.reward_weights = {
            'risk_mitigation': 1.0,
            'resource_efficiency': 0.8,
            'system_stability': 0.9,
            'action_effectiveness': 0.7,
            'long_term_value': 0.6,
            'penalty_avoidance': 1.2
        }

        # Reward history for learning
        self.reward_history = deque(maxlen=1000)

        # Adaptive reward components
        self.risk_thresholds = {
            'low': 0.3,
            'medium': 0.6,
            'high': 0.8,
            'critical': 0.9
        }

        # Context-aware reward modifiers
        self.context_modifiers = {
            'business_hours': 1.2,      # Higher rewards during business hours
            'high_threat_level': 1.5,   # Higher rewards during high threat periods
            'resource_scarcity': 1.3,   # Higher rewards when resources are scarce
            'system_criticality': 1.4   # Higher rewards for critical systems
        }

        # Long-term value estimator
        self.value_estimator = None
        self._initialize_value_estimator()

    def calculate_reward(self, state_before: Any, state_after: Any,
                        action: Any, context: Dict[str, Any] = None) -> RewardComponents:
        """
        Calculate comprehensive reward for a defense action

        Args:
            state_before: Environment state before action
            state_after: Environment state after action
            action: The defense action taken
            context: Additional context information

        Returns:
            reward_components: Detailed reward breakdown
        """
        context = context or {}

        # Calculate individual reward components
        risk_mitigation = self._calculate_risk_mitigation_reward(state_before, state_after, action)
        resource_efficiency = self._calculate_resource_efficiency_reward(state_before, state_after, action)
        system_stability = self._calculate_system_stability_reward(state_before, state_after)
        action_effectiveness = self._calculate_action_effectiveness_reward(action, state_before, state_after)
        long_term_value = self._estimate_long_term_value(state_after, action)
        penalty_avoidance = self._calculate_penalty_avoidance_reward(state_before, state_after, action)

        # Apply context modifiers
        context_multiplier = self._calculate_context_multiplier(context)

        # Apply weights and context
        weighted_components = {
            'risk_mitigation': risk_mitigation * self.reward_weights['risk_mitigation'] * context_multiplier,
            'resource_efficiency': resource_efficiency * self.reward_weights['resource_efficiency'] * context_multiplier,
            'system_stability': system_stability * self.reward_weights['system_stability'] * context_multiplier,
            'action_effectiveness': action_effectiveness * self.reward_weights['action_effectiveness'] * context_multiplier,
            'long_term_value': long_term_value * self.reward_weights['long_term_value'] * context_multiplier,
            'penalty_avoidance': penalty_avoidance * self.reward_weights['penalty_avoidance'] * context_multiplier
        }

        # Calculate total reward
        total_reward = sum(weighted_components.values())

        reward_components = RewardComponents(
            risk_mitigation=weighted_components['risk_mitigation'],
            resource_efficiency=weighted_components['resource_efficiency'],
            system_stability=weighted_components['system_stability'],
            action_effectiveness=weighted_components['action_effectiveness'],
            long_term_value=weighted_components['long_term_value'],
            penalty_avoidance=weighted_components['penalty_avoidance'],
            total_reward=total_reward
        )

        # Store in history for learning
        self._store_reward_history(state_before, state_after, action, reward_components, context)

        return reward_components

    def _calculate_risk_mitigation_reward(self, state_before: Any, state_after: Any, action: Any) -> float:
        """Calculate reward for risk mitigation"""
        # Calculate risk reduction
        risk_before = sum(state_before.risk_levels.values())
        risk_after = sum(state_after.risk_levels.values())
        risk_reduction = risk_before - risk_after

        # Calculate risk reduction efficiency
        action_cost = self._get_action_cost(action)
        if action_cost > 0:
            efficiency = risk_reduction / action_cost
        else:
            efficiency = risk_reduction

        # Apply risk threshold bonuses
        risk_level_before = self._assess_risk_level(risk_before / len(state_before.risk_levels))
        risk_level_after = self._assess_risk_level(risk_after / len(state_after.risk_levels))

        # Bonus for moving from critical to lower levels
        level_improvement_bonus = 0.0
        if risk_level_before == 'critical' and risk_level_after in ['high', 'medium', 'low']:
            level_improvement_bonus = 2.0
        elif risk_level_before == 'high' and risk_level_after in ['medium', 'low']:
            level_improvement_bonus = 1.0

        return efficiency + level_improvement_bonus

    def _calculate_resource_efficiency_reward(self, state_before: Any, state_after: Any, action: Any) -> float:
        """Calculate reward for resource efficiency"""
        # Calculate resource utilization change
        resource_change = 0.0
        for resource in state_before.resource_utilization:
            change = state_after.resource_utilization[resource] - state_before.resource_utilization[resource]
            # Penalize resource increases, reward decreases
            resource_change += change

        # Get action's resource impact
        action_resource_impact = self._get_action_resource_impact(action)

        # Efficiency is negative resource change divided by impact
        if action_resource_impact > 0:
            efficiency = -resource_change / action_resource_impact
        else:
            efficiency = -resource_change  # No resource impact expected

        # Bonus for resource optimization
        resource_bonus = 0.0
        if resource_change < 0:  # Resources decreased
            resource_bonus = 0.5

        return efficiency + resource_bonus

    def _calculate_system_stability_reward(self, state_before: Any, state_after: Any) -> float:
        """Calculate reward for system stability maintenance"""
        # Stability based on health change and risk variance
        health_change = state_after.system_health - state_before.system_health

        # Calculate risk variance (lower variance = more stability)
        risk_values_before = list(state_before.risk_levels.values())
        risk_values_after = list(state_after.risk_levels.values())

        variance_before = np.var(risk_values_before) if risk_values_before else 0.0
        variance_after = np.var(risk_values_after) if risk_values_after else 0.0
        variance_change = variance_before - variance_after

        # Stability reward combines health improvement and variance reduction
        stability_reward = health_change * 2.0 + variance_change * 1.0

        # Penalty for health degradation
        if health_change < 0:
            stability_reward += health_change * 0.5  # Additional penalty

        return stability_reward

    def _calculate_action_effectiveness_reward(self, action: Any, state_before: Any, state_after: Any) -> float:
        """Calculate reward for action effectiveness"""
        # Get expected effectiveness from action profile
        expected_effectiveness = self._get_action_effectiveness(action)

        # Calculate actual effectiveness based on risk reduction for target
        target_node = getattr(action, 'target_node', None)
        if target_node and target_node in state_before.risk_levels and target_node in state_after.risk_levels:
            risk_before = state_before.risk_levels[target_node]
            risk_after = state_after.risk_levels[target_node]
            actual_effectiveness = (risk_before - risk_after) / max(risk_before, 1e-6)
        else:
            # General effectiveness based on overall risk reduction
            risk_before = sum(state_before.risk_levels.values())
            risk_after = sum(state_after.risk_levels.values())
            actual_effectiveness = (risk_before - risk_after) / max(risk_before, 1e-6)

        # Effectiveness reward is how well action performed vs expectation
        effectiveness_ratio = actual_effectiveness / max(expected_effectiveness, 1e-6)

        if effectiveness_ratio >= 1.0:
            # Better than expected
            reward = effectiveness_ratio * 1.0
        else:
            # Worse than expected
            reward = effectiveness_ratio * 0.5 - 0.5  # Penalty for underperformance

        return reward

    def _estimate_long_term_value(self, state_after: Any, action: Any) -> float:
        """Estimate long-term value of the current state and action"""
        if self.value_estimator is None:
            # Fallback: simple heuristic
            return self._heuristic_long_term_value(state_after, action)

        # Use trained value estimator
        try:
            state_features = self._extract_state_features(state_after)
            action_features = self._extract_action_features(action)

            features = np.concatenate([state_features, action_features])
            long_term_value = self.value_estimator.predict(features.reshape(1, -1))[0]

            return long_term_value
        except Exception as e:
            logger.warning(f"Value estimation failed: {e}")
            return self._heuristic_long_term_value(state_after, action)

    def _calculate_penalty_avoidance_reward(self, state_before: Any, state_after: Any, action: Any) -> float:
        """Calculate reward for avoiding penalties (e.g., breaches, downtime)"""
        penalty_avoidance = 0.0

        # Check for avoided breaches
        risk_before = sum(state_before.risk_levels.values()) / len(state_before.risk_levels)
        risk_after = sum(state_after.risk_levels.values()) / len(state_after.risk_levels)

        # Avoided breach if risk was high but reduced significantly
        if risk_before > 0.8 and risk_after < 0.7:
            penalty_avoidance += 2.0  # Major breach avoidance

        # Avoided system compromise
        health_degradation = state_before.system_health - state_after.system_health
        if health_degradation < 0.1:  # Health maintained
            penalty_avoidance += 0.5

        # Avoided resource exhaustion
        resource_violations_before = sum(1 for r, u in state_before.resource_utilization.items()
                                       if u > 0.9)
        resource_violations_after = sum(1 for r, u in state_after.resource_utilization.items()
                                      if u > 0.9)

        if resource_violations_after < resource_violations_before:
            penalty_avoidance += 0.3

        return penalty_avoidance

    def _calculate_context_multiplier(self, context: Dict[str, Any]) -> float:
        """Calculate context-based reward multiplier"""
        multiplier = 1.0

        # Business hours modifier
        current_hour = datetime.now().hour
        is_business_hours = 9 <= current_hour <= 17
        if is_business_hours:
            multiplier *= self.context_modifiers['business_hours']

        # High threat level modifier
        threat_level = context.get('threat_level', 0.5)
        if threat_level > 0.7:
            multiplier *= self.context_modifiers['high_threat_level']

        # Resource scarcity modifier
        resource_usage = context.get('avg_resource_usage', 0.5)
        if resource_usage > 0.8:
            multiplier *= self.context_modifiers['resource_scarcity']

        # System criticality modifier
        system_criticality = context.get('system_criticality', 0.5)
        if system_criticality > 0.7:
            multiplier *= self.context_modifiers['system_criticality']

        return multiplier

    def _assess_risk_level(self, avg_risk: float) -> str:
        """Assess risk level category"""
        if avg_risk >= self.risk_thresholds['critical']:
            return 'critical'
        elif avg_risk >= self.risk_thresholds['high']:
            return 'high'
        elif avg_risk >= self.risk_thresholds['medium']:
            return 'medium'
        else:
            return 'low'

    def _get_action_cost(self, action: Any) -> float:
        """Get the cost of an action"""
        # This would typically look up from action profiles
        action_type = getattr(action, 'action_type', 'unknown')
        cost_map = {
            'block_ip': 0.1,
            'isolate_host': 0.3,
            'patch_vulnerability': 0.2,
            'deploy_honeypot': 0.15,
            'increase_monitoring': 0.05,
            'quarantine_user': 0.25,
            'update_firewall': 0.1,
            'enable_2fa': 0.05,
            'rotate_credentials': 0.1
        }
        return cost_map.get(action_type, 0.1)

    def _get_action_resource_impact(self, action: Any) -> float:
        """Get the resource impact of an action"""
        action_type = getattr(action, 'action_type', 'unknown')
        impact_map = {
            'block_ip': 0.05,
            'isolate_host': 0.2,
            'patch_vulnerability': 0.05,
            'deploy_honeypot': 0.07,
            'increase_monitoring': 0.05,
            'quarantine_user': 0.05,
            'update_firewall': 0.01,
            'enable_2fa': 0.0,
            'rotate_credentials': 0.02
        }
        return impact_map.get(action_type, 0.05)

    def _get_action_effectiveness(self, action: Any) -> float:
        """Get the expected effectiveness of an action"""
        action_type = getattr(action, 'action_type', 'unknown')
        effectiveness_map = {
            'block_ip': 0.9,
            'isolate_host': 0.95,
            'patch_vulnerability': 0.85,
            'deploy_honeypot': 0.6,
            'increase_monitoring': 0.7,
            'quarantine_user': 0.8,
            'update_firewall': 0.75,
            'enable_2fa': 0.8,
            'rotate_credentials': 0.9
        }
        return effectiveness_map.get(action_type, 0.7)

    def _heuristic_long_term_value(self, state_after: Any, action: Any) -> float:
        """Heuristic long-term value estimation"""
        # Simple heuristic: combination of system health, low risk, and resource efficiency
        system_health = state_after.system_health
        avg_risk = sum(state_after.risk_levels.values()) / len(state_after.risk_levels)
        avg_resource_usage = sum(state_after.resource_utilization.values()) / len(state_after.resource_utilization)

        # Long-term value favors health, low risk, and efficient resource use
        long_term_value = (system_health * 0.4 - avg_risk * 0.4 - avg_resource_usage * 0.2)

        return long_term_value

    def _initialize_value_estimator(self):
        """Initialize the long-term value estimator"""
        try:
            self.value_estimator = RandomForestRegressor(
                n_estimators=100,
                max_depth=10,
                random_state=42
            )
        except ImportError:
            logger.warning("RandomForestRegressor not available, using heuristic value estimation")
            self.value_estimator = None

    def _extract_state_features(self, state: Any) -> np.ndarray:
        """Extract features from state for value estimation"""
        features = []

        # System health
        features.append(state.system_health)

        # Risk statistics
        risk_values = list(state.risk_levels.values())
        features.extend([
            np.mean(risk_values),
            np.std(risk_values),
            np.max(risk_values),
            np.min(risk_values)
        ])

        # Resource utilization
        resource_values = list(state.resource_utilization.values())
        features.extend([
            np.mean(resource_values),
            np.std(resource_values),
            np.max(resource_values)
        ])

        # Threat indicators
        threat_values = list(state.threat_indicators.values())
        features.extend([
            np.mean(threat_values),
            np.max(threat_values)
        ])

        return np.array(features)

    def _extract_action_features(self, action: Any) -> np.ndarray:
        """Extract features from action for value estimation"""
        features = []

        # Action type (one-hot encoded, simplified to index)
        action_type = getattr(action, 'action_type', 'unknown')
        action_types = ['block_ip', 'isolate_host', 'patch_vulnerability', 'deploy_honeypot',
                       'increase_monitoring', 'quarantine_user', 'update_firewall',
                       'enable_2fa', 'rotate_credentials']
        action_index = action_types.index(action_type) if action_type in action_types else -1
        features.append(action_index)

        # Action cost and effectiveness
        features.extend([
            getattr(action, 'cost', 0.1),
            getattr(action, 'effectiveness', 0.7)
        ])

        # Duration (in hours)
        duration_hours = getattr(action, 'duration', timedelta(hours=24)).total_seconds() / 3600
        features.append(duration_hours)

        return np.array(features)

    def _store_reward_history(self, state_before: Any, state_after: Any,
                            action: Any, reward_components: RewardComponents,
                            context: Dict[str, Any]):
        """Store reward history for learning"""
        reward_entry = RewardHistory(
            timestamp=datetime.now(),
            action=action,
            state_before=state_before,
            state_after=state_after,
            reward_components=reward_components,
            context_factors=context
        )

        self.reward_history.append(reward_entry)

    def update_reward_model(self):
        """Update the reward model based on historical data"""
        if len(self.reward_history) < 50 or self.value_estimator is None:
            return

        # Prepare training data
        X = []
        y = []

        for entry in self.reward_history:
            try:
                state_features = self._extract_state_features(entry.state_after)
                action_features = self._extract_action_features(entry.action)

                features = np.concatenate([state_features, action_features])
                target = entry.reward_components.long_term_value

                X.append(features)
                y.append(target)
            except Exception as e:
                logger.debug(f"Skipping reward entry: {e}")
                continue

        if len(X) < 10:
            return

        # Train value estimator
        X = np.array(X)
        y = np.array(y)

        try:
            self.value_estimator.fit(X, y)
            logger.info(f"Updated value estimator with {len(X)} samples")
        except Exception as e:
            logger.warning(f"Failed to update value estimator: {e}")

    def get_reward_statistics(self) -> Dict[str, Any]:
        """Get statistics about reward distributions"""
        if not self.reward_history:
            return {'total_samples': 0}

        rewards = [entry.reward_components.total_reward for entry in self.reward_history]

        return {
            'total_samples': len(rewards),
            'mean_reward': np.mean(rewards),
            'std_reward': np.std(rewards),
            'min_reward': np.min(rewards),
            'max_reward': np.max(rewards),
            'median_reward': np.median(rewards),
            'positive_reward_ratio': sum(1 for r in rewards if r > 0) / len(rewards)
        }

    def adapt_reward_weights(self, performance_metrics: Dict[str, float]):
        """Adapt reward weights based on performance metrics"""
        # Adjust weights based on what components are most important for success
        risk_focus = performance_metrics.get('risk_reduction_importance', 1.0)
        efficiency_focus = performance_metrics.get('efficiency_importance', 1.0)
        stability_focus = performance_metrics.get('stability_importance', 1.0)

        # Update weights with learning rate
        self.reward_weights['risk_mitigation'] += self.alpha * (risk_focus - self.reward_weights['risk_mitigation'])
        self.reward_weights['resource_efficiency'] += self.alpha * (efficiency_focus - self.reward_weights['resource_efficiency'])
        self.reward_weights['system_stability'] += self.alpha * (stability_focus - self.reward_weights['system_stability'])

        # Ensure weights stay positive
        for key in self.reward_weights:
            self.reward_weights[key] = max(0.1, self.reward_weights[key])

        logger.info(f"Adapted reward weights: {self.reward_weights}")

# Example usage
if __name__ == "__main__":
    from .defense_environment import DefenseEnvironment, DefenseState, DefenseAction
    from datetime import timedelta

    # Create mock states
    mock_state_before = DefenseState(
        attack_graph=None,
        active_defenses=[],
        system_health=0.7,
        risk_levels={'node1': 0.8, 'node2': 0.6},
        resource_utilization={'cpu': 0.5, 'memory': 0.4},
        threat_indicators={'threat1': 0.3},
        timestamp=datetime.now()
    )

    mock_state_after = DefenseState(
        attack_graph=None,
        active_defenses=[],
        system_health=0.75,
        risk_levels={'node1': 0.6, 'node2': 0.5},
        resource_utilization={'cpu': 0.55, 'memory': 0.45},
        threat_indicators={'threat1': 0.2},
        timestamp=datetime.now()
    )

    mock_action = DefenseAction(
        action_type='block_ip',
        target_node='node1',
        parameters={},
        cost=0.1,
        effectiveness=0.9,
        duration=timedelta(hours=24),
        timestamp=datetime.now()
    )

    # Create reward model
    reward_model = RewardModel()

    # Calculate reward
    reward = reward_model.calculate_reward(mock_state_before, mock_state_after, mock_action)

    print("Reward Components:")
    print(f"Risk Mitigation: {reward.risk_mitigation:.3f}")
    print(f"Resource Efficiency: {reward.resource_efficiency:.3f}")
    print(f"System Stability: {reward.system_stability:.3f}")
    print(f"Action Effectiveness: {reward.action_effectiveness:.3f}")
    print(f"Long-term Value: {reward.long_term_value:.3f}")
    print(f"Penalty Avoidance: {reward.penalty_avoidance:.3f}")
    print(f"Total Reward: {reward.total_reward:.3f}")

    # Get reward statistics
    stats = reward_model.get_reward_statistics()
    print(f"\nReward Statistics: {stats}")