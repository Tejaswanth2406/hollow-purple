"""
Defense Agent for Autonomous Cyber Defense

This module implements the main reinforcement learning agent that coordinates
defense actions, learns optimal policies, and adapts to evolving threats.
"""

import numpy as np
from typing import Dict, List, Tuple, Optional, Any, Union, Set
from dataclasses import dataclass
from datetime import datetime, timedelta
import logging
from collections import defaultdict, deque
import threading
import time
import json
import os

logger = logging.getLogger(__name__)

@dataclass
class AgentConfig:
    """Configuration for the defense agent"""
    learning_rate: float = 3e-4
    gamma: float = 0.99
    lambda_: float = 0.95
    clip_ratio: float = 0.2
    value_loss_coef: float = 0.5
    entropy_coef: float = 0.01
    max_grad_norm: float = 0.5
    batch_size: int = 64
    epochs_per_update: int = 10
    experience_buffer_size: int = 10000
    update_frequency: int = 100
    evaluation_frequency: int = 500
    checkpoint_frequency: int = 1000

@dataclass
class AgentMetrics:
    """Performance metrics for the defense agent"""
    episodes_completed: int = 0
    total_steps: int = 0
    average_reward: float = 0.0
    average_episode_length: float = 0.0
    policy_loss: float = 0.0
    value_loss: float = 0.0
    entropy: float = 0.0
    risk_reduction: float = 0.0
    system_health: float = 0.0
    successful_defenses: int = 0
    failed_defenses: int = 0

@dataclass
class AgentExperience:
    """Experience tuple for reinforcement learning"""
    state: np.ndarray
    action: int
    reward: float
    next_state: np.ndarray
    done: bool
    log_prob: float
    state_value: float
    timestamp: datetime

class DefenseAgent:
    """
    Main reinforcement learning agent for autonomous cyber defense

    This agent learns optimal defense strategies through interaction with
    the cyber defense environment, adapting to evolving threats and system conditions.
    """

    def __init__(self, environment: Any, config: AgentConfig = None,
                 model_path: str = None, device: str = 'auto'):
        self.environment = environment
        self.config = config or AgentConfig()

        # Extract dimensions from environment
        self.state_dim = self.environment.observation_space.shape[0]
        self.action_dim = self.environment.action_space.n

        # Initialize policy network
        from .policy_network import DefensePolicyNetwork
        self.policy_network = DefensePolicyNetwork(
            state_dim=self.state_dim,
            action_dim=self.action_dim,
            learning_rate=self.config.learning_rate,
            device=device
        )

        # Initialize reward model
        from .reward_model import RewardModel
        self.reward_model = RewardModel(
            alpha=0.1,
            gamma=self.config.gamma
        )

        # Experience buffer
        self.experience_buffer = deque(maxlen=self.config.experience_buffer_size)

        # Training state
        self.training_mode = True
        self.current_episode = 0
        self.current_step = 0
        self.last_update_step = 0

        # Metrics tracking
        self.metrics = AgentMetrics()
        self.episode_rewards = []
        self.episode_lengths = []

        # Model persistence
        self.model_path = model_path or "defense_agent_model.pth"
        self.checkpoint_dir = os.path.dirname(self.model_path) or "."

        # Load existing model if available
        if os.path.exists(self.model_path):
            try:
                self.load_model()
                logger.info(f"Loaded existing model from {self.model_path}")
            except Exception as e:
                logger.warning(f"Failed to load model: {e}")

        # Background training thread
        self.training_thread = None
        self.training_active = False

    def select_action(self, state: np.ndarray, deterministic: bool = False) -> Tuple[int, Dict[str, Any]]:
        """
        Select an action given the current state

        Args:
            state: Current environment state
            deterministic: Whether to use deterministic policy

        Returns:
            action: Selected action
            action_info: Additional action information
        """
        # Get action from policy network
        policy_output = self.policy_network.get_action(state, deterministic)

        action_info = {
            'log_prob': policy_output.log_prob,
            'state_value': policy_output.state_value,
            'entropy': policy_output.entropy,
            'action_probs': policy_output.action_probs.cpu().numpy()
        }

        return policy_output.action, action_info

    def train_episode(self, max_steps: int = 1000, render: bool = False) -> Dict[str, Any]:
        """
        Train for one episode

        Args:
            max_steps: Maximum steps per episode
            render: Whether to render environment

        Returns:
            episode_info: Information about the episode
        """
        # Reset environment
        state = self.environment.reset()
        episode_reward = 0.0
        episode_steps = 0
        episode_experience = []

        done = False

        while not done and episode_steps < max_steps:
            # Select action
            action, action_info = self.select_action(state, deterministic=not self.training_mode)

            # Execute action
            next_state, reward, done, info = self.environment.step(action)

            # Store experience
            experience = AgentExperience(
                state=state.copy(),
                action=action,
                reward=reward,
                next_state=next_state.copy(),
                done=done,
                log_prob=action_info['log_prob'],
                state_value=action_info['state_value'],
                timestamp=datetime.now()
            )

            episode_experience.append(experience)

            # Store in replay buffer
            self.experience_buffer.append(experience)

            # Update metrics
            episode_reward += reward
            episode_steps += 1
            self.current_step += 1

            # Update state
            state = next_state

            if render:
                self.environment.render()

            # Periodic policy updates
            if (self.current_step - self.last_update_step) >= self.config.update_frequency:
                self._update_policy()
                self.last_update_step = self.current_step

        # Update episode metrics
        self.current_episode += 1
        self.episode_rewards.append(episode_reward)
        self.episode_lengths.append(episode_steps)

        # Update running averages
        self._update_metrics(episode_reward, episode_steps, info)

        episode_info = {
            'episode': self.current_episode,
            'reward': episode_reward,
            'steps': episode_steps,
            'average_reward': self.metrics.average_reward,
            'system_health': info.get('system_health', 0.0),
            'total_risk': info.get('total_risk', 0.0)
        }

        logger.info(f"Episode {self.current_episode}: Reward={episode_reward:.2f}, "
                   f"Steps={episode_steps}, Avg Reward={self.metrics.average_reward:.2f}")

        return episode_info

    def _update_policy(self):
        """Update the policy network using accumulated experience"""
        if len(self.experience_buffer) < self.config.batch_size:
            return

        try:
            losses = self.policy_network.train_on_experience(
                batch_size=self.config.batch_size,
                epochs=self.config.epochs_per_update
            )

            if losses:
                latest_loss = losses[-1]
                self.metrics.policy_loss = latest_loss.actor_loss
                self.metrics.value_loss = latest_loss.critic_loss
                self.metrics.entropy = -latest_loss.entropy_loss  # Positive entropy

                logger.debug(f"Policy update: Loss={latest_loss.total_loss:.4f}, "
                           f"Actor={latest_loss.actor_loss:.4f}, Critic={latest_loss.critic_loss:.4f}")

        except Exception as e:
            logger.error(f"Policy update failed: {e}")

    def _update_metrics(self, episode_reward: float, episode_steps: int, info: Dict[str, Any]):
        """Update running metrics"""
        # Update averages
        alpha = 0.1  # Smoothing factor

        self.metrics.episodes_completed = self.current_episode
        self.metrics.total_steps = self.current_step
        self.metrics.average_reward = (1 - alpha) * self.metrics.average_reward + alpha * episode_reward
        self.metrics.average_episode_length = (1 - alpha) * self.metrics.average_episode_length + alpha * episode_steps

        # Update domain-specific metrics
        self.metrics.system_health = info.get('system_health', self.metrics.system_health)
        self.metrics.risk_reduction = info.get('total_risk', 0.0)  # Simplified

        # Update success/failure counts (simplified logic)
        if episode_reward > 0:
            self.metrics.successful_defenses += 1
        else:
            self.metrics.failed_defenses += 1

    def evaluate_policy(self, num_episodes: int = 10, deterministic: bool = True) -> Dict[str, Any]:
        """
        Evaluate the current policy

        Args:
            num_episodes: Number of evaluation episodes
            deterministic: Whether to use deterministic policy

        Returns:
            evaluation_results: Evaluation metrics
        """
        original_training_mode = self.training_mode
        self.training_mode = False

        evaluation_rewards = []
        evaluation_steps = []
        evaluation_health = []
        evaluation_risk = []

        for episode in range(num_episodes):
            state = self.environment.reset()
            episode_reward = 0.0
            episode_steps = 0
            done = False

            while not done and episode_steps < 1000:
                action, _ = self.select_action(state, deterministic=deterministic)
                next_state, reward, done, info = self.environment.step(action)

                episode_reward += reward
                episode_steps += 1
                state = next_state

            evaluation_rewards.append(episode_reward)
            evaluation_steps.append(episode_steps)
            evaluation_health.append(info.get('system_health', 0.0))
            evaluation_risk.append(info.get('total_risk', 0.0))

        # Restore training mode
        self.training_mode = original_training_mode

        evaluation_results = {
            'mean_reward': np.mean(evaluation_rewards),
            'std_reward': np.std(evaluation_rewards),
            'mean_steps': np.mean(evaluation_steps),
            'mean_health': np.mean(evaluation_health),
            'mean_risk': np.mean(evaluation_risk),
            'success_rate': sum(1 for r in evaluation_rewards if r > 0) / len(evaluation_rewards)
        }

        logger.info(f"Policy evaluation: Mean reward={evaluation_results['mean_reward']:.2f}, "
                   f"Success rate={evaluation_results['success_rate']:.2f}")

        return evaluation_results

    def start_continuous_training(self, episodes_per_batch: int = 10):
        """Start continuous training in background thread"""
        if self.training_thread and self.training_thread.is_alive():
            logger.warning("Training already active")
            return

        self.training_active = True

        def training_loop():
            while self.training_active:
                try:
                    # Train batch of episodes
                    batch_rewards = []
                    for _ in range(episodes_per_batch):
                        if not self.training_active:
                            break
                        episode_info = self.train_episode(render=False)
                        batch_rewards.append(episode_info['reward'])

                    # Periodic evaluation
                    if self.current_episode % self.config.evaluation_frequency == 0:
                        eval_results = self.evaluate_policy(num_episodes=5)
                        logger.info(f"Evaluation at episode {self.current_episode}: {eval_results}")

                    # Periodic checkpointing
                    if self.current_episode % self.config.checkpoint_frequency == 0:
                        self.save_model()
                        logger.info(f"Saved checkpoint at episode {self.current_episode}")

                    # Adaptive reward model updates
                    self.reward_model.update_reward_model()

                    time.sleep(0.1)  # Small delay to prevent overwhelming

                except Exception as e:
                    logger.error(f"Training error: {e}")
                    time.sleep(1.0)

        self.training_thread = threading.Thread(target=training_loop, daemon=True)
        self.training_thread.start()
        logger.info("Started continuous training")

    def stop_training(self):
        """Stop continuous training"""
        self.training_active = False
        if self.training_thread:
            self.training_thread.join(timeout=5.0)
        logger.info("Stopped training")

    def adapt_to_threat(self, threat_info: Dict[str, Any]):
        """
        Adapt agent behavior based on threat intelligence

        Args:
            threat_info: Information about current threats
        """
        # Adjust reward weights based on threat type
        threat_type = threat_info.get('type', 'unknown')
        threat_severity = threat_info.get('severity', 0.5)

        if threat_type == 'ransomware':
            # Prioritize data protection and backup
            self.reward_model.reward_weights['risk_mitigation'] *= 1.5
            self.reward_model.reward_weights['resource_efficiency'] *= 0.8
        elif threat_type == 'ddos':
            # Prioritize availability and resource management
            self.reward_model.reward_weights['system_stability'] *= 1.3
            self.reward_model.reward_weights['resource_efficiency'] *= 1.2
        elif threat_type == 'advanced_persistent_threat':
            # Prioritize long-term monitoring and detection
            self.reward_model.reward_weights['long_term_value'] *= 1.4
            self.reward_model.reward_weights['action_effectiveness'] *= 1.1

        # Scale adjustments by threat severity
        for key in self.reward_model.reward_weights:
            self.reward_model.reward_weights[key] *= (1 + threat_severity * 0.5)

        logger.info(f"Adapted to threat: {threat_type} (severity: {threat_severity})")

    def get_agent_status(self) -> Dict[str, Any]:
        """Get current agent status and metrics"""
        return {
            'training_active': self.training_active,
            'current_episode': self.current_episode,
            'current_step': self.current_step,
            'metrics': {
                'episodes_completed': self.metrics.episodes_completed,
                'total_steps': self.metrics.total_steps,
                'average_reward': self.metrics.average_reward,
                'average_episode_length': self.metrics.average_episode_length,
                'policy_loss': self.metrics.policy_loss,
                'value_loss': self.metrics.value_loss,
                'entropy': self.metrics.entropy,
                'system_health': self.metrics.system_health,
                'successful_defenses': self.metrics.successful_defenses,
                'failed_defenses': self.metrics.failed_defenses
            },
            'experience_buffer_size': len(self.experience_buffer),
            'policy_info': self.policy_network.get_policy_info(),
            'reward_weights': self.reward_model.reward_weights.copy()
        }

    def save_model(self, path: str = None):
        """Save the agent model"""
        path = path or self.model_path

        try:
            # Save policy network
            self.policy_network.save_policy(path)

            # Save additional agent state
            agent_state = {
                'config': self.config.__dict__,
                'current_episode': self.current_episode,
                'current_step': self.current_step,
                'metrics': self.metrics.__dict__,
                'reward_weights': self.reward_model.reward_weights
            }

            state_path = path.replace('.pth', '_agent_state.json')
            with open(state_path, 'w') as f:
                json.dump(agent_state, f, indent=2, default=str)

            logger.info(f"Saved agent model to {path}")

        except Exception as e:
            logger.error(f"Failed to save model: {e}")

    def load_model(self, path: str = None):
        """Load the agent model"""
        path = path or self.model_path

        try:
            # Load policy network
            self.policy_network.load_policy(path)

            # Load agent state
            state_path = path.replace('.pth', '_agent_state.json')
            if os.path.exists(state_path):
                with open(state_path, 'r') as f:
                    agent_state = json.load(f)

                self.current_episode = agent_state.get('current_episode', 0)
                self.current_step = agent_state.get('current_step', 0)

                # Load metrics
                metrics_dict = agent_state.get('metrics', {})
                for key, value in metrics_dict.items():
                    if hasattr(self.metrics, key):
                        setattr(self.metrics, key, value)

                # Load reward weights
                reward_weights = agent_state.get('reward_weights', {})
                self.reward_model.reward_weights.update(reward_weights)

            logger.info(f"Loaded agent model from {path}")

        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            raise

    def export_training_data(self, path: str):
        """Export training data for analysis"""
        training_data = {
            'episodes': self.episode_rewards,
            'episode_lengths': self.episode_lengths,
            'metrics': self.metrics.__dict__,
            'config': self.config.__dict__,
            'timestamp': datetime.now().isoformat()
        }

        with open(path, 'w') as f:
            json.dump(training_data, f, indent=2, default=str)

        logger.info(f"Exported training data to {path}")

# Example usage
if __name__ == "__main__":
    from .defense_environment import DefenseEnvironment
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

    # Create defense agent
    agent = DefenseAgent(env)

    print("Agent Status:")
    status = agent.get_agent_status()
    print(f"Episodes: {status['current_episode']}")
    print(f"Average Reward: {status['metrics']['average_reward']:.3f}")
    print(f"Policy Info: {status['policy_info']['network_type']}")

    # Train for a few episodes
    print("\nTraining episodes:")
    for episode in range(3):
        episode_info = agent.train_episode(max_steps=50)
        print(f"Episode {episode + 1}: Reward={episode_info['reward']:.2f}, "
              f"Steps={episode_info['steps']}")

    # Evaluate policy
    print("\nEvaluating policy:")
    eval_results = agent.evaluate_policy(num_episodes=2)
    print(f"Evaluation: Mean Reward={eval_results['mean_reward']:.2f}, "
          f"Success Rate={eval_results['success_rate']:.2f}")

    # Save model
    agent.save_model("test_defense_agent.pth")
    print("\nModel saved")