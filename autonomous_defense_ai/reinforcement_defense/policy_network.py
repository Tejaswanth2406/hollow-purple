"""
Policy Network for Defense Actions

This module implements neural network policies for autonomous cyber defense,
including actor-critic architectures, attention mechanisms, and multi-head policies.
"""

import numpy as np
from typing import Dict, List, Tuple, Optional, Any, Union, Set
from dataclasses import dataclass
from datetime import datetime, timedelta
import logging
from collections import defaultdict, deque
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.distributions import Categorical, Normal
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import warnings

logger = logging.getLogger(__name__)

@dataclass
class PolicyOutput:
    """Output from policy network"""
    action: int
    action_probs: torch.Tensor
    state_value: float
    entropy: float
    log_prob: float

@dataclass
class PolicyLoss:
    """Policy loss components"""
    actor_loss: float
    critic_loss: float
    entropy_loss: float
    total_loss: float

class ActorCriticNetwork(nn.Module):
    """
    Actor-Critic neural network for defense policy learning

    This network combines policy (actor) and value (critic) estimation
    for reinforcement learning in cyber defense scenarios.
    """

    def __init__(self, state_dim: int, action_dim: int, hidden_dim: int = 256,
                 num_layers: int = 3, dropout_rate: float = 0.1):
        super(ActorCriticNetwork, self).__init__()

        self.state_dim = state_dim
        self.action_dim = action_dim
        self.hidden_dim = hidden_dim

        # Shared feature extractor
        layers = []
        input_dim = state_dim

        for i in range(num_layers):
            layers.extend([
                nn.Linear(input_dim, hidden_dim),
                nn.LayerNorm(hidden_dim),
                nn.ReLU(),
                nn.Dropout(dropout_rate)
            ])
            input_dim = hidden_dim

        self.feature_extractor = nn.Sequential(*layers)

        # Actor head (policy)
        self.actor = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Linear(hidden_dim // 2, action_dim)
        )

        # Critic head (value)
        self.critic = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Linear(hidden_dim // 2, 1)
        )

        # Initialize weights
        self.apply(self._init_weights)

    def _init_weights(self, module):
        """Initialize network weights"""
        if isinstance(module, nn.Linear):
            nn.init.orthogonal_(module.weight, gain=np.sqrt(2))
            nn.init.constant_(module.bias, 0.0)

    def forward(self, state: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Forward pass through the network

        Args:
            state: Input state tensor

        Returns:
            action_logits: Logits for action distribution
            state_value: Estimated state value
        """
        features = self.feature_extractor(state)

        action_logits = self.actor(features)
        state_value = self.critic(features).squeeze(-1)

        return action_logits, state_value

    def get_action(self, state: torch.Tensor, deterministic: bool = False) -> PolicyOutput:
        """
        Get action from policy

        Args:
            state: Current state
            deterministic: Whether to return deterministic action

        Returns:
            policy_output: Action and associated information
        """
        with torch.no_grad():
            action_logits, state_value = self.forward(state)

            # Create action distribution
            action_dist = Categorical(logits=action_logits)

            if deterministic:
                action = torch.argmax(action_logits, dim=-1)
                log_prob = action_dist.log_prob(action)
                entropy = action_dist.entropy()
            else:
                action = action_dist.sample()
                log_prob = action_dist.log_prob(action)
                entropy = action_dist.entropy()

            action_probs = F.softmax(action_logits, dim=-1)

            return PolicyOutput(
                action=action.item(),
                action_probs=action_probs,
                state_value=state_value.item(),
                entropy=entropy.item(),
                log_prob=log_prob.item()
            )

class AttentionPolicyNetwork(nn.Module):
    """
    Attention-based policy network for complex defense scenarios

    This network uses attention mechanisms to focus on relevant parts
    of the cyber defense state for better decision making.
    """

    def __init__(self, state_dim: int, action_dim: int, hidden_dim: int = 256,
                 num_heads: int = 8, num_layers: int = 2):
        super(AttentionPolicyNetwork, self).__init__()

        self.state_dim = state_dim
        self.action_dim = action_dim
        self.hidden_dim = hidden_dim
        self.num_heads = num_heads

        # Input projection
        self.input_proj = nn.Linear(state_dim, hidden_dim)

        # Multi-head attention layers
        self.attention_layers = nn.ModuleList([
            nn.MultiheadAttention(hidden_dim, num_heads, batch_first=True)
            for _ in range(num_layers)
        ])

        # Feed-forward layers
        self.ff_layers = nn.ModuleList([
            nn.Sequential(
                nn.Linear(hidden_dim, hidden_dim * 4),
                nn.ReLU(),
                nn.Linear(hidden_dim * 4, hidden_dim),
                nn.LayerNorm(hidden_dim)
            )
            for _ in range(num_layers)
        ])

        # Actor and critic heads
        self.actor = nn.Linear(hidden_dim, action_dim)
        self.critic = nn.Linear(hidden_dim, 1)

        # Layer normalization
        self.layer_norm1 = nn.LayerNorm(hidden_dim)
        self.layer_norm2 = nn.LayerNorm(hidden_dim)

    def forward(self, state: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Forward pass with attention mechanism

        Args:
            state: Input state tensor (batch_size, state_dim)

        Returns:
            action_logits: Action logits
            state_value: State value estimate
        """
        # Add batch and sequence dimensions for attention
        x = state.unsqueeze(1)  # (batch_size, 1, state_dim)

        # Input projection
        x = self.input_proj(x)

        # Attention layers
        for attention, ff in zip(self.attention_layers, self.ff_layers):
            # Self-attention (using the same sequence as query, key, value)
            attn_output, _ = attention(x, x, x)

            # Residual connection and layer norm
            x = self.layer_norm1(x + attn_output)

            # Feed-forward
            ff_output = ff(x)
            x = self.layer_norm2(x + ff_output)

        # Remove sequence dimension
        x = x.squeeze(1)

        # Actor and critic outputs
        action_logits = self.actor(x)
        state_value = self.critic(x).squeeze(-1)

        return action_logits, state_value

class MultiHeadPolicyNetwork(nn.Module):
    """
    Multi-head policy network for different defense scenarios

    This network has separate heads for different types of defense actions,
    allowing specialized policies for different threat scenarios.
    """

    def __init__(self, state_dim: int, action_dims: Dict[str, int], hidden_dim: int = 256):
        super(MultiHeadPolicyNetwork, self).__init__()

        self.state_dim = state_dim
        self.action_dims = action_dims
        self.head_names = list(action_dims.keys())

        # Shared feature extractor
        self.feature_extractor = nn.Sequential(
            nn.Linear(state_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.ReLU()
        )

        # Separate policy heads for different action types
        self.policy_heads = nn.ModuleDict()
        for head_name, action_dim in action_dims.items():
            self.policy_heads[head_name] = nn.Sequential(
                nn.Linear(hidden_dim, hidden_dim // 2),
                nn.ReLU(),
                nn.Linear(hidden_dim // 2, action_dim)
            )

        # Shared critic
        self.critic = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Linear(hidden_dim // 2, 1)
        )

    def forward(self, state: torch.Tensor, head_name: str = None) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Forward pass through specified head

        Args:
            state: Input state
            head_name: Which policy head to use (if None, uses first head)

        Returns:
            action_logits: Action logits for specified head
            state_value: State value
        """
        if head_name is None:
            head_name = self.head_names[0]

        features = self.feature_extractor(state)

        action_logits = self.policy_heads[head_name](features)
        state_value = self.critic(features).squeeze(-1)

        return action_logits, state_value

    def get_all_heads(self, state: torch.Tensor) -> Dict[str, Tuple[torch.Tensor, torch.Tensor]]:
        """Get outputs from all policy heads"""
        features = self.feature_extractor(state)

        outputs = {}
        for head_name in self.head_names:
            action_logits = self.policy_heads[head_name](features)
            outputs[head_name] = action_logits

        state_value = self.critic(features).squeeze(-1)

        return {'heads': outputs, 'value': state_value}

class DefensePolicyNetwork:
    """
    Main policy network class for cyber defense

    This class manages different policy architectures and provides
    training and inference capabilities.
    """

    def __init__(self, state_dim: int, action_dim: int, network_type: str = 'actor_critic',
                 hidden_dim: int = 256, learning_rate: float = 3e-4,
                 device: str = 'auto'):
        self.state_dim = state_dim
        self.action_dim = action_dim
        self.network_type = network_type

        # Device configuration
        if device == 'auto':
            self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        else:
            self.device = torch.device(device)

        # Create network
        if network_type == 'actor_critic':
            self.network = ActorCriticNetwork(state_dim, action_dim, hidden_dim)
        elif network_type == 'attention':
            self.network = AttentionPolicyNetwork(state_dim, action_dim, hidden_dim)
        elif network_type == 'multi_head':
            # Default multi-head configuration
            action_dims = {
                'immediate': action_dim,  # Immediate defense actions
                'strategic': action_dim,  # Strategic/long-term actions
                'preventive': action_dim  # Preventive measures
            }
            self.network = MultiHeadPolicyNetwork(state_dim, action_dims, hidden_dim)
        else:
            raise ValueError(f"Unknown network type: {network_type}")

        self.network.to(self.device)

        # Optimizer
        self.optimizer = optim.Adam(self.network.parameters(), lr=learning_rate)

        # Training parameters
        self.value_loss_coef = 0.5
        self.entropy_coef = 0.01
        self.max_grad_norm = 0.5

        # Experience buffer
        self.experience_buffer = deque(maxlen=10000)

    def get_action(self, state: np.ndarray, deterministic: bool = False,
                  head_name: str = None) -> PolicyOutput:
        """
        Get action from policy

        Args:
            state: Current state as numpy array
            deterministic: Whether to use deterministic policy
            head_name: Which head to use (for multi-head networks)

        Returns:
            policy_output: Action and associated information
        """
        # Convert to tensor
        state_tensor = torch.FloatTensor(state).unsqueeze(0).to(self.device)

        # Get action from network
        if hasattr(self.network, 'get_action'):
            # ActorCriticNetwork has its own get_action method
            return self.network.get_action(state_tensor, deterministic)
        else:
            # For other networks, implement action selection
            with torch.no_grad():
                if isinstance(self.network, MultiHeadPolicyNetwork):
                    action_logits, state_value = self.network(state_tensor, head_name)
                else:
                    action_logits, state_value = self.network(state_tensor)

                # Create action distribution
                action_dist = Categorical(logits=action_logits)

                if deterministic:
                    action = torch.argmax(action_logits, dim=-1)
                    log_prob = action_dist.log_prob(action)
                    entropy = action_dist.entropy()
                else:
                    action = action_dist.sample()
                    log_prob = action_dist.log_prob(action)
                    entropy = action_dist.entropy()

                action_probs = F.softmax(action_logits, dim=-1)

                return PolicyOutput(
                    action=action.item(),
                    action_probs=action_probs,
                    state_value=state_value.item(),
                    entropy=entropy.item(),
                    log_prob=log_prob.item()
                )

    def update_policy(self, states: torch.Tensor, actions: torch.Tensor,
                     old_log_probs: torch.Tensor, advantages: torch.Tensor,
                     returns: torch.Tensor, clip_ratio: float = 0.2) -> PolicyLoss:
        """
        Update policy using PPO-style clipped objective

        Args:
            states: Batch of states
            actions: Batch of actions taken
            old_log_probs: Log probabilities of actions at time of taking
            advantages: Advantage estimates
            returns: Computed returns
            clip_ratio: PPO clipping ratio

        Returns:
            policy_loss: Loss components
        """
        # Get current policy outputs
        action_logits, state_values = self.network(states)

        # Create action distribution
        action_dist = Categorical(logits=action_logits)

        # Get log probabilities of taken actions
        new_log_probs = action_dist.log_prob(actions)
        entropy = action_dist.entropy().mean()

        # PPO clipped objective
        ratios = torch.exp(new_log_probs - old_log_probs)
        clipped_ratios = torch.clamp(ratios, 1 - clip_ratio, 1 + clip_ratio)
        actor_loss = -torch.min(ratios * advantages, clipped_ratios * advantages).mean()

        # Value loss (critic)
        critic_loss = F.mse_loss(state_values, returns)

        # Entropy bonus
        entropy_loss = -entropy * self.entropy_coef

        # Total loss
        total_loss = actor_loss + self.value_loss_coef * critic_loss + entropy_loss

        # Update network
        self.optimizer.zero_grad()
        total_loss.backward()

        # Clip gradients
        torch.nn.utils.clip_grad_norm_(self.network.parameters(), self.max_grad_norm)

        self.optimizer.step()

        return PolicyLoss(
            actor_loss=actor_loss.item(),
            critic_loss=critic_loss.item(),
            entropy_loss=entropy_loss.item(),
            total_loss=total_loss.item()
        )

    def store_experience(self, state: np.ndarray, action: int, reward: float,
                        next_state: np.ndarray, done: bool, log_prob: float):
        """Store experience tuple for later training"""
        self.experience_buffer.append({
            'state': state,
            'action': action,
            'reward': reward,
            'next_state': next_state,
            'done': done,
            'log_prob': log_prob
        })

    def train_on_experience(self, batch_size: int = 64, epochs: int = 10) -> List[PolicyLoss]:
        """Train policy on stored experience"""
        if len(self.experience_buffer) < batch_size:
            return []

        # Convert experience to tensors
        experiences = list(self.experience_buffer)
        states = torch.FloatTensor([exp['state'] for exp in experiences]).to(self.device)
        actions = torch.LongTensor([exp['action'] for exp in experiences]).to(self.device)
        rewards = torch.FloatTensor([exp['reward'] for exp in experiences]).to(self.device)
        next_states = torch.FloatTensor([exp['next_state'] for exp in experiences]).to(self.device)
        dones = torch.FloatTensor([exp['done'] for exp in experiences]).to(self.device)
        old_log_probs = torch.FloatTensor([exp['log_prob'] for exp in experiences]).to(self.device)

        # Compute returns and advantages
        returns, advantages = self._compute_returns_and_advantages(rewards, next_states, dones)

        # Create dataset
        dataset = TensorDataset(states, actions, old_log_probs, advantages, returns)
        dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

        losses = []

        for epoch in range(epochs):
            for batch_states, batch_actions, batch_old_log_probs, batch_advantages, batch_returns in dataloader:
                loss = self.update_policy(
                    batch_states, batch_actions, batch_old_log_probs,
                    batch_advantages, batch_returns
                )
                losses.append(loss)

        # Clear experience buffer after training
        self.experience_buffer.clear()

        return losses

    def _compute_returns_and_advantages(self, rewards: torch.Tensor,
                                       next_states: torch.Tensor, dones: torch.Tensor,
                                       gamma: float = 0.99, lambda_: float = 0.95) -> Tuple[torch.Tensor, torch.Tensor]:
        """Compute returns and advantages using GAE"""
        with torch.no_grad():
            # Get value estimates for next states
            _, next_values = self.network(next_states)
            next_values = next_values * (1 - dones)

            # Compute returns and advantages
            returns = torch.zeros_like(rewards)
            advantages = torch.zeros_like(rewards)

            gae = 0
            for t in reversed(range(len(rewards))):
                if t == len(rewards) - 1:
                    next_value = next_values[t]
                else:
                    next_value = next_values[t + 1]

                delta = rewards[t] + gamma * next_value - next_values[t]
                gae = delta + gamma * lambda_ * (1 - dones[t]) * gae

                returns[t] = gae + next_values[t]
                advantages[t] = gae

            # Normalize advantages
            advantages = (advantages - advantages.mean()) / (advantages.std() + 1e-8)

        return returns, advantages

    def save_policy(self, path: str):
        """Save policy network to file"""
        torch.save({
            'network_state_dict': self.network.state_dict(),
            'optimizer_state_dict': self.optimizer.state_dict(),
            'network_type': self.network_type,
            'state_dim': self.state_dim,
            'action_dim': self.action_dim
        }, path)

    def load_policy(self, path: str):
        """Load policy network from file"""
        checkpoint = torch.load(path, map_location=self.device)

        # Recreate network if necessary
        if checkpoint['network_type'] != self.network_type:
            logger.warning(f"Network type mismatch: {checkpoint['network_type']} vs {self.network_type}")

        self.network.load_state_dict(checkpoint['network_state_dict'])
        self.optimizer.load_state_dict(checkpoint['optimizer_state_dict'])

    def get_policy_info(self) -> Dict[str, Any]:
        """Get information about the policy network"""
        return {
            'network_type': self.network_type,
            'state_dim': self.state_dim,
            'action_dim': self.action_dim,
            'device': str(self.device),
            'trainable_parameters': sum(p.numel() for p in self.network.parameters() if p.requires_grad),
            'experience_buffer_size': len(self.experience_buffer)
        }

# Example usage
if __name__ == "__main__":
    # Example state and action dimensions
    state_dim = 50  # Example state dimension
    action_dim = 18  # 9 nodes × 2 action types (simplified)

    # Create policy network
    policy = DefensePolicyNetwork(state_dim, action_dim, network_type='actor_critic')

    # Example state
    state = np.random.randn(state_dim)

    # Get action
    action_output = policy.get_action(state)

    print("Policy Network Info:")
    print(f"Network Type: {policy.network_type}")
    print(f"State Dim: {policy.state_dim}")
    print(f"Action Dim: {policy.action_dim}")
    print(f"Selected Action: {action_output.action}")
    print(f"Action Probabilities Shape: {action_output.action_probs.shape}")
    print(f"State Value: {action_output.state_value:.3f}")
    print(f"Entropy: {action_output.entropy:.3f}")

    # Simulate some experience
    for _ in range(100):
        next_state = np.random.randn(state_dim)
        reward = np.random.randn()
        done = np.random.rand() > 0.95

        policy.store_experience(state, action_output.action, reward, next_state, done, action_output.log_prob)
        state = next_state

    print(f"Experience buffer size: {len(policy.experience_buffer)}")

    # Train on experience
    losses = policy.train_on_experience(batch_size=32, epochs=5)

    if losses:
        final_loss = losses[-1]
        print(f"Final training loss: {final_loss.total_loss:.3f}")
        print(f"Actor loss: {final_loss.actor_loss:.3f}")
        print(f"Critic loss: {final_loss.critic_loss:.3f}")
        print(f"Entropy loss: {final_loss.entropy_loss:.3f}")