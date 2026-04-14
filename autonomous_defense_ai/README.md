# Autonomous Defense AI

Enterprise-grade AI capabilities for autonomous cyber defense, combining advanced machine learning, probabilistic reasoning, and reinforcement learning for comprehensive threat detection and mitigation.

## Architecture Overview

Hollow Purple's Autonomous Defense AI implements a three-layer architecture:

### 1. Graph Neural Networks (GNN)
- **Purpose**: Learn attack patterns and predict attacker movements
- **Components**:
  - `GraphNeuralNetwork`: Core GNN with PyTorch Geometric
  - `ThreatPredictor`: Real-time threat prediction
  - `AdvancedGraphFeatureBuilder`: Temporal and behavioral features
  - `TemporalAttackPredictor`: Evolution prediction over time

### 2. Probabilistic Attack Graphs
- **Purpose**: Bayesian reasoning for uncertainty quantification
- **Components**:
  - `BayesianAttackGraph`: Belief propagation for attack modeling
  - `ProbabilityEngine`: Monte Carlo simulation and uncertainty analysis
  - `RiskPropagationEngine`: Multi-dimensional risk assessment
  - `TemporalRiskModel`: Time-series risk forecasting

### 3. Reinforcement Defense
- **Purpose**: Adaptive defense strategies and optimal action selection
- **Components**:
  - `DefenseEnvironment`: RL environment for cyber defense
  - `DefenseAgent`: PPO-based agent with continuous learning
  - `RewardModel`: Multi-objective reward optimization
  - `DefensePolicyNetwork`: Actor-critic networks with attention

## Key Features

### Advanced Threat Intelligence
- **Graph-based Attack Modeling**: Represent complex attack chains as graphs
- **Probabilistic Reasoning**: Handle uncertainty in threat assessment
- **Temporal Analysis**: Predict attack evolution over time
- **Multi-dimensional Risk**: Assess confidentiality, integrity, availability, financial, operational, and reputational risks

### Autonomous Defense Actions
- **Reinforcement Learning**: Learn optimal defense strategies
- **Action Types**: Block IPs, isolate hosts, patch vulnerabilities, deploy honeypots, etc.
- **Resource Optimization**: Balance defense effectiveness with operational impact
- **Adaptive Learning**: Continuously improve from outcomes and threat intelligence

### Enterprise Scale
- **Production Ready**: Comprehensive error handling and logging
- **Scalable Architecture**: Support for planet-scale deployments
- **Integration**: Works with existing security infrastructure
- **Monitoring**: Advanced telemetry and performance metrics

## Installation

```bash
pip install -r requirements.txt
```

## Quick Start

```python
from autonomous_defense_ai import (
    GraphNeuralNetwork,
    BayesianAttackGraph,
    DefenseAgent,
    DefenseEnvironment
)

# 1. Create attack graph
attack_graph = BayesianAttackGraph()
# Add nodes and edges representing your infrastructure

# 2. Initialize GNN for threat prediction
gnn = GraphNeuralNetwork(
    input_dim=64,
    hidden_dim=128,
    output_dim=32,
    num_layers=3
)

# 3. Create defense environment and agent
env = DefenseEnvironment(attack_graph)
agent = DefenseAgent(env)

# 4. Start autonomous defense
agent.start_continuous_training()

# 5. Evaluate performance
results = agent.evaluate_policy(num_episodes=10)
print(f"Mean reward: {results['mean_reward']:.2f}")
```

## Core Components

### Graph Neural Network Module

```python
from autonomous_defense_ai.graph_neural_network import (
    GraphNeuralNetwork,
    AdvancedGraphFeatureBuilder,
    GNNModelTrainer
)

# Create feature builder
feature_builder = AdvancedGraphFeatureBuilder()

# Build GNN model
gnn = GraphNeuralNetwork(
    input_dim=feature_builder.feature_dim,
    hidden_dim=128,
    output_dim=32
)

# Train on attack data
trainer = GNNModelTrainer(gnn, feature_builder)
trainer.train(attack_graphs, epochs=100)
```

### Probabilistic Attack Graph Module

```python
from autonomous_defense_ai.probabilistic_attack_graph import (
    BayesianAttackGraph,
    ProbabilityEngine,
    RiskPropagationEngine
)

# Create Bayesian attack graph
graph = BayesianAttackGraph()

# Add probabilistic nodes and edges
node = ProbabilisticNode("web_server", "server", 0.3)
graph.add_node(node)

edge = ProbabilisticEdge("attacker", "web_server", "exploit", 0.8, 0.2, 1.5)
graph.add_edge(edge)

# Perform risk propagation
risk_engine = RiskPropagationEngine()
propagation_result = risk_engine.propagate_risk(graph)

print(f"System risk: {propagation_result.node_risks}")
```

### Reinforcement Defense Module

```python
from autonomous_defense_ai.reinforcement_defense import (
    DefenseEnvironment,
    DefenseAgent,
    RewardModel
)

# Create environment
env = DefenseEnvironment(attack_graph)

# Create agent with custom configuration
agent = DefenseAgent(
    env,
    config=AgentConfig(
        learning_rate=3e-4,
        gamma=0.99,
        batch_size=64
    )
)

# Train agent
for episode in range(100):
    info = agent.train_episode()
    print(f"Episode {episode}: Reward = {info['reward']:.2f}")

# Adapt to specific threats
agent.adapt_to_threat({
    'type': 'ransomware',
    'severity': 0.8
})
```

## Configuration

### Agent Configuration

```python
from autonomous_defense_ai.reinforcement_defense import AgentConfig

config = AgentConfig(
    learning_rate=3e-4,      # Policy learning rate
    gamma=0.99,              # Discount factor
    lambda_=0.95,            # GAE lambda
    clip_ratio=0.2,          # PPO clipping
    batch_size=64,           # Training batch size
    update_frequency=100,    # Policy update frequency
    checkpoint_frequency=1000  # Model saving frequency
)
```

### Network Architecture

```python
# Actor-Critic Network
policy = DefensePolicyNetwork(
    state_dim=128,
    action_dim=64,
    network_type='actor_critic',
    hidden_dim=256
)

# Attention-based Network
policy = DefensePolicyNetwork(
    state_dim=128,
    action_dim=64,
    network_type='attention',
    hidden_dim=256,
    num_heads=8
)
```

## API Reference

### GraphNeuralNetwork

```python
class GraphNeuralNetwork(nn.Module):
    def __init__(self, input_dim, hidden_dim, output_dim, num_layers=3):
        # Initialize GNN layers

    def forward(self, x, edge_index, edge_attr=None):
        # Forward pass through GNN
        pass

    def predict_threat(self, graph_data):
        # Predict threat levels
        pass
```

### BayesianAttackGraph

```python
class BayesianAttackGraph:
    def __init__(self):
        self.nodes = {}
        self.edges = {}

    def add_node(self, node: ProbabilisticNode):
        # Add probabilistic node
        pass

    def add_edge(self, edge: ProbabilisticEdge):
        # Add probabilistic edge
        pass

    def propagate_belief(self, evidence: Dict[str, float]):
        # Perform belief propagation
        pass
```

### DefenseAgent

```python
class DefenseAgent:
    def __init__(self, environment, config=None):
        # Initialize agent
        pass

    def select_action(self, state, deterministic=False):
        # Select defense action
        pass

    def train_episode(self, max_steps=1000):
        # Train for one episode
        pass

    def evaluate_policy(self, num_episodes=10):
        # Evaluate current policy
        pass

    def start_continuous_training(self):
        # Start background training
        pass
```

## Performance Metrics

The system tracks comprehensive metrics:

- **Risk Metrics**: Overall system risk, risk distribution, high-risk nodes
- **Defense Effectiveness**: Successful defenses, risk reduction, response time
- **System Health**: Availability, performance impact, resource utilization
- **Learning Metrics**: Policy loss, value loss, entropy, reward trends

## Integration Examples

### With Existing SIEM

```python
# Integrate with SIEM alerts
def process_siem_alert(alert):
    # Convert alert to graph update
    attack_graph.update_from_alert(alert)

    # Get AI prediction
    threat_level = gnn.predict_threat(attack_graph)

    # Take autonomous action
    if threat_level > 0.8:
        action = agent.select_action(current_state, deterministic=True)
        execute_defense_action(action)

# Real-time processing
siem_stream.subscribe(process_siem_alert)
```

### With Threat Intelligence

```python
# Incorporate threat intelligence
def update_threat_intelligence(ti_feed):
    # Update attack graph probabilities
    attack_graph.update_probabilities(ti_feed)

    # Adapt agent behavior
    agent.adapt_to_threat({
        'type': ti_feed['threat_type'],
        'severity': ti_feed['confidence']
    })

# Continuous learning
ti_stream.subscribe(update_threat_intelligence)
```

## Monitoring and Logging

The system provides comprehensive monitoring:

```python
# Get agent status
status = agent.get_agent_status()
print(f"Episodes: {status['current_episode']}")
print(f"Average Reward: {status['metrics']['average_reward']:.3f}")

# Export training data
agent.export_training_data("training_metrics.json")

# Log performance
logger.info(f"Risk reduction: {status['metrics']['risk_reduction']:.2f}")
```

## Deployment

### Docker Deployment

```dockerfile
FROM python:3.9-slim

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY autonomous_defense_ai/ ./autonomous_defense_ai/
COPY main.py .

CMD ["python", "main.py"]
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: hollow-purple-ai
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: defense-ai
        image: hollow-purple/ai:latest
        resources:
          requests:
            memory: "2Gi"
            cpu: "1000m"
          limits:
            memory: "4Gi"
            cpu: "2000m"
```

## Security Considerations

- **Model Security**: Protect trained models from tampering
- **Data Privacy**: Ensure sensitive data is not exposed in training
- **Access Control**: Implement RBAC for AI system management
- **Audit Logging**: Comprehensive logging of AI decisions and actions

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions:
- Documentation: [docs/](docs/)
- Issues: [GitHub Issues](https://github.com/hollow-purple/issues)
- Email: support@hollow-purple.ai

---

**Hollow Purple**: Enterprise Autonomous Cyber Defense Platform