Hollow Purple

Adaptive Cloud Identity Attack Detection Platform with Autonomous AI Defense

Hollow Purple is an advanced cybersecurity analysis platform designed to detect complex identity-based attacks in cloud environments. The system continuously ingests events, builds temporal identity graphs, models baseline behavior, and detects anomalous activity such as privilege escalation, lateral movement, and token abuse.

**🚀 NEW: Autonomous Defense AI** - Hollow Purple now includes enterprise-grade AI capabilities for autonomous cyber defense, featuring DARPA/Palantir-style autonomous threat response with graph neural networks, probabilistic reasoning, and reinforcement learning.

The platform is built as a modular distributed system with a strong focus on security, verifiability, and deterministic state reconstruction.

---

## Architecture Overview

Hollow Purple operates through multiple coordinated subsystems:

1. **Ingestion Pipeline**
   * Collects identity and activity events from multiple sources
   * Performs validation, deduplication, and normalization
   * Provides high-throughput event streaming

2. **Graph Engine**
   * Constructs a dynamic identity interaction graph
   * Maintains temporal relationships between entities
   * Enables path analysis for attack detection

3. **Baseline Engine**
   * Learns normal behavior patterns for identities and services
   * Detects behavioral drift and abnormal activity

4. **Attack Pattern Detection**
   * Privilege escalation detection
   * Lateral movement analysis
   * Token abuse detection

5. **Risk Engine**
   * Aggregates signals from multiple detectors
   * Produces a unified risk score for entities and events

6. **Autonomous Defense AI** 🧠
   * **Graph Neural Networks**: Learn attack patterns and predict threats
   * **Probabilistic Attack Graphs**: Bayesian reasoning for uncertainty quantification
   * **Reinforcement Defense**: Adaptive autonomous response and mitigation
   * Real-time threat prediction and autonomous defense actions

7. **State Snapshot & Replay**
   * Deterministic state reconstruction
   * Historical replay for forensic analysis

8. **Integrity Verification System**
   * Merkle-based event verification
   * Tamper-evident audit trail

---

## Core Features

* High-throughput event ingestion
* Temporal identity graph modeling
* Behavior baseline modeling
* Attack path discovery
* **Autonomous AI Defense** 🚀
  * Graph neural networks for threat prediction
  * Probabilistic attack graph modeling
  * Reinforcement learning for optimal defense
  * Real-time autonomous response
  * Continuous learning and adaptation
* Deterministic replay engine
* Tamper-evident event logs
* Modular micro-service architecture
* Distributed deployment ready

---

## Project Structure

```
HOLLOW_PURPLE/
│
├── autonomous_defense_ai/          # AI Brain - Autonomous Defense 🧠
│   ├── graph_neural_network/       # GNN for threat prediction
│   ├── probabilistic_attack_graph/ # Bayesian attack modeling
│   ├── reinforcement_defense/      # RL for autonomous response
│   └── README.md                   # AI module documentation
│
├── api/                # API layer and service endpoints
├── ingestion/          # Event ingestion pipeline
├── graph/              # Graph construction and analysis
├── engine/             # Detection and orchestration engine
├── baseline/           # Behavioral baseline models
├── patterns/           # Attack pattern detection modules
├── projections/        # Risk projection and scoring
├── storage/            # Data persistence layer
├── state/              # State management
├── configs/            # System configuration
├── bootstrap/          # System startup controller
├── MAHORAGHA/          # Integrity verification system
├── scripts/            # Utility scripts
├── tests/              # System test suite
│
├── main.py             # Platform entrypoint
├── main.env            # System configuration
└── requirements.txt
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/Tejaswanth2406/hollow-purple.git
cd hollow-purple
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Configuration

The system uses a centralized environment configuration file.

```
main.env
```

This file defines:

* API configuration
* ingestion pipeline limits
* graph engine limits
* baseline parameters
* risk scoring thresholds
* system telemetry

---

## Autonomous Defense AI 🧠

Hollow Purple includes enterprise-grade AI capabilities for autonomous cyber defense:

### Graph Neural Networks
Learn complex attack patterns and predict attacker movements through graph-based deep learning.

### Probabilistic Attack Graphs
Bayesian reasoning for uncertainty quantification in threat assessment and risk propagation.

### Reinforcement Defense
Adaptive agents that learn optimal defense strategies through interaction with cyber environments.

### Key AI Features
* **Real-time Threat Prediction**: Predict attacks before they occur
* **Autonomous Response**: AI-driven defense actions (block IPs, isolate hosts, patch vulnerabilities)
* **Probabilistic Reasoning**: Handle uncertainty in threat assessments
* **Continuous Learning**: Adapt to new threats and improve over time
* **Multi-objective Optimization**: Balance security effectiveness with operational impact

### AI Quick Start
```python
from autonomous_defense_ai import GraphNeuralNetwork, BayesianAttackGraph, DefenseAgent

# Initialize AI components
gnn = GraphNeuralNetwork(input_dim=64, hidden_dim=128, output_dim=32)
attack_graph = BayesianAttackGraph()
agent = DefenseAgent(DefenseEnvironment(attack_graph))

# Start autonomous defense
agent.start_continuous_training()
```

See `autonomous_defense_ai/README.md` for comprehensive AI documentation.

---

Start the Hollow Purple kernel:

```bash
python main.py
```

The platform will automatically start:

* ingestion pipeline
* graph engine
* detection engine
* API server
* health monitoring
* metrics collection

---

## Development

Run tests:

```bash
pytest
```

Lint the code:

```bash
pylint .
```

---

## Security

Hollow Purple includes a tamper-evident event verification system.
All events can be cryptographically verified through the integrity subsystem.

If you discover a vulnerability, please open a responsible disclosure through GitHub Issues.

---

## Roadmap

### ✅ Completed Features
* **Autonomous Defense AI**: Graph neural networks, probabilistic attack graphs, reinforcement learning
* Core identity attack detection platform
* Distributed consensus mode
* Multi-cluster deployment support
* Advanced identity risk modeling
* Attack simulation framework
* Visualization dashboard

### 🚧 In Development
* Enhanced AI model training pipelines
* Multi-modal threat intelligence integration
* Advanced adversarial attack simulation
* Real-time AI model updates
* Global threat intelligence sharing

### 🔮 Future Plans
* Quantum-resistant cryptographic verification
* AI-powered threat hunting automation
* Predictive cyber insurance modeling
* Zero-trust autonomous enforcement
* Cross-organization threat correlation

---

## Contributing

Contributions are welcome.
Please open an issue before submitting large changes to discuss design proposals.

---

---

## License

This project is licensed under the MIT License.

---

*Last updated: April 14, 2026*

**Hollow Purple**: Enterprise Autonomous Cyber Defense Platform 🛡️
