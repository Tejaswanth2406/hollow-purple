Hollow Purple

Adaptive Cloud Identity Attack Detection Platform

Hollow Purple is an advanced cybersecurity analysis platform designed to detect complex identity-based attacks in cloud environments. The system continuously ingests events, builds temporal identity graphs, models baseline behavior, and detects anomalous activity such as privilege escalation, lateral movement, and token abuse.

The platform is built as a modular distributed system with a strong focus on security, verifiability, and deterministic state reconstruction.

---

## Architecture Overview

Hollow Purple operates through multiple coordinated subsystems:

1. Ingestion Pipeline

   * Collects identity and activity events from multiple sources
   * Performs validation, deduplication, and normalization
   * Provides high-throughput event streaming

2. Graph Engine

   * Constructs a dynamic identity interaction graph
   * Maintains temporal relationships between entities
   * Enables path analysis for attack detection

3. Baseline Engine

   * Learns normal behavior patterns for identities and services
   * Detects behavioral drift and abnormal activity

4. Attack Pattern Detection

   * Privilege escalation detection
   * Lateral movement analysis
   * Token abuse detection

5. **Risk Engine**

   * Aggregates signals from multiple detectors
   * Produces a unified risk score for entities and events

6. State Snapshot & Replay

   * Deterministic state reconstruction
   * Historical replay for forensic analysis

7. Integrity Verification System

   * Merkle-based event verification
   * Tamper-evident audit trail

---

## Core Features

* High-throughput event ingestion
* Temporal identity graph modeling
* Behavior baseline modeling
* Attack path discovery
* Deterministic replay engine
* Tamper-evident event logs
* Modular micro-service architecture
* Distributed deployment ready

---

## Project Structure

```
HOLLOW_PURPLE/
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

## Running the Platform

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

Planned features include:

* distributed consensus mode
* multi-cluster deployment
* advanced identity risk modeling
* attack simulation framework
* visualization dashboard

---

## Contributing

Contributions are welcome.
Please open an issue before submitting large changes to discuss design proposals.

---

## License

This project is licensed under the MIT License.
