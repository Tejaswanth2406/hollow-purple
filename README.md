# Hollow Purple

Deterministic Intelligence Engine for Event-Driven Systems
Hollow Purple is a deterministic intelligence engine designed for high-integrity event processing, system observability, and state reconstruction.

The system captures events, stores them in a tamper-evident log, builds relationship graphs, and enables deterministic replay of system state at any point in time.

This architecture ensures transparency, traceability, and auditability across complex systems.

---

## Backend Framework

The backend is built using **FastAPI**, providing:

* High-performance async APIs
* Automatic OpenAPI documentation
* Strong typing and validation
* Scalable microservice architecture

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/Tejaswanth2406/hollow-purple.git
cd hollow-purple
```

---

### 2. Create virtual environment

```bash
python -m venv venv
```

Activate environment

Linux / macOS:

```bash
source venv/bin/activate
```

Windows:

```bash
venv\Scripts\activate
```

---

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

## Running the Backend

Start the API server:

```bash
uvicorn api.main:app --reload
```

Server will start at:

```
http://127.0.0.1:8000
```

Interactive API docs:

```
http://127.0.0.1:8000/docs
```

---

## API Endpoints

| Endpoint               | Description                   |
| ---------------------- | ----------------------------- |
| POST /events           | Ingest system events          |
| GET /replay/{time}     | Reconstruct system state      |
| GET /graph/entity/{id} | Retrieve entity relationships |
| GET /alerts            | Fetch anomaly alerts          |
| GET /health            | System health check           |

---

## Testing

Run unit tests with:

```bash
pytest
```

---

## Future Roadmap

### Hollow Purple v3

* AI anomaly detection
* Behavioral modeling
* Risk prediction engine
* Vector embeddings for event patterns

### Hollow Purple v4

* Self-evolving intelligence system
* Autonomous anomaly response
* Adaptive system learning

---

## Author

Tejaswanth2406

Built for high-integrity deterministic intelligence systems.
