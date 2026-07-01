# Hollow Purple - Enterprise Autonomous Cyber Defense Platform
# Multi-stage Docker build for production deployment

# Base stage with Python and dependencies
FROM python:3.11-slim as base

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    curl \
    wget \
    netcat \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Create application user
RUN groupadd -r hollowpurple && useradd -r -g hollowpurple hollowpurple

# Set work directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Production stage
FROM base as production

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /app/logs /app/data /app/models /app/cache

# Set permissions
RUN chown -R hollowpurple:hollowpurple /app

# Switch to non-root user
USER hollowpurple

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; import urllib.error; import json; import sys; sys.path.append('.'); url='http://127.0.0.1:8000/health';
try:
    with urllib.request.urlopen(url, timeout=5) as resp:
        status = resp.getcode();
        if status != 200:
            raise SystemExit(1)
        data = json.loads(resp.read().decode('utf-8'))
        if data.get('status') != 'healthy':
            raise SystemExit(1)
        print('Health check passed')
except (urllib.error.URLError, ValueError, SystemExit):
    raise
" || exit 1

# Expose port
EXPOSE 8000

# Start application
CMD ["python", "-m", "uvicorn", "api_gateway:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]

# Development stage
FROM base as development

# Install development dependencies
RUN pip install --no-cache-dir \
    pytest \
    pytest-asyncio \
    pytest-cov \
    black \
    isort \
    flake8 \
    mypy \
    pre-commit

# Copy application code
COPY . .

# Create development directories
RUN mkdir -p /app/logs /app/data /app/models /app/cache

# Set permissions
RUN chown -R hollowpurple:hollowpurple /app

# Switch to non-root user
USER hollowpurple

# Expose port
EXPOSE 8000

# Development command
CMD ["python", "-m", "uvicorn", "api_gateway:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

# Testing stage
FROM development as testing

# Copy test files
COPY tests/ ./tests/

# Run tests
RUN pytest --cov=. --cov-report=xml --cov-report=term

# Data processing stage (for ML model training)
FROM base as data-processor

# Install additional data science dependencies
RUN pip install --no-cache-dir \
    pandas \
    scikit-learn \
    jupyter \
    matplotlib \
    seaborn \
    plotly

# Copy data processing scripts
COPY scripts/ ./scripts/
COPY autonomous_defense_ai/ ./autonomous_defense_ai/

# Set permissions
RUN chown -R hollowpurple:hollowpurple /app

# Switch to non-root user
USER hollowpurple

# Command for data processing
CMD ["python", "scripts/run_pipeline.py"]

# Simulation stage (for attack simulations)
FROM base as simulator

# Install simulation dependencies
RUN pip install --no-cache-dir \
    numpy \
    scipy \
    networkx \
    simpy

# Copy simulation components
COPY control_plane/simulation_orchestrator.py ./control_plane/
COPY autonomous_defense_ai/ ./autonomous_defense_ai/

# Set permissions
RUN chown -R hollowpurple:hollowpurple /app

# Switch to non-root user
USER hollowpurple

# Command for running simulations
CMD ["python", "-c", "from control_plane.simulation_orchestrator import simulation_orchestrator; import asyncio; asyncio.run(simulation_orchestrator.start_simulation('phishing_attack_chain'))"]