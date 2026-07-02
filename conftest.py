"""
conftest.py — Root pytest configuration
Adds all necessary package paths to sys.path so tests can import
modules using their canonical names (policy_engine, etc.)
"""
import sys
from pathlib import Path

ROOT = Path(__file__).parent

# Make the project root importable
sys.path.insert(0, str(ROOT))

# Make baseline/ importable so `import policy_engine` resolves to
# baseline/policy_engine/ — which is the canonical location for the
# feature_extractor, baseline_engine, drift_detector, etc.
sys.path.insert(0, str(ROOT / "baseline"))
