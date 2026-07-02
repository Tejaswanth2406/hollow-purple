"""
ingestion/normalizer.py — Compatibility shim
=============================================
The canonical EventNormalizer lives at ingestion/processors/normalizer.py.
This module re-exports it from the top-level ingestion package for
backward-compatibility with any code that imports from ingestion.normalizer.
"""

from ingestion.processors.normalizer import EventNormalizer  # noqa: F401

__all__ = ["EventNormalizer"]
