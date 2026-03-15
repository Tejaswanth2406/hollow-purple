"""
baseline_store.py
=================
Persistent storage layer for ``IdentityBaseline`` objects.

Provides:
  • ``BaselineStore``        – abstract interface
  • ``InMemoryBaselineStore`` – thread-safe in-memory implementation
  • ``FileBaselineStore``    – thread-safe, JSON file-based implementation

All implementations are safe for concurrent reads; writes are serialised with
a ``threading.RLock``.

JSON Serialisation
------------------
Each baseline is stored as a self-contained JSON document whose ``content_hash``
field is verified on load to detect corruption or tampering.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterator

from .identity_baseline import IdentityBaseline

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Abstract interface
# ---------------------------------------------------------------------------


class BaselineStore(ABC):
    """Abstract persistent store for identity baselines."""

    @abstractmethod
    def save_baseline(self, baseline: IdentityBaseline) -> None:
        """Persist (or overwrite) a baseline."""

    @abstractmethod
    def load_baseline(self, identity_id: str) -> IdentityBaseline:
        """
        Load the baseline for ``identity_id``.

        Raises
        ------
        KeyError
            If no baseline exists for the given identity.
        """

    @abstractmethod
    def list_baselines(self) -> list[str]:
        """Return a sorted list of stored identity IDs."""

    @abstractmethod
    def delete_baseline(self, identity_id: str) -> None:
        """
        Remove the baseline for ``identity_id``.

        Raises
        ------
        KeyError
            If no baseline exists for the given identity.
        """

    # ------------------------------------------------------------------ #
    # Convenience helpers (non-abstract, shared implementation)
    # ------------------------------------------------------------------ #

    def exists(self, identity_id: str) -> bool:
        try:
            self.load_baseline(identity_id)
            return True
        except KeyError:
            return False

    def save_all(self, baselines: list[IdentityBaseline]) -> None:
        for b in baselines:
            self.save_baseline(b)

    def load_all(self) -> list[IdentityBaseline]:
        return [self.load_baseline(iid) for iid in self.list_baselines()]

    def __len__(self) -> int:
        return len(self.list_baselines())

    def __contains__(self, identity_id: str) -> bool:
        return self.exists(identity_id)

    def __iter__(self) -> Iterator[str]:
        return iter(self.list_baselines())


# ---------------------------------------------------------------------------
# In-memory implementation
# ---------------------------------------------------------------------------


class InMemoryBaselineStore(BaselineStore):
    """
    Thread-safe in-memory baseline store.

    Suitable for testing, caching layers, or short-lived processing pipelines.
    Data is lost when the process exits.
    """

    def __init__(self) -> None:
        self._store: dict[str, IdentityBaseline] = {}
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ #
    # BaselineStore implementation
    # ------------------------------------------------------------------ #

    def save_baseline(self, baseline: IdentityBaseline) -> None:
        if not isinstance(baseline, IdentityBaseline):
            raise TypeError(
                f"Expected IdentityBaseline, got {type(baseline).__name__}"
            )
        with self._lock:
            previous = self._store.get(baseline.identity_id)
            self._store[baseline.identity_id] = baseline
            if previous is None:
                logger.debug(
                    "InMemoryStore.save: created baseline for %r (hash=%s)",
                    baseline.identity_id, baseline.content_hash()[:12],
                )
            else:
                logger.debug(
                    "InMemoryStore.save: updated baseline for %r "
                    "(old_hash=%s → new_hash=%s)",
                    baseline.identity_id,
                    previous.content_hash()[:12],
                    baseline.content_hash()[:12],
                )

    def load_baseline(self, identity_id: str) -> IdentityBaseline:
        with self._lock:
            baseline = self._store.get(identity_id)
        if baseline is None:
            raise KeyError(
                f"No baseline found for identity {identity_id!r}."
            )
        return baseline

    def list_baselines(self) -> list[str]:
        with self._lock:
            return sorted(self._store.keys())

    def delete_baseline(self, identity_id: str) -> None:
        with self._lock:
            if identity_id not in self._store:
                raise KeyError(
                    f"Cannot delete: no baseline for identity {identity_id!r}."
                )
            del self._store[identity_id]
        logger.debug("InMemoryStore.delete: removed baseline for %r", identity_id)

    # ------------------------------------------------------------------ #
    # Extras
    # ------------------------------------------------------------------ #

    def clear(self) -> None:
        with self._lock:
            self._store.clear()
        logger.debug("InMemoryStore.clear: all baselines removed.")

    def __repr__(self) -> str:
        with self._lock:
            n = len(self._store)
        return f"InMemoryBaselineStore(count={n})"


# ---------------------------------------------------------------------------
# File-based implementation
# ---------------------------------------------------------------------------


class FileBaselineStore(BaselineStore):
    """
    Thread-safe, file-based JSON baseline store.

    Layout
    ------
    ``storage_dir/
        <identity_id>.json``

    Each file is a self-contained JSON document validated on load via its
    embedded ``content_hash`` field.

    Parameters
    ----------
    storage_dir:
        Directory in which baseline JSON files are stored.
        Created automatically if it does not exist.
    indent:
        JSON indentation level (default: 2).  Use ``None`` for compact output.
    """

    _SUFFIX = ".json"

    def __init__(
        self,
        storage_dir: str | Path,
        *,
        indent: int | None = 2,
    ) -> None:
        self._dir = Path(storage_dir).resolve()
        self._indent = indent
        self._lock = threading.RLock()
        self._dir.mkdir(parents=True, exist_ok=True)
        logger.info("FileBaselineStore initialised at %s", self._dir)

    # ------------------------------------------------------------------ #
    # BaselineStore implementation
    # ------------------------------------------------------------------ #

    def save_baseline(self, baseline: IdentityBaseline) -> None:
        if not isinstance(baseline, IdentityBaseline):
            raise TypeError(
                f"Expected IdentityBaseline, got {type(baseline).__name__}"
            )
        path = self._path_for(baseline.identity_id)
        payload = baseline.to_json(indent=self._indent)
        with self._lock:
            # Atomic write: write to temp file then rename
            tmp_path = path.with_suffix(".tmp")
            try:
                tmp_path.write_text(payload, encoding="utf-8")
                tmp_path.replace(path)
            except Exception:
                tmp_path.unlink(missing_ok=True)
                raise
        logger.debug(
            "FileStore.save: %r → %s (hash=%s)",
            baseline.identity_id, path.name, baseline.content_hash()[:12],
        )

    def load_baseline(self, identity_id: str) -> IdentityBaseline:
        path = self._path_for(identity_id)
        with self._lock:
            if not path.exists():
                raise KeyError(
                    f"No baseline file for identity {identity_id!r} at {path}."
                )
            raw = path.read_text(encoding="utf-8")

        try:
            baseline = IdentityBaseline.from_json(raw)
        except (ValueError, KeyError, json.JSONDecodeError) as exc:
            logger.error(
                "FileStore.load: corrupt baseline file %s – %s", path, exc
            )
            raise ValueError(
                f"Baseline file {path} is corrupt or tampered: {exc}"
            ) from exc

        logger.debug(
            "FileStore.load: %r ← %s (hash=%s)",
            identity_id, path.name, baseline.content_hash()[:12],
        )
        return baseline

    def list_baselines(self) -> list[str]:
        with self._lock:
            files = sorted(self._dir.glob(f"*{self._SUFFIX}"))
        return [f.stem for f in files]

    def delete_baseline(self, identity_id: str) -> None:
        path = self._path_for(identity_id)
        with self._lock:
            if not path.exists():
                raise KeyError(
                    f"Cannot delete: no baseline file for identity {identity_id!r}."
                )
            path.unlink()
        logger.debug("FileStore.delete: removed %s", path.name)

    # ------------------------------------------------------------------ #
    # Extras
    # ------------------------------------------------------------------ #

    def purge_all(self) -> int:
        """Delete every baseline in the store.  Returns the number deleted."""
        with self._lock:
            files = list(self._dir.glob(f"*{self._SUFFIX}"))
            for f in files:
                f.unlink()
        logger.info("FileStore.purge_all: removed %d baselines.", len(files))
        return len(files)

    def storage_path(self) -> Path:
        return self._dir

    def _path_for(self, identity_id: str) -> Path:
        # Sanitise identity_id to avoid directory traversal
        safe_name = "".join(
            c if (c.isalnum() or c in "-_.") else "_"
            for c in identity_id
        )
        if not safe_name:
            raise ValueError(f"Invalid identity_id: {identity_id!r}")
        return self._dir / f"{safe_name}{self._SUFFIX}"

    def __repr__(self) -> str:
        return f"FileBaselineStore(dir={self._dir}, count={len(self)})"