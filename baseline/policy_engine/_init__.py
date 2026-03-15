"""
config.py — Hollow Purple Core Layer
======================================
Environment-driven, typed configuration management with validation.
Exposes a singleton Config loader for safe, consistent access throughout the system.

Author: Hollow Purple Infrastructure Team
Version: 1.0.0
"""

from __future__ import annotations

import logging
import os
import threading
from dataclasses import dataclass, field
from typing import Optional

from .constants import (
    DEFAULT_LOG_DIR,
    HASH_ALGORITHM,
    LOG_LEVEL_DEFAULT,
    MAX_LOG_FILE_SIZE_BYTES,
    LOG_ROTATION_BACKUP_COUNT,
    ReplayMode,
    VerificationStrictness,
    SYSTEM_VERSION,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Typed Configuration Model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class HollowPurpleConfig:
    """
    Immutable, fully typed configuration object for the Hollow Purple platform.

    All values are sourced from environment variables with validated defaults.
    This model is frozen to prevent accidental mutation at runtime.
    """

    # Filesystem
    log_dir: str
    event_log_filename: str
    checkpoint_filename: str

    # Hashing
    hash_algorithm: str

    # Node identity
    node_id: str

    # Replay
    replay_mode: ReplayMode
    verification_strictness: VerificationStrictness

    # Log rotation
    max_log_size_bytes: int
    log_rotation_backup_count: int

    # Debug & observability
    debug: bool
    log_level: str

    # System
    system_version: str

    def __post_init__(self) -> None:
        """Validate configuration values after construction."""
        self._validate()

    def _validate(self) -> None:
        """Run all validation rules; raise ValueError on failure."""
        if not self.log_dir:
            raise ValueError("log_dir must not be empty.")
        if not self.node_id:
            raise ValueError("node_id must not be empty.")
        if self.hash_algorithm not in ("sha256", "sha512", "sha3_256"):
            raise ValueError(
                f"Unsupported hash_algorithm '{self.hash_algorithm}'. "
                "Allowed: sha256, sha512, sha3_256."
            )
        if self.max_log_size_bytes <= 0:
            raise ValueError("max_log_size_bytes must be a positive integer.")
        if self.log_rotation_backup_count < 0:
            raise ValueError("log_rotation_backup_count must be >= 0.")
        if self.log_level not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            raise ValueError(f"Invalid log_level '{self.log_level}'.")

    @property
    def event_log_path(self) -> str:
        """Full path to the event log file."""
        return os.path.join(self.log_dir, self.event_log_filename)

    @property
    def checkpoint_path(self) -> str:
        """Full path to the checkpoint file."""
        return os.path.join(self.log_dir, self.checkpoint_filename)

    def as_dict(self) -> dict[str, object]:
        """Return a plain-dict representation for structured logging."""
        return {
            "log_dir": self.log_dir,
            "event_log_filename": self.event_log_filename,
            "checkpoint_filename": self.checkpoint_filename,
            "hash_algorithm": self.hash_algorithm,
            "node_id": self.node_id,
            "replay_mode": self.replay_mode.value,
            "verification_strictness": self.verification_strictness.value,
            "max_log_size_bytes": self.max_log_size_bytes,
            "log_rotation_backup_count": self.log_rotation_backup_count,
            "debug": self.debug,
            "log_level": self.log_level,
            "system_version": self.system_version,
        }


# ---------------------------------------------------------------------------
# Singleton Config Loader
# ---------------------------------------------------------------------------

class _ConfigLoader:
    """
    Thread-safe singleton loader for HollowPurpleConfig.

    Reads configuration once from environment variables and caches the result.
    Use `ConfigLoader.get()` to retrieve the config anywhere in the application.
    """

    _instance: Optional[HollowPurpleConfig] = None
    _lock: threading.Lock = threading.Lock()

    @classmethod
    def get(cls) -> HollowPurpleConfig:
        """
        Retrieve the singleton HollowPurpleConfig instance.

        Reads environment variables on first call; subsequent calls return the
        cached, immutable config object.

        Returns:
            HollowPurpleConfig: The validated, frozen configuration object.

        Raises:
            ValueError: If required environment variables are missing or invalid.
        """
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls._build()
                    logger.info(
                        "HollowPurple configuration loaded.",
                        extra={"config": cls._instance.as_dict()},
                    )
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """
        Reset the singleton (test use only).

        This clears the cached config so that a fresh one can be built.
        """
        with cls._lock:
            cls._instance = None

    @classmethod
    def _build(cls) -> HollowPurpleConfig:
        """Construct a HollowPurpleConfig from environment variables."""

        def _env(key: str, default: Optional[str] = None) -> str:
            value = os.environ.get(key, default)
            if value is None:
                raise ValueError(
                    f"Required environment variable '{key}' is not set "
                    "and has no default."
                )
            return value

        def _env_int(key: str, default: int) -> int:
            raw = os.environ.get(key)
            if raw is None:
                return default
            try:
                return int(raw)
            except ValueError:
                raise ValueError(
                    f"Environment variable '{key}' must be an integer; got '{raw}'."
                )

        def _env_bool(key: str, default: bool) -> bool:
            raw = os.environ.get(key)
            if raw is None:
                return default
            return raw.strip().lower() in ("1", "true", "yes")

        replay_mode_raw = _env("HP_REPLAY_MODE", ReplayMode.STRICT.value)
        try:
            replay_mode = ReplayMode(replay_mode_raw)
        except ValueError:
            raise ValueError(
                f"Invalid HP_REPLAY_MODE '{replay_mode_raw}'. "
                f"Allowed: {[m.value for m in ReplayMode]}."
            )

        strictness_raw = _env(
            "HP_VERIFICATION_STRICTNESS", VerificationStrictness.STRICT.value
        )
        try:
            verification_strictness = VerificationStrictness(strictness_raw)
        except ValueError:
            raise ValueError(
                f"Invalid HP_VERIFICATION_STRICTNESS '{strictness_raw}'. "
                f"Allowed: {[s.value for s in VerificationStrictness]}."
            )

        return HollowPurpleConfig(
            log_dir=_env("HP_LOG_DIR", DEFAULT_LOG_DIR),
            event_log_filename=_env("HP_EVENT_LOG_FILENAME", "events.jsonl"),
            checkpoint_filename=_env("HP_CHECKPOINT_FILENAME", "checkpoint.json"),
            hash_algorithm=_env("HP_HASH_ALGORITHM", HASH_ALGORITHM),
            node_id=_env("HP_NODE_ID", "node-default"),
            replay_mode=replay_mode,
            verification_strictness=verification_strictness,
            max_log_size_bytes=_env_int(
                "HP_MAX_LOG_SIZE_BYTES", MAX_LOG_FILE_SIZE_BYTES
            ),
            log_rotation_backup_count=_env_int(
                "HP_LOG_ROTATION_BACKUP_COUNT", LOG_ROTATION_BACKUP_COUNT
            ),
            debug=_env_bool("HP_DEBUG", False),
            log_level=_env("HP_LOG_LEVEL", LOG_LEVEL_DEFAULT).upper(),
            system_version=SYSTEM_VERSION,
        )


# Public singleton accessor
ConfigLoader: _ConfigLoader = _ConfigLoader()