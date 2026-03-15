"""
configs/config_loader.py — HOLLOW PURPLE Enterprise Configuration Loader
"""

import asyncio
import copy
import hashlib
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger("hollow_purple.config_loader")


PROVIDER_CONFIG_MAP = {
    "aws": "aws_weights.yaml",
    "gcp": "gcp_weights.yaml",
    "azure": "azure_weights.yaml",
}

DEFAULT_CONFIG_FILE = "default.yaml"


class ConfigValidationError(ValueError):
    def __init__(self, path: str, message: str):
        self.path = path
        super().__init__(f"Config validation error [{path}]: {message}")


class ConfigView:
    """
    Immutable view of a loaded configuration dict.
    Provides dotted-key access and typed getters.
    """

    def __init__(self, data: dict, source: str = ""):
        self._data = data
        self._source = source
        self._loaded_at = time.time()

    def get(self, path: str, default: Any = None) -> Any:
        keys = path.split(".")
        value = self._data

        for key in keys:
            if not isinstance(value, dict):
                return default
            value = value.get(key)
            if value is None:
                return default

        return value

    def get_float(self, path: str, default: float = 0.0) -> float:
        return float(self.get(path, default))

    def get_int(self, path: str, default: int = 0) -> int:
        return int(self.get(path, default))

    def get_bool(self, path: str, default: bool = False) -> bool:
        val = self.get(path, default)

        if isinstance(val, bool):
            return val

        return str(val).lower() in ("true", "1", "yes")

    def get_str(self, path: str, default: str = "") -> str:
        val = self.get(path, default)
        return str(val)

    def get_list(self, path: str, default: list | None = None) -> list:
        val = self.get(path)

        if val is None:
            return default or []

        if isinstance(val, list):
            return val

        return [val]

    def get_section(self, section: str) -> dict:
        return copy.deepcopy(self._data.get(section, {}))

    def raw(self) -> dict:
        return copy.deepcopy(self._data)

    def checksum(self) -> str:
        raw = json.dumps(self._data, sort_keys=True, default=str)
        return hashlib.sha256(raw.encode()).hexdigest()[:12]

    @property
    def source(self) -> str:
        return self._source

    @property
    def loaded_at(self) -> float:
        return self._loaded_at

    def __repr__(self):
        return f"ConfigView(source={self._source}, checksum={self.checksum()})"


class ConfigLoader:

    def __init__(self, base_dir: str = "configs/"):
        self._base_dir = Path(base_dir)

        self._active_config: ConfigView | None = None
        self._reload_callbacks = []

        self._file_checksums: dict[str, str] = {}
        self._watched_files: list[Path] = []

        self._lock = threading.RLock()

    # ----------------------------------------------------
    # Loading
    # ----------------------------------------------------

    def load(self, provider: str | None = None, config_file: str | None = None) -> ConfigView:

        base = self._load_file(self._base_dir / DEFAULT_CONFIG_FILE)

        if provider is None:
            provider = os.environ.get("HP_CLOUD_PROVIDER", "").lower() or None

        override = {}
        source = DEFAULT_CONFIG_FILE

        if config_file:
            override = self._load_file(Path(config_file))
            source = config_file

        elif provider and provider in PROVIDER_CONFIG_MAP:

            override_path = self._base_dir / PROVIDER_CONFIG_MAP[provider]

            if override_path.exists():
                override = self._load_file(override_path)
                source = str(override_path)

        merged = _deep_merge(base, override)

        merged = self._apply_env_overrides(merged)

        self._validate(merged)

        view = ConfigView(merged, source)

        with self._lock:
            self._active_config = view

        self._watched_files = [self._base_dir / DEFAULT_CONFIG_FILE]

        if provider and provider in PROVIDER_CONFIG_MAP:
            self._watched_files.append(self._base_dir / PROVIDER_CONFIG_MAP[provider])

        self._record_checksums()

        logger.info(
            "Config loaded provider=%s source=%s checksum=%s",
            provider,
            source,
            view.checksum(),
        )

        return view

    def active(self) -> ConfigView | None:
        with self._lock:
            return self._active_config

    # ----------------------------------------------------
    # Hot reload
    # ----------------------------------------------------

    def register_reload_callback(self, fn):
        self._reload_callbacks.append(fn)

    async def watch(self, interval_sec: float = 30.0, provider: str | None = None):

        logger.info("Watching config files every %.0fs", interval_sec)

        while True:

            await asyncio.sleep(interval_sec)

            if self._files_changed():

                logger.info("Config change detected, reloading")

                try:

                    new_config = self.load(provider=provider)

                    for cb in self._reload_callbacks:

                        try:
                            cb(new_config)
                        except Exception as exc:
                            logger.error("Reload callback failed: %s", exc)

                except Exception as exc:
                    logger.error("Config reload failed: %s", exc)

    # ----------------------------------------------------
    # Validation
    # ----------------------------------------------------

    def _validate(self, config: dict):

        weights = config.get("risk_engine", {}).get("weights", {})

        if weights:

            total = sum(float(v) for v in weights.values())

            if abs(total - 1.0) > 0.01:
                raise ConfigValidationError(
                    "risk_engine.weights",
                    f"Weights must sum to 1.0, got {total}",
                )

        alerts = config.get("alerts", {})

        if alerts:

            tiers = [
                ("critical_threshold", "high_threshold"),
                ("high_threshold", "medium_threshold"),
                ("medium_threshold", "low_threshold"),
            ]

            for upper, lower in tiers:

                u = alerts.get(upper, 1.0)
                l = alerts.get(lower, 0.0)

                if u <= l:
                    raise ConfigValidationError(
                        f"alerts.{upper}",
                        f"{upper} must be greater than {lower}",
                    )

        batch = config.get("ingestion", {}).get("batch_size", 1)

        if batch < 1:
            raise ConfigValidationError(
                "ingestion.batch_size",
                "Must be >= 1",
            )

    # ----------------------------------------------------
    # Internal
    # ----------------------------------------------------

    def _load_file(self, path: Path) -> dict:

        if not path.exists():
            logger.warning("Config file not found: %s", path)
            return {}

        with open(path, "r") as f:
            data = yaml.safe_load(f) or {}

        data.pop("inherits", None)
        data.pop("cloud_provider", None)

        return data

    def _apply_env_overrides(self, config: dict) -> dict:

        prefix = "HP_"

        for key, value in os.environ.items():

            if not key.startswith(prefix):
                continue

            path = key[len(prefix):].lower()
            path = path.replace("__", ".")

            parts = path.split(".")

            node = config

            for part in parts[:-1]:
                node = node.setdefault(part, {})

            node[parts[-1]] = _coerce(value)

        return config

    def _record_checksums(self):

        for path in self._watched_files:

            if path.exists():
                content = path.read_bytes()
                self._file_checksums[str(path)] = hashlib.md5(content).hexdigest()

    def _files_changed(self) -> bool:

        for path in self._watched_files:

            if not path.exists():
                continue

            current = hashlib.md5(path.read_bytes()).hexdigest()

            if self._file_checksums.get(str(path)) != current:
                return True

        return False


# ----------------------------------------------------
# Utilities
# ----------------------------------------------------

def _deep_merge(base: dict, override: dict) -> dict:

    result = copy.deepcopy(base)

    for key, value in override.items():

        if isinstance(value, dict) and isinstance(result.get(key), dict):

            result[key] = _deep_merge(result[key], value)

        else:

            result[key] = copy.deepcopy(value)

    return result


def _coerce(value: str) -> Any:

    v = value.lower()

    if v in ("true", "yes"):
        return True

    if v in ("false", "no"):
        return False

    try:
        return int(value)
    except ValueError:
        pass

    try:
        return float(value)
    except ValueError:
        pass

    return value