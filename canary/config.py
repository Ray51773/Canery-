"""Configuration loading.

Config is YAML and lives in ``config/config.yaml`` (copied from
``config.example.yaml``). Secrets are never stored in the file - adapters read
tokens from environment variables named in the config. This keeps the config
committable and auditable.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG_PATH = "config/config.yaml"


class ConfigError(Exception):
    """Raised when the config file is missing or malformed."""


@dataclass
class Config:
    """Parsed configuration, with a few typed convenience accessors.

    The raw dict is kept on ``data`` so adapters can read their own sections
    without this class needing to know every key.
    """

    data: dict[str, Any]
    path: Path

    # --- convenience accessors -------------------------------------------
    @property
    def storage(self) -> dict[str, Any]:
        return self.data.get("storage", {})

    @property
    def generator(self) -> dict[str, Any]:
        return self.data.get("generator", {})

    @property
    def aws(self) -> dict[str, Any]:
        return self.data.get("aws", {})

    @property
    def injection(self) -> dict[str, Any]:
        return self.data.get("injection", {})

    @property
    def probe(self) -> dict[str, Any]:
        return self.data.get("probe", {})

    @property
    def database_path(self) -> str:
        return self.storage.get("database_path", "canary.db")

    @property
    def log_path(self) -> str:
        return self.storage.get("log_path", "canary.log")

    @property
    def log_level(self) -> str:
        return self.storage.get("log_level", "INFO")

    def injection_target(self, name: str | None = None) -> dict[str, Any]:
        """Return the config block for an injection target by name.

        Falls back to ``injection.default_target`` when ``name`` is None.
        """
        targets = self.injection.get("targets", {})
        chosen = name or self.injection.get("default_target")
        if not chosen:
            raise ConfigError("No injection target requested and no default_target set")
        if chosen not in targets:
            raise ConfigError(
                f"Injection target {chosen!r} not found in config; "
                f"known targets: {sorted(targets)}"
            )
        block = dict(targets[chosen])
        block.setdefault("name", chosen)
        return block

    @staticmethod
    def env(var_name: str | None) -> str | None:
        """Read a secret from the environment (adapters use this)."""
        if not var_name:
            return None
        return os.environ.get(var_name)


def load_config(path: str | Path = DEFAULT_CONFIG_PATH) -> Config:
    """Load and lightly validate the YAML config."""
    p = Path(path)
    if not p.exists():
        raise ConfigError(
            f"Config file not found: {p}. Copy config/config.example.yaml to "
            f"{DEFAULT_CONFIG_PATH} and edit it."
        )
    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"Could not parse {p}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"Config root must be a mapping, got {type(raw).__name__}")
    return Config(data=raw, path=p)
