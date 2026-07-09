"""
config_loader.py — Centralized Configuration Management

Loads config.yaml, validates keys, provides typed accessors,
and supports ENV-variable overrides for Docker/CI deployments.

Usage:
    from config_loader import cfg
    port = cfg.get("services.ssh.port", 2222)
"""

import os
import yaml
import logging
from functools import reduce
from typing import Any

logger = logging.getLogger("HoneypotConfig")

_DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.yaml")
_config: dict = {}


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base."""
    result = base.copy()
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result


def _apply_env_overrides(config: dict) -> dict:
    """
    Override config values via environment variables.
    Format: HONEYPOT__SECTION__KEY=value
    E.g.:   HONEYPOT__DASHBOARD__PORT=8080
    """
    prefix = "HONEYPOT__"
    for key, value in os.environ.items():
        if not key.startswith(prefix):
            continue
        parts = key[len(prefix):].lower().split("__")
        target = config
        for part in parts[:-1]:
            target = target.setdefault(part, {})
        # Type coercion
        leaf = parts[-1]
        if value.lower() in ("true", "yes", "1"):
            target[leaf] = True
        elif value.lower() in ("false", "no", "0"):
            target[leaf] = False
        elif value.isdigit():
            target[leaf] = int(value)
        else:
            try:
                target[leaf] = float(value)
            except ValueError:
                target[leaf] = value
    return config


def load(path: str = _DEFAULT_CONFIG_PATH) -> dict:
    """Load and parse config.yaml, apply ENV overrides."""
    global _config
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        _config = _apply_env_overrides(raw)
        logger.info(f"Config loaded from {path}")
    except FileNotFoundError:
        logger.warning(f"Config file not found at {path}, using defaults")
        _config = {}
    except yaml.YAMLError as e:
        logger.error(f"YAML parse error in {path}: {e}")
        _config = {}
    return _config


def get(dotted_key: str, default: Any = None) -> Any:
    """
    Fetch a config value using dot notation.
    Example: cfg.get("services.ssh.port", 2222)
    """
    keys = dotted_key.split(".")
    try:
        return reduce(lambda d, k: d[k], keys, _config)
    except (KeyError, TypeError):
        return default


def reload(path: str = _DEFAULT_CONFIG_PATH) -> dict:
    """Hot-reload config without restarting."""
    return load(path)


def as_dict() -> dict:
    """Return full config as dict (read-only copy)."""
    import copy
    return copy.deepcopy(_config)


# ── Auto-load on import ──────────────────────────────────────
load()


# ── Convenience shortcuts ────────────────────────────────────
class _ConfigAccessor:
    """Dot-notation accessor: cfg.services_ssh_port"""
    def get(self, key: str, default: Any = None) -> Any:
        return get(key, default)

    def __call__(self, key: str, default: Any = None) -> Any:
        return get(key, default)


cfg = _ConfigAccessor()
