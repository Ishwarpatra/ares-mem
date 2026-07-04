"""
config/settings.py — ARES-Mem Configuration Loader.

Loads config/settings.yaml and exposes typed namespaces for each agent.
Falls back to hardcoded defaults if the YAML file is not found, so the
system works out-of-the-box without requiring a config file.

Override the config path via environment variable:
    ARES_CONFIG_PATH=/path/to/custom/settings.yaml

Usage:
    from config.settings import load_settings
    cfg = load_settings()
    threshold = cfg.memory_guard.sem_dist_threshold
"""
import os
from types import SimpleNamespace
from typing import Any, Dict

# ── Default values (mirror of config/settings.yaml) ──────────────────────────
# These are the fallback values used when settings.yaml is not present.
# Keep in sync with config/settings.yaml.
_DEFAULTS: Dict[str, Any] = {
    "memory_guard": {
        "sem_dist_threshold":       0.48,
        "imp_den_threshold":        0.25,
        "perplexity_threshold":     1500.0,
        "perplexity_sem_companion": 0.26,
        "entropy_soft_threshold":   5.2,
        "entropy_soft_sem_companion": 0.35,
    },
    "decision_agent": {
        "block_threshold":          80,
        "escalate_threshold":       60,
        "escalate_confidence_max":  0.4,
        "quarantine_threshold":     50,
        "alert_threshold":          20,
    },
    "threat_analysis": {
        "malicious_ip_score":       30,
        "privileged_port_score":    15,
        "critical_severity_score":  10,
        "multi_sig_bonus_per":      5,
    },
}

# ── Locate config file ────────────────────────────────────────────────────────
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEFAULT_CONFIG_PATH = os.path.join(_REPO_ROOT, "config", "settings.yaml")


def _dict_to_namespace(d: Dict[str, Any]) -> SimpleNamespace:
    """Recursively convert a nested dict to SimpleNamespace."""
    ns = SimpleNamespace()
    for key, value in d.items():
        if isinstance(value, dict):
            setattr(ns, key, _dict_to_namespace(value))
        else:
            setattr(ns, key, value)
    return ns


def load_settings(config_path: str = None) -> SimpleNamespace:
    """
    Load settings from YAML, falling back to hardcoded defaults.

    Args:
        config_path: Optional explicit path to a settings YAML file.
                     If None, reads ARES_CONFIG_PATH env var, then
                     falls back to config/settings.yaml in the repo root.

    Returns:
        SimpleNamespace with nested namespaces: .memory_guard, .decision_agent,
        .threat_analysis. Access thresholds as attributes, e.g.:
            cfg.memory_guard.sem_dist_threshold
    """
    resolved_path = (
        config_path
        or os.environ.get("ARES_CONFIG_PATH")
        or _DEFAULT_CONFIG_PATH
    )

    merged = {section: dict(values) for section, values in _DEFAULTS.items()}

    if os.path.isfile(resolved_path):
        try:
            import yaml  # PyYAML — listed in requirements.txt
            with open(resolved_path, "r", encoding="utf-8") as fh:
                file_cfg = yaml.safe_load(fh) or {}
            # Deep merge: YAML values override defaults section by section
            for section, values in file_cfg.items():
                if isinstance(values, dict):
                    merged.setdefault(section, {})
                    merged[section].update(values)
        except Exception as exc:
            import warnings
            warnings.warn(
                f"[ARES-Mem] Failed to load config from {resolved_path}: {exc}. "
                "Using hardcoded defaults.",
                stacklevel=2,
            )
    else:
        import warnings
        warnings.warn(
            f"[ARES-Mem] Config file not found at {resolved_path}. "
            "Using hardcoded defaults. Create config/settings.yaml to customise.",
            stacklevel=2,
        )

    return _dict_to_namespace(merged)


# ── Module-level singleton (loaded once) ──────────────────────────────────────
# Import and use this directly for zero-overhead repeated access:
#   from config.settings import SETTINGS
#   threshold = SETTINGS.memory_guard.sem_dist_threshold
SETTINGS = load_settings()
