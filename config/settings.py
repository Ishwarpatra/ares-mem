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
import yaml
import warnings
from functools import lru_cache
from typing import Optional
from pydantic import BaseModel, Field, ValidationError

class MemoryGuardSettings(BaseModel):
    sem_dist_threshold: float = Field(default=0.41, ge=0.0, le=1.0)
    imp_den_threshold: float = Field(default=0.25, ge=0.0, le=1.0)
    perplexity_threshold: float = Field(default=1500.0, ge=0.0)
    perplexity_sem_companion: float = Field(default=0.40, ge=0.0, le=1.0)
    entropy_soft_threshold: float = Field(default=5.2, ge=0.0, le=10.0)
    entropy_soft_sem_companion: float = Field(default=0.35, ge=0.0, le=1.0)

class DecisionAgentSettings(BaseModel):
    block_threshold: int = Field(default=80, ge=0, le=100)
    escalate_threshold: int = Field(default=60, ge=0, le=100)
    escalate_confidence_max: float = Field(default=0.4, ge=0.0, le=1.0)
    quarantine_threshold: int = Field(default=50, ge=0, le=100)
    alert_threshold: int = Field(default=20, ge=0, le=100)

class ThreatAnalysisSettings(BaseModel):
    malicious_ip_score: int = Field(default=30, ge=0, le=100)
    privileged_port_score: int = Field(default=15, ge=0, le=100)
    critical_severity_score: int = Field(default=10, ge=0, le=100)
    multi_sig_bonus_per: int = Field(default=5, ge=0, le=50)

class PolicyRulesSettings(BaseModel):
    quarantine_action: str = Field(default="LOG_ONLY", pattern="^(LOG_ONLY|QUARANTINE_HOST)$")
    webhook_url: str = Field(default="http://localhost:8080/api/webhook/simulate")

class LoggingSettings(BaseModel):
    level: str = Field(default="INFO", pattern="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")
    format: str = "json"

class Settings(BaseModel):
    app_name: str = "ARES-Mem API"
    version: str = "2.0.0"
    
    memory_guard: MemoryGuardSettings = Field(default_factory=MemoryGuardSettings)
    decision_agent: DecisionAgentSettings = Field(default_factory=DecisionAgentSettings)
    threat_analysis: ThreatAnalysisSettings = Field(default_factory=ThreatAnalysisSettings)
    policy_rules: PolicyRulesSettings = Field(default_factory=PolicyRulesSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)

@lru_cache(maxsize=1)
def load_settings() -> Settings:
    """Load and validate settings from YAML."""
    config_path = os.environ.get("ARES_CONFIG_PATH")
    
    if not config_path:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(base_dir, "settings.yaml")
        
    resolved_path = os.path.abspath(config_path)
    
    if os.path.exists(resolved_path):
        try:
            with open(resolved_path, "r", encoding="utf-8") as fh:
                file_cfg = yaml.safe_load(fh) or {}
                return Settings(**file_cfg)
        except ValidationError as exc:
            raise ValueError(f"Configuration validation failed in {resolved_path}:\n{exc}")
        except Exception as exc:
            warnings.warn(f"[ARES-Mem] Failed to load config from {resolved_path}: {exc}. Using defaults.", stacklevel=2)
    else:
        warnings.warn(f"[ARES-Mem] Config file not found at {resolved_path}. Using defaults.", stacklevel=2)
        
    return Settings()

SETTINGS = load_settings()
