# Configuration Precedence Guide for ARES-Mem

This document outlines the architecture, layout, and priority order for loading runtime configuration parameters and thresholds in the ARES-Mem system.

## 1. Precedence Priority Order

ARES-Mem loads its configuration properties sequentially using the following resolution order (highest priority first):

1. **Environment Variable Override**: If the environment variable `ARES_CONFIG_PATH` is specified, settings will be parsed from that location.
2. **Local Configuration File**: If the env var is absent, the system attempts to load settings from [config/settings.yaml](file:///c:/Users/DELL/Desktop/codego/ares-mem/config/settings.yaml).
3. **Hardcoded Defaults**: If the file is not found or fails to parse, settings fall back on typed default values defined programmatically inside [config/settings.py](file:///c:/Users/DELL/Desktop/codego/ares-mem/config/settings.py).

---

## 2. Setting Namespaces & Thresholds

The following configuration sections are defined and customizable:

### `memory_guard`
Feature boundaries for the ETVL (Entropy, Verb Density, Semantic Distance, Perplexity) pipeline:
* `sem_dist_threshold` (default `0.48`): Max cosine similarity distance boundary.
* `imp_den_threshold` (default `0.25`): High command-verb density boundary.
* `perplexity_threshold` (default `1500.0`): Bigram character perplexity floor.
* `perplexity_sem_companion` (default `0.40`): Elevated companion similarity.
* `entropy_soft_threshold` (default `5.2`): Shannon entropy threshold.
* `entropy_soft_sem_companion` (default `0.35`): Entropy companion similarity.

### `decision_agent`
Policy scoring bands for composite threat levels:
* `block_threshold` (default `80`)
* `escalate_threshold` (default `60`)
* `escalate_confidence_max` (default `0.4`)
* `quarantine_threshold` (default `50`)
* `alert_threshold` (default `20`)

### `policy_rules`
* `quarantine_action` (default `LOG_ONLY`): Action taken when memory guard quarantines a log. Options: `LOG_ONLY` | `QUARANTINE_HOST`.
* `webhook_url` (default `http://localhost:8080/api/webhook/simulate`): Async fire-and-forget SIEM/Slack integration.
