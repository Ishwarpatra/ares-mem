"""
models.py — Shared data models and threat signature definitions for ARES-Mem.

Uses TypedDict for lightweight, zero-dependency type safety compatible with
LangGraph's AgentState schema.
"""
from typing import TypedDict, Optional, List, Dict, Any


# ══════════════════════════════════════════════════════════════════════════════
# Data Models (TypedDicts)
# ══════════════════════════════════════════════════════════════════════════════

class StructuredLog(TypedDict, total=False):
    """Output of LogIngestionAgent.ingest_log()"""
    raw: str                        # Original raw log string
    source_ip: str                  # Parsed source IP address
    dest_ip: str                    # Destination IP
    port: int                       # Port number (if applicable)
    protocol: str                   # TCP / UDP / ICMP / etc.
    event_type: str                 # AUTH_FAILURE / PORT_SCAN / CONNECTION / etc.
    severity: str                   # LOW / MEDIUM / HIGH / CRITICAL (never INFO)
    timestamp: str                  # ISO-8601 timestamp
    summary: str                    # Rule-based natural language summary
    log_format: str                 # SYSLOG / FIREWALL / AUTH / NETFLOW


class ThreatAnalysis(TypedDict, total=False):
    """Output of ThreatAnalysisAgent.analyze()"""
    threat_type: str                # PORT_SCAN / BRUTE_FORCE / DATA_EXFIL / MALWARE_C2 / BENIGN
    risk_score: int                 # 0–100 composite risk score
    confidence: float               # 0.0–1.0 confidence in classification
    indicators: List[str]           # List of matched threat indicators
    recommended_action: str         # Suggested response (informational)
    structured_log: StructuredLog   # Pass-through of the parsed log


class Decision(TypedDict, total=False):
    """Output of DecisionAgent.decide()"""
    decision: str                   # BLOCK_IP / QUARANTINE / ALERT / LOG_ONLY / ESCALATE
    action: str                     # Human-readable description of action
    task_type: str                  # block_ip / quarantine / notify / log_analysis
    priority: str                   # CRITICAL / HIGH / MEDIUM / LOW
    requires_escalation: bool       # Whether human review is required
    rationale: str                  # Policy reasoning
    source_ip: str                  # Threat source IP address


class ExecutionResult(TypedDict, total=False):
    """Output of ResponseAgent.execute()"""
    status: str                     # SUCCESS / FAILED / PENDING_APPROVAL
    action: str                     # Action taken
    message: str                    # Human-readable result
    target: str                     # IP / host / resource acted upon
    latency_ms: float               # Time taken to execute the action (ms)


# ══════════════════════════════════════════════════════════════════════════════
# Threat Signatures — Rule-Based Pattern Matching Dictionary
# ══════════════════════════════════════════════════════════════════════════════

THREAT_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "brute_force": {
        "keywords": [
            "failed login", "authentication failure", "invalid password",
            "login attempt", "bad password", "failed password",
            "repeated auth", "multiple failures", "account locked",
        ],
        "risk_delta": 50,
        "threat_type": "BRUTE_FORCE",
        "confidence": 0.85,
        "recommended_action": "BLOCK_IP",
    },
    "port_scan": {
        "keywords": [
            "port scan", "nmap", "syn flood", "connection refused",
            "multiple ports", "sequential ports", "probe", "fingerprint",
            "masscan", "service discovery",
        ],
        "risk_delta": 40,
        "threat_type": "PORT_SCAN",
        "confidence": 0.80,
        "recommended_action": "QUARANTINE",
    },
    "data_exfiltration": {
        "keywords": [
            "large upload", "data transfer", "exfil", "unusual outbound",
            "dns tunneling", "covert channel", "high volume", "egress anomaly",
            "unusual destination",
        ],
        "risk_delta": 60,
        "threat_type": "DATA_EXFIL",
        "confidence": 0.75,
        "recommended_action": "BLOCK_IP",
    },
    "malware_c2": {
        "keywords": [
            "c2", "command and control", "beacon", "callback", "reverse shell",
            "malware", "trojan", "ransomware", "botnet", "payload",
            "dropper", "exploit", "shellcode",
        ],
        "risk_delta": 70,
        "threat_type": "MALWARE_C2",
        "confidence": 0.90,
        "recommended_action": "BLOCK_IP",
    },
    "privilege_escalation": {
        "keywords": [
            "sudo", "privilege escalation", "root access", "admin override",
            "unauthorized elevation", "permission denied", "setuid",
        ],
        "risk_delta": 45,
        "threat_type": "PRIVILEGE_ESC",
        "confidence": 0.78,
        "recommended_action": "ALERT",
    },
    "prompt_injection": {
        "keywords": [
            "ignore all previous", "ignore previous instructions",
            "bypass authentication", "reveal secret", "disregard",
            "jailbreak", "act as", "pretend you are", "override policy",
            "forget your instructions", "new instructions",
        ],
        "risk_delta": 80,
        "threat_type": "PROMPT_INJECTION",
        "confidence": 0.95,
        "recommended_action": "QUARANTINE",
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# Privilege Level Definitions (5-Tier ACL System)
# ══════════════════════════════════════════════════════════════════════════════

PRIVILEGE_LEVELS: Dict[str, int] = {
    "system":    5,   # Immutable system policies / hardcoded rules
    "high":      4,   # Verified agent reasoning / trusted internal analyses
    "medium":    3,   # Internal operational data / network logs
    "low":       2,   # External unverified data / user-agents
    "untrusted": 1,   # Known untrusted sources / public internet
}

TASK_SENSITIVITY: Dict[str, str] = {
    "block_ip":     "high",
    "quarantine":   "high",
    "notify":       "medium",
    "log_analysis": "medium",
    "audit":        "low",
}

# Minimum privilege required per task type
MIN_PRIVILEGE_FOR_TASK: Dict[str, int] = {
    task: PRIVILEGE_LEVELS[level]
    for task, level in TASK_SENSITIVITY.items()
}
