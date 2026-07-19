"""
models.py — Shared TypedDicts, constants, and schema definitions for ARES-Mem.

All agents import from here to ensure type consistency across the pipeline.
Extended for ACIF: AgentReliability, ConflictReport, EvidenceFusionResult, CIEOutput.
"""
from typing import Any, Dict, List, Optional, TypedDict, Generic, TypeVar
from pydantic import BaseModel, Field
from datetime import datetime

T = TypeVar('T')

class ErrorResponse(BaseModel):
    status: str = "error"
    code: str
    message: str
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    request_id: Optional[str] = None

class SuccessResponse(BaseModel, Generic[T]):
    status: str = "success"
    data: T
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    meta: Optional[Dict] = None


# ── Privilege tier constants (5-tier) ───────────────────────────────────────
PRIVILEGE_LEVELS: Dict[str, int] = {
    "system":     5,
    "high":       4,
    "medium":     3,
    "low":        2,
    "untrusted":  1,
    "SYSTEM":     5,
    "HIGH":       4,
    "MEDIUM":     3,
    "LOW":        2,
    "UNTRUSTED":  1,
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

# ── Threat Signatures — Rule-Based Pattern Matching Dictionary ────────────────
THREAT_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "brute_force": {
        "keywords": [
            "failed login", "authentication failure", "invalid password",
            "login attempt", "bad password", "failed password",
            "repeated auth", "multiple failures", "account locked",
            "brute force", "brute-force", "credential stuffing",
            "password spray", "ssh brute",
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
            "masscan", "service discovery", "syn scan", "connect scan",
            "port sweep", "service enumeration", "network scan", "scanning ports",
            "sequential port",
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
            "unusual destination", "data exfil", "exfiltration", "large outbound",
            "unusual upload", "data transfer anomaly", "outbound spike",
            "unauthorized transfer", "bulk download", "sensitive data",
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
            "dropper", "exploit", "shellcode", "c2 beacon", "c&c", "backdoor",
            "c2 server", "lateral movement",
        ],
        "risk_delta": 70,
        "threat_type": "MALWARE_C2",
        "confidence": 0.90,
        "recommended_action": "BLOCK_IP",
    },
    "privilege_escalation": {
        "keywords": [
            "sudo", "privilege escalation", "root access", "admin override",
            "unauthorized elevation", "permission denied", "setuid", "suid",
            "elevation of privilege", "privesc", "privilege abuse",
            "unauthorized sudo", "admin access",
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
            "forget your instructions", "new instructions", "ignore previous instructions",
            "override instructions", "forget your role", "ignore your training",
            "pretend you have no restrictions", "system override", "admin mode",
        ],
        "risk_delta": 80,
        "threat_type": "PROMPT_INJECTION",
        "confidence": 0.95,
        "recommended_action": "QUARANTINE",
    },
}

# ── TypedDicts ───────────────────────────────────────────────────────────────

class StructuredLog(TypedDict, total=False):
    raw:         str
    source_ip:   str
    dest_ip:     str
    port:        int
    protocol:    str
    event_type:  str
    severity:    str
    timestamp:   str
    summary:     str
    log_format:  str
    source:      str          # ingestion source tag


class ThreatAnalysis(TypedDict, total=False):
    threat_type:         str
    risk_score:          int
    confidence:          float
    indicators:          List[str]
    recommended_action:  str
    structured_log:      StructuredLog


class Decision(TypedDict, total=False):
    decision:           str    # BLOCK_IP | QUARANTINE | MONITOR | ALERT | LOG_ONLY | ESCALATE | DELAY | ROLLBACK
    action:             str
    task_type:          str
    priority:           str
    requires_escalation: bool
    rationale:          str
    source_ip:          str


class ExecutionResult(TypedDict, total=False):
    status:      str    # SUCCESS | FAILED | PENDING_APPROVAL
    action:      str
    result:      str
    target:      str
    latency_ms:  float


# ── ACIF — Coordination Intelligence Engine TypedDicts ───────────────────────

class AgentReliability(TypedDict, total=False):
    """Per-agent reliability snapshot computed by the CIE Reliability Evaluator."""
    agent_name:         str
    reliability_score:  float          # 0.0 – 1.0; higher = more trustworthy
    calibration_error:  float          # |confidence – actual accuracy|
    alpha:              float          # Beta prior alpha (successes + 1)
    beta:               float          # Beta prior beta  (failures  + 1)
    total_events:       int            # Rolling window event count


class ConflictReport(TypedDict, total=False):
    """Output of the CIE Conflict Detector."""
    conflict_detected:  bool
    conflict_type:      str            # RISK_MG_DISAGREE | NONE
    conflicting_agents: List[str]      # e.g. ['ThreatAnalysisAgent', 'MemoryGuard']
    resolution:         str            # ESCALATE | TRUST_HIGHER_WEIGHT | ACCEPT_THREAT
    risk_score:         int
    mg_quarantine:      bool


class EvidenceFusionResult(TypedDict, total=False):
    """Output of the CIE Evidence Fusion sub-module (Dempster-Shafer)."""
    threat_belief:      float          # Combined mass m({THREAT})
    benign_belief:      float          # Combined mass m({BENIGN})
    uncertainty:        float          # Combined mass m({THREAT, BENIGN})
    method:             str            # 'dempster_shafer' | 'bayesian' | 'gnn'
    agent_masses:       Dict[str, Any] # Per-agent mass function inputs


class CIEOutput(TypedDict, total=False):
    """Umbrella output of the full Coordination Intelligence Engine."""
    reliability_map:    Dict[str, AgentReliability]  # keyed by agent name
    trust_weights:      Dict[str, float]              # current Beta posterior means
    conflict_report:    ConflictReport
    fusion_result:      EvidenceFusionResult
    decision:           Decision
    explanation:        str            # Human-readable audit narrative
    event_id:           str            # UUID for /explain lookup
