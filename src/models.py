"""
models.py — Shared TypedDicts, constants, and schema definitions for ARES-Mem.

All agents import from here to ensure type consistency across the pipeline.
Extended for ACIF: AgentReliability, ConflictReport, EvidenceFusionResult, CIEOutput.
"""
from typing import Any, Dict, List, Optional, TypedDict


# ── Privilege tier constants (5-tier) ───────────────────────────────────────
PRIVILEGE_LEVELS: Dict[str, int] = {
    "SYSTEM":     5,
    "HIGH":       4,
    "MEDIUM":     3,
    "LOW":        2,
    "UNTRUSTED":  1,
}

# ── Threat Signature Dictionary ──────────────────────────────────────────────
# Each entry: keywords (matched against lower-case raw log), risk_delta (0-100),
# threat_type label, and a recommended_action hint.
THREAT_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "PORT_SCAN": {
        "threat_type": "PORT_SCAN",
        "keywords": [
            "port scan", "nmap", "masscan", "syn scan", "connect scan",
            "port sweep", "service enumeration", "network scan", "scanning ports",
            "multiple ports", "sequential port",
        ],
        "risk_delta": 40,
        "recommended_action": "QUARANTINE",
    },
    "BRUTE_FORCE": {
        "threat_type": "BRUTE_FORCE",
        "keywords": [
            "brute force", "brute-force", "failed login", "authentication failure",
            "invalid password", "failed password", "repeated login", "credential stuffing",
            "login attempt", "password spray", "ssh brute",
        ],
        "risk_delta": 50,
        "recommended_action": "BLOCK_IP",
    },
    "DATA_EXFIL": {
        "threat_type": "DATA_EXFIL",
        "keywords": [
            "data exfil", "exfiltration", "large outbound", "dns tunneling",
            "unusual upload", "data transfer anomaly", "exfil", "outbound spike",
            "unauthorized transfer", "bulk download", "sensitive data",
        ],
        "risk_delta": 70,
        "recommended_action": "BLOCK_IP",
    },
    "MALWARE_C2": {
        "threat_type": "MALWARE_C2",
        "keywords": [
            "command and control", "c2 beacon", "c&c", "malware", "backdoor",
            "reverse shell", "callback", "beacon", "c2 server", "botnet",
            "trojan", "ransomware", "lateral movement",
        ],
        "risk_delta": 80,
        "recommended_action": "BLOCK_IP",
    },
    "PRIVILEGE_ESC": {
        "threat_type": "PRIVILEGE_ESC",
        "keywords": [
            "privilege escalation", "sudo", "root access", "setuid", "suid",
            "elevation of privilege", "privesc", "privilege abuse",
            "unauthorized sudo", "admin access", "privilege abuse",
        ],
        "risk_delta": 60,
        "recommended_action": "QUARANTINE",
    },
    "PROMPT_INJECTION": {
        "threat_type": "PROMPT_INJECTION",
        "keywords": [
            "ignore previous instructions", "bypass authentication", "override policy",
            "disregard instructions", "forget your role", "act as", "jailbreak",
            "ignore your training", "pretend you have no restrictions",
            "system override", "admin mode", "override instructions",
        ],
        "risk_delta": 90,
        "recommended_action": "BLOCK_IP",
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
