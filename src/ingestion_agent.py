"""
ingestion_agent.py — The Eyes of ARES-Mem (Layer 1, Always-ON).

Responsibilities:
- Parse raw log strings in SYSLOG, FIREWALL, AUTH, NETFLOW, and GENERIC formats
- Extract structured fields: source_ip, dest_ip, port, protocol, event_type, severity
- Generate a deterministic natural-language episodic summary (no LLM)
- Assign severity level based on event keywords

Design: deterministic (no LLM calls), runs at SOC velocity (< 1 ms per log).
Security: enforces max-length and control-char sanitisation on all inputs.
"""
import re
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from models import StructuredLog, THREAT_SIGNATURES

# ── Maximum raw log size (64 KB) ─────────────────────────────────────────────
MAX_LOG_BYTES = 64_000

# ── Core regex patterns ───────────────────────────────────────────────────────
_IP_RAW = r"(?:\d{1,3}\.){3}\d{1,3}"
_IP_RE       = re.compile(r"\b(?P<ip>" + _IP_RAW + r")\b")
_PORT_RE     = re.compile(r"(?:port|dport|sport|:)\s*(?P<port>\d{2,5})\b", re.IGNORECASE)
_PROTOCOL_RE = re.compile(r"\b(?P<proto>TCP|UDP|ICMP|HTTP|HTTPS|SSH|FTP|DNS|SMTP|SNMP)\b", re.IGNORECASE)

# ── Event type keyword maps ───────────────────────────────────────────────────
_EVENT_KEYWORDS: Dict[str, List[str]] = {
    "BRUTE_FORCE":    ["failed login", "authentication failure", "failed password",
                       "invalid password", "login attempt", "brute force", "credential"],
    "PORT_SCAN":      ["port scan", "nmap", "masscan", "syn scan", "port sweep",
                       "service enumeration", "network scan"],
    "DATA_EXFIL":     ["data exfil", "large outbound", "outbound spike", "dns tunnel",
                       "unauthorized transfer", "bulk download", "exfil"],
    "MALWARE_C2":     ["malware", "c2 beacon", "command and control", "backdoor",
                       "reverse shell", "ransomware", "trojan", "botnet"],
    "PRIVILEGE_ESC":  ["privilege escalation", "sudo", "setuid", "suid", "privesc",
                       "unauthorized sudo", "elevation of privilege"],
    "PROMPT_INJECTION":["ignore previous instructions", "bypass authentication",
                        "override policy", "jailbreak", "admin mode"],
    "FIREWALL_BLOCK": ["deny", "blocked", "dropped", "reject", "firewall block"],
    "SUCCESSFUL_AUTH":["accepted password", "session opened", "login successful",
                       "authentication success", "accepted publickey"],
    "DATA_TRANSFER":  ["transferred", "bytes sent", "upload", "download", "ftp", "sftp"],
}

_SEVERITY_MAP = {
    "CRITICAL": ["critical", "emergency", "alert", "ransomware", "malware", "c2 beacon",
                 "data exfil", "prompt injection", "privilege escalation"],
    "HIGH":     ["error", "failed login", "brute force", "port scan", "authentication failure",
                 "blocked", "denied", "attack"],
    "MEDIUM":   ["warning", "warn", "suspicious", "anomaly", "unusual", "multiple"],
    "LOW":      ["notice", "info", "connection", "request", "login successful"],
}


class LogIngestionAgent:
    """
    The Log Ingestion Agent (The Eyes).

    Parses raw security event strings and returns a StructuredLog TypedDict.
    Supports: Syslog, Firewall rules, Authentication logs, NetFlow summaries.
    """

    def __init__(self, data_dir: str = "data"):
        self.data_dir = data_dir
        os.makedirs(self.data_dir, exist_ok=True)

    # ── Public API ────────────────────────────────────────────────────────────

    def ingest_log(self, raw_log: Any) -> StructuredLog:
        """
        Primary ingestion method called by the orchestrator node.

        Args:
            raw_log: Raw log string, or an already-structured dict.

        Returns:
            StructuredLog with all parsed fields populated.
        """
        if isinstance(raw_log, dict):
            return {**raw_log, "source": raw_log.get("source", "external_stream")}  # type: ignore

        if not isinstance(raw_log, str):
            return {  # type: ignore
                "raw": str(raw_log)[:200],
                "source": "ingestion_agent",
                "event_type": "GENERIC",
                "severity": "LOW",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "error": f"Unsupported log type: {type(raw_log).__name__}",
            }

        # Enforce max size
        if len(raw_log.encode("utf-8", errors="replace")) > MAX_LOG_BYTES:
            return {  # type: ignore
                "raw": raw_log[:MAX_LOG_BYTES].strip(),
                "source": "ingestion_agent",
                "event_type": "GENERIC",
                "severity": "LOW",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "error": f"Log exceeds maximum allowed size ({MAX_LOG_BYTES} bytes). Truncated.",
            }

        sanitized = self._sanitize(raw_log)
        return self._parse(sanitized)

    def read_from_file(self, filename: str) -> StructuredLog:
        """Reads a log file from the data directory and ingests it."""
        path = os.path.join(self.data_dir, filename)
        if not os.path.exists(path):
            return {"raw": "", "error": f"File not found: {filename}",  # type: ignore
                    "event_type": "GENERIC", "severity": "LOW",
                    "timestamp": datetime.now(timezone.utc).isoformat()}
        with open(path, encoding="utf-8", errors="replace") as f:
            return self.ingest_log(f.read())

    # ── Core parsing ─────────────────────────────────────────────────────────

    def _sanitize(self, text: str) -> str:
        """Strip null bytes and C0/C1 control characters (allow tab/newline/CR)."""
        allowed = {0x09, 0x0A, 0x0D}
        return "".join(ch for ch in text if ord(ch) >= 0x20 or ord(ch) in allowed)

    def _parse(self, raw: str) -> StructuredLog:
        log_lower = raw.lower()

        source_ip  = self._extract_source_ip(raw)
        dest_ip    = self._extract_dest_ip(raw, source_ip)
        port       = self._extract_port(raw)
        protocol   = self._extract_protocol(raw)
        event_type = self._classify_event_type(log_lower)
        severity   = self._classify_severity(log_lower)
        log_format = self._detect_log_format(raw)
        summary    = self._generate_summary(raw, source_ip, event_type, severity, port)

        return {  # type: ignore
            "raw":        raw,
            "source_ip":  source_ip,
            "dest_ip":    dest_ip,
            "port":       port,
            "protocol":   protocol,
            "event_type": event_type,
            "severity":   severity,
            "timestamp":  datetime.now(timezone.utc).isoformat(),
            "summary":    summary,
            "log_format": log_format,
            "source":     "external_stream",
        }

    # ── Field extractors ─────────────────────────────────────────────────────

    def _extract_source_ip(self, text: str) -> str:
        """Extract source IP — prefers explicit 'from/src/source/client' keywords."""
        m = re.search(
            r"(?:from|src|source|client)[:\s]+(" + _IP_RAW + r")\b",
            text, re.IGNORECASE
        )
        if m:
            return m.group(1)
        m = _IP_RE.search(text)
        return m.group("ip") if m else "0.0.0.0"

    def _extract_dest_ip(self, text: str, source_ip: str) -> str:
        """Extract destination IP — prefers 'to/dst/dest/server' keywords."""
        m = re.search(
            r"(?:to|dst|dest|destination|server)[:\s]+(" + _IP_RAW + r")\b",
            text, re.IGNORECASE
        )
        if m:
            return m.group(1)
        # Find second distinct IP
        all_ips = [m.group("ip") for m in _IP_RE.finditer(text)]
        for ip in all_ips:
            if ip != source_ip:
                return ip
        return "0.0.0.0"

    def _extract_port(self, text: str) -> int:
        m = _PORT_RE.search(text)
        if m:
            try:
                p = int(m.group("port"))
                return p if 1 <= p <= 65535 else 0
            except ValueError:
                pass
        return 0

    def _extract_protocol(self, text: str) -> str:
        m = _PROTOCOL_RE.search(text)
        return m.group("proto").upper() if m else "UNKNOWN"

    # ── Classification helpers ────────────────────────────────────────────────

    def _classify_event_type(self, log_lower: str) -> str:
        """Return the first matching event type, or GENERIC."""
        for event_type, keywords in _EVENT_KEYWORDS.items():
            if any(kw in log_lower for kw in keywords):
                return event_type
        return "GENERIC"

    def _classify_severity(self, log_lower: str) -> str:
        """Return severity level based on keyword matching, highest priority first."""
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if any(kw in log_lower for kw in _SEVERITY_MAP[level]):
                return level
        return "INFO"

    def _detect_log_format(self, raw: str) -> str:
        """Heuristically detect the log format."""
        if re.match(r"^\w+\s+\d+\s+\d{2}:\d{2}:\d{2}", raw):
            return "SYSLOG"
        if re.search(r"\b(?:DENY|ALLOW|ACCEPT|DROP|REJECT)\b", raw, re.IGNORECASE):
            return "FIREWALL"
        if re.search(r"(?:sshd|pam_unix|auth|login)", raw, re.IGNORECASE):
            return "AUTH"
        if re.search(r"(?:bytes|packets|flow|src port|dst port)", raw, re.IGNORECASE):
            return "NETFLOW"
        return "GENERIC"

    def _generate_summary(self, raw: str, source_ip: str, event_type: str,
                           severity: str, port: int) -> str:
        """Generate a deterministic natural-language episodic summary."""
        port_str = f" on port {port}" if port else ""
        return (
            f"[{severity}] {event_type.replace('_', ' ').title()} event detected "
            f"from {source_ip}{port_str}. "
            f"Raw: {raw[:120].strip()}"
        )
