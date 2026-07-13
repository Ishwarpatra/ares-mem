"""
log_ingestion_agent.py — The Eyes of ARES-Mem (Layer 1, Always-ON).

Responsibilities:
- Parse raw log strings in multiple formats (Syslog, Firewall, Auth, NetFlow)
- Extract structured fields: source IP, destination IP, port, protocol, event type
- Generate a dense natural language episodic summary (rule-based, temperature=0)
- Assign a severity level based on event keywords

Design constraint: deterministic (no LLM calls), runs at SOC velocity.
"""
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, cast

from base import BaseAgent
from models import StructuredLog, THREAT_SIGNATURES


# ── Common IPv4 regex ────────────────────────────────────────────────────────
_IP_RE = re.compile(
    r"\b(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\b"
)
# Plain IP pattern without named group — safe to embed inside other patterns
_IP_RAW = r"(?:\d{1,3}\.){3}\d{1,3}"
_PORT_RE = re.compile(r"(?:port|:)\s*(?P<port>\d{2,5})\b", re.IGNORECASE)
_PROTOCOL_RE = re.compile(r"\b(?P<proto>TCP|UDP|ICMP|HTTP|HTTPS|SSH|FTP|DNS)\b", re.IGNORECASE)


class LogIngestionAgent(BaseAgent):
    """
    The Log Ingestion Agent (E-layer / The Eyes).

    Parses raw security event strings and returns a StructuredLog dict.
    Supports: Syslog, Firewall rules, Authentication logs, NetFlow summaries.
    """

    def __init__(self):
        super().__init__("LogIngestionAgent")

    # ── Public API ───────────────────────────────────────────────────────────

    def ingest_log(self, raw_log: str) -> StructuredLog:
        """
        Primary ingestion method called by the orchestrator node.

        Args:
            raw_log: Raw log string from any supported format.

        Returns:
            StructuredLog with all parsed fields populated.
        """
        return cast(StructuredLog, self.process(raw_log))

    # ── BaseAgent implementation ─────────────────────────────────────────────

    def process(self, payload: Any) -> Dict[str, Any]:
        raw_log: str = str(payload)
        log_lower = raw_log.lower()

        # Extract fields
        source_ip = self._extract_source_ip(raw_log)
        dest_ip = self._extract_dest_ip(raw_log, source_ip)
        port = self._extract_port(raw_log)
        protocol = self._extract_protocol(raw_log)
        event_type = self._classify_event_type(log_lower)
        severity = self._classify_severity(log_lower, event_type)
        log_format = self._detect_log_format(raw_log)
        summary = self._generate_summary(raw_log, source_ip, event_type, severity, port)

        structured: StructuredLog = {
            "raw": raw_log,
            "source_ip": source_ip,
            "dest_ip": dest_ip,
            "port": port,
            "protocol": protocol,
            "event_type": event_type,
            "severity": severity,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "summary": summary,
            "log_format": log_format,
        }
        return structured  # type: ignore[return-value]

    # ── Private helpers ──────────────────────────────────────────────────────

    def _extract_source_ip(self, text: str) -> str:
        """Extract first IP found — assumed to be the source."""
        # Prefer explicit keywords. Use _IP_RAW (no named group) for safe embedding.
        src_pattern = re.search(
            r"(?:from|src|source|client)[:\s]+(" + _IP_RAW + r")\b",
            text, re.IGNORECASE
        )
        if src_pattern:
            return src_pattern.group(1)
        match = _IP_RE.search(text)
        return match.group("ip") if match else "0.0.0.0"

    def _extract_dest_ip(self, text: str, source_ip: str) -> str:
        """Extract destination IP — second distinct IP in string."""
        # Use _IP_RAW (no named group) for safe embedding inside other patterns.
        dst_pattern = re.search(
            r"(?:to|dst|dest|destination|server)[:\s]+(" + _IP_RAW + r")\b",
            text, re.IGNORECASE
        )
        if dst_pattern:
            return dst_pattern.group(1)
        # Find all IPs and return second one if different
        ips = [m.group("ip") for m in _IP_RE.finditer(text)]
        for ip in ips:
            if ip != source_ip:
                return ip
        return "0.0.0.0"

    def _extract_port(self, text: str) -> int:
        match = _PORT_RE.search(text)
        if match:
            port_val = int(match.group("port"))
            if 1 <= port_val <= 65535:
                return port_val
        return 0

    def _extract_protocol(self, text: str) -> str:
        match = _PROTOCOL_RE.search(text)
        return match.group("proto").upper() if match else "UNKNOWN"

    def _classify_event_type(self, log_lower: str) -> str:
        """Rule-based event classification against THREAT_SIGNATURES."""
        for sig_name, sig in THREAT_SIGNATURES.items():
            for kw in sig["keywords"]:
                if kw in log_lower:
                    # Map signature name to event type
                    return sig["threat_type"]
        # Generic classification
        if any(k in log_lower for k in ["login", "auth", "password", "credential"]):
            return "AUTH_EVENT"
        if any(k in log_lower for k in ["connect", "session", "established"]):
            return "CONNECTION"
        if any(k in log_lower for k in ["update", "patch", "upgrade", "restart"]):
            return "SYSTEM_EVENT"
        if any(k in log_lower for k in ["deny", "block", "drop", "reject"]):
            return "FIREWALL_DENY"
        return "GENERIC"

    def _classify_severity(self, log_lower: str, event_type: str) -> str:
        """Map event type and keywords to a severity label."""
        critical_types = {"BRUTE_FORCE", "MALWARE_C2", "DATA_EXFIL", "PROMPT_INJECTION"}
        high_types = {"PORT_SCAN", "PRIVILEGE_ESC"}

        if event_type in critical_types:
            return "CRITICAL"
        if event_type in high_types:
            return "HIGH"
        if any(k in log_lower for k in ["error", "critical", "alert", "emergency"]):
            return "HIGH"
        if any(k in log_lower for k in ["warning", "warn", "unusual", "anomaly"]):
            return "MEDIUM"
        return "LOW"

    def _detect_log_format(self, text: str) -> str:
        """Heuristically detect the source log format."""
        if re.search(r"\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}", text):
            return "SYSLOG"
        if re.search(r"(?:ACCEPT|DENY|DROP|BLOCK)\s", text, re.IGNORECASE):
            return "FIREWALL"
        if re.search(r"(?:authentication|login|password|pam)", text, re.IGNORECASE):
            return "AUTH"
        if re.search(r"(?:bytes|packets|flow|duration)", text, re.IGNORECASE):
            return "NETFLOW"
        return "GENERIC"

    def _generate_summary(
        self,
        raw: str,
        source_ip: str,
        event_type: str,
        severity: str,
        port: int,
    ) -> str:
        """
        Rule-based episodic summarisation (deterministic, temperature=0 equivalent).
        Converts the raw log into a dense natural language trace for embedding.
        """
        port_str = f" on port {port}" if port else ""
        type_phrases = {
            "BRUTE_FORCE":    f"Brute-force authentication attack detected from {source_ip}{port_str}.",
            "PORT_SCAN":      f"Port scanning activity detected from {source_ip}{port_str}.",
            "DATA_EXFIL":     f"Potential data exfiltration attempt from {source_ip}{port_str}.",
            "MALWARE_C2":     f"Malware command-and-control communication from {source_ip}{port_str}.",
            "PRIVILEGE_ESC":  f"Privilege escalation attempt from {source_ip}.",
            "PROMPT_INJECTION": f"Prompt injection payload detected in log from {source_ip}.",
            "AUTH_EVENT":     f"Authentication event from {source_ip}{port_str}.",
            "CONNECTION":     f"Network connection event from {source_ip}{port_str}.",
            "SYSTEM_EVENT":   f"System maintenance event logged.",
            "FIREWALL_DENY":  f"Firewall denied connection from {source_ip}{port_str}.",
        }
        base = type_phrases.get(event_type, f"Security event from {source_ip}{port_str}.")
        return f"[{severity}] {base} Original: {raw[:120]}"
