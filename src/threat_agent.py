"""
threat_agent.py — The Brain of ARES-Mem (Layer 1, Always-ON).

Responsibilities:
- Correlate structured log fields against THREAT_SIGNATURES
- Compute a composite risk score (0-100) deterministically
- Classify threat type with confidence score
- Enumerate matched threat indicators for audit trail

Design: fully deterministic, reproducible scoring. No LLM calls.
Satisfies the temperature=0.0 and n=100 trial methodology requirements.
"""
from typing import Any, Dict, List

from models import StructuredLog, ThreatAnalysis, THREAT_SIGNATURES

# ── Known malicious IP prefixes (IOC set) ────────────────────────────────────
# Narrowed to specific threat-lab / Tor-exit / spam ranges per audit finding.
_KNOWN_MALICIOUS_IP_PREFIXES = {
    "10.13.",        # Internal threat-lab ranges
    "172.16.99.",    # Internal threat-lab ranges
    "192.168.250.",  # Internal threat-lab ranges
    "185.220.",      # Known Tor exit nodes
    "91.108.",       # Telegram spam source range
}

# ── Scoring deltas (class constants for research reproducibility) ─────────────
_MALICIOUS_IP_DELTA  = 30
_PRIV_PORT_DELTA     = 15   # ports < 1024
_SEVERITY_CRITICAL   = 10   # CRITICAL severity amplifier
_MULTI_IND_BONUS     = 5    # per additional indicator beyond first


class ThreatAnalysisAgent:
    """
    The Threat Analysis Agent (The Brain).

    Accepts a StructuredLog and produces a ThreatAnalysis with a composite
    risk score and threat classification using a deterministic scoring matrix.

    Risk Score Components:
    ─────────────────────────────────────────────────────────────────────
    Indicator                               Delta
    ─────────────────────────────────────────────────────────────────────
    Keyword match in THREAT_SIGNATURES      per-signature risk_delta
    Known malicious IP prefix               +30
    Privileged port targeted (< 1024)       +15
    Severity == CRITICAL                    +10
    Multiple indicators simultaneously      +5 each (beyond first)
    ─────────────────────────────────────────────────────────────────────
    Score clamped to [0, 100].
    """

    def analyze(self, structured_log: Any) -> ThreatAnalysis:
        """
        Primary analysis method called by the orchestrator node.

        Args:
            structured_log: StructuredLog dict from LogIngestionAgent,
                            or a raw string / plain dict on legacy paths.

        Returns:
            ThreatAnalysis with risk_score, threat_type, confidence, indicators.
        """
        if isinstance(structured_log, str):
            structured_log = {"raw": structured_log, "source_ip": "0.0.0.0",
                              "severity": "INFO", "port": 0}

        raw       = structured_log.get("raw", "")
        src_ip    = structured_log.get("source_ip", "0.0.0.0")
        severity  = structured_log.get("severity", "INFO")
        port      = structured_log.get("port", 0)
        log_lower = raw.lower()

        indicators:        List[str] = []
        matched_sigs:      List[Dict] = []
        risk_score:        int = 0

        # ── 1. Keyword matching against THREAT_SIGNATURES ─────────────────────
        for sig_name, sig in THREAT_SIGNATURES.items():
            matched_kws = [kw for kw in sig["keywords"] if kw in log_lower]
            if matched_kws:
                matched_sigs.append(sig)
                risk_score += sig["risk_delta"]
                for kw in matched_kws[:3]:   # cap indicator list per signature
                    indicators.append(f"{sig['threat_type']}: '{kw}'")

        # ── 2. Known malicious IP prefix ──────────────────────────────────────
        for prefix in _KNOWN_MALICIOUS_IP_PREFIXES:
            if src_ip.startswith(prefix):
                risk_score += _MALICIOUS_IP_DELTA
                indicators.append(f"Known malicious IP prefix: {prefix}")
                break

        # ── 3. Privileged port targeted ───────────────────────────────────────
        if isinstance(port, int) and 0 < port < 1024:
            risk_score += _PRIV_PORT_DELTA
            indicators.append(f"Privileged port targeted: {port}")

        # ── 4. Severity amplifier ─────────────────────────────────────────────
        if severity == "CRITICAL":
            risk_score += _SEVERITY_CRITICAL
            indicators.append("Severity: CRITICAL")

        # ── 5. Multi-indicator correlation bonus ──────────────────────────────
        if len(matched_sigs) > 1:
            bonus = (len(matched_sigs) - 1) * _MULTI_IND_BONUS
            risk_score += bonus
            indicators.append(f"Multi-signature correlation bonus: +{bonus}")

        risk_score = min(max(risk_score, 0), 100)

        # ── Determine primary threat type & confidence ────────────────────────
        if matched_sigs:
            # Use the highest-risk matched signature as primary type
            primary_sig  = max(matched_sigs, key=lambda s: s["risk_delta"])
            threat_type  = primary_sig["threat_type"]
            # Confidence scales with number of matched keywords (more = higher)
            n_kws = sum(len([kw for kw in s["keywords"] if kw in log_lower])
                        for s in matched_sigs)
            confidence = min(0.4 + (n_kws * 0.08), 0.99)
            recommended_action = primary_sig["recommended_action"]
        else:
            threat_type        = "BENIGN"
            confidence         = 0.95
            recommended_action = "LOG_ONLY"

        return {  # type: ignore
            "threat_type":        threat_type,
            "risk_score":         risk_score,
            "confidence":         round(confidence, 3),
            "indicators":         indicators,
            "recommended_action": recommended_action,
            "structured_log":     structured_log,
        }
