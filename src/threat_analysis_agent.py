"""
threat_analysis_agent.py — The Brain of ARES-Mem (Layer 1, Always-ON).

Responsibilities:
- Correlate structured log fields against THREAT_SIGNATURES
- Compute a composite risk score (0–100) deterministically
- Classify threat type with confidence score
- Enumerate matched threat indicators for audit trail

Design constraint: deterministic, reproducible scoring (no LLM stochasticity).
Satisfies the "temperature=0.0" and "n=100 trial" methodology requirements.
"""
import sys
import os
from typing import Any, Dict, List, cast

from base import BaseAgent
from models import StructuredLog, ThreatAnalysis, THREAT_SIGNATURES

# Load scoring deltas from config package
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)
from config import SETTINGS
_TA_CFG = SETTINGS.threat_analysis


# ── Known malicious IP ranges (example IOCs) ────────────────────────────────
_KNOWN_MALICIOUS_IP_PREFIXES = {
    "10.13.", "192.168.250.", "172.16.99.",  # Internal threat lab ranges
    "185.220.",  # Known Tor exit nodes
    "91.108.",   # Telegram spam source range
}


class ThreatAnalysisAgent(BaseAgent):
    """
    The Threat Analysis Agent (The Brain).

    Accepts a StructuredLog and produces a ThreatAnalysis with a composite
    risk score and threat classification using a deterministic scoring matrix.

    Risk Score Components:
    ┌─────────────────────────────────────────────┬────────────┐
    │ Indicator                                   │ Delta      │
    ├─────────────────────────────────────────────┼────────────┤
    │ Keyword match in THREAT_SIGNATURES          │ per-sig    │
    │ Known malicious IP prefix                   │ +30        │
    │ Privileged port targeted (< 1024)           │ +15        │
    │ Severity == CRITICAL                        │ +10        │
    │ Multiple indicators matched simultaneously  │ +5 each    │
    └─────────────────────────────────────────────┴────────────┘
    """

    def __init__(self):
        super().__init__("ThreatAnalysisAgent")

    # ── Public API ───────────────────────────────────────────────────────────

    def analyze(self, structured_log: StructuredLog) -> ThreatAnalysis:
        """
        Primary analysis method called by the orchestrator node.

        Args:
            structured_log: Output from LogIngestionAgent.

        Returns:
            ThreatAnalysis with risk score, threat type, confidence, indicators.
        """
        return cast(ThreatAnalysis, self.process(structured_log))

    # ── BaseAgent implementation ─────────────────────────────────────────────

    def process(self, payload: Any) -> Dict[str, Any]:
        structured_log: StructuredLog = payload
        raw = structured_log.get("raw", "")
        log_lower = raw.lower()

        indicators: List[str] = []
        matched_signatures = []
        risk_score = 0

        # ── 1. Keyword matching against THREAT_SIGNATURES ───────────────────
        for sig_name, sig in THREAT_SIGNATURES.items():
            matched_keywords = [kw for kw in sig["keywords"] if kw in log_lower]
            if matched_keywords:
                matched_signatures.append(sig)
                risk_score += sig["risk_delta"]
                for kw in matched_keywords[:3]:  # cap indicator list
                    indicators.append(f"{sig['threat_type']}: '{kw}'")

        # -- 2. Known malicious IP --
        # Scoring delta from config/settings.yaml (threat_analysis.malicious_ip_score)
        src_ip = structured_log.get("source_ip", "0.0.0.0")
        for prefix in _KNOWN_MALICIOUS_IP_PREFIXES:
            if src_ip.startswith(prefix):
                risk_score += _TA_CFG.malicious_ip_score
                indicators.append(f"Known malicious IP prefix: {prefix}")
                break

        # -- 3. Privileged port targeting --
        port = structured_log.get("port", 0)
        if 0 < port < 1024:
            risk_score += _TA_CFG.privileged_port_score
            indicators.append(f"Privileged port targeted: {port}")

        # -- 4. Severity amplifier --
        severity = structured_log.get("severity", "LOW")
        if severity == "CRITICAL":
            risk_score += _TA_CFG.critical_severity_score
            indicators.append("Log severity: CRITICAL")

        # -- 5. Multi-indicator bonus --
        if len(matched_signatures) > 1:
            bonus = (len(matched_signatures) - 1) * _TA_CFG.multi_sig_bonus_per
            risk_score += bonus
            indicators.append(f"Multi-signature correlation bonus: +{bonus}")

        # ── Determine primary threat type ───────────────────────────────────
        if matched_signatures:
            # Sort by risk_delta, pick highest
            primary = max(matched_signatures, key=lambda s: s["risk_delta"])
            threat_type = primary["threat_type"]
            confidence = primary["confidence"]
            recommended_action = primary["recommended_action"]
        else:
            threat_type = structured_log.get("event_type", "BENIGN")
            confidence = 0.95 if risk_score == 0 else 0.6
            recommended_action = "LOG_ONLY"

        # ── Clamp score to [0, 100] ─────────────────────────────────────────
        risk_score = max(0, min(100, risk_score))

        # Reduce confidence if no indicators matched
        if not indicators:
            confidence = min(confidence, 0.5)

        analysis: ThreatAnalysis = {
            "threat_type": threat_type,
            "risk_score": risk_score,
            "confidence": round(confidence, 3),
            "indicators": indicators,
            "recommended_action": recommended_action,
            "structured_log": structured_log,
        }
        return analysis  # type: ignore[return-value]
