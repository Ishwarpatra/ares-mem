"""
decision_agents.py — The Commander of ARES-Mem (Layer 2, Sequential Pipeline).

DecisionAgent: Evaluates ThreatAnalysis against organizational policy and
               issues a governed decision (BLOCK_IP, QUARANTINE, ALERT, LOG_ONLY, ESCALATE).

ResponseAgent: Executes the governed decision via simulated infrastructure APIs.
               Tracks action latency in ms to satisfy the SOC overhead constraint.

Design: Both agents are deterministic policy-table driven (no LLM stochasticity).
"""
import time
from typing import Any, Dict

from base import BaseAgent
from models import ThreatAnalysis, Decision, ExecutionResult


# ══════════════════════════════════════════════════════════════════════════════
# Decision Agent (The Commander)
# ══════════════════════════════════════════════════════════════════════════════

class DecisionAgent(BaseAgent):
    """
    The Decision Agent evaluates threat analysis against a policy matrix.

    Policy Matrix (risk_score thresholds):
    ┌──────────────────────┬──────────────────────────────────────────────────┐
    │ Risk Score           │ Decision                                         │
    ├──────────────────────┼──────────────────────────────────────────────────┤
    │ > 80                 │ BLOCK_IP (immediate firewall block)              │
    │ > 60 AND conf < 0.4  │ ESCALATE (human review required)                │
    │ > 50                 │ QUARANTINE (isolate host/session)                │
    │ > 20                 │ ALERT (SOC notification)                        │
    │ ≤ 20                 │ LOG_ONLY (record and monitor)                   │
    └──────────────────────┴──────────────────────────────────────────────────┘
    """

    def __init__(self):
        super().__init__("DecisionAgent")

    def decide(self, threat_analysis: ThreatAnalysis) -> Decision:
        """
        Primary decision method called by the orchestrator node.

        Args:
            threat_analysis: Output from ThreatAnalysisAgent.

        Returns:
            Decision specifying the governed response action.
        """
        return self.process(threat_analysis)

    def process(self, payload: Any) -> Dict[str, Any]:
        analysis: ThreatAnalysis = payload
        risk_score: int = analysis.get("risk_score", 0)
        confidence: float = analysis.get("confidence", 1.0)
        threat_type: str = analysis.get("threat_type", "BENIGN")
        recommended: str = analysis.get("recommended_action", "LOG_ONLY")

        # ── Policy evaluation ────────────────────────────────────────────────
        requires_escalation = False

        if risk_score > 80:
            decision = "BLOCK_IP"
            action = f"Immediately block source IP via firewall API. Threat: {threat_type}"
            task_type = "block_ip"
            priority = "CRITICAL"
        elif risk_score > 60 and confidence < 0.4:
            # Ambiguous high-risk: requires human judgement
            decision = "ESCALATE"
            action = f"Escalate to SOC analyst for review. Score: {risk_score}, Confidence: {confidence}"
            task_type = "notify"
            priority = "HIGH"
            requires_escalation = True
        elif risk_score > 50:
            decision = "QUARANTINE"
            action = f"Isolate source host/session from network segment. Threat: {threat_type}"
            task_type = "quarantine"
            priority = "HIGH"
        elif risk_score > 20:
            decision = "ALERT"
            action = f"Send SOC alert notification. Risk score: {risk_score}"
            task_type = "notify"
            priority = "MEDIUM"
        else:
            decision = "LOG_ONLY"
            action = "Record event for baseline analysis. No immediate action required."
            task_type = "log_analysis"
            priority = "LOW"

        rationale = (
            f"Policy evaluation: risk_score={risk_score}, confidence={confidence:.2f}, "
            f"threat_type={threat_type}. "
            f"Applied threshold: {'> 80 → BLOCK' if risk_score > 80 else f'> 60 + low conf → ESCALATE' if requires_escalation else f'score-band policy'}."
        )

        result: Decision = {
            "decision": decision,
            "action": action,
            "task_type": task_type,
            "priority": priority,
            "requires_escalation": requires_escalation,
            "rationale": rationale,
        }
        return result  # type: ignore[return-value]


# ══════════════════════════════════════════════════════════════════════════════
# Response Agent (The Muscle)
# ══════════════════════════════════════════════════════════════════════════════

class ResponseAgent(BaseAgent):
    """
    The Response Agent executes governed defensive actions.

    In production this would call real infrastructure APIs (firewall, SIEM, SOAR).
    In this implementation, actions are simulated with measured latency to satisfy
    the SOC latency overhead documentation requirement.
    """

    def __init__(self):
        super().__init__("ResponseAgent")

    def execute(self, decision: Decision) -> ExecutionResult:
        """
        Primary execution method called by the orchestrator node.

        Args:
            decision: Output from DecisionAgent.

        Returns:
            ExecutionResult with action status and timing.
        """
        return self.process(decision)

    def process(self, payload: Any) -> Dict[str, Any]:
        decision: Decision = payload
        action_name = decision.get("decision", "LOG_ONLY")
        task_type = decision.get("task_type", "log_analysis")

        start_ms = time.monotonic() * 1000

        # ── Dispatch to simulated action handlers ────────────────────────────
        handler_map = {
            "BLOCK_IP":    self._block_ip,
            "QUARANTINE":  self._quarantine_host,
            "ALERT":       self._send_alert,
            "LOG_ONLY":    self._log_event,
            "ESCALATE":    self._escalate,
        }
        handler = handler_map.get(action_name, self._log_event)
        status, message, target = handler(decision)

        elapsed_ms = time.monotonic() * 1000 - start_ms

        result: ExecutionResult = {
            "status": status,
            "action": action_name,
            "message": message,
            "target": target,
            "latency_ms": round(elapsed_ms, 3),
        }
        return result  # type: ignore[return-value]

    # ── Simulated action handlers ────────────────────────────────────────────

    def _block_ip(self, decision: Decision):
        """Simulate a firewall API call to block a source IP."""
        # In production: call iptables / cloud WAF / Palo Alto API
        structured = decision.get("rationale", "")
        # Extract IP mention from rationale for simulation
        target = "source_ip_extracted_from_state"
        self.logger.info("SIMULATED: iptables -I INPUT -s %s -j DROP", target)
        return "SUCCESS", f"Source IP blocked at firewall layer. Action: {decision.get('action')}", target

    def _quarantine_host(self, decision: Decision):
        """Simulate network segmentation / VLAN quarantine."""
        target = "quarantine_vlan_99"
        self.logger.info("SIMULATED: Moving host to quarantine VLAN 99")
        return "SUCCESS", f"Host isolated to quarantine VLAN. Action: {decision.get('action')}", target

    def _send_alert(self, decision: Decision):
        """Simulate SIEM / PagerDuty / Slack alert notification."""
        target = "soc_alert_queue"
        self.logger.info("SIMULATED: Sending SOC alert via SIEM webhook")
        return "SUCCESS", f"SOC alert dispatched. Priority: {decision.get('priority')}. {decision.get('action')}", target

    def _log_event(self, decision: Decision):
        """Record event in audit log with no active response."""
        target = "audit_log"
        self.logger.info("LOG_ONLY: Recording event to audit trail")
        return "SUCCESS", f"Event recorded for baseline analysis. {decision.get('action')}", target

    def _escalate(self, decision: Decision):
        """Simulate human escalation ticket creation."""
        target = "human_review_queue"
        self.logger.info("SIMULATED: Creating human escalation ticket")
        return "PENDING_APPROVAL", f"Escalation ticket created. Awaiting analyst review. {decision.get('action')}", target
