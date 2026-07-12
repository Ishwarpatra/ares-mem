"""
decision_agents.py — The Commander of ARES-Mem (Layer 2, Sequential Pipeline).

DecisionAgent: Evaluates ThreatAnalysis against organizational policy and
               issues a governed decision (BLOCK_IP, QUARANTINE, ALERT, LOG_ONLY, ESCALATE).

ResponseAgent: Executes the governed decision via simulated infrastructure APIs.
               Tracks action latency in ms to satisfy the SOC overhead constraint.

Design: Both agents are deterministic policy-table driven (no LLM stochasticity).
"""
import time
import sys
import os
from typing import Any, Dict, cast
import requests
import concurrent.futures

from base import BaseAgent
from models import ThreatAnalysis, Decision, ExecutionResult

_WEBHOOK_EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=5)

def _send_webhook_async(url: str, payload: Decision, logger):
    try:
        # Enforce strict 2-second HTTP connection/response timeout
        res = requests.post(url, json=payload, timeout=2.0)
        logger.info("Webhook alert dispatched successfully to %s. Status code: %d", url, res.status_code)
    except Exception as err:
        logger.error("Failed to dispatch webhook alert to %s: %s", url, err)

# Load decision thresholds from config package
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)
from config import SETTINGS
_DA_CFG = SETTINGS.decision_agent


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
        return cast(Decision, self.process(threat_analysis))

    def process(self, payload: Any) -> Dict[str, Any]:
        analysis: ThreatAnalysis = payload
        risk_score: int = analysis.get("risk_score", 0)
        confidence: float = analysis.get("confidence", 1.0)
        threat_type: str = analysis.get("threat_type", "BENIGN")
        recommended: str = analysis.get("recommended_action", "LOG_ONLY")

        # -- Policy evaluation --
        # Thresholds from config/settings.yaml (decision_agent section).
        requires_escalation = False

        if risk_score > _DA_CFG.block_threshold:
            decision = "BLOCK_IP"
            action = f"Immediately block source IP via firewall API. Threat: {threat_type}"
            task_type = "block_ip"
            priority = "CRITICAL"
        elif risk_score > _DA_CFG.escalate_threshold and confidence < _DA_CFG.escalate_confidence_max:
            # Ambiguous high-risk: requires human judgement
            decision = "ESCALATE"
            action = f"Escalate to SOC analyst for review. Score: {risk_score}, Confidence: {confidence}"
            task_type = "notify"
            priority = "HIGH"
            requires_escalation = True
        elif risk_score > _DA_CFG.quarantine_threshold:
            decision = "QUARANTINE"
            action = f"Isolate source host/session from network segment. Threat: {threat_type}"
            task_type = "quarantine"
            priority = "HIGH"
        elif risk_score > _DA_CFG.alert_threshold:
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
            # Null-safe: structured_log may be None if validation short-circuited
            "source_ip": (analysis.get("structured_log") or {}).get("source_ip", "0.0.0.0"),
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
        return cast(ExecutionResult, self.process(decision))

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
        target = decision.get("source_ip", "0.0.0.0")
        self.logger.info("SIMULATED: iptables -I INPUT -s %s -j DROP", target)
        return "SUCCESS", f"Source IP blocked at firewall layer. Action: {decision.get('action')}", target

    def _quarantine_host(self, decision: Decision):
        """Simulate network segmentation / VLAN quarantine."""
        target = "quarantine_vlan_99"
        self.logger.info("SIMULATED: Moving host to quarantine VLAN 99")
        return "SUCCESS", f"Host isolated to quarantine VLAN. Action: {decision.get('action')}", target

    def _send_alert(self, decision: Decision):
        """Simulate SIEM / PagerDuty / Slack alert notification and send async webhook."""
        target = "soc_alert_queue"
        self.logger.info("SIMULATED: Sending SOC alert via SIEM webhook")
        
        # Look up webhook_url from environment or SETTINGS config
        url = os.getenv("ARES_WEBHOOK_URL")
        if not url:
            try:
                url = SETTINGS.policy_rules.webhook_url
            except AttributeError:
                url = "http://localhost:8080/api/webhook/simulate"
                
        if url:
            self.logger.info("Dispatching fire-and-forget webhook alert to %s", url)
            _WEBHOOK_EXECUTOR.submit(_send_webhook_async, url, decision, self.logger)
            
        return "SUCCESS", f"SOC alert dispatched. Priority: {decision.get('priority')}. {decision.get('action')}", target

    def _log_event(self, decision: Decision):
        """Record event in audit log with no active response."""
        target = "audit_log"
        self.logger.info("LOG_ONLY: Recording event to audit trail")
        return "SUCCESS", f"Event recorded for baseline analysis. {decision.get('action')}", target

    def _escalate(self, decision: Decision):
        """Simulate human escalation ticket creation.

        NOTE: This handler is effectively dead code in the normal pipeline flow.
        The orchestrator's conditional edge (route_after_decision) intercepts
        ESCALATE *before* response_node is called, routing directly to
        human_escalation_node instead. By the time response_node runs, the
        decision has already been overridden (to QUARANTINE/ALERT by the
        operator). This method is retained as a direct-call fallback only
        (e.g., unit tests that invoke ResponseAgent.execute() in isolation).
        """
        target = "human_review_queue"
        self.logger.info("SIMULATED: Creating human escalation ticket")
        return "PENDING_APPROVAL", f"Escalation ticket created. Awaiting analyst review. {decision.get('action')}", target
