"""
human_escalation_agent.py — Layer 3 On-Demand Human Oversight (The Oversight).

Triggered when the Decision Agent determines that a high-risk event has
insufficient confidence for autonomous action. Simulates an approval workflow:
  - In test/local mode: auto-approves after logging the escalation
  - In production mode: blocks and awaits out-of-band operator signal

Architecture layer: Layer 3 (On-Demand, triggered by conditional edge).
"""
import os
import time
from typing import Any, Dict

from base import BaseAgent
from models import Decision


class HumanEscalationAgent(BaseAgent):
    """
    The Human Escalation Agent (The Oversight).

    Handles high-risk, low-confidence decisions that require human review
    before defensive action is taken. This prevents autonomous over-blocking
    on ambiguous threat intelligence.

    Trigger Conditions (configured in orchestrator):
        threat_score > 60 AND confidence < 0.4
    """

    def __init__(self):
        super().__init__("HumanEscalationAgent")
        # Determine environment: test/local auto-approves, docker/production blocks
        self.env = os.getenv("ARES_ENV", "local")
        self.auto_approve = self.env in ("local", "test")

    # ── Public API ───────────────────────────────────────────────────────────

    def review(self, decision: Decision, threat_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Primary review method called by the orchestrator escalation node.

        Args:
            decision:        The ESCALATE decision from DecisionAgent.
            threat_context:  Full threat analysis context for analyst review.

        Returns:
            Dict with `approved` (bool), `operator_decision`, and `audit_trail`.
        """
        return self.process({"decision": decision, "context": threat_context})

    # ── BaseAgent implementation ─────────────────────────────────────────────

    def process(self, payload: Any) -> Dict[str, Any]:
        decision: Decision = payload.get("decision", {})
        context: Dict[str, Any] = payload.get("context", {})

        risk_score = context.get("risk_score", 0)
        confidence = context.get("confidence", 0.0)
        threat_type = context.get("threat_type", "UNKNOWN")
        indicators = context.get("indicators", [])

        escalation_ticket = self._create_ticket(
            risk_score=risk_score,
            confidence=confidence,
            threat_type=threat_type,
            indicators=indicators,
            decision=decision,
        )

        self.logger.warning(
            "ESCALATION REQUIRED | ticket=%s | risk=%d | confidence=%.2f | type=%s",
            escalation_ticket["ticket_id"],
            risk_score,
            confidence,
            threat_type,
        )

        if self.auto_approve:
            # Test/local mode: simulate analyst approving the escalation
            # Default operator decision: escalate to QUARANTINE (safe middle ground)
            operator_decision = "QUARANTINE"
            approved = True
            resolution = f"[AUTO-APPROVED in {self.env} mode] Operator decision: {operator_decision}"
            self.logger.info("Auto-approving escalation. Operator decision: %s", operator_decision)
        else:
            # Production mode: in a real system this would block on a signal/webhook
            # For now we simulate a timeout and fall back to ALERT (conservative)
            operator_decision = "ALERT"
            approved = False
            resolution = "[PENDING] Awaiting human operator approval via SOC dashboard."
            self.logger.critical(
                "PRODUCTION ESCALATION: Awaiting human approval for ticket %s",
                escalation_ticket["ticket_id"],
            )

        return {
            "approved": approved,
            "operator_decision": operator_decision,
            "resolution": resolution,
            "escalation_ticket": escalation_ticket,
            "escalation_required": True,
        }

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _create_ticket(
        self,
        risk_score: int,
        confidence: float,
        threat_type: str,
        indicators: list,
        decision: Decision,
    ) -> Dict[str, Any]:
        """Generates a structured escalation ticket for the SOC audit trail."""
        ticket_id = f"ESC-{int(time.time() * 1000) % 1_000_000:06d}"
        return {
            "ticket_id": ticket_id,
            "severity": "HIGH",
            "risk_score": risk_score,
            "confidence_score": round(confidence, 3),
            "threat_classification": threat_type,
            "matched_indicators": indicators[:5],  # Cap at 5 for readability
            "original_decision": decision.get("decision", "ESCALATE"),
            "rationale": decision.get("rationale", ""),
            "environment": self.env,
            "status": "AUTO_RESOLVED" if self.auto_approve else "PENDING_HUMAN",
        }
