# src/adk_agents/llm_decision_adk.py — LLM Decision Agent using Google ADK
from typing import Optional
from pydantic import BaseModel, Field

# Guard optional google-adk imports — module loads cleanly without them.
try:
    from google.adk.agents.llm_agent import LlmAgent
    from google.adk.models.lite_llm import LiteLlm
    _ADK_AVAILABLE = True
except ImportError:
    LlmAgent = None   # type: ignore[assignment,misc]
    LiteLlm = None    # type: ignore[assignment,misc]
    _ADK_AVAILABLE = False

class DecisionSchema(BaseModel):
    """Pydantic schema representing the required structure for remediation decisions."""
    decision: str = Field(description="The final action to take. Must be exactly one of: BLOCK_IP, QUARANTINE, ALERT, LOG_ONLY, ESCALATE.")
    action: str = Field(description="Human-readable description of the action to execute.")
    task_type: str = Field(description="The classification task type. Must be exactly one of: block_ip, quarantine, notify, log_analysis.")
    priority: str = Field(description="The priority of the action. Must be exactly one of: CRITICAL, HIGH, MEDIUM, LOW.")
    requires_escalation: bool = Field(description="True if the threat is highly risky and ambiguous (e.g., risk_score > 60 and confidence < 0.4) and requires human review.")
    rationale: str = Field(description="Step-by-step reasoning explaining how the threat score, confidence, and type mapped to the chosen action under the policy.")
    source_ip: str = Field(default="0.0.0.0", description="Source IP address of the threat actor, copied from the input source_ip field.")

# System instructions detailing the policy mapping table:
DECISION_POLICY_INSTRUCTIONS = """You are the LLM-driven Decision Agent (Commander) for the ARES-Mem cybersecurity pipeline.
Your job is to evaluate threat analysis data and produce a structured remediation decision in strict JSON format.

Evaluate the inputs using the following Policy Matrix:
1. BLOCK_IP: If risk_score > 80. Action: "Immediately block source IP via firewall API." Priority: CRITICAL, task_type: block_ip, requires_escalation: false.
2. ESCALATE: If risk_score > 60 AND confidence < 0.4. Action: "Escalate to SOC analyst for review." Priority: HIGH, task_type: notify, requires_escalation: true.
3. QUARANTINE: If risk_score > 50 (and doesn't match above). Action: "Isolate source host/session from network segment." Priority: HIGH, task_type: quarantine, requires_escalation: false.
4. ALERT: If risk_score > 20 (and doesn't match above). Action: "Send SOC alert notification." Priority: MEDIUM, task_type: notify, requires_escalation: false.
5. LOG_ONLY: If risk_score <= 20. Action: "Record event for baseline analysis. No immediate action required." Priority: LOW, task_type: log_analysis, requires_escalation: false.

Inputs to evaluate will be presented as a JSON string containing:
- threat_type
- risk_score
- confidence
- recommended_action
- indicators
- source_ip  (echo this value back verbatim in the source_ip field of your response)

Return a valid JSON object matching the requested schema. Do not output anything else.
"""

def create_decision_agent(model_name: str = "qwen2.5:0.5b-instruct", api_base: str = "http://localhost:11434") -> LlmAgent:
    """Helper to instantiate the LlmDecisionADKAgent with LiteLlm backend."""
    return LlmAgent(
        name="LlmDecisionAgent",
        model=LiteLlm(
            model=f"ollama/{model_name}",
            api_base=api_base,
            temperature=0.0,
            seed=42
        ),
        instruction=DECISION_POLICY_INSTRUCTIONS,
        output_schema=DecisionSchema,
        output_key="decision"
    )
