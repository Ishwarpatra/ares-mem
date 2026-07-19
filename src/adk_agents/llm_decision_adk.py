"""
llm_decision_adk.py — LLM Decision Agent using Ollama via LiteLLM.

Replaces the Google ADK dependency with a direct litellm.completion() call.
Validates output against DecisionSchema (Pydantic) and falls back to the
deterministic DecisionAgent on any failure.

Default model: qwen2.5:1.5b-instruct (upgrade from 0.5b per audit report).
Slow-path escalation model: qwen2.5:7b-instruct (set via model_name param).
"""
import json
import re
import logging
from typing import Any, Dict

from pydantic import BaseModel, Field

logger = logging.getLogger("LlmDecisionADK")

# ── Try to import litellm ─────────────────────────────────────────────────────
try:
    import litellm
    from src.circuit_breaker import llm_circuit_breaker
    litellm.set_verbose = False          # suppress litellm debug logs
    _LITELLM_AVAILABLE = True
except ImportError:
    _LITELLM_AVAILABLE = False


# ── Output schema ─────────────────────────────────────────────────────────────

class DecisionSchema(BaseModel):
    """Pydantic schema for the LLM decision output — enforces strict field types."""
    decision:            str   = Field(description="Exactly one of: BLOCK_IP, QUARANTINE, ALERT, LOG_ONLY, ESCALATE")
    action:              str   = Field(description="Human-readable description of the action to execute")
    task_type:           str   = Field(description="Exactly one of: block_ip, quarantine, notify, log_analysis")
    priority:            str   = Field(description="Exactly one of: CRITICAL, HIGH, MEDIUM, LOW")
    requires_escalation: bool  = Field(description="True if risk > 60 and confidence < 0.4")
    rationale:           str   = Field(description="Step-by-step reasoning mapping score/confidence to decision")
    source_ip:           str   = Field(default="0.0.0.0", description="Echo source_ip from input")


# ── Policy system prompt ──────────────────────────────────────────────────────

DECISION_POLICY_INSTRUCTIONS = """\
You are the LLM Decision Agent (The Commander) for the ARES-Mem cybersecurity pipeline.
Evaluate the threat analysis data and produce a structured remediation decision in strict JSON.

Policy Matrix (apply in order — first match wins):
1. BLOCK_IP:   risk_score > 80.  Priority: CRITICAL, task_type: block_ip,  requires_escalation: false.
2. ESCALATE:   risk_score > 60 AND confidence < 0.4.  Priority: HIGH, task_type: notify, requires_escalation: true.
3. QUARANTINE: risk_score > 50.  Priority: HIGH, task_type: quarantine, requires_escalation: false.
4. ALERT:      risk_score > 20.  Priority: MEDIUM, task_type: notify, requires_escalation: false.
5. LOG_ONLY:   risk_score <= 20. Priority: LOW, task_type: log_analysis, requires_escalation: false.

You will receive a JSON object with:
  threat_type, risk_score, confidence, recommended_action, indicators, source_ip

Return ONLY a valid JSON object matching this exact schema (no markdown, no preamble):
{
  "decision": "<one of BLOCK_IP|QUARANTINE|ALERT|LOG_ONLY|ESCALATE>",
  "action": "<what to do>",
  "task_type": "<block_ip|quarantine|notify|log_analysis>",
  "priority": "<CRITICAL|HIGH|MEDIUM|LOW>",
  "requires_escalation": <true|false>,
  "rationale": "<step-by-step reasoning>",
  "source_ip": "<echo source_ip from input>"
}"""


# ── Core LLM call ─────────────────────────────────────────────────────────────

def run_llm_decision(
    threat_analysis: Dict[str, Any],
    model_name: str = "qwen2.5:1.5b-instruct",
    api_base: str = "http://localhost:11434",
) -> Dict[str, Any]:
    """
    Executes the LLM Decision Agent via Ollama + LiteLLM.

    Falls back to None on any failure — the caller (decision_agent.py)
    handles the deterministic fallback.

    Args:
        threat_analysis: ThreatAnalysis dict from ThreatAnalysisAgent.
        model_name:      Ollama model tag (default: qwen2.5:1.5b-instruct).
        api_base:        Ollama API base URL.

    Returns:
        Validated DecisionSchema dict, or None on failure.
    """
    if not _LITELLM_AVAILABLE:
        logger.warning("[LLM] litellm not installed — skipping LLM path.")
        return None

    sl = threat_analysis.get("structured_log") or {}
    if isinstance(sl, str):
        sl = {}

    prompt_data = {
        "threat_type":        threat_analysis.get("threat_type", "BENIGN"),
        "risk_score":         threat_analysis.get("risk_score", 0),
        "confidence":         threat_analysis.get("confidence", 1.0),
        "recommended_action": threat_analysis.get("recommended_action", "LOG_ONLY"),
        "indicators":         threat_analysis.get("indicators", []),
        "source_ip":          sl.get("source_ip", "0.0.0.0"),
    }

    def _call_llm():
        response = litellm.completion(
            model=f"ollama/{model_name}",
            api_base=api_base,
            messages=[
                {"role": "system",  "content": DECISION_POLICY_INSTRUCTIONS},
                {"role": "user",    "content": json.dumps(prompt_data)},
            ],
            temperature=0.0,
            seed=42,
            timeout=15,
        )

        raw_text = response.choices[0].message.content.strip()

        # Strip markdown fences if present
        match = re.search(r"```(?:json)?\s*(.*?)\s*```", raw_text, re.DOTALL)
        if match:
            raw_text = match.group(1).strip()

        parsed    = json.loads(raw_text)
        validated = DecisionSchema(**parsed)
        logger.info("[LLM] Decision: %s | Score: %s | Model: %s",
                    validated.decision, prompt_data["risk_score"], model_name)
        return validated.model_dump()

    def _fallback():
        logger.warning("[LLM] LLM circuit OPEN or failed. Using None fallback.")
        return None

    try:
        return llm_circuit_breaker.call(_call_llm, _fallback)
    except Exception as e:
        logger.warning("[LLM] Fallback failed: %s", str(e))
        return None
