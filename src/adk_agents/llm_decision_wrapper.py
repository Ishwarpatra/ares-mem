# src/adk_agents/llm_decision_wrapper.py — LLM Decision Agent Integration & Fallback
import json
import logging
from typing import Dict, Any, cast
from google.adk.runners import InMemoryRunner
from google.genai import types

from adk_agents.llm_decision_adk import create_decision_agent, DecisionSchema
from decision_agents import DecisionAgent as DeterministicDecisionAgent
from models import ThreatAnalysis, Decision

logger = logging.getLogger("LlmDecisionWrapper")

def run_llm_decision(
    threat_analysis: Dict[str, Any],
    model_name: str = "qwen2.5:0.5b-instruct",
    api_base: str = "http://localhost:11434"
) -> Dict[str, Any]:
    """
    Executes the LLM-driven Decision Agent using the ADK framework.
    Applies strict temperature controls, validates outputs, and falls back to
    the rule-based DecisionAgent in case of parsing, schema, or endpoint failure.
    """
    prompt = json.dumps({
        "threat_type": threat_analysis.get("threat_type", "BENIGN"),
        "risk_score": threat_analysis.get("risk_score", 0),
        "confidence": threat_analysis.get("confidence", 1.0),
        "recommended_action": threat_analysis.get("recommended_action", "LOG_ONLY"),
        "indicators": threat_analysis.get("indicators", [])
    })

    try:
        # 1. Instantiate the ADK Agent
        agent = create_decision_agent(model_name=model_name, api_base=api_base)

        # 2. Setup the runner
        runner = InMemoryRunner(agent)

        # 3. Create the input message in the structure expected by the ADK
        user_message = types.Content(
            role="user",
            parts=[types.Part.from_text(text=prompt)]
        )

        # 4. Execute the run sequence
        events = list(runner.run(
            user_id="eval_user",
            session_id="eval_session",
            new_message=user_message
        ))

        # 5. Extract and validate output
        session = runner.session_service.get_session(
            app_name=runner.app_name,
            user_id="eval_user",
            session_id="eval_session"
        )
        decision_dict = session.state.get("decision") if session is not None else None

        if decision_dict:
            # Successful validation and automatic schema parsing from state
            validated = DecisionSchema(**decision_dict)
            return cast(Dict[str, Any], validated.model_dump())
        else:
            # Fallback manual text extraction if state output key not populated
            text_response = ""
            for event in events:
                if event.content and event.content.parts:
                    for part in event.content.parts:
                        if part.text:
                            text_response += part.text

            # Clean output blocks
            clean_text = text_response.strip()
            if clean_text.startswith("```json"):
                clean_text = clean_text.split("```json", 1)[1]
            if "```" in clean_text:
                clean_text = clean_text.split("```", 1)[0]
            clean_text = clean_text.strip()

            parsed = json.loads(clean_text)
            validated = DecisionSchema(**parsed)
            return cast(Dict[str, Any], validated.model_dump())

    except Exception as e:
        logger.warning(
            "[Wrapper] LLM Decision Agent execution failed: %s. Falling back to rule-based agent.",
            str(e),
            exc_info=True
        )
        
        # Safe fallback to deterministic rule-based DecisionAgent
        fallback_agent = DeterministicDecisionAgent()
        fallback_decision = fallback_agent.decide(cast(ThreatAnalysis, threat_analysis))
        
        # Tag the rationale so we know a fallback occurred
        fallback_decision["rationale"] = (
            f"[FALLBACK] {fallback_decision.get('rationale', '')} "
            f"(Reason: LLM failed: {str(e)})"
        )
        return cast(Dict[str, Any], fallback_decision)
