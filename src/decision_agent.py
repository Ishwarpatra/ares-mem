import json
import os
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser

class DecisionAgent:
    """
    The Commander: Evaluates threats against organizational policy and dictates remediation.
    """
    def __init__(self):
        self.use_llm = bool(
            os.getenv("OPENAI_API_KEY") or os.getenv("OPENAI_ADMIN_KEY") or os.getenv("OPENAI_API_KEY")
        )
        self.parser = JsonOutputParser()

        if self.use_llm:
            try:
                self.llm = ChatOpenAI(model="gpt-4o", temperature=0)
            except Exception:
                self.use_llm = False
                self.llm = None

        self.prompt = ChatPromptTemplate.from_template(
            "You are the Security Decision Engine. Based on the threat analysis, decide on a response.\n"
            "Analysis: {analysis}\n"
            "Policy: \n"
            "- Score > 80: IMMEDIATE_BLOCK\n"
            "- Score > 50: INVESTIGATE\n"
            "- Score <= 50: LOG_ONLY\n"
            "Provide your decision and the specific action to take in JSON format.\n"
            "Format: {{\"decision\": \"string\", \"action\": \"string\", \"confidence\": float}}"
        )

    def decide(self, analysis_data):
        """
        Makes a decision based on the risk score and policy.
        """
        if not self.use_llm:
            return self._local_decision(analysis_data)

        chain = self.prompt | self.llm | self.parser
        try:
            decision = chain.invoke({"analysis": json.dumps(analysis_data)})
            return decision
        except Exception as e:
            return self._local_decision(analysis_data, str(e))

    def _local_decision(self, analysis_data, error_message=None):
        if isinstance(analysis_data, str):
            try:
                analysis = json.loads(analysis_data)
            except json.JSONDecodeError:
                analysis = {}
        else:
            analysis = analysis_data if isinstance(analysis_data, dict) else {}

        score = analysis.get("risk_score", 50)
        if not isinstance(score, (int, float)):
            try:
                score = float(score)
            except (ValueError, TypeError):
                score = 50

        if score > 80:
            decision = "IMMEDIATE_BLOCK"
            action = "BLOCK_IP"
        elif score > 50:
            decision = "INVESTIGATE"
            action = "COLLECT_EVIDENCE"
        else:
            decision = "LOG_ONLY"
            action = "NO_ACTION"

        result = {
            "decision": decision,
            "action": action,
            "confidence": 0.75
        }
        if error_message:
            result["error"] = f"Fallback decision due to LLM error: {error_message}"
        return result
