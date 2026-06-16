import json
import os
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser

class ThreatAnalysisAgent:
    """
    The Brain: Correlates log patterns against threat intelligence and assigns risk scores.
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
            "You are a Senior SOC Analyst. Analyze the following log for potential threats.\n"
            "Log: {log_content}\n"
            "Provide a risk score (0-100) and a brief justification in JSON format.\n"
            "Format: {{\"risk_score\": int, \"justification\": \"string\", \"threat_type\": \"string\"}}"
        )

    def analyze(self, log_data):
        """
        Analyzes structured log data using an LLM to determine risk.
        """
        if not self.use_llm:
            return self._local_analysis(log_data)

        chain = self.prompt | self.llm | self.parser
        try:
            analysis = chain.invoke({
                "log_content": json.dumps(log_data) if isinstance(log_data, dict) else log_data
            })
            return analysis
        except Exception as e:
            return self._local_analysis(log_data, str(e))

    def _local_analysis(self, log_data, error_message=None):
        text = json.dumps(log_data) if isinstance(log_data, dict) else str(log_data)
        normalized = text.lower()
        score = 25
        threat_type = "informational"
        justification = "Local heuristic analysis."

        high_risk_terms = ["unauthorized", "failed login", "suspicious", "attack", "breach", "critical", "password"]
        medium_risk_terms = ["error", "timeout", "warning", "failed", "denied"]

        if any(term in normalized for term in high_risk_terms):
            score = 85
            threat_type = "intrusion"
        elif any(term in normalized for term in medium_risk_terms):
            score = 55
            threat_type = "anomaly"

        if error_message:
            justification = f"Fallback analysis due to LLM error: {error_message}"

        return {
            "risk_score": score,
            "justification": justification,
            "threat_type": threat_type
        }
