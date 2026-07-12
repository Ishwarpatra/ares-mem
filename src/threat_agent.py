from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
import json
import os

class ThreatAnalysisAgent:
    """
    The Brain: Correlates log patterns against threat intelligence and assigns risk scores.
    """
    def __init__(self):
        self.llm = ChatOpenAI(model="gpt-4o", temperature=0)
        self.parser = JsonOutputParser()
        
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
        chain = self.prompt | self.llm | self.parser
        try:
            analysis = chain.invoke({
                "log_content": json.dumps(log_data) if isinstance(log_data, dict) else log_data
            })
            return analysis
        except Exception as e:
            return {"error": f"Threat analysis failed: {str(e)}", "risk_score": 50} # Default to medium risk on error
