from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
import json

class DecisionAgent:
    """
    The Commander: Evaluates threats against organizational policy and dictates remediation.
    """
    def __init__(self):
        self.llm = ChatOpenAI(model="gpt-4o", temperature=0)
        self.parser = JsonOutputParser()
        
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
        chain = self.prompt | self.llm | self.parser
        try:
            decision = chain.invoke({"analysis": json.dumps(analysis_data)})
            return decision
        except Exception as e:
            return {"error": f"Decision engine failed: {str(e)}", "decision": "MANUAL_REVIEW"}
