from log_ingestion_agent import LogIngestionAgent
from threat_analysis_agent import ThreatAnalysisAgent
from decision_agents import DecisionAgent
from response_agents import ResponseAgent
import json

def run_test_pipeline():
    print("--- Starting Project ARES-Mem Phase 2 Test Pipeline ---")
    
    # 1. Ingestion
    ingestor = LogIngestionAgent()
    raw_log = "Failed login attempt from IP 192.168.1.100 - 5 attempts in 10 seconds."
    structured_log = ingestor.ingest_log(raw_log)
    print(f"[Ingestion] Structured Log: {structured_log}")

    # 2. Threat Analysis
    threat_analyst = ThreatAnalysisAgent()
    analysis = threat_analyst.analyze(structured_log)
    print(f"[Threat Analysis] Risk Score: {analysis.get('risk_score')}, Type: {analysis.get('threat_type')}")

    # 3. Decision
    commander = DecisionAgent()
    decision = commander.decide(analysis)
    print(f"[Decision] Decision: {decision.get('decision')}, Action: {decision.get('action')}")

    # 4. Response
    muscle = ResponseAgent()
    execution = muscle.execute(decision)
    print(f"[Response] Execution Status: {execution.get('status')}")
    print(f"[Response] Message: {execution.get('message')}")

    print("--- Pipeline Test Complete ---")

if __name__ == "__main__":
    run_test_pipeline()
