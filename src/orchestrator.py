from typing import TypedDict, List, Dict, Any, Annotated
import operator
from langgraph.graph import StateGraph, END
from ingestion_agent import LogIngestionAgent
from threat_agent import ThreatAnalysisAgent
from decision_agent import DecisionAgent
from response_agent import ResponseAgent
from memory_guard import MemoryGuard
from memory_store import MemoryStore
from analytics_agent import AnalyticsAgent
import os
from datetime import datetime

# 1. Define the shared state schema
class AgentState(TypedDict):
    raw_log: str
    structured_log: Dict[str, Any]
    threat_analysis: Dict[str, Any]
    decision: Dict[str, Any]
    execution_result: Dict[str, Any]
    memory_validation: Dict[str, Any]
    history: Annotated[List[str], operator.add]

# 2. Initialize Agents and Services
ingestor = LogIngestionAgent()
threat_analyst = ThreatAnalysisAgent()
commander = DecisionAgent()
muscle = ResponseAgent()
guard = MemoryGuard()
store = MemoryStore()
analyzer = AnalyticsAgent()

# 3. Define Node Functions
def ingestion_node(state: AgentState):
    print("[Node] Ingesting Log...")
    structured = ingestor.ingest_log(state["raw_log"])
    return {
        "structured_log": structured,
        "history": ["Log ingested and structured"]
    }

def threat_analysis_node(state: AgentState):
    print("[Node] Analyzing Threats...")
    analysis = threat_analyst.analyze(state["structured_log"])
    return {
        "threat_analysis": analysis,
        "history": [f"Threat analysis complete: Score {analysis.get('risk_score')}"]
    }

def decision_node(state: AgentState):
    print("[Node] Making Decision...")
    decision = commander.decide(state["threat_analysis"])
    return {
        "decision": decision,
        "history": [f"Decision finalized: {decision.get('decision')}"]
    }

def response_node(state: AgentState):
    print("[Node] Executing Response...")
    execution = muscle.execute(state["decision"])
    return {
        "execution_result": execution,
        "history": [f"Response executed: {execution.get('action')}"]
    }

def memory_guard_node(state: AgentState):
    print("[Node] Securing Memory...")
    # Validate the entire trace of this execution
    trace = f"Log: {state['raw_log']} | Risk: {state['threat_analysis'].get('risk_score')} | Decision: {state['decision'].get('decision')}"
    validation = guard.validate_trace(trace)
    store.add_memory(validation)
    return {
        "memory_validation": validation,
        "history": ["Execution trace secured in memory"]
    }

# 4. Define Conditional Routing
def should_respond(state: AgentState):
    if state["decision"].get("decision") == "LOG_ONLY":
        return "secure_memory"
    return "execute_response"

# 5. Build the Graph
workflow = StateGraph(AgentState)

# Add Nodes
workflow.add_node("ingest", ingestion_node)
workflow.add_node("analyze", threat_analysis_node)
workflow.add_node("decide", decision_node)
workflow.add_node("execute_response", response_node)
workflow.add_node("secure_memory", memory_guard_node)

# Define Edges
workflow.set_entry_point("ingest")
workflow.add_edge("ingest", "analyze")
workflow.add_edge("analyze", "decide")

# Conditional Edge
workflow.add_conditional_edges(
    "decide",
    should_respond,
    {
        "execute_response": "execute_response",
        "secure_memory": "secure_memory"
    }
)

workflow.add_edge("execute_response", "secure_memory")
def analytics_node(state: AgentState):
    print("[Node] Generating Analytics...")
    # Simulate data collection for the graph
    # In a real scenario, this would pull from store.query_memories()
    mock_data = [
        {"risk_score": state["threat_analysis"].get("risk_score", 50), "timestamp": datetime.now()},
        {"risk_score": 20, "timestamp": datetime.now()},
        {"risk_score": 80, "timestamp": datetime.now()}
    ]
    analyzer.generate_risk_trend(mock_data)
    analyzer.generate_agent_activity({
        "Ingestion": 1, 
        "Threat": 1, 
        "Decision": 1, 
        "Response": 1 if state["decision"].get("decision") != "LOG_ONLY" else 0
    })
    return {
        "history": ["Analytics graphs generated"]
    }

workflow.add_node("analytics", analytics_node)
workflow.add_edge("secure_memory", "analytics")
workflow.add_edge("analytics", END)

# Compile
ares_app = workflow.compile()

def run_ares(log_text: str):
    """Entry point to run the ARES-Mem orchestration."""
    initial_state = {
        "raw_log": log_text,
        "history": []
    }
    return ares_app.invoke(initial_state)

def main():
    test_log = "Suspicious login attempt from unknown IP 10.0.0.5"
    result = run_ares(test_log)
    print("\n--- Final Execution History ---")
    for event in result["history"]:
        print(f"- {event}")

if __name__ == "__main__":
    main()
