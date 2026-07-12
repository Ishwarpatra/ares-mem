from typing import TypedDict, List, Dict, Any, Annotated, Optional
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
#    All fields are Optional so partial state never causes KeyError mid-pipeline.
class AgentState(TypedDict, total=False):
    raw_log:           str
    structured_log:    Dict[str, Any]
    threat_analysis:   Dict[str, Any]
    decision:          Dict[str, Any]
    execution_result:  Dict[str, Any]
    memory_validation: Dict[str, Any]
    history:           Annotated[List[str], operator.add]
    pipeline_error:    Optional[str]   # Propagates error context if any node fails

# 2. Lazy agent registry — agents are instantiated on first use, not at import time.
#    This allows importing orchestrator.py without OPENAI_API_KEY being set,
#    enabling unit tests, routing checks, and partial imports.
_agents: Dict[str, Any] = {}

def _get_agent(name: str):
    """Returns a cached agent instance, creating it on first call."""
    if name not in _agents:
        if name == "ingestor":
            _agents[name] = LogIngestionAgent()
        elif name == "threat_analyst":
            _agents[name] = ThreatAnalysisAgent()
        elif name == "commander":
            _agents[name] = DecisionAgent()
        elif name == "muscle":
            _agents[name] = ResponseAgent()
        elif name == "guard":
            _agents[name] = MemoryGuard()
        elif name == "store":
            _agents[name] = MemoryStore()
        elif name == "analyzer":
            _agents[name] = AnalyticsAgent()
        else:
            raise ValueError(f"Unknown agent: {name!r}")
    return _agents[name]

# 3. Define Node Functions

def ingestion_node(state: AgentState) -> dict:
    print("[Node] Ingesting Log...")
    raw = state.get("raw_log", "")
    structured = _get_agent("ingestor").ingest_log(raw)
    if "error" in structured:
        return {
            "structured_log": structured,
            "history":        [f"[ERROR] Ingestion failed: {structured['error']}"],
            "pipeline_error": structured["error"],
        }
    return {
        "structured_log": structured,
        "history":        ["Log ingested and structured"],
    }

def threat_analysis_node(state: AgentState) -> dict:
    print("[Node] Analyzing Threats...")
    if state.get("pipeline_error"):
        return {"history": ["[SKIP] Threat analysis skipped due to upstream error"]}
    analysis = _get_agent("threat_analyst").analyze(state.get("structured_log", {}))
    return {
        "threat_analysis": analysis,
        "history":         [f"Threat analysis complete: Score {analysis.get('risk_score')}"],
    }

def decision_node(state: AgentState) -> dict:
    print("[Node] Making Decision...")
    if state.get("pipeline_error"):
        return {
            "decision": {"decision": "MANUAL_REVIEW", "action": "Pipeline error — human review required"},
            "history":  ["[SKIP] Decision skipped due to upstream error"],
        }
    decision = _get_agent("commander").decide(state.get("threat_analysis", {}))
    return {
        "decision": decision,
        "history":  [f"Decision finalized: {decision.get('decision')}"],
    }

def response_node(state: AgentState) -> dict:
    print("[Node] Executing Response...")
    execution = _get_agent("muscle").execute(state.get("decision", {}))
    return {
        "execution_result": execution,
        "history":          [f"Response executed: {execution.get('action')}"],
    }

def manual_review_node(state: AgentState) -> dict:
    """Handles ESCALATE / MANUAL_REVIEW decisions — logs for human analyst."""
    print("[Node] Escalating for Manual Review...")
    decision = state.get("decision", {})
    return {
        "execution_result": {
            "status":   "PENDING_HUMAN_REVIEW",
            "action":   decision.get("action", "No action — human review required"),
            "decision": decision.get("decision"),
            "message":  "This decision requires human analyst review before action is taken.",
        },
        "history": ["[ESCALATE] Routed to human review queue"],
    }

def memory_guard_node(state: AgentState) -> dict:
    print("[Node] Securing Memory...")
    decision_label = state.get("decision", {}).get("decision", "UNKNOWN")
    risk_score     = state.get("threat_analysis", {}).get("risk_score", 0)
    raw_log        = state.get("raw_log", "")

    trace = (
        f"Log: {raw_log} | "
        f"Risk: {risk_score} | "
        f"Decision: {decision_label}"
    )
    guard = _get_agent("guard")
    store = _get_agent("store")
    validation = guard.validate_trace(trace)
    store.add_memory(validation)
    return {
        "memory_validation": validation,
        "history":           [f"Trace secured — trust tier: {validation['trust_tier']}"],
    }

def analytics_node(state: AgentState) -> dict:
    print("[Node] Generating Analytics...")
    store    = _get_agent("store")
    analyzer = _get_agent("analyzer")

    # Pull real historical data from the memory store
    memories = store.get_all_memories(limit=200)

    # Build risk trend data — mix store history + current event
    current_score = state.get("threat_analysis", {}).get("risk_score", 0)
    trend_data = [
        {"risk_score": m.get("risk_score", 0), "timestamp": datetime.now()}
        for m in memories
        if "risk_score" in m
    ]
    trend_data.append({"risk_score": current_score, "timestamp": datetime.now()})

    analyzer.generate_risk_trend(trend_data)

    decision_label = state.get("decision", {}).get("decision", "")
    analyzer.generate_agent_activity({
        "Ingestion":  1,
        "Threat":     1,
        "Decision":   1,
        "Response":   1 if decision_label not in ("LOG_ONLY", "MANUAL_REVIEW") else 0,
        "Escalation": 1 if decision_label in ("MANUAL_REVIEW", "ESCALATE") else 0,
    })

    if memories:
        analyzer.generate_memory_stats(memories)

    return {"history": ["Analytics graphs generated from real store data"]}

# 4. Conditional Routing

def should_respond(state: AgentState) -> str:
    decision_label = state.get("decision", {}).get("decision", "")

    if decision_label == "LOG_ONLY":
        return "secure_memory"
    if decision_label in ("MANUAL_REVIEW", "ESCALATE"):
        return "manual_review"
    if state.get("pipeline_error"):
        return "manual_review"
    return "execute_response"

# 5. Build the Graph
workflow = StateGraph(AgentState)

workflow.add_node("ingest",           ingestion_node)
workflow.add_node("analyze",          threat_analysis_node)
workflow.add_node("decide",           decision_node)
workflow.add_node("execute_response", response_node)
workflow.add_node("manual_review",    manual_review_node)
workflow.add_node("secure_memory",    memory_guard_node)
workflow.add_node("analytics",        analytics_node)

workflow.set_entry_point("ingest")
workflow.add_edge("ingest",   "analyze")
workflow.add_edge("analyze",  "decide")

workflow.add_conditional_edges(
    "decide",
    should_respond,
    {
        "execute_response": "execute_response",
        "manual_review":    "manual_review",
        "secure_memory":    "secure_memory",
    }
)

workflow.add_edge("execute_response", "secure_memory")
workflow.add_edge("manual_review",    "secure_memory")
workflow.add_edge("secure_memory",    "analytics")
workflow.add_edge("analytics",        END)

ares_app = workflow.compile()

def run_ares(log_text: str) -> dict:
    """Entry point to run the ARES-Mem orchestration pipeline."""
    initial_state: AgentState = {
        "raw_log": log_text,
        "history": [],
    }
    return ares_app.invoke(initial_state)

def main():
    test_log = "Suspicious login attempt from unknown IP 10.0.0.5"
    result = run_ares(test_log)
    print("\n--- Final Execution History ---")
    for event in result.get("history", []):
        print(f"  - {event}")

if __name__ == "__main__":
    main()
