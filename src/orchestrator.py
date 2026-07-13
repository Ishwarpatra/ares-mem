"""
orchestrator.py — LangGraph Orchestrator for ARES-Mem (ACIF v2).

ACIF graph rewiring:
  ingest
    → analyze
      → memory_guard_pre      (validate incoming log BEFORE CIE decision)
        → cie                 (Coordination Intelligence Engine — replaces decide)
          → (conditional)
            ├─ execute_response   (BLOCK_IP / QUARANTINE / MONITOR / ALERT / LOG_ONLY / DELAY / ROLLBACK)
            ├─ manual_review      (ESCALATE — routed to HumanEscalationAgent)
            └─ memory_guard_post  (LOG_ONLY fast-path)
          → memory_guard_post (store final trace)
            → self_learning   (update trust weights if feedback is ready)
              → analytics

Agent lazy registry extended with:
  'cie'            → CoordinationEngine
  'self_learner'   → SelfLearningAgent
  'escalation'     → HumanEscalationAgent
"""

from typing import TypedDict, List, Dict, Any, Annotated, Optional
import operator
import json
import logging
from datetime import datetime

from langgraph.graph import StateGraph, END

from ingestion_agent import LogIngestionAgent
from threat_agent import ThreatAnalysisAgent
from response_agent import ResponseAgent
from memory_guard import MemoryGuard
from memory_store import MemoryStore
from analytics_agent import AnalyticsAgent
from coordination_engine import CoordinationEngine
from self_learning_agent import SelfLearningAgent
from human_escalation_agent import HumanEscalationAgent

logger = logging.getLogger("Orchestrator")


# ── 1. Shared State Schema ────────────────────────────────────────────────────

class AgentState(TypedDict, total=False):
    # Core pipeline fields (unchanged from v1)
    raw_log:            str
    structured_log:     Dict[str, Any]
    threat_analysis:    Dict[str, Any]
    decision:           Dict[str, Any]
    execution_result:   Dict[str, Any]
    memory_validation:  Dict[str, Any]     # post-decision MemoryGuard trace
    history:            Annotated[List[str], operator.add]
    pipeline_error:     Optional[str]

    # ACIF v2 — new fields (additive only; total=False so no breaking changes)
    memory_validation_pre: Dict[str, Any]  # pre-CIE MemoryGuard tag (CIE input)
    cie_output:            Dict[str, Any]  # full CoordinationEngine output
    escalation_ticket:     Dict[str, Any]  # HumanEscalationAgent ticket dict
    feedback_event:        Dict[str, Any]  # analyst feedback payload


# ── 2. Lazy Agent Registry ────────────────────────────────────────────────────

_agents: Dict[str, Any] = {}

def _get_agent(name: str):
    """Returns a cached agent instance, creating it on first call."""
    if name not in _agents:
        if name == "ingestor":
            _agents[name] = LogIngestionAgent()
        elif name == "threat_analyst":
            _agents[name] = ThreatAnalysisAgent()
        elif name == "muscle":
            _agents[name] = ResponseAgent()
        elif name == "guard":
            _agents[name] = MemoryGuard()
        elif name == "store":
            _agents[name] = MemoryStore()
        elif name == "analyzer":
            _agents[name] = AnalyticsAgent()
        elif name == "cie":
            _agents[name] = CoordinationEngine()
        elif name == "self_learner":
            cie   = _get_agent("cie")
            guard = _get_agent("guard")
            _agents[name] = SelfLearningAgent(
                coordination_engine=cie,
                memory_guard=guard,
            )
        elif name == "escalation":
            _agents[name] = HumanEscalationAgent()
        else:
            raise ValueError(f"Unknown agent: {name!r}")
    return _agents[name]


# ── 3. Node Functions ─────────────────────────────────────────────────────────

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


def memory_guard_pre_node(state: AgentState) -> dict:
    """
    ACIF v2 — Pre-CIE MemoryGuard pass.
    Validates the incoming log and makes the quarantine signal available
    as input to the Coordination Intelligence Engine.
    Does NOT store the trace — that is memory_guard_post_node's job.
    """
    print("[Node] MemoryGuard Pre-Validation...")
    if state.get("pipeline_error"):
        return {"history": ["[SKIP] MG pre-validation skipped due to upstream error"]}

    raw_log    = state.get("raw_log", "")
    risk_score = state.get("threat_analysis", {}).get("risk_score", 0)
    decision_label = state.get("decision", {}).get("decision", "")

    trace = (
        f"Log: {raw_log} | "
        f"Risk: {risk_score} | "
        f"Decision: {decision_label}"
    )
    guard = _get_agent("guard")
    tag   = guard.validate_and_tag(trace)
    return {
        "memory_validation_pre": tag,
        "history": [
            f"MG pre-validation: quarantine={tag['quarantine']} "
            f"tier={tag['trust_tier']} family={tag.get('matched_family', '')}"
        ],
    }


def cie_node(state: AgentState) -> dict:
    """
    ACIF v2 — Coordination Intelligence Engine node.
    Replaces the legacy decision_node. Takes threat_analysis + memory_validation_pre
    + structured_log as inputs; outputs a full CIEOutput.
    """
    print("[Node] Coordination Intelligence Engine...")
    if state.get("pipeline_error"):
        return {
            "decision": {"decision": "MANUAL_REVIEW", "action": "Pipeline error — human review required"},
            "history":  ["[SKIP] CIE skipped due to upstream error"],
        }

    cie = _get_agent("cie")
    cie_output = cie.run(
        threat_analysis=state.get("threat_analysis", {}),
        memory_validation=state.get("memory_validation_pre", {}),
        structured_log=state.get("structured_log", {}),
    )

    decision = cie_output["decision"]
    conflict  = cie_output["conflict_report"]
    fusion    = cie_output["fusion_result"]

    return {
        "decision":   decision,
        "cie_output": cie_output,
        "history": [
            f"CIE decision: {decision.get('decision')} | "
            f"priority={decision.get('priority')} | "
            f"conflict={conflict.get('conflict_detected')} | "
            f"threat_belief={fusion.get('threat_belief'):.3f} | "
            f"event_id={cie_output.get('event_id')}"
        ],
    }


def response_node(state: AgentState) -> dict:
    print("[Node] Executing Response...")
    execution = _get_agent("muscle").execute(state.get("decision", {}))
    return {
        "execution_result": execution,
        "history":          [f"Response executed: {execution.get('action')} → {execution.get('status')}"],
    }


def manual_review_node(state: AgentState) -> dict:
    """
    ACIF v2 — Routes escalations through HumanEscalationAgent.
    Creates a structured ticket and fires async SIEM notification.
    """
    print("[Node] HumanEscalationAgent — Creating Ticket...")
    cie_output      = state.get("cie_output", {})
    threat_analysis = state.get("threat_analysis", {})
    structured_log  = state.get("structured_log", {})
    decision        = state.get("decision", {})
    conflict        = cie_output.get("conflict_report", {})

    source_ip  = decision.get("source_ip", structured_log.get("source_ip", "0.0.0.0"))
    event_id   = cie_output.get("event_id", "unknown")

    escalation = _get_agent("escalation")
    ticket = escalation.create_ticket(
        event_id=event_id,
        source_ip=source_ip,
        threat_analysis=threat_analysis,
        cie_output=cie_output,
        structured_log=structured_log,
        decision=decision.get("decision", "ESCALATE"),
        conflict_detected=conflict.get("conflict_detected", False),
    )
    escalation.notify_analyst(ticket)

    # Store ticket in the escalations collection
    store = _get_agent("store")
    try:
        if hasattr(store, "escalations"):
            store.escalations.add(
                documents=[json.dumps(ticket)],
                metadatas=[{
                    "ticket_id":  ticket["ticket_id"],
                    "status":     ticket["status"],
                    "source_ip":  ticket["source_ip"],
                    "risk_score": ticket["risk_score"],
                    "created_at": ticket["created_at"],
                }],
                ids=[ticket["ticket_id"]],
            )
    except Exception as exc:
        logger.warning(f"[Orchestrator] Escalation ticket store failed (non-critical): {exc}")

    return {
        "escalation_ticket": ticket,
        "execution_result": {
            "status":   "PENDING_HUMAN_REVIEW",
            "action":   decision.get("action", "Escalated — human review required"),
            "decision": decision.get("decision"),
            "ticket_id": event_id,
            "message":  "Escalation ticket created. Analyst notified via SIEM webhook.",
        },
        "history": [f"[ESCALATE] Ticket {event_id} created — SIEM notified"],
    }


def memory_guard_post_node(state: AgentState) -> dict:
    """
    ACIF v2 — Post-decision MemoryGuard pass.
    Stores the final execution trace (with decision label) in the memory store.
    """
    print("[Node] Securing Memory (Post-Decision)...")
    decision_label = state.get("decision", {}).get("decision", "UNKNOWN")
    risk_score     = state.get("threat_analysis", {}).get("risk_score", 0)
    raw_log        = state.get("raw_log", "")

    trace = (
        f"Log: {raw_log} | "
        f"Risk: {risk_score} | "
        f"Decision: {decision_label}"
    )
    guard      = _get_agent("guard")
    store      = _get_agent("store")
    validation = guard.validate_trace(trace)
    store.add_memory(validation)
    return {
        "memory_validation": validation,
        "history":           [f"Trace stored — trust tier: {validation['trust_tier']}"],
    }


def self_learning_node(state: AgentState) -> dict:
    """
    ACIF v2 — Self-Learning node.
    If a feedback_event is present in state (injected by /feedback endpoint),
    process it through the SelfLearningAgent to update trust weights.
    Normally this node is a no-op unless feedback has been queued.
    """
    print("[Node] Self-Learning Check...")
    feedback = state.get("feedback_event")
    if not feedback:
        return {"history": ["[Self-Learning] No feedback event queued — skipping"]}

    learner = _get_agent("self_learner")
    try:
        result = learner.record_feedback(
            event_id=feedback.get("event_id", ""),
            decision_made=feedback.get("decision_made", ""),
            analyst_verdict=feedback.get("analyst_verdict", ""),
            trace_id=feedback.get("trace_id"),
            analyst_note=feedback.get("analyst_note"),
        )
        return {
            "history": [
                f"[Self-Learning] Feedback processed: "
                f"{result.get('analyst_verdict')} | "
                f"ThreatAgent→{result.get('threat_outcome')} | "
                f"MG→{result.get('mg_outcome')}"
            ]
        }
    except Exception as exc:
        logger.warning(f"[Self-Learning] Feedback processing failed: {exc}")
        return {"history": [f"[Self-Learning] Feedback error: {exc}"]}


def analytics_node(state: AgentState) -> dict:
    print("[Node] Generating Analytics...")
    store    = _get_agent("store")
    analyzer = _get_agent("analyzer")

    memories = store.get_all_memories(limit=200)

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
        "Ingestion":    1,
        "Threat":       1,
        "MG Pre":       1,
        "CIE":          1,
        "Response":     1 if decision_label not in ("LOG_ONLY", "MANUAL_REVIEW", "ESCALATE") else 0,
        "Escalation":   1 if decision_label in ("MANUAL_REVIEW", "ESCALATE") else 0,
        "Self-Learning": 1 if state.get("feedback_event") else 0,
    })

    if memories:
        analyzer.generate_memory_stats(memories)

    return {"history": ["Analytics generated from real store data"]}


# ── 4. Conditional Routing ────────────────────────────────────────────────────

def should_respond(state: AgentState) -> str:
    """Route after CIE decision to the appropriate action node."""
    decision_label = state.get("decision", {}).get("decision", "")

    if decision_label == "LOG_ONLY":
        return "memory_guard_post"
    if decision_label in ("MANUAL_REVIEW", "ESCALATE") or state.get("pipeline_error"):
        return "manual_review"
    # All active responses (BLOCK_IP, QUARANTINE, MONITOR, ALERT, DELAY, ROLLBACK)
    return "execute_response"


# ── 5. Build the Graph ────────────────────────────────────────────────────────

workflow = StateGraph(AgentState)

# Register all nodes
workflow.add_node("ingest",            ingestion_node)
workflow.add_node("analyze",           threat_analysis_node)
workflow.add_node("memory_guard_pre",  memory_guard_pre_node)
workflow.add_node("cie",               cie_node)
workflow.add_node("execute_response",  response_node)
workflow.add_node("manual_review",     manual_review_node)
workflow.add_node("memory_guard_post", memory_guard_post_node)
workflow.add_node("self_learning",     self_learning_node)
workflow.add_node("analytics",         analytics_node)

# Linear backbone
workflow.set_entry_point("ingest")
workflow.add_edge("ingest",           "analyze")
workflow.add_edge("analyze",          "memory_guard_pre")
workflow.add_edge("memory_guard_pre", "cie")

# Conditional branching after CIE
workflow.add_conditional_edges(
    "cie",
    should_respond,
    {
        "execute_response": "execute_response",
        "manual_review":    "manual_review",
        "memory_guard_post": "memory_guard_post",
    },
)

# Converge back to memory_guard_post
workflow.add_edge("execute_response", "memory_guard_post")
workflow.add_edge("manual_review",    "memory_guard_post")

# Post-decision linear tail
workflow.add_edge("memory_guard_post", "self_learning")
workflow.add_edge("self_learning",     "analytics")
workflow.add_edge("analytics",         END)

ares_app = workflow.compile()


# ── 6. Public Entry Points ────────────────────────────────────────────────────

def run_ares(log_text: str, feedback_event: Optional[Dict[str, Any]] = None) -> dict:
    """
    Entry point to run the ARES-Mem ACIF orchestration pipeline.

    Args:
        log_text:       Raw log string to process.
        feedback_event: Optional analyst feedback dict to inject into the
                        self_learning_node during this pipeline run.
    """
    initial_state: AgentState = {
        "raw_log": log_text,
        "history": [],
    }
    if feedback_event:
        initial_state["feedback_event"] = feedback_event  # type: ignore[assignment]
    return ares_app.invoke(initial_state)


def main():
    test_log = "Suspicious login attempt from unknown IP 10.0.0.5"
    result = run_ares(test_log)
    print("\n--- Final Execution History ---")
    for event in result.get("history", []):
        print(f"  - {event}")
    if "cie_output" in result:
        cie = result["cie_output"]
        print(f"\n--- CIE Summary ---")
        print(f"  Decision:     {cie.get('decision', {}).get('decision')}")
        print(f"  Conflict:     {cie.get('conflict_report', {}).get('conflict_detected')}")
        print(f"  Fusion:       threat_belief={cie.get('fusion_result', {}).get('threat_belief')}")
        print(f"  Trust Weights:{cie.get('trust_weights')}")


if __name__ == "__main__":
    main()
