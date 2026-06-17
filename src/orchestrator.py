"""
orchestrator.py — ARES-Mem LangGraph State Machine (Phase 4 — Full Implementation).

Defines the complete StateGraph with:
  - 6 nodes: ingest → analyze → decide → [escalate?] → execute_response → secure_memory
  - Conditional edges for human escalation and LOG_ONLY bypass
  - Full state payload: raw_log, structured_log, threat_analysis, decision,
    execution_result, memory_validation, validation_flag, threat_score,
    privilege_level, escalation_result, history

Architecture layers:
  Layer 1 (Parallel-capable): ingest, analyze, secure_memory
  Layer 2 (Sequential):       decide → execute_response
  Layer 3 (On-Demand):        human_escalation
"""
import os
import operator
from typing import TypedDict, List, Dict, Any, Optional, Annotated

from langgraph.graph import StateGraph, END
from dotenv import load_dotenv

# ── Agent Imports ─────────────────────────────────────────────────────────────
from log_ingestion_agent import LogIngestionAgent
from threat_analysis_agent import ThreatAnalysisAgent
from decision_agents import DecisionAgent, ResponseAgent
from human_escalation_agent import HumanEscalationAgent
from memory_guard import MemoryGuard
from memory_store import MemoryStore

load_dotenv()


# ══════════════════════════════════════════════════════════════════════════════
# 1. Shared State Schema
# ══════════════════════════════════════════════════════════════════════════════

class AgentState(TypedDict, total=False):
    """
    The canonical state payload passed between LangGraph nodes.

    All fields are optional (total=False) so nodes only need to return
    the fields they update — LangGraph merges the rest.
    """
    # ── Input ──────────────────────────────────────────────────────────────
    raw_log: str                            # Raw log string from data pipeline

    # ── Layer 1 outputs ────────────────────────────────────────────────────
    structured_log: Dict[str, Any]          # Parsed log from LogIngestionAgent
    threat_analysis: Dict[str, Any]         # Risk score & classification

    # ── Core state scalars (exposed per architecture spec) ────────────────
    threat_score: int                       # Extracted from threat_analysis.risk_score
    validation_flag: bool                   # True if memory guard quarantined the trace
    privilege_level: int                    # 1–5 privilege from MemoryGuard
    origin_trust_tier: float                # Continuous view of privilege level (0.0-1.0)

    # ── Layer 2 outputs ────────────────────────────────────────────────────
    decision: Dict[str, Any]                # Governed decision from DecisionAgent
    execution_result: Dict[str, Any]        # Action result from ResponseAgent

    # ── Layer 3 output (on-demand) ─────────────────────────────────────────
    escalation_result: Dict[str, Any]       # Human escalation outcome

    # ── Memory Layer ───────────────────────────────────────────────────────
    memory_validation: Dict[str, Any]       # Validated trace from MemoryGuard

    # ── Audit trail (append-only via operator.add) ─────────────────────────
    history: Annotated[List[str], operator.add]


# ── Continuous Trust Tier Mapping ─────────────────────────────────────────────
PRIVILEGE_TO_TRUST_TIER: Dict[int, float] = {
    5: 1.0,  # SYSTEM
    4: 0.8,  # HIGH
    3: 0.5,  # MEDIUM
    2: 0.3,  # LOW
    1: 0.1,  # UNTRUSTED
}

def derive_origin_trust_tier(privilege_level: int) -> float:
    """Deterministic float-tier view of the categorical PrivilegeLevel."""
    return PRIVILEGE_TO_TRUST_TIER.get(privilege_level, 0.1)


# ══════════════════════════════════════════════════════════════════════════════
# 2. Agent / Service Initialization
# ══════════════════════════════════════════════════════════════════════════════

_ingestor    = LogIngestionAgent()
_analyst     = ThreatAnalysisAgent()
_commander   = DecisionAgent()
_muscle      = ResponseAgent()
_overseer    = HumanEscalationAgent()
_guard       = MemoryGuard()
_store       = MemoryStore()


# ══════════════════════════════════════════════════════════════════════════════
# 3. Node Functions
# ══════════════════════════════════════════════════════════════════════════════

def ingestion_node(state: AgentState) -> Dict[str, Any]:
    """Layer 1: Parse raw log into StructuredLog."""
    print("[Node: ingest] Ingesting log...")
    structured = _ingestor.ingest_log(state["raw_log"])
    return {
        "structured_log": structured,
        "history": [f"[ingest] Structured log: event_type={structured.get('event_type')}, severity={structured.get('severity')}"]
    }


def memory_guard_validation_node(state: AgentState) -> Dict[str, Any]:
    """Layer 1: Validate incoming log trust tier and check for injections."""
    print("[Node: memory_guard_val] Validating raw log...")
    validated = _guard.validate_and_tag(
        state["raw_log"],
        source="external",
        provenance_hops=1
    )
    quarantine_flag = validated.get("quarantine", False)
    priv_level = validated.get("privilege_level", 3)
    trust_tier = derive_origin_trust_tier(priv_level)
    return {
        "validation_flag": quarantine_flag,
        "privilege_level": priv_level,
        "origin_trust_tier": trust_tier,
        "history": [
            f"[memory_guard_val] quarantined={quarantine_flag}, "
            f"privilege={validated.get('privilege_label')}, trust_tier={trust_tier:.1f}"
        ]
    }


def threat_analysis_node(state: AgentState) -> Dict[str, Any]:
    """Layer 1: Score threat and classify."""
    print("[Node: analyze] Analyzing threats...")
    analysis = _analyst.analyze(state["structured_log"])
    risk_score = analysis.get("risk_score", 0)
    return {
        "threat_analysis": analysis,
        "threat_score":    risk_score,
        "history": [
            f"[analyze] threat_type={analysis.get('threat_type')}, "
            f"risk_score={risk_score}, confidence={analysis.get('confidence'):.3f}"
        ]
    }


def decision_node(state: AgentState) -> Dict[str, Any]:
    """Layer 2: Evaluate threat against policy matrix."""
    print("[Node: decide] Making decision...")
    
    # CRITICAL GATE: if the Memory Guard quarantined this log (validation_flag is True),
    # force a safe fallback action (LOG_ONLY/no_action) to prevent acting on poisoned content.
    if state.get("validation_flag") is True:
        decision = {
            "decision": "LOG_ONLY",
            "action": "no_action",
            "task_type": "log_analysis",
            "priority": "LOW",
            "requires_escalation": False,
            "rationale": "Memory Guard quarantined this log. Threat assessment bypassed. Safe fallback applied.",
        }
        return {
            "decision": decision,
            "history": [
                "[decide] Memory Guard quarantined this log. Safe fallback applied: LOG_ONLY/no_action."
            ]
        }

    decision = _commander.decide(state["threat_analysis"])
    return {
        "decision": decision,
        "history":  [f"[decide] decision={decision.get('decision')}, priority={decision.get('priority')}"]
    }


def human_escalation_node(state: AgentState) -> Dict[str, Any]:
    """Layer 3 (On-Demand): Request human analyst review."""
    print("[Node: escalate] Requesting human oversight...")
    result = _overseer.review(
        decision=state["decision"],
        threat_context=state["threat_analysis"],
    )
    ticket = result.get("escalation_ticket", {})
    # Override decision with operator's ruling
    overridden_decision = {**state["decision"], "decision": result.get("operator_decision", "ALERT")}
    return {
        "escalation_result": result,
        "decision":          overridden_decision,
        "history": [
            f"[escalate] ticket={ticket.get('ticket_id')}, "
            f"approved={result.get('approved')}, "
            f"operator_decision={result.get('operator_decision')}"
        ]
    }


def response_node(state: AgentState) -> Dict[str, Any]:
    """Layer 2: Execute the governed decision."""
    print("[Node: execute_response] Executing response...")
    execution = _muscle.execute(state["decision"])
    return {
        "execution_result": execution,
        "history": [
            f"[execute] action={execution.get('action')}, "
            f"status={execution.get('status')}, "
            f"latency={execution.get('latency_ms')}ms"
        ]
    }


def memory_guard_node(state: AgentState) -> Dict[str, Any]:
    """Secure the full execution trace in validated memory."""
    print("[Node: secure_memory] Securing execution trace...")

    # Build a rich trace combining the full execution context
    risk = state.get("threat_score", 0)
    dec = state.get("decision", {}).get("decision", "UNKNOWN")
    threat = state.get("threat_analysis", {}).get("threat_type", "UNKNOWN")

    trace = (
        f"ARES-Mem Execution Trace | "
        f"Log: {state.get('raw_log', '')[:80]} | "
        f"ThreatType: {threat} | "
        f"RiskScore: {risk} | "
        f"Decision: {dec}"
    )

    # Determine provenance: internal agent trace
    source = "internal"
    hops = 1

    validated = _guard.validate_and_tag(trace, source=source, provenance_hops=hops)
    doc_id, collection = _store.add_memory_with_quarantine(validated)

    quarantine_flag = validated.get("quarantine", False)
    priv_level = validated.get("privilege_level", 3)

    return {
        "memory_validation": validated,
        "validation_flag":   quarantine_flag,
        "privilege_level":   priv_level,
        "history": [
            f"[secure_memory] collection={collection}, "
            f"privilege={validated.get('privilege_label')}, "
            f"quarantined={quarantine_flag}, "
            f"doc_id={doc_id}"
        ]
    }


# ══════════════════════════════════════════════════════════════════════════════
# 4. Conditional Routing Functions
# ══════════════════════════════════════════════════════════════════════════════

def route_after_decision(state: AgentState) -> str:
    """
    Routes from 'decide' based on decision type:
    - ESCALATE  → human_escalation (Layer 3)
    - LOG_ONLY  → secure_memory (skip response)
    - else      → execute_response (Layer 2)
    """
    decision_val = state.get("decision", {}).get("decision", "LOG_ONLY")
    if decision_val == "ESCALATE":
        return "human_escalation"
    if decision_val == "LOG_ONLY":
        return "secure_memory"
    return "execute_response"


def route_after_escalation(state: AgentState) -> str:
    """
    Routes from 'human_escalation':
    - If approved and operator_decision is not LOG_ONLY → execute_response
    - Otherwise → secure_memory
    """
    result = state.get("escalation_result", {})
    op_decision = result.get("operator_decision", "ALERT")
    if op_decision not in ("LOG_ONLY", "ESCALATE"):
        return "execute_response"
    return "secure_memory"


# ══════════════════════════════════════════════════════════════════════════════
# 5. Build the State Graph
# ══════════════════════════════════════════════════════════════════════════════

def build_graph() -> StateGraph:
    """Constructs and returns the compiled ARES-Mem LangGraph workflow."""
    workflow = StateGraph(AgentState)

    # ── Register Nodes ──────────────────────────────────────────────────────
    workflow.add_node("ingest",            ingestion_node)
    workflow.add_node("memory_guard_val",  memory_guard_validation_node)
    workflow.add_node("analyze",           threat_analysis_node)
    workflow.add_node("decide",            decision_node)
    workflow.add_node("human_escalation",  human_escalation_node)
    workflow.add_node("execute_response",  response_node)
    workflow.add_node("secure_memory",     memory_guard_node)

    # ── Define Edges ────────────────────────────────────────────────────────
    workflow.set_entry_point("ingest")
    
    # Fan-out from ingest to memory_guard_val and analyze
    workflow.add_edge("ingest", "memory_guard_val")
    workflow.add_edge("ingest", "analyze")
    
    # Fan-in to decide from both memory_guard_val and analyze
    workflow.add_edge("memory_guard_val", "decide")
    workflow.add_edge("analyze", "decide")

    # Conditional: decide → escalate | execute | skip-to-memory
    workflow.add_conditional_edges(
        "decide",
        route_after_decision,
        {
            "human_escalation": "human_escalation",
            "execute_response": "execute_response",
            "secure_memory":    "secure_memory",
        }
    )

    # Conditional: escalation → execute | skip-to-memory
    workflow.add_conditional_edges(
        "human_escalation",
        route_after_escalation,
        {
            "execute_response": "execute_response",
            "secure_memory":    "secure_memory",
        }
    )

    # Sequential pipeline tail
    workflow.add_edge("execute_response", "secure_memory")
    workflow.add_edge("secure_memory",    END)

    return workflow.compile()


# ── Singleton compiled graph ─────────────────────────────────────────────────
ares_app = build_graph()


# ══════════════════════════════════════════════════════════════════════════════
# 6. Public Entry Point
# ══════════════════════════════════════════════════════════════════════════════

def run_ares(log_text: str) -> Dict[str, Any]:
    """
    Entry point to run the ARES-Mem orchestration pipeline.

    Args:
        log_text: Raw log string to process.

    Returns:
        Final AgentState dict after all nodes have executed.
    """
    initial_state: AgentState = {
        "raw_log": log_text,
        "history": [],
    }
    return ares_app.invoke(initial_state)


def main():
    """Smoke test using a single synthetic log."""
    test_log = "Authentication failure: 20 failed login attempts from IP 192.168.1.100 port 22 in 10 seconds"
    print(f"\n{'='*60}")
    print("ARES-Mem Orchestrator — Single Log Test")
    print(f"{'='*60}")
    print(f"Input: {test_log}\n")

    result = run_ares(test_log)

    print(f"\n{'='*60}")
    print("Execution History:")
    print(f"{'='*60}")
    for event in result.get("history", []):
        print(f"  {event}")

    print(f"\nFinal threat_score : {result.get('threat_score')}")
    print(f"Final decision     : {result.get('decision', {}).get('decision')}")
    print(f"Validation flag    : {result.get('validation_flag')}")
    print(f"Privilege level    : {result.get('privilege_level')}")


if __name__ == "__main__":
    main()
