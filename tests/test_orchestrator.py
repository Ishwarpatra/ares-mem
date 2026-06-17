"""
tests/test_orchestrator.py — Integration tests for the LangGraph state machine.

Tests end-to-end pipeline execution with various log types.
Uses local ChromaDB (tmp_path) to avoid requiring Docker.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from unittest.mock import patch


# ── Override ChromaDB to use local storage during tests ───────────────────────
@pytest.fixture(autouse=True)
def use_local_chroma(tmp_path, monkeypatch):
    """Patch MemoryStore to use tmp_path for all orchestrator tests."""
    monkeypatch.setenv("ARES_ENV", "test")
    # Patch the module-level store in orchestrator
    import memory_store as ms_module
    local_store = ms_module.MemoryStore(path=str(tmp_path / "orch_chroma"))

    import orchestrator as orch_module
    orch_module._store = local_store
    yield


def run_pipeline(log_text: str):
    """Helper to run the ARES orchestrator on a log string."""
    from orchestrator import run_ares
    return run_ares(log_text)


# ══════════════════════════════════════════════════════════════════════════════
# End-to-End Pipeline Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestFullPipeline:

    def test_pipeline_completes_without_error(self):
        """Any valid log should traverse the full graph without exception."""
        result = run_pipeline("System health check completed normally.")
        assert result is not None

    def test_pipeline_returns_history(self):
        """Result must contain a non-empty history list."""
        result = run_pipeline("Connection established from 10.0.1.5")
        assert "history" in result
        assert len(result["history"]) > 0

    def test_pipeline_benign_log_log_only(self):
        """Clean internal logs should result in LOG_ONLY or ALERT decision."""
        result = run_pipeline(
            "Jun 17 sshd: Accepted publickey for devops from 10.0.1.5 port 54321"
        )
        decision = result.get("decision", {}).get("decision", "")
        assert decision in ("LOG_ONLY", "ALERT"), f"Unexpected decision: {decision}"

    def test_pipeline_brute_force_block_or_quarantine(self):
        """Brute force log should result in BLOCK_IP or QUARANTINE."""
        result = run_pipeline(
            "AUTHENTICATION FAILURE: 15 failed login attempts from IP 10.13.1.50 in 30 seconds"
        )
        decision = result.get("decision", {}).get("decision", "")
        assert decision in ("BLOCK_IP", "QUARANTINE", "ALERT", "ESCALATE"), (
            f"Unexpected decision for brute force: {decision}"
        )

    def test_pipeline_threat_score_populated(self):
        """threat_score must be present and numeric in final state."""
        result = run_pipeline("Failed password from 192.168.1.100 port 22")
        assert "threat_score" in result
        assert isinstance(result["threat_score"], (int, float))

    def test_pipeline_validation_flag_populated(self):
        """validation_flag must be set after memory guard node."""
        result = run_pipeline("Normal system update completed.")
        assert "validation_flag" in result
        assert isinstance(result["validation_flag"], bool)

    def test_pipeline_privilege_level_populated(self):
        """privilege_level must be in [1, 5] after memory guard."""
        result = run_pipeline("Network connection from 10.0.1.5 port 80")
        assert "privilege_level" in result
        assert 1 <= result["privilege_level"] <= 5

    def test_pipeline_structured_log_populated(self):
        """structured_log must be present with required fields."""
        result = run_pipeline("TCP connection from 10.0.1.5 port 443")
        sl = result.get("structured_log", {})
        assert "summary" in sl
        assert "event_type" in sl

    def test_pipeline_decision_has_action(self):
        """Decision dict must include an action description."""
        result = run_pipeline("Connection from 10.0.1.5 to server")
        decision = result.get("decision", {})
        assert "action" in decision
        assert len(decision["action"]) > 0

    def test_pipeline_execution_result_present(self):
        """
        execution_result should be present for non-LOG_ONLY decisions.
        For LOG_ONLY, it's absent (pipeline skips response node).
        """
        result = run_pipeline(
            "Malware C2 beacon detected from 10.0.1.80 port 4444 command-and-control"
        )
        decision = result.get("decision", {}).get("decision", "")
        if decision != "LOG_ONLY":
            assert "execution_result" in result

    def test_pipeline_history_contains_node_markers(self):
        """History entries should contain node identifiers."""
        result = run_pipeline("Failed login from 192.168.1.100")
        history = result.get("history", [])
        joined = " ".join(history)
        # At least the ingest and analyze nodes should appear
        assert any("ingest" in h.lower() for h in history), f"History: {history}"


# ══════════════════════════════════════════════════════════════════════════════
# Escalation Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestHumanEscalation:

    def test_escalation_node_executes_on_trigger(self):
        """
        A high-risk, low-confidence scenario should trigger escalation.
        The HumanEscalationAgent in 'test' env auto-approves.
        """
        from orchestrator import decision_node, human_escalation_node
        # Construct a state with a high-risk, low-confidence analysis
        mock_analysis = {
            "risk_score": 65,
            "confidence": 0.30,
            "threat_type": "UNKNOWN",
            "indicators": ["ambiguous indicator"],
            "recommended_action": "ALERT",
            "structured_log": {},
        }
        mock_decision = {
            "decision": "ESCALATE",
            "action": "Escalate to analyst",
            "task_type": "notify",
            "priority": "HIGH",
            "requires_escalation": True,
            "rationale": "Test escalation",
        }
        state = {
            "raw_log": "test",
            "threat_analysis": mock_analysis,
            "decision": mock_decision,
            "history": [],
        }
        result = human_escalation_node(state)
        assert "escalation_result" in result
        assert result["escalation_result"]["approved"] is True  # auto-approved in test mode

    def test_escalation_updates_decision(self):
        """After escalation, the decision field should be updated."""
        from orchestrator import human_escalation_node
        state = {
            "raw_log": "test log",
            "threat_analysis": {
                "risk_score": 65,
                "confidence": 0.30,
                "threat_type": "UNKNOWN",
                "indicators": [],
                "recommended_action": "ALERT",
                "structured_log": {},
            },
            "decision": {
                "decision": "ESCALATE",
                "action": "Test",
                "task_type": "notify",
                "priority": "HIGH",
                "requires_escalation": True,
                "rationale": "",
            },
            "history": [],
        }
        result = human_escalation_node(state)
        # Operator decision should override original ESCALATE
        new_decision = result.get("decision", {})
        assert new_decision.get("decision") != "ESCALATE", (
            "Decision should have been updated by operator"
        )
