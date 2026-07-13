"""
response_agent.py — The Muscle: Executes defensive actions for ARES-Mem.

ACIF v2 — extended to support all 8 decision types from the Adaptive Decision Maker:
  BLOCK_IP   | QUARANTINE | MONITOR | ALERT | LOG_ONLY | ESCALATE | DELAY | ROLLBACK

New action handlers:
  MONITOR  — activates enhanced monitoring mode (no blocking, increased log verbosity)
  DELAY    — defers action for a configurable number of minutes; adds to pending queue
  ROLLBACK — reverses a previously executed action; calls undo_callback if registered

Thread-safe: PENDING_DELAY queue is protected by threading.Lock().
"""

import logging
import threading
from datetime import datetime, timezone, timedelta
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("ResponseAgent")


class ResponseAgent:
    """
    The Muscle: Executes defensive actions via infrastructure APIs.

    Supported decisions (ACIF v2):
      BLOCK_IP   — hard block on source IP
      QUARANTINE — isolate host for investigation
      MONITOR    — enhanced monitoring (no block)
      ALERT      — send SOC notification
      LOG_ONLY   — log event, no further action
      ESCALATE   — route to human escalation agent
      DELAY      — defer action; schedule re-evaluation
      ROLLBACK   — reverse a previously executed action

    In the current implementation, actions are simulated (no live infrastructure
    API calls). To integrate with real systems, inject an infrastructure adapter
    into __init__ and replace the _simulate_* methods.
    """

    # ── Delay duration (minutes) for DELAY actions ────────────────────────────
    DEFAULT_DELAY_MINUTES = 5

    def __init__(self, undo_callback: Optional[Callable[[str, str], bool]] = None):
        """
        Args:
            undo_callback: Optional callable(action, source_ip) → bool.
                           Called on ROLLBACK to reverse a prior action.
                           If None, ROLLBACK logs a warning and returns ROLLBACK_REQUESTED.
        """
        self.action_history:    List[Dict[str, Any]] = []
        self._pending_queue:    List[Dict[str, Any]] = []
        self._lock              = threading.Lock()
        self._undo_callback     = undo_callback

    # ── Core execute() ───────────────────────────────────────────────────────

    def execute(self, decision_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a defensive action based on the CIE decision.

        Args:
            decision_data: Decision dict from CoordinationEngine (or legacy DecisionAgent).
                           Expected keys: decision, action, source_ip, priority, rationale.

        Returns:
            Execution result dict with status, action, message, and timestamp.
        """
        decision   = decision_data.get("decision", "UNKNOWN")
        action     = decision_data.get("action",   "NO_ACTION")
        source_ip  = decision_data.get("source_ip", "0.0.0.0")
        priority   = decision_data.get("priority",  "LOW")

        handler_map = {
            "BLOCK_IP":   self._execute_block_ip,
            "QUARANTINE": self._execute_quarantine,
            "MONITOR":    self._execute_monitor,
            "ALERT":      self._execute_alert,
            "LOG_ONLY":   self._execute_log_only,
            "ESCALATE":   self._execute_escalate,
            "DELAY":      self._execute_delay,
            "ROLLBACK":   self._execute_rollback,
        }

        handler = handler_map.get(decision, self._execute_unknown)
        result  = handler(decision_data)

        # Enrich with common fields
        result["decision"]  = decision
        result["action"]    = action
        result["source_ip"] = source_ip
        result["priority"]  = priority
        result["timestamp"] = datetime.now(timezone.utc).isoformat()

        with self._lock:
            self.action_history.append(result)

        logger.info(
            f"[ResponseAgent] {decision} on {source_ip} → status={result.get('status')}"
        )
        return result

    # ── Action Handlers ──────────────────────────────────────────────────────

    def _execute_block_ip(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Hard block: simulate adding source_ip to deny list."""
        source_ip = data.get("source_ip", "0.0.0.0")
        return {
            "status":  "SUCCESS",
            "message": f"IP {source_ip} added to deny list. All traffic blocked.",
        }

    def _execute_quarantine(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Quarantine: isolate host from network, preserve for forensics."""
        source_ip = data.get("source_ip", "0.0.0.0")
        return {
            "status":  "SUCCESS",
            "message": f"Host {source_ip} quarantined. Network access revoked pending investigation.",
        }

    def _execute_monitor(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enhanced monitoring: no blocking action, increase log verbosity and
        activate anomaly detection triggers on the source.
        """
        source_ip = data.get("source_ip", "0.0.0.0")
        return {
            "status":      "MONITORING",
            "message":     (
                f"Enhanced monitoring activated for {source_ip}. "
                f"Log verbosity increased. Anomaly detection triggered. "
                f"No blocking action taken — threat confidence below threshold."
            ),
            "monitor_active": True,
        }

    def _execute_alert(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Alert: notify SOC team via internal alerting channel."""
        source_ip   = data.get("source_ip", "0.0.0.0")
        threat_type = data.get("task_type", "UNKNOWN")
        return {
            "status":  "ALERT_SENT",
            "message": (
                f"SOC alert sent for {source_ip}. "
                f"Category: {threat_type}. Awaiting analyst acknowledgement."
            ),
        }

    def _execute_log_only(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Log only: record event, no active response."""
        source_ip = data.get("source_ip", "0.0.0.0")
        return {
            "status":  "LOGGED",
            "message": f"Event from {source_ip} logged. Threat belief below action threshold.",
        }

    def _execute_escalate(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Escalate: route to human escalation queue (HumanEscalationAgent)."""
        source_ip = data.get("source_ip", "0.0.0.0")
        rationale = data.get("rationale", "")
        return {
            "status":  "ESCALATED",
            "message": (
                f"Event from {source_ip} escalated to human analyst. "
                f"Reason: {rationale}"
            ),
        }

    def _execute_delay(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Defer action: add to pending queue with a scheduled re-evaluation time.
        The orchestrator's next pipeline cycle will re-process pending items.
        """
        source_ip    = data.get("source_ip", "0.0.0.0")
        delay_min    = self.DEFAULT_DELAY_MINUTES
        re_eval_time = (
            datetime.now(timezone.utc) + timedelta(minutes=delay_min)
        ).isoformat()

        pending_entry = {
            "source_ip":      source_ip,
            "decision_data":  data,
            "re_evaluate_at": re_eval_time,
            "queued_at":      datetime.now(timezone.utc).isoformat(),
        }
        with self._lock:
            self._pending_queue.append(pending_entry)

        return {
            "status":         "PENDING_DELAY",
            "message":        (
                f"Action on {source_ip} deferred for {delay_min} minutes. "
                f"Re-evaluation scheduled at {re_eval_time}."
            ),
            "re_evaluate_at": re_eval_time,
        }

    def _execute_rollback(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Reverse a previously executed action.
        Calls the registered undo_callback if available.
        """
        source_ip = data.get("source_ip", "0.0.0.0")
        last_action = data.get("action", "UNKNOWN")

        if self._undo_callback is not None:
            try:
                success = self._undo_callback(last_action, source_ip)
                status  = "ROLLBACK_SUCCESS" if success else "ROLLBACK_FAILED"
                msg     = (
                    f"Action '{last_action}' on {source_ip} "
                    f"{'successfully reversed' if success else 'could not be reversed'}."
                )
            except Exception as exc:
                status = "ROLLBACK_ERROR"
                msg    = f"Rollback error for {source_ip}: {exc}"
        else:
            # No live callback — log the rollback request for manual execution
            status = "ROLLBACK_REQUESTED"
            msg    = (
                f"Rollback of '{last_action}' on {source_ip} requested. "
                f"No automated undo_callback registered — manual intervention required."
            )
            logger.warning(f"[ResponseAgent] ROLLBACK requested but no undo_callback: {source_ip}")

        return {"status": status, "message": msg}

    def _execute_unknown(self, data: Dict[str, Any]) -> Dict[str, Any]:
        decision = data.get("decision", "UNKNOWN")
        return {
            "status":  "UNHANDLED",
            "message": f"Unknown decision type '{decision}'. No action taken.",
        }

    # ── Query API ─────────────────────────────────────────────────────────────

    def get_history(self) -> List[Dict[str, Any]]:
        """Return full action history (newest first)."""
        with self._lock:
            return list(reversed(self.action_history))

    def get_pending_delays(self) -> List[Dict[str, Any]]:
        """Return all events currently in the PENDING_DELAY queue."""
        with self._lock:
            return list(self._pending_queue)

    def flush_due_delays(self) -> List[Dict[str, Any]]:
        """
        Remove and return all DELAY entries whose re_evaluate_at time has passed.
        The orchestrator should call this periodically to re-process deferred events.
        """
        now = datetime.now(timezone.utc)
        due = []
        remaining = []
        with self._lock:
            for entry in self._pending_queue:
                try:
                    re_eval = datetime.fromisoformat(entry["re_evaluate_at"])
                    if re_eval.tzinfo is None:
                        re_eval = re_eval.replace(tzinfo=timezone.utc)
                    if now >= re_eval:
                        due.append(entry)
                    else:
                        remaining.append(entry)
                except Exception:
                    remaining.append(entry)
            self._pending_queue = remaining
        return due
