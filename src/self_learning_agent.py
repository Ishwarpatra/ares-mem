"""
self_learning_agent.py — Self-Learning & Feedback Integration for ARES-Mem.

Implements the 'Self-Learning & Feedback Integration' module from the ACIF diagram:
  - Receives post-action feedback from human analysts via the /feedback endpoint
  - Translates analyst labels to TP/TN/FP/FN outcomes per agent
  - Updates CoordinationEngine Beta trust priors for the involved agents
  - Triggers MemoryGuard repair on reversal events (false positive recovery)
  - Persists all feedback events to src/data/feedback_log.json for audit trail

Thread-safe: all state mutations are guarded by a threading.Lock().
"""

import json
import logging
import os
import threading
from datetime import datetime
from typing import Any, Dict, Optional

logger = logging.getLogger("SelfLearningAgent")

# ── Feedback log persistence path ─────────────────────────────────────────────
_FEEDBACK_LOG_PATH = os.path.join(
    os.path.dirname(__file__), "data", "feedback_log.json"
)

# ── Outcome constants ─────────────────────────────────────────────────────────
OUTCOME_TP = "TP"   # True Positive:  correct threat detection
OUTCOME_TN = "TN"   # True Negative:  correct benign classification
OUTCOME_FP = "FP"   # False Positive: quarantined a benign event
OUTCOME_FN = "FN"   # False Negative: missed a real threat

# ── Valid analyst verdict labels ──────────────────────────────────────────────
VERDICT_CONFIRMED  = "CONFIRMED_THREAT"     # analyst confirms this was a real threat
VERDICT_FALSE_POS  = "FALSE_POSITIVE"       # analyst reverses — benign event quarantined
VERDICT_MISSED     = "MISSED_THREAT"        # analyst flags a missed detection
VERDICT_BENIGN     = "CONFIRMED_BENIGN"     # analyst confirms benign classification correct

# Map (decision_was_action, analyst_verdict) → per-agent outcome
# Simplified heuristic: treat ThreatAnalysisAgent and MemoryGuard as the
# primary sensing agents whose trust should be updated.
_VERDICT_TO_THREAT_OUTCOME: Dict[str, str] = {
    VERDICT_CONFIRMED: OUTCOME_TP,   # Threat agent detected correctly
    VERDICT_FALSE_POS: OUTCOME_FP,   # Threat agent over-triggered
    VERDICT_MISSED:    OUTCOME_FN,   # Threat agent missed the threat
    VERDICT_BENIGN:    OUTCOME_TN,   # Correct benign — both agents correct
}
_VERDICT_TO_MG_OUTCOME: Dict[str, str] = {
    VERDICT_CONFIRMED: OUTCOME_TP,
    VERDICT_FALSE_POS: OUTCOME_FP,   # MemoryGuard quarantined incorrectly
    VERDICT_MISSED:    OUTCOME_FN,   # MemoryGuard failed to quarantine
    VERDICT_BENIGN:    OUTCOME_TN,
}
# Trust success/failure mapping per outcome
_OUTCOME_IS_SUCCESS: Dict[str, bool] = {
    OUTCOME_TP: True,
    OUTCOME_TN: True,
    OUTCOME_FP: False,
    OUTCOME_FN: False,
}


class SelfLearningAgent:
    """
    Self-Learning & Feedback Integration Agent.

    Typical flow:
      1. POST /feedback → record_feedback(event_id, decision, analyst_verdict)
      2. Agent maps verdict to TP/FP/FN/TN per agent
      3. Updates CoordinationEngine trust weights (Bayesian Beta update)
      4. On FALSE_POSITIVE reversals: calls MemoryGuard.repair_trace()
      5. Appends event to feedback_log.json
    """

    def __init__(self, coordination_engine=None, memory_guard=None):
        """
        Args:
            coordination_engine: CoordinationEngine instance (injected by orchestrator)
            memory_guard:        MemoryGuard instance (injected by orchestrator)
        """
        self._cie  = coordination_engine
        self._mg   = memory_guard
        self._lock = threading.Lock()
        self._log: list = []
        self._load_log()

    # ── Persistence ──────────────────────────────────────────────────────────

    def _load_log(self) -> None:
        """Load existing feedback log from disk."""
        if os.path.exists(_FEEDBACK_LOG_PATH):
            try:
                with open(_FEEDBACK_LOG_PATH, "r", encoding="utf-8") as f:
                    self._log = json.load(f)
                logger.info(f"[SelfLearning] Loaded {len(self._log)} feedback events")
            except Exception as exc:
                logger.warning(f"[SelfLearning] Could not load feedback log: {exc}")
                self._log = []
        else:
            self._log = []

    def _save_log(self) -> None:
        """Persist feedback log to disk (called within lock)."""
        os.makedirs(os.path.dirname(_FEEDBACK_LOG_PATH), exist_ok=True)
        with open(_FEEDBACK_LOG_PATH, "w", encoding="utf-8") as f:
            json.dump(self._log, f, indent=2)

    # ── Core API ─────────────────────────────────────────────────────────────

    def record_feedback(
        self,
        event_id: str,
        decision_made: str,
        analyst_verdict: str,
        trace_id: Optional[str] = None,
        analyst_note: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Process analyst feedback for a CIE decision event.

        Args:
            event_id:        UUID from CIEOutput.event_id
            decision_made:   The decision label that was executed (e.g. QUARANTINE)
            analyst_verdict: One of CONFIRMED_THREAT, FALSE_POSITIVE,
                             MISSED_THREAT, CONFIRMED_BENIGN
            trace_id:        Optional ChromaDB trace ID for MemoryGuard repair
            analyst_note:    Free-text note from analyst (stored in log)

        Returns:
            Dict with processing summary and updated trust weights.
        """
        if analyst_verdict not in _VERDICT_TO_THREAT_OUTCOME:
            raise ValueError(
                f"Invalid analyst_verdict '{analyst_verdict}'. "
                f"Valid values: {list(_VERDICT_TO_THREAT_OUTCOME.keys())}"
            )

        threat_outcome = _VERDICT_TO_THREAT_OUTCOME[analyst_verdict]
        mg_outcome     = _VERDICT_TO_MG_OUTCOME[analyst_verdict]
        threat_success = _OUTCOME_IS_SUCCESS[threat_outcome]
        mg_success     = _OUTCOME_IS_SUCCESS[mg_outcome]

        updates_applied = []

        with self._lock:
            # ── Update CIE trust weights ──────────────────────────────────────
            if self._cie is not None:
                self._cie.update_trust("ThreatAnalysisAgent", threat_success)
                self._cie.update_trust("MemoryGuard",         mg_success)
                self._cie.record_outcome("ThreatAnalysisAgent", threat_outcome)
                self._cie.record_outcome("MemoryGuard",         mg_outcome)
                updates_applied.append("trust_weights_updated")
                logger.info(
                    f"[SelfLearning] event={event_id} verdict={analyst_verdict} "
                    f"ThreatAgent→{threat_outcome} MG→{mg_outcome}"
                )

            # ── Repair MemoryGuard trace on false positive ────────────────────
            if analyst_verdict == VERDICT_FALSE_POS and self._mg is not None and trace_id:
                try:
                    self._mg.repair_trace(trace_id, feedback=analyst_verdict)
                    updates_applied.append("mg_trace_repaired")
                    logger.info(f"[SelfLearning] MemoryGuard trace repaired: {trace_id}")
                except Exception as exc:
                    logger.warning(f"[SelfLearning] MG repair failed for {trace_id}: {exc}")

            # ── Persist to feedback log ───────────────────────────────────────
            feedback_event = {
                "event_id":       event_id,
                "timestamp":      datetime.utcnow().isoformat(),
                "decision_made":  decision_made,
                "analyst_verdict": analyst_verdict,
                "threat_outcome": threat_outcome,
                "mg_outcome":     mg_outcome,
                "trace_id":       trace_id,
                "analyst_note":   analyst_note,
                "updates":        updates_applied,
            }
            self._log.append(feedback_event)
            self._save_log()

        # Build response summary
        updated_weights = {}
        if self._cie is not None:
            updated_weights = self._cie.trust_estimator.get_all_weights()

        return {
            "status":          "feedback_recorded",
            "event_id":        event_id,
            "analyst_verdict": analyst_verdict,
            "threat_outcome":  threat_outcome,
            "mg_outcome":      mg_outcome,
            "updates_applied": updates_applied,
            "current_trust_weights": updated_weights,
        }

    # ── Audit / query API ─────────────────────────────────────────────────────

    def get_feedback_log(self, limit: int = 50) -> list:
        """Return the most recent feedback events (newest first)."""
        with self._lock:
            return list(reversed(self._log[-limit:]))

    def get_summary_stats(self) -> Dict[str, Any]:
        """Return aggregate statistics over all recorded feedback events."""
        with self._lock:
            total = len(self._log)
            if total == 0:
                return {"total_events": 0}
            verdicts: Dict[str, int] = {}
            for e in self._log:
                v = e.get("analyst_verdict", "UNKNOWN")
                verdicts[v] = verdicts.get(v, 0) + 1
            fp_count = verdicts.get(VERDICT_FALSE_POS, 0)
            fn_count = verdicts.get(VERDICT_MISSED,    0)
            tp_count = verdicts.get(VERDICT_CONFIRMED, 0)
            tn_count = verdicts.get(VERDICT_BENIGN,    0)
            precision = tp_count / (tp_count + fp_count) if (tp_count + fp_count) > 0 else None
            recall    = tp_count / (tp_count + fn_count) if (tp_count + fn_count) > 0 else None
            return {
                "total_events": total,
                "verdict_counts": verdicts,
                "precision":      round(precision, 4) if precision is not None else "N/A",
                "recall":         round(recall,    4) if recall    is not None else "N/A",
                "false_positives": fp_count,
                "false_negatives": fn_count,
            }
