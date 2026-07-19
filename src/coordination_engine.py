"""
coordination_engine.py — Coordination Intelligence Engine (CIE) for ARES-Mem.

Implements the 6-sub-module CIE from the ACIF architectural diagram:
  1. Agent Reliability Evaluation  — tracks per-agent TP/FP/FN/TN history
  2. Trust Estimation (Adaptive)   — Bayesian Beta-distribution trust weights
  3. Conflict Detection            — flags disagreements between agents
  4. Evidence Fusion               — Dempster-Shafer combination rule
  5. Adaptive Decision             — policy applied to fused belief
  6. Explainable Reasoning         — human-readable audit narrative (Ollama optional)

All sub-modules are fully deterministic. The LLM call in sub-module 6 is optional;
it degrades gracefully to a template string when Ollama is unavailable.
"""

import json
import logging
import math
import os
import uuid
from collections import deque
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("CoordinationEngine")

# ── Optional LiteLLM import (for Explainable Reasoning) ──────────────────────
try:
    import litellm
    from src.circuit_breaker import llm_circuit_breaker
    litellm.set_verbose = False
    _LITELLM_AVAILABLE = True
except ImportError:
    _LITELLM_AVAILABLE = False

# ── Trust state persistence path ─────────────────────────────────────────────
_TRUST_STATE_PATH = os.path.join(
    os.path.dirname(__file__), "data", "agent_trust_state.json"
)

# ── Agent names (canonical keys for trust state) ──────────────────────────────
AGENT_THREAT = "ThreatAnalysisAgent"
AGENT_MEMORY = "MemoryGuard"
AGENT_INGEST  = "LogIngestionAgent"

# ── Conflict detection thresholds (Decision Card: 30/70) ──────────────────────
CONFLICT_LOW_RISK  = 30   # risk_score < this AND quarantine=True  → conflict
CONFLICT_HIGH_RISK = 70   # risk_score > this AND quarantine=False → conflict

# ── Adaptive decision policy matrix (applied to fused threat belief) ──────────
# First matching rule wins. Thresholds on fused threat_belief [0,1].
DECISION_POLICY = [
    # (min_threat_belief, decision, task_type, priority, requires_escalation)
    (0.85, "BLOCK_IP",   "block_ip",    "CRITICAL", False),
    (0.65, "QUARANTINE", "quarantine",  "HIGH",     False),
    (0.45, "MONITOR",    "monitor",     "MEDIUM",   False),
    (0.20, "ALERT",      "notify",      "MEDIUM",   False),
    (0.00, "LOG_ONLY",   "log_analysis","LOW",      False),
]

# ── Conflict override: ESCALATE when conflict is unresolved ───────────────────
CONFLICT_ESCALATE_POLICY = {
    "decision": "ESCALATE",
    "task_type": "notify",
    "priority": "HIGH",
    "requires_escalation": True,
}

# ── Beta parameter bounds (prevent divergence) ────────────────────────────────
BETA_MIN = 1.0
BETA_MAX = 100.0


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  Sub-Module 1: Agent Reliability Evaluator                                  ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

class AgentReliabilityEvaluator:
    """
    Tracks per-agent TP/FP/FN/TN counts over a rolling window (last 100 events).
    Computes reliability_score = (TP + TN) / total and calibration_error = |conf - acc|.
    """

    WINDOW = 100  # rolling window size

    def __init__(self):
        # agent_name → deque of outcome dicts
        self._history: Dict[str, deque] = {}

    def record(self, agent_name: str, outcome: str, confidence: float = 1.0) -> None:
        """
        Record an outcome for an agent.
        outcome ∈ {'TP', 'TN', 'FP', 'FN'}
        """
        if agent_name not in self._history:
            self._history[agent_name] = deque(maxlen=self.WINDOW)
        self._history[agent_name].append({
            "outcome": outcome,
            "confidence": confidence,
            "ts": datetime.now(timezone.utc).isoformat(),
        })

    def evaluate(self, agent_name: str) -> Dict[str, Any]:
        """Returns a reliability snapshot for the given agent."""
        history = list(self._history.get(agent_name, []))
        total = len(history)
        if total == 0:
            return {
                "agent_name": agent_name,
                "reliability_score": 0.75,  # optimistic prior for unknown agents
                "calibration_error": 0.0,
                "total_events": 0,
            }
        correct = sum(1 for h in history if h["outcome"] in ("TP", "TN"))
        reliability_score = correct / total
        # Calibration: mean |confidence - (1 if correct else 0)|
        calibration_error = float(
            sum(
                abs(h["confidence"] - (1.0 if h["outcome"] in ("TP", "TN") else 0.0))
                for h in history
            ) / total
        )
        return {
            "agent_name": agent_name,
            "reliability_score": round(reliability_score, 4),
            "calibration_error": round(calibration_error, 4),
            "total_events": total,
        }

    def get_all(self) -> Dict[str, Dict[str, Any]]:
        """Returns reliability snapshots for all tracked agents."""
        all_agents = list(self._history.keys())
        if not all_agents:
            # Return defaults for core agents
            all_agents = [AGENT_THREAT, AGENT_MEMORY, AGENT_INGEST]
        return {name: self.evaluate(name) for name in all_agents}


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  Sub-Module 2: Trust Estimator (Adaptive Bayesian)                          ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

class TrustEstimator:
    """
    Maintains a Beta(alpha, beta) prior per agent.
    Trust weight (posterior mean) = alpha / (alpha + beta).
    Parameters are updated on each feedback event and persisted to JSON.
    """

    _DEFAULT_ALPHA = 2.0  # slightly optimistic prior (not flat)
    _DEFAULT_BETA  = 1.0

    def __init__(self, state_path: str = _TRUST_STATE_PATH):
        self._path = state_path
        self._state: Dict[str, Dict[str, float]] = {}
        self._load()

    # ── Persistence ──────────────────────────────────────────────────────────

    def _load(self) -> None:
        """Load trust state from JSON if it exists."""
        if os.path.exists(self._path):
            try:
                with open(self._path, "r", encoding="utf-8") as f:
                    self._state = json.load(f)
                logger.info(f"[TrustEstimator] Loaded trust state from {self._path}")
            except Exception as exc:
                logger.warning(f"[TrustEstimator] Could not load trust state: {exc} — using defaults")
                self._state = {}
        else:
            self._state = {}

    def save(self) -> None:
        """Persist current Beta parameters to JSON."""
        os.makedirs(os.path.dirname(self._path), exist_ok=True)
        with open(self._path, "w", encoding="utf-8") as f:
            json.dump(self._state, f, indent=2)
        logger.debug(f"[TrustEstimator] Trust state saved to {self._path}")

    # ── Access ────────────────────────────────────────────────────────────────

    def _get_params(self, agent_name: str) -> Dict[str, float]:
        if agent_name not in self._state:
            self._state[agent_name] = {
                "alpha": self._DEFAULT_ALPHA,
                "beta":  self._DEFAULT_BETA,
            }
        return self._state[agent_name]

    def trust_weight(self, agent_name: str) -> float:
        """Posterior mean trust weight ∈ [0, 1]."""
        p = self._get_params(agent_name)
        return p["alpha"] / (p["alpha"] + p["beta"])

    def get_all_weights(self) -> Dict[str, float]:
        """Returns trust weight for every tracked agent."""
        all_agents = list(self._state.keys()) or [AGENT_THREAT, AGENT_MEMORY, AGENT_INGEST]
        return {name: self.trust_weight(name) for name in all_agents}

    def get_all_params(self) -> Dict[str, Dict[str, float]]:
        """Returns raw Beta (alpha, beta) for every tracked agent."""
        return dict(self._state)

    # ── Update ────────────────────────────────────────────────────────────────

    def update(self, agent_name: str, success: bool) -> None:
        """
        Bayesian conjugate update.
        success=True  → increment alpha (agent was correct / helpful)
        success=False → increment beta  (agent was incorrect / harmful)
        Parameters are clipped to [BETA_MIN, BETA_MAX] to prevent divergence.
        """
        p = self._get_params(agent_name)
        if success:
            p["alpha"] = min(p["alpha"] + 1.0, BETA_MAX)
        else:
            p["beta"] = min(p["beta"] + 1.0, BETA_MAX)
        # Reset to prior if severely biased (divergence guard)
        if p["alpha"] >= BETA_MAX and p["beta"] <= BETA_MIN:
            logger.warning(f"[TrustEstimator] Resetting {agent_name} alpha (divergence)")
            p["alpha"] = BETA_MAX / 2
        if p["beta"] >= BETA_MAX and p["alpha"] <= BETA_MIN:
            logger.warning(f"[TrustEstimator] Resetting {agent_name} beta (divergence)")
            p["beta"] = BETA_MAX / 2

    def reset(self, agent_name: str) -> None:
        """Reset an agent to the default prior."""
        self._state[agent_name] = {
            "alpha": self._DEFAULT_ALPHA,
            "beta":  self._DEFAULT_BETA,
        }


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  Sub-Module 3: Conflict Detector                                             ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

class ConflictDetector:
    """
    Detects agent disagreements using configurable risk-score / quarantine thresholds.
    Default: (30, 70) per Decision Card.
    """

    def __init__(self, low_risk: int = CONFLICT_LOW_RISK, high_risk: int = CONFLICT_HIGH_RISK):
        self.low_risk  = low_risk
        self.high_risk = high_risk

    def detect(
        self,
        risk_score: int,
        mg_quarantine: bool,
        trust_weights: Dict[str, float],
    ) -> Dict[str, Any]:
        """
        Evaluate for conflicts between ThreatAnalysisAgent and MemoryGuard signals.

        Conflict rules:
          A. risk_score < low_risk  AND mg_quarantine == True  → MG is over-triggering
          B. risk_score > high_risk AND mg_quarantine == False → MG under-flagged a threat

        Resolution:
          - No conflict → TRUST_HIGHER_WEIGHT (use weighted decision)
          - Conflict A (over-trigger, low risk) → ACCEPT_BENIGN
          - Conflict B (under-flag, high risk)  → ESCALATE
        """
        conflict_a = risk_score < self.low_risk and mg_quarantine
        conflict_b = risk_score > self.high_risk and not mg_quarantine

        if conflict_a:
            return {
                "conflict_detected":  True,
                "conflict_type":      "MG_OVER_TRIGGER",
                "conflicting_agents": [AGENT_THREAT, AGENT_MEMORY],
                "resolution":         "ACCEPT_BENIGN",
                "risk_score":         risk_score,
                "mg_quarantine":      mg_quarantine,
            }
        if conflict_b:
            return {
                "conflict_detected":  True,
                "conflict_type":      "MG_UNDER_FLAG",
                "conflicting_agents": [AGENT_THREAT, AGENT_MEMORY],
                "resolution":         "ESCALATE",
                "risk_score":         risk_score,
                "mg_quarantine":      mg_quarantine,
            }

        return {
            "conflict_detected":  False,
            "conflict_type":      "NONE",
            "conflicting_agents": [],
            "resolution":         "TRUST_HIGHER_WEIGHT",
            "risk_score":         risk_score,
            "mg_quarantine":      mg_quarantine,
        }


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  Sub-Module 4: Evidence Fusion (Dempster-Shafer)                             ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

class EvidenceFusion:
    """
    Implements Dempster-Shafer (D-S) combination rule to fuse evidence from multiple agents.

    Frame of Discernment: Θ = {THREAT, BENIGN}
    Each agent produces a basic probability assignment (mass function):
        m({THREAT})         = agent's threat evidence mass
        m({BENIGN})         = agent's benign evidence mass
        m({THREAT, BENIGN}) = agent's uncertainty (1 - threat_mass - benign_mass)

    The D-S combination rule is then applied to all agent mass functions.
    """

    def fuse(
        self,
        agent_masses: Dict[str, Dict[str, float]],
        trust_weights: Dict[str, float],
    ) -> Dict[str, Any]:
        """
        Combine agent mass functions using weighted D-S combination.

        agent_masses: {agent_name: {"threat": float, "benign": float, "uncertainty": float}}
        trust_weights: {agent_name: float in [0,1]}

        Returns EvidenceFusionResult dict.
        """
        if not agent_masses:
            return {
                "threat_belief": 0.0,
                "benign_belief": 1.0,
                "uncertainty": 0.0,
                "method": "dempster_shafer",
                "agent_masses": {},
            }

        # Scale each agent's masses by its trust weight, then normalize
        agents = list(agent_masses.keys())
        weighted: List[Dict[str, float]] = []
        for name in agents:
            raw = agent_masses[name]
            w   = trust_weights.get(name, 0.5)
            # Discount factor: dilute toward pure uncertainty by (1 - w)
            threat     = raw.get("threat",     0.0) * w
            benign     = raw.get("benign",     0.0) * w
            uncertainty = 1.0 - threat - benign  # remaining mass to uncertainty
            # Clamp to valid mass range
            threat      = max(0.0, min(1.0, threat))
            benign      = max(0.0, min(1.0, benign))
            uncertainty = max(0.0, 1.0 - threat - benign)
            weighted.append({"threat": threat, "benign": benign, "uncertainty": uncertainty})

        # Combine all weighted mass functions pairwise using D-S rule
        combined = weighted[0]
        for i in range(1, len(weighted)):
            combined = self._ds_combine(combined, weighted[i])

        return {
            "threat_belief": round(combined["threat"], 4),
            "benign_belief": round(combined["benign"], 4),
            "uncertainty":   round(combined["uncertainty"], 4),
            "method":        "dempster_shafer",
            "agent_masses":  agent_masses,
        }

    @staticmethod
    def _ds_combine(m1: Dict[str, float], m2: Dict[str, float]) -> Dict[str, float]:
        """
        Core Dempster-Shafer orthogonal sum.
        Sets: T={THREAT}, B={BENIGN}, U={THREAT,BENIGN}=uncertainty
        """
        # Compute all intersections
        m_TT = m1["threat"]      * m2["threat"]
        m_BB = m1["benign"]      * m2["benign"]
        m_TU = m1["threat"]      * m2["uncertainty"]
        m_UT = m1["uncertainty"] * m2["threat"]
        m_BU = m1["benign"]      * m2["uncertainty"]
        m_UB = m1["uncertainty"] * m2["benign"]
        m_UU = m1["uncertainty"] * m2["uncertainty"]

        # Conflict mass (empty set intersections: T∩B and B∩T)
        conflict = m1["threat"] * m2["benign"] + m1["benign"] * m2["threat"]

        # Normalisation constant K = 1 - conflict
        K = 1.0 - conflict
        if K <= 1e-9:
            # Total conflict — return maximum uncertainty (safe fallback)
            return {"threat": 0.0, "benign": 0.0, "uncertainty": 1.0}

        threat      = (m_TT + m_TU + m_UT) / K
        benign      = (m_BB + m_BU + m_UB) / K
        uncertainty = m_UU / K

        return {
            "threat":      max(0.0, min(1.0, threat)),
            "benign":      max(0.0, min(1.0, benign)),
            "uncertainty": max(0.0, min(1.0, uncertainty)),
        }

    @staticmethod
    def _gnn_fuse(
        agent_embeddings: Dict[str, Any],
        adjacency: Any,
    ) -> Dict[str, float]:
        """
        GNN-based evidence fusion stub.

        This method is intentionally left unimplemented. A Graph Neural Network
        (e.g., via PyTorch Geometric) would:
          1. Encode each agent's evidence as a node embedding.
          2. Pass messages across a fully-connected agent graph.
          3. Aggregate node representations to produce fused threat/benign scores.

        To activate: install torch_geometric, implement a 2-layer GCN or GAT,
        and replace the D-S call in EvidenceFusion.fuse() with _gnn_fuse().

        Args:
            agent_embeddings: {agent_name: embedding vector}
            adjacency: adjacency matrix (NxN numpy array)

        Returns:
            {"threat": float, "benign": float, "uncertainty": float}
        """
        raise NotImplementedError(
            "_gnn_fuse() is a placeholder. "
            "Install torch_geometric and implement a GCN/GAT to use this path."
        )


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  Sub-Module 5: Adaptive Decision Maker                                       ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

class AdaptiveDecisionMaker:
    """
    Applies the policy matrix to the fused threat belief.
    If a conflict requires escalation, overrides the policy-based decision.
    Supports all 8 decision types: BLOCK_IP, QUARANTINE, MONITOR, ALERT,
    LOG_ONLY, ESCALATE, DELAY, ROLLBACK.
    """

    def decide(
        self,
        fusion_result: Dict[str, Any],
        conflict_report: Dict[str, Any],
        source_ip: str = "0.0.0.0",
        threat_type: str = "UNKNOWN",
    ) -> Dict[str, Any]:
        """
        Determine the final adaptive decision based on fused evidence.

        Conflict override: if conflict_report resolution == ESCALATE, always ESCALATE.
        Otherwise, apply DECISION_POLICY to threat_belief.
        """
        threat_belief = fusion_result.get("threat_belief", 0.0)

        # Conflict override check
        if conflict_report.get("conflict_detected") and conflict_report.get("resolution") == "ESCALATE":
            decision_label = "ESCALATE"
            task_type      = "notify"
            priority       = "HIGH"
            req_esc        = True
            rationale = (
                f"Conflict detected ({conflict_report.get('conflict_type')}): "
                f"ThreatAnalysisAgent risk score={conflict_report.get('risk_score')} "
                f"disagrees with MemoryGuard quarantine={conflict_report.get('mg_quarantine')}. "
                f"Escalating to human analyst for resolution."
            )
        else:
            # Apply policy matrix
            decision_label = "LOG_ONLY"
            task_type      = "log_analysis"
            priority       = "LOW"
            req_esc        = False
            for (min_belief, label, ttype, prio, esc) in DECISION_POLICY:
                if threat_belief >= min_belief:
                    decision_label = label
                    task_type      = ttype
                    priority       = prio
                    req_esc        = esc
                    break
            rationale = (
                f"Fused threat belief={threat_belief:.3f} "
                f"(D-S combination of {len(fusion_result.get('agent_masses', {})) } agents). "
                f"Policy match: threat_belief >= {min_belief} → {decision_label}."
            )

        return {
            "decision":            decision_label,
            "action":              self._action_description(decision_label, source_ip, threat_type),
            "task_type":           task_type,
            "priority":            priority,
            "requires_escalation": req_esc,
            "rationale":           rationale,
            "source_ip":           source_ip,
        }

    @staticmethod
    def _action_description(decision: str, source_ip: str, threat_type: str) -> str:
        actions = {
            "BLOCK_IP":   f"Block all traffic from {source_ip} — threat type: {threat_type}",
            "QUARANTINE": f"Quarantine host at {source_ip} for investigation",
            "MONITOR":    f"Activate enhanced monitoring on {source_ip}",
            "ALERT":      f"Send alert to SOC — potential {threat_type} from {source_ip}",
            "LOG_ONLY":   f"Log event for {source_ip} — no immediate action required",
            "ESCALATE":   f"Escalate {source_ip} event to human analyst — agent conflict detected",
            "DELAY":      f"Defer action on {source_ip} by 5 minutes; re-evaluate on next cycle",
            "ROLLBACK":   f"Reverse previous action on {source_ip} — false positive suspected",
        }
        return actions.get(decision, f"Execute {decision} for {source_ip}")


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  Sub-Module 6: Explainable Reasoning                                         ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

class ExplainableReasoner:
    """
    Generates a human-readable audit narrative for each CIE decision.
    Tries the Ollama LLM first; falls back to a deterministic template string.
    """

    _OLLAMA_MODEL   = "qwen2.5:1.5b-instruct"
    _OLLAMA_BASE    = "http://localhost:11434"
    _TIMEOUT_SECS   = 5

    def explain(
        self,
        reliability_map: Dict[str, Any],
        trust_weights: Dict[str, float],
        conflict_report: Dict[str, Any],
        fusion_result: Dict[str, Any],
        decision: Dict[str, Any],
    ) -> str:
        """
        Generate explanation. Attempts LLM; falls back to template on any error.
        """
        template_explanation = self._template_explain(
            reliability_map, trust_weights, conflict_report, fusion_result, decision
        )
        if not _LITELLM_AVAILABLE:
            return template_explanation
        try:
            return self._llm_explain(template_explanation)
        except Exception as exc:
            logger.debug(f"[ExplainableReasoner] LLM unavailable ({exc}); using template")
            return template_explanation

    def _template_explain(
        self,
        reliability_map: Dict[str, Any],
        trust_weights: Dict[str, float],
        conflict_report: Dict[str, Any],
        fusion_result: Dict[str, Any],
        decision: Dict[str, Any],
    ) -> str:
        lines = [
            "=== ARES-Mem CIE Audit Explanation ===",
            f"Decision  : {decision.get('decision')} | Priority: {decision.get('priority')}",
            f"Rationale : {decision.get('rationale')}",
            "",
            "--- Agent Reliability ---",
        ]
        for name, rel in reliability_map.items():
            tw  = trust_weights.get(name, 0.5)
            rs  = rel.get("reliability_score", 0.75)
            lines.append(
                f"  {name:<30} reliability={rs:.2f}  trust_weight={tw:.2f}"
                f"  events={rel.get('total_events', 0)}"
            )
        lines += [
            "",
            "--- Evidence Fusion (Dempster-Shafer) ---",
            f"  Method      : {fusion_result.get('method')}",
            f"  Threat Mass : {fusion_result.get('threat_belief', 0):.4f}",
            f"  Benign Mass : {fusion_result.get('benign_belief', 0):.4f}",
            f"  Uncertainty : {fusion_result.get('uncertainty', 0):.4f}",
            "",
            "--- Conflict Report ---",
            f"  Conflict Detected : {conflict_report.get('conflict_detected')}",
            f"  Conflict Type     : {conflict_report.get('conflict_type')}",
            f"  Resolution        : {conflict_report.get('resolution')}",
            "",
            "=== End of CIE Explanation ===",
        ]
        return "\n".join(lines)

    def _llm_explain(self, template: str) -> str:
        """Call Ollama to produce a natural-language summary of the template explanation."""
        prompt = (
            "You are a cybersecurity audit assistant. "
            "Summarize the following technical decision report in 2-3 clear sentences "
            "suitable for a security analyst. Focus on the decision rationale and any conflicts.\n\n"
            f"{template}\n\nSummary:"
        )

        def _call_llm():
            resp = litellm.completion(
                model=f"ollama/{self._OLLAMA_MODEL}",
                messages=[{"role": "user", "content": prompt}],
                api_base=self._OLLAMA_BASE,
                timeout=self._TIMEOUT_SECS,
                temperature=0.0,
            )
            summary = resp.choices[0].message.content.strip()
            return f"{template}\n\n--- LLM Summary ---\n{summary}"

        def _fallback():
            logger.warning("[ExplainableReasoner] LLM circuit OPEN. Using template fallback.")
            return template

        return llm_circuit_breaker.call(_call_llm, _fallback)


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  Main: CoordinationEngine                                                    ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

class CoordinationEngine:
    """
    Top-level Coordination Intelligence Engine (CIE).

    Orchestrates the 6 sub-modules in sequence and returns a CIEOutput.
    Designed to be instantiated once (singleton via orchestrator lazy registry)
    so trust state and reliability history persist across requests.
    """

    def __init__(self):
        self.reliability_evaluator = AgentReliabilityEvaluator()
        self.trust_estimator       = TrustEstimator()
        self.conflict_detector     = ConflictDetector()
        self.evidence_fusion       = EvidenceFusion()
        self.decision_maker        = AdaptiveDecisionMaker()
        self.reasoner              = ExplainableReasoner()
        logger.info("[CIE] Coordination Intelligence Engine initialized")

    # ── Core pipeline ─────────────────────────────────────────────────────────

    def run(
        self,
        threat_analysis: Dict[str, Any],
        memory_validation: Dict[str, Any],
        structured_log: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Execute the full 6-sub-module CIE pipeline.

        Args:
            threat_analysis:   output of ThreatAnalysisAgent.analyze()
            memory_validation: output of MemoryGuard.validate_and_tag()
            structured_log:    output of LogIngestionAgent.ingest_log()

        Returns:
            CIEOutput dict with reliability_map, trust_weights, conflict_report,
            fusion_result, decision, explanation, event_id.
        """
        event_id = str(uuid.uuid4())

        # ── Extract signals ───────────────────────────────────────────────────
        risk_score    = int(threat_analysis.get("risk_score", 0))
        confidence    = float(threat_analysis.get("confidence", 0.5))
        threat_type   = str(threat_analysis.get("threat_type", "UNKNOWN"))
        source_ip     = str(structured_log.get("source_ip", "0.0.0.0"))
        mg_quarantine = bool(memory_validation.get("quarantine", False))
        mg_trust_tier = str(memory_validation.get("trust_tier", "unknown"))

        # ── Sub-module 1: Agent Reliability ───────────────────────────────────
        reliability_map = self.reliability_evaluator.get_all()

        # ── Sub-module 2: Trust Weights ───────────────────────────────────────
        trust_weights = self.trust_estimator.get_all_weights()

        # Ensure core agents are always present in trust weights
        for agent in [AGENT_THREAT, AGENT_MEMORY, AGENT_INGEST]:
            if agent not in trust_weights:
                trust_weights[agent] = self.trust_estimator.trust_weight(agent)

        # ── Sub-module 3: Conflict Detection ──────────────────────────────────
        conflict_report = self.conflict_detector.detect(
            risk_score=risk_score,
            mg_quarantine=mg_quarantine,
            trust_weights=trust_weights,
        )

        # ── Sub-module 4: Evidence Fusion (D-S) ───────────────────────────────
        # Convert agent signals to mass functions
        # ThreatAnalysisAgent mass: risk_score/100 threat mass, scaled by confidence
        ta_threat  = min(1.0, (risk_score / 100.0) * confidence)
        ta_benign  = max(0.0, (1.0 - risk_score / 100.0) * confidence)
        ta_uncert  = max(0.0, 1.0 - ta_threat - ta_benign)

        # MemoryGuard mass: quarantine=True → high threat mass; tier-adjusted
        mg_threat  = 0.85 if mg_quarantine else 0.15
        mg_uncert  = 0.15
        mg_benign  = max(0.0, 1.0 - mg_threat - mg_uncert)

        agent_masses = {
            AGENT_THREAT: {"threat": ta_threat, "benign": ta_benign, "uncertainty": ta_uncert},
            AGENT_MEMORY: {"threat": mg_threat, "benign": mg_benign, "uncertainty": mg_uncert},
        }

        fusion_result = self.evidence_fusion.fuse(agent_masses, trust_weights)

        # ── Sub-module 5: Adaptive Decision ───────────────────────────────────
        decision = self.decision_maker.decide(
            fusion_result=fusion_result,
            conflict_report=conflict_report,
            source_ip=source_ip,
            threat_type=threat_type,
        )

        # ── Sub-module 6: Explainable Reasoning ───────────────────────────────
        explanation = self.reasoner.explain(
            reliability_map=reliability_map,
            trust_weights=trust_weights,
            conflict_report=conflict_report,
            fusion_result=fusion_result,
            decision=decision,
        )

        return {
            "reliability_map": reliability_map,
            "trust_weights":   trust_weights,
            "conflict_report": conflict_report,
            "fusion_result":   fusion_result,
            "decision":        decision,
            "explanation":     explanation,
            "event_id":        event_id,
        }

    # ── Trust update API (called by SelfLearningAgent) ────────────────────────

    def update_trust(self, agent_name: str, success: bool) -> None:
        """Update the Beta prior for an agent based on feedback outcome."""
        self.trust_estimator.update(agent_name, success)
        self.trust_estimator.save()
        logger.info(
            f"[CIE] Trust updated: {agent_name} success={success} "
            f"→ weight={self.trust_estimator.trust_weight(agent_name):.3f}"
        )

    def record_outcome(self, agent_name: str, outcome: str, confidence: float = 1.0) -> None:
        """Record an agent outcome for reliability tracking."""
        self.reliability_evaluator.record(agent_name, outcome, confidence)

    def get_metrics(self) -> Dict[str, Any]:
        """Return current CIE health metrics for the /metrics endpoint."""
        return {
            "trust_weights":    self.trust_estimator.get_all_weights(),
            "beta_params":      self.trust_estimator.get_all_params(),
            "reliability":      self.reliability_evaluator.get_all(),
        }
