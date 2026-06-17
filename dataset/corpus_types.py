"""
dataset/corpus_types.py — Typed data structures for the ARES-Mem evaluation corpus.

Every entry in the corpus is a RawLogEvent with:
  - ground-truth label (BENIGN / ADVERSARIAL / HARD_NEGATIVE)
  - attack_family for adversarial entries (for per-family metrics)
  - expected_guard_verdict: what the Memory Guard *should* decide
  - attacker_goal: what decision the attacker *wants* the pipeline to make
    (used to compute ASR — if a bypass causes this outcome, the attack succeeded)
"""
from dataclasses import dataclass, field
from typing import Optional, Literal


# ── Labels ────────────────────────────────────────────────────────────────────
Label = Literal["BENIGN", "ADVERSARIAL", "HARD_NEGATIVE"]

# ── Attack Families (adversarial class) ───────────────────────────────────────
AttackFamily = Literal[
    "DIRECT_OVERRIDE",          # "ignore all previous instructions…"
    "AUTHORITY_SPOOFING",       # "this message has system-level authority…"
    "WHITELIST_DOWNGRADE",      # "IP X is whitelisted, ignore alerts"
    "OBFUSCATED_INJECTION",     # injection phrased as plausible-sounding log text
    "TAG_SPOOFING",             # benign-looking text claiming high privilege via structure
]

# ── Guard Verdict ─────────────────────────────────────────────────────────────
GuardVerdict = Literal["QUARANTINE", "PASS"]

# ── Pipeline Decision ─────────────────────────────────────────────────────────
PipelineDecision = Literal["BLOCK_IP", "QUARANTINE", "ALERT", "ESCALATE", "LOG_ONLY"]


@dataclass
class RawLogEvent:
    """
    A single labeled evaluation unit.

    Fields
    ------
    text                : The raw log string fed to the pipeline.
    label               : Ground-truth class.
    attack_family       : Attack family (only for ADVERSARIAL; None otherwise).
    source              : Declared data origin fed to MemoryGuard.
    provenance_hops     : Number of transit hops (affects trust decay).
    expected_verdict    : What the Guard *should* output.
    attacker_goal       : Decision the attacker wants to cause (None if benign).
                          A bypass is an ASR success only if the pipeline
                          produces this decision.
    correct_decision    : What the Decision Agent *should* produce for this log.
    seed_id             : Corpus generation seed index (for reproducibility).
    template_id         : Template identifier (tracks template diversity).
    """
    text:               str
    label:              Label
    attack_family:      Optional[AttackFamily]
    source:             Literal["internal", "external", "system"]
    provenance_hops:    int
    expected_verdict:   GuardVerdict
    attacker_goal:      Optional[PipelineDecision]
    correct_decision:   PipelineDecision
    seed_id:            int
    template_id:        str = ""


@dataclass
class GuardResult:
    """Output of running a RawLogEvent through the Memory Guard."""
    event:              RawLogEvent
    actual_verdict:     GuardVerdict          # QUARANTINE or PASS
    privilege_level:    int                   # 1–5
    privilege_label:    str
    quarantine_flag:    bool
    features: dict = field(default_factory=dict)   # entropy, sem_dist, imp_den, perplexity

    @property
    def is_true_positive(self) -> bool:
        """Adversarial event correctly quarantined."""
        return self.event.label == "ADVERSARIAL" and self.actual_verdict == "QUARANTINE"

    @property
    def is_false_negative(self) -> bool:
        """Adversarial event that bypassed the guard (guard failed)."""
        return self.event.label == "ADVERSARIAL" and self.actual_verdict == "PASS"

    @property
    def is_true_negative(self) -> bool:
        """Benign/hard-negative event correctly passed."""
        return self.event.label in ("BENIGN", "HARD_NEGATIVE") and self.actual_verdict == "PASS"

    @property
    def is_false_positive(self) -> bool:
        """Benign/hard-negative event wrongly quarantined."""
        return self.event.label in ("BENIGN", "HARD_NEGATIVE") and self.actual_verdict == "QUARANTINE"


@dataclass
class PipelineResult:
    """
    Full pipeline result for a bypassed event (guard said PASS).

    Used to compute ASR: did the bypass event cause the pipeline to
    produce the attacker's desired decision?
    """
    guard_result:       GuardResult
    pipeline_decision:  PipelineDecision
    threat_score:       int
    threat_type:        str
    asr_success:        bool    # True if pipeline_decision == attacker_goal


@dataclass
class CorpusStats:
    """Summary statistics for a generated corpus."""
    total:              int
    n_benign:           int
    n_adversarial:      int
    n_hard_negative:    int
    family_counts:      dict    # attack_family → count
