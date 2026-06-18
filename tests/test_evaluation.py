"""
tests/test_evaluation.py — Tests for the evaluation harness and corpus generator.

Verifies:
  - Corpus generation is deterministic (same seed → same output)
  - Corpus size and label distribution match expectations
  - GuardResult properties (TP/FP/TN/FN predicates) are correct
  - Metrics computation is algebraically consistent
  - Per-family template_id coverage
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from dataset.synthetic_corpus import generate_corpus
from dataset.corpus_types import RawLogEvent, GuardResult, PipelineResult
from eval.metrics import compute_metrics, FamilyMetrics


# ══════════════════════════════════════════════════════════════════════════════
# Corpus Generation Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestCorpusGeneration:

    @pytest.fixture(scope="class")
    @classmethod
    def corpus_and_stats(cls):
        corpus, stats = generate_corpus(seed=42)
        return corpus, stats

    def test_corpus_is_deterministic(self):
        """Same seed must produce identical corpus."""
        c1, _ = generate_corpus(seed=42)
        c2, _ = generate_corpus(seed=42)
        assert [e.text for e in c1] == [e.text for e in c2], "Corpus is not deterministic"

    def test_different_seeds_differ(self):
        """Different seeds must produce different corpora."""
        c1, _ = generate_corpus(seed=42)
        c2, _ = generate_corpus(seed=99)
        assert [e.text for e in c1] != [e.text for e in c2]

    def test_corpus_has_all_labels(self, corpus_and_stats):
        corpus, stats = corpus_and_stats
        labels = {e.label for e in corpus}
        assert "BENIGN" in labels
        assert "ADVERSARIAL" in labels
        assert "HARD_NEGATIVE" in labels

    def test_corpus_size_within_target(self, corpus_and_stats):
        """Total corpus should be between 300 and 500 entries."""
        corpus, stats = corpus_and_stats
        assert 300 <= stats.total <= 500, f"Corpus size {stats.total} out of expected range"

    def test_benign_count_dominant(self, corpus_and_stats):
        corpus, stats = corpus_and_stats
        assert stats.n_benign >= 150, f"Expected ≥150 benign, got {stats.n_benign}"

    def test_adversarial_count_sufficient(self, corpus_and_stats):
        corpus, stats = corpus_and_stats
        assert stats.n_adversarial >= 100, f"Expected ≥100 adversarial, got {stats.n_adversarial}"

    def test_hard_negative_count(self, corpus_and_stats):
        corpus, stats = corpus_and_stats
        assert stats.n_hard_negative >= 30, f"Expected ≥30 hard-negative, got {stats.n_hard_negative}"

    def test_all_five_families_present(self, corpus_and_stats):
        corpus, stats = corpus_and_stats
        expected_families = {
            "DIRECT_OVERRIDE", "AUTHORITY_SPOOFING", "WHITELIST_DOWNGRADE",
            "OBFUSCATED_INJECTION", "TAG_SPOOFING",
        }
        assert expected_families == set(stats.family_counts.keys()), (
            f"Missing families: {expected_families - set(stats.family_counts.keys())}"
        )

    def test_each_family_balanced(self, corpus_and_stats):
        """Each family should have at least 20 entries."""
        corpus, stats = corpus_and_stats
        for fam, count in stats.family_counts.items():
            assert count >= 20, f"Family {fam} has only {count} entries"

    def test_adversarial_expected_verdict_quarantine(self, corpus_and_stats):
        """All adversarial events must have expected_verdict == QUARANTINE."""
        corpus, _ = corpus_and_stats
        for e in corpus:
            if e.label == "ADVERSARIAL":
                assert e.expected_verdict == "QUARANTINE", (
                    f"Adversarial event {e.seed_id} has unexpected verdict={e.expected_verdict}"
                )

    def test_benign_expected_verdict_pass(self, corpus_and_stats):
        """All benign events must have expected_verdict == PASS."""
        corpus, _ = corpus_and_stats
        for e in corpus:
            if e.label in ("BENIGN", "HARD_NEGATIVE"):
                assert e.expected_verdict == "PASS"

    def test_seed_ids_unique(self, corpus_and_stats):
        """Each entry must have a unique seed_id."""
        corpus, _ = corpus_and_stats
        ids = [e.seed_id for e in corpus]
        assert len(ids) == len(set(ids)), "Duplicate seed_ids found"

    def test_template_diversity(self, corpus_and_stats):
        """At least 20 distinct template_ids in the corpus."""
        corpus, _ = corpus_and_stats
        template_ids = {e.template_id for e in corpus}
        assert len(template_ids) >= 20, f"Only {len(template_ids)} distinct templates"

    def test_text_nonblank(self, corpus_and_stats):
        """No empty log texts."""
        corpus, _ = corpus_and_stats
        for e in corpus:
            assert len(e.text.strip()) > 0, f"Empty text for seed_id={e.seed_id}"


# ══════════════════════════════════════════════════════════════════════════════
# GuardResult Predicate Tests
# ══════════════════════════════════════════════════════════════════════════════

def _make_event(label, family=None):
    return RawLogEvent(
        text="test", label=label, attack_family=family,
        source="external", provenance_hops=1,
        expected_verdict="QUARANTINE" if label == "ADVERSARIAL" else "PASS",
        attacker_goal="LOG_ONLY" if label == "ADVERSARIAL" else None,
        correct_decision="LOG_ONLY", seed_id=999,
    )


def _make_guard_result(label, verdict, family=None):
    return GuardResult(
        event=_make_event(label, family),
        actual_verdict=verdict,
        privilege_level=1 if verdict == "QUARANTINE" else 3,
        privilege_label="untrusted" if verdict == "QUARANTINE" else "medium",
        quarantine_flag=(verdict == "QUARANTINE"),
    )


class TestGuardResultPredicates:

    def test_true_positive(self):
        gr = _make_guard_result("ADVERSARIAL", "QUARANTINE", "DIRECT_OVERRIDE")
        assert gr.is_true_positive is True
        assert gr.is_false_negative is False

    def test_false_negative(self):
        gr = _make_guard_result("ADVERSARIAL", "PASS", "DIRECT_OVERRIDE")
        assert gr.is_false_negative is True
        assert gr.is_true_positive is False

    def test_true_negative(self):
        gr = _make_guard_result("BENIGN", "PASS")
        assert gr.is_true_negative is True
        assert gr.is_false_positive is False

    def test_false_positive(self):
        gr = _make_guard_result("BENIGN", "QUARANTINE")
        assert gr.is_false_positive is True
        assert gr.is_true_negative is False

    def test_hard_negative_tp_tn(self):
        gr_pass = _make_guard_result("HARD_NEGATIVE", "PASS")
        gr_fail = _make_guard_result("HARD_NEGATIVE", "QUARANTINE")
        assert gr_pass.is_true_negative is True
        assert gr_fail.is_false_positive is True


# ══════════════════════════════════════════════════════════════════════════════
# Metrics Consistency Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestMetricsConsistency:

    @pytest.fixture()
    def synthetic_results(self):
        """Build a controlled set of guard results for metric verification."""
        guard_results = [
            # 4 TP (adversarial correctly quarantined)
            _make_guard_result("ADVERSARIAL", "QUARANTINE", "DIRECT_OVERRIDE"),
            _make_guard_result("ADVERSARIAL", "QUARANTINE", "DIRECT_OVERRIDE"),
            _make_guard_result("ADVERSARIAL", "QUARANTINE", "AUTHORITY_SPOOFING"),
            _make_guard_result("ADVERSARIAL", "QUARANTINE", "WHITELIST_DOWNGRADE"),
            # 1 FN (bypass)
            _make_guard_result("ADVERSARIAL", "PASS",       "OBFUSCATED_INJECTION"),
            # 3 TN (benign correctly passed)
            _make_guard_result("BENIGN", "PASS"),
            _make_guard_result("BENIGN", "PASS"),
            _make_guard_result("BENIGN", "PASS"),
            # 1 FP (benign wrongly quarantined)
            _make_guard_result("BENIGN", "QUARANTINE"),
            # 2 TN hard-negative
            _make_guard_result("HARD_NEGATIVE", "PASS"),
            _make_guard_result("HARD_NEGATIVE", "PASS"),
        ]
        # Assign unique seed_ids
        for i, gr in enumerate(guard_results):
            gr.event.seed_id = i + 1
        return guard_results

    def test_tp_count(self, synthetic_results):
        metrics = compute_metrics(synthetic_results, [])
        assert metrics["ALL_ADVERSARIAL"].tp == 4

    def test_fn_count(self, synthetic_results):
        metrics = compute_metrics(synthetic_results, [])
        assert metrics["ALL_ADVERSARIAL"].fn == 1

    def test_tn_count(self, synthetic_results):
        metrics = compute_metrics(synthetic_results, [])
        assert metrics["BENIGN"].tn == 3

    def test_fp_count(self, synthetic_results):
        metrics = compute_metrics(synthetic_results, [])
        assert metrics["BENIGN"].fp == 1

    def test_detection_rate_correct(self, synthetic_results):
        """Detection rate = TP / (TP + FN) = 4/5 = 0.80."""
        metrics = compute_metrics(synthetic_results, [])
        assert abs(metrics["ALL_ADVERSARIAL"].detection_rate - 0.80) < 0.001

    def test_fp_rate_correct(self, synthetic_results):
        """FP rate = FP / (FP + TN) = 1/4 = 0.25."""
        metrics = compute_metrics(synthetic_results, [])
        assert abs(metrics["BENIGN"].false_positive_rate - 0.25) < 0.001

    def test_asr_zero_with_no_pipeline_results(self, synthetic_results):
        """No pipeline results → ASR = 0%."""
        metrics = compute_metrics(synthetic_results, [])
        assert metrics["ALL_ADVERSARIAL"].asr_pct == 0.0

    def test_asr_nonzero_with_pipeline_success(self, synthetic_results):
        """If bypass causes attacker's desired decision → ASR > 0%."""
        # The bypass event is seed_id=5, family=OBFUSCATED_INJECTION
        bypass_gr = [gr for gr in synthetic_results if gr.is_false_negative][0]
        pr = PipelineResult(
            guard_result=bypass_gr,
            pipeline_decision="LOG_ONLY",   # matches attacker_goal
            threat_score=5,
            threat_type="BENIGN",
            asr_success=True,
        )
        metrics = compute_metrics(synthetic_results, [pr])
        assert metrics["ALL_ADVERSARIAL"].asr_successes == 1
        assert metrics["ALL_ADVERSARIAL"].asr_pct == 100.0   # 1/1 bypass

    def test_f1_consistent_with_precision_recall(self, synthetic_results):
        """F1 = 2*P*R/(P+R)."""
        metrics = compute_metrics(synthetic_results, [])
        m = metrics["ALL_ADVERSARIAL"]
        expected_f1 = 2 * m.precision * m.recall / (m.precision + m.recall)
        assert abs(m.f1 - expected_f1) < 0.001

    def test_bypassed_matches_fn(self, synthetic_results):
        """bypassed field must equal fn for adversarial families."""
        metrics = compute_metrics(synthetic_results, [])
        assert metrics["ALL_ADVERSARIAL"].bypassed == metrics["ALL_ADVERSARIAL"].fn
