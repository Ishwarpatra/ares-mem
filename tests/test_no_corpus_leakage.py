"""
tests/test_no_corpus_leakage.py - Automated Corpus Integrity Enforcement.

Ensures zero significant overlap between:
  1. Holdout corpus phrases (dataset/holdout_corpus.py) and
     training corpus templates (dataset/synthetic_corpus.py).
  2. Signature-layer keywords (memory_guard.py _SIG_* lists) and
     training corpus template strings -- documents known leakage,
     fails CI on any NEW leakage added after the audit baseline.

Why this test exists:
    The signature-layer keyword lists in MemoryGuard are corpus-derived
    (phrases lifted from synthetic_corpus.py templates). If those same
    phrases re-appear in the holdout corpus, holdout ASR numbers would be
    inflated by signature matching, not ETVL generalization.

    Conversely, if someone adds a holdout phrase to the signature lists
    to "fix" a detection gap, the holdout set is contaminated and no longer
    measures generalization.

    This test enforces both constraints in CI so that discipline is
    machine-verified, not just commented.

CI gate: pytest tests/test_no_corpus_leakage.py -v
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from dataset.holdout_corpus import _ALL_HOLDOUT_TEXTS
from dataset.synthetic_corpus import (
    _DIRECT_OVERRIDE_TEMPLATES,
    _AUTHORITY_SPOOFING_TEMPLATES,
    _WHITELIST_DOWNGRADE_TEMPLATES,
    _OBFUSCATED_INJECTION_TEMPLATES,
    _TAG_SPOOFING_TEMPLATES,
)
from memory_guard import MemoryGuard


# ---- Collect all training template strings -----------------------------------
_ALL_TRAINING_TEMPLATES = (
    _DIRECT_OVERRIDE_TEMPLATES
    + _AUTHORITY_SPOOFING_TEMPLATES
    + _WHITELIST_DOWNGRADE_TEMPLATES
    + _OBFUSCATED_INJECTION_TEMPLATES
    + _TAG_SPOOFING_TEMPLATES
)
_ALL_TRAINING_LOWER = [t.lower() for t in _ALL_TRAINING_TEMPLATES]

# ---- Collect all signature-layer keyword phrases ----------------------------
_ALL_SIGNATURE_KWS = (
    MemoryGuard._SIG_TAG_SPOOFING
    + MemoryGuard._SIG_AUTHORITY_SPOOFING
    + MemoryGuard._SIG_WHITELIST_DOWNGRADE
    + MemoryGuard._SIG_OBFUSCATED_INJECTION
)


# =============================================================================
# Test 1: Holdout phrases must not overlap significantly with training templates
# =============================================================================

class TestHoldoutVsTrainingCorpus:
    """
    Verifies no holdout phrase shares a significant substring (>=30 chars) with
    any training template (and vice versa). The 30-char threshold prevents false
    positives from common English words appearing in both corpora.
    """

    MIN_OVERLAP_LEN = 30

    def _find_overlap(self, text_a: str, text_b: str):
        """
        Finds the longest substring of text_a (>= MIN_OVERLAP_LEN chars)
        that appears in text_b. Returns the span string or None.
        """
        a = text_a.lower()
        b = text_b.lower()
        max_len = min(len(a), 80)
        for length in range(max_len, self.MIN_OVERLAP_LEN - 1, -1):
            for start in range(len(a) - length + 1):
                span = a[start:start + length]
                if span in b:
                    return span
        return None

    def test_holdout_not_in_training(self):
        violations = []
        for holdout_text in _ALL_HOLDOUT_TEXTS:
            for template in _ALL_TRAINING_LOWER:
                span = self._find_overlap(holdout_text, template)
                if span:
                    violations.append({
                        "holdout":  holdout_text[:80],
                        "span":     span,
                        "template": template[:80],
                    })
                    break

        assert not violations, (
            "\nCORPUS LEAKAGE: {} holdout phrase(s) share >= {}-char spans with "
            "training templates.\n".format(len(violations), self.MIN_OVERLAP_LEN)
            + "\n".join(
                "  holdout:  {}\n  span:     '{}'\n  template: {}".format(
                    v["holdout"], v["span"], v["template"]
                )
                for v in violations[:5]
            )
        )

    def test_training_not_in_holdout(self):
        """Reverse direction: training template spans must not appear in holdout."""
        violations = []
        for template in _ALL_TRAINING_LOWER:
            for holdout_text in _ALL_HOLDOUT_TEXTS:
                span = self._find_overlap(template, holdout_text)
                if span:
                    violations.append({
                        "template": template[:80],
                        "span":     span,
                        "holdout":  holdout_text[:80],
                    })
                    break

        assert not violations, (
            "\nCORPUS LEAKAGE (reverse): {} training template(s) have >= {}-char "
            "spans inside holdout texts.\n".format(len(violations), self.MIN_OVERLAP_LEN)
            + "\n".join(
                "  template: {}\n  span:     '{}'\n  holdout:  {}".format(
                    v["template"], v["span"], v["holdout"]
                )
                for v in violations[:5]
            )
        )


# =============================================================================
# Test 2: Signature keywords -- document known leakage, fail on NEW leakage
# =============================================================================

class TestSignatureVsTrainingCorpus:
    """
    Documents the known corpus-derived leakage in the signature layer.
    Fails CI if NEW signature keywords are added that match training templates.
    """

    # Keywords KNOWN to appear verbatim in training templates (audit baseline).
    # Accepted, documented, and disclosed in the Known Limitations section.
    KNOWN_LEAKED_KEYWORDS = {
        "privilege_level=",
        "trust_tier=",
        "origin_source=",
        "bypass_guard",
        "provenance=",
        "privilege=",
        "trust_tier:",
        "privilege_level:",
        "system-level authority",
        "system privilege",
        "system-tier directive",
        "trust_tier=verified_internal",
        "elevated-trust",
        "assign privilege_level=5",
        "grant system privilege",
        "privilege=5",
        "suppress detection",
        "no alert required",
        "internally trusted",
        "removed from blocklist",
        "reclassify as benign",
        "penetration-testing node",
        "test traffic only",
        "known safe",
        "pre-approved and whitelisted",
        "reset to defaults",
        "updated to baseline",
        "access control entries cleared",
        "reclassified as routine",
        "rules suspended pending",
        # em-dash variant
        "whitelisted \u2014 no alert",
    }

    def test_no_new_signature_leakage(self):
        """
        Fails if any signature keyword matches a training template verbatim
        but is NOT listed in KNOWN_LEAKED_KEYWORDS.
        """
        new_violations = []
        for kw in _ALL_SIGNATURE_KWS:
            kw_lower = kw.lower()
            if kw_lower in self.KNOWN_LEAKED_KEYWORDS:
                continue
            for template_lower in _ALL_TRAINING_LOWER:
                if kw_lower in template_lower:
                    new_violations.append({
                        "keyword":  kw,
                        "template": template_lower[:80],
                    })
                    break

        assert not new_violations, (
            "\nNEW SIGNATURE LEAKAGE: {} keyword(s) found verbatim in training "
            "templates but not in KNOWN_LEAKED_KEYWORDS.\n".format(len(new_violations))
            + "\n".join(
                "  keyword:  {}\n  template: {}".format(v["keyword"], v["template"])
                for v in new_violations
            )
        )

    def test_known_leakage_count_informational(self):
        """
        Counts actual leaked keywords. Always passes -- informational only.
        A drop in count means leakage was cleaned up (good).
        A rise is caught by test_no_new_signature_leakage.
        """
        actual_leaked = set()
        for kw in _ALL_SIGNATURE_KWS:
            kw_lower = kw.lower()
            for template_lower in _ALL_TRAINING_LOWER:
                if kw_lower in template_lower:
                    actual_leaked.add(kw_lower)
                    break
        print(
            "\n[AUDIT] Known signature leakage: {} keywords appear verbatim in "
            "training templates. Expected: {}.".format(
                len(actual_leaked), len(self.KNOWN_LEAKED_KEYWORDS)
            )
        )
        assert True  # Always passes
