"""
Patch script: replaces hardcoded threshold literals in memory_guard.py
with reads from _MG_CFG (config/settings.yaml).
Run from repo root: python scripts/patch_mg_thresholds.py
"""
import re
import os

path = os.path.join("src", "memory_guard.py")
with open(path, encoding="utf-8") as f:
    src = f.read()

# Normalize to LF for matching
src = src.replace("\r\n", "\n")

changes = 0

# 1. ETVL Tier 2 header comment + hardcoded thresholds
patterns = [
    (
        "        # -- Tier 2: ETVL semantic/statistical detection -------------------\n"
        "        # sem_dist threshold 0.48: catches DIRECT_OVERRIDE (mean 0.51) while\n"
        "        #   keeping benign (mean 0.11) well clear of the decision boundary.\n"
        "        # imp_den threshold 0.25: catches jailbreak imperative verb density.\n"
        "        if sem_dist > 0.48:\n"
        "            return 1, \"untrusted\", True, (\n"
        "                f\"[ETVL:SEM_DIST] Adversarial centroid similarity: {sem_dist:.3f} > 0.48\"\n"
        "            )\n"
        "        if imp_den > 0.25:\n"
        "            return 1, \"untrusted\", True, (\n"
        "                f\"[ETVL:IMP_DEN] Imperative density: {imp_den:.3f} > 0.25\"\n"
        "            )\n"
        "        # Compound perplexity gate \u2014 calibrated 2026-07 against 8 benign\n"
        "        # edge-case log types (session tokens, JWTs, IPs, health checks, etc.).\n"
        "        # sem_dist companion raised from 0.20 to 0.26 after session_token_hex\n"
        "        # (PP=2787, sem_dist=0.234) triggered a false positive at 0.20.\n"
        "        # All 8 benign edge cases pass at perplexity > 1500 AND sem_dist > 0.26.\n"
        "        # (See tests/test_memory_guard.py::TestPerplexityThreshold)\n"
        "        if perplexity > 1500.0 and sem_dist > 0.26:\n"
        "            return 1, \"untrusted\", True, (\n"
        "                f\"[ETVL:PERPLEXITY] Anomaly ({perplexity:.0f}) + elevated sim ({sem_dist:.3f})\"\n"
        "            )",
        "        # -- Tier 2: ETVL semantic/statistical detection -------------------\n"
        "        # Thresholds from config/settings.yaml (memory_guard section).\n"
        "        # Edit that file to tune without touching source code.\n"
        "        _sd_thr = _MG_CFG.sem_dist_threshold        # default 0.48\n"
        "        _id_thr = _MG_CFG.imp_den_threshold          # default 0.25\n"
        "        _pp_thr = _MG_CFG.perplexity_threshold       # default 1500.0\n"
        "        _pp_sd  = _MG_CFG.perplexity_sem_companion   # default 0.26\n"
        "\n"
        "        if sem_dist > _sd_thr:\n"
        "            return 1, \"untrusted\", True, (\n"
        "                f\"[ETVL:SEM_DIST] Adversarial centroid similarity: {sem_dist:.3f} > {_sd_thr}\"\n"
        "            )\n"
        "        if imp_den > _id_thr:\n"
        "            return 1, \"untrusted\", True, (\n"
        "                f\"[ETVL:IMP_DEN] Imperative density: {imp_den:.3f} > {_id_thr}\"\n"
        "            )\n"
        "        # Compound perplexity gate. Calibrated 2026-07 against 8 benign edge-case\n"
        "        # log types. sem_dist companion raised 0.20 -> 0.26 after session_token_hex FP.\n"
        "        # (See tests/test_memory_guard.py::TestPerplexityThreshold)\n"
        "        if perplexity > _pp_thr and sem_dist > _pp_sd:\n"
        "            return 1, \"untrusted\", True, (\n"
        "                f\"[ETVL:PERPLEXITY] Anomaly ({perplexity:.0f}) + elevated sim ({sem_dist:.3f})\"\n"
        "            )",
    ),
    # 2. Soft downgrade block
    (
        "        # -- Secondary risk factors (soft downgrade, not hard quarantine) ------\n"
        "        # entropy > 5.2: benign mean 4.6, std 0.16 \u2192 ~4\u03c3 above benign mean\n"
        "        reason = f\"[CLEAN] Source={source}, hops={provenance_hops}, all features within bounds\"\n"
        "        if entropy > 5.2:\n"
        "            base_level = max(1, base_level - 1)\n"
        "            reason = f\"[SOFT:ENTROPY] High entropy {entropy:.2f} + source={source}\"\n"
        "        elif sem_dist > 0.35:\n"
        "            # Moderate similarity: soft downgrade (passes, but lower trust)\n"
        "            base_level = max(2, base_level - 1)\n"
        "            reason = f\"[SOFT:SEM_DIST] Moderate similarity {sem_dist:.3f} + source={source}\"",
        "        # -- Secondary risk factors (soft downgrade, not hard quarantine) ------\n"
        "        # Thresholds from config/settings.yaml (memory_guard section).\n"
        "        _ent_thr = _MG_CFG.entropy_soft_threshold       # default 5.2\n"
        "        _ent_sd  = _MG_CFG.entropy_soft_sem_companion   # default 0.35\n"
        "        reason = f\"[CLEAN] Source={source}, hops={provenance_hops}, all features within bounds\"\n"
        "        if entropy > _ent_thr:\n"
        "            base_level = max(1, base_level - 1)\n"
        "            reason = f\"[SOFT:ENTROPY] High entropy {entropy:.2f} + source={source}\"\n"
        "        elif sem_dist > _ent_sd:\n"
        "            # Moderate similarity: soft downgrade (passes, but lower trust)\n"
        "            base_level = max(2, base_level - 1)\n"
        "            reason = f\"[SOFT:SEM_DIST] Moderate similarity {sem_dist:.3f} + source={source}\"",
    ),
]

for old, new in patterns:
    if old in src:
        src = src.replace(old, new, 1)
        changes += 1
        print(f"[OK] Replaced pattern ({old[:60].strip()!r}...)")
    else:
        # Print the actual lines around known keywords so we can debug
        print(f"[MISS] Pattern not found. First 80 chars: {old[:80].strip()!r}")
        print("  Searching for key substrings:")
        for kw in ["0.48", "1500.0", "5.2", "0.35"]:
            for i, line in enumerate(src.splitlines(), 1):
                if kw in line and "_MG_CFG" not in line:
                    print(f"    line {i}: {line!r}")

print(f"\nTotal replacements: {changes}")
with open(path, "w", encoding="utf-8") as f:
    f.write(src)
print("Written.")
