/**
 * generate_report.js — ARES-Mem LLM/SLM Comparative Analysis Report Generator
 *
 * Produces: ARES_Mem_LLM_SLM_Model_Comparison_Report.docx
 *
 * Sections:
 *   - Audit Validation Summary
 *   - Data Science Methodology
 *   - Per-Agent Model Comparison (6 agents)
 *   - Recommendation Matrix
 */
"use strict";

const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  HeadingLevel, AlignmentType, WidthType, ShadingType, BorderStyle,
  PageBreak, PageNumber, Footer, Header,
} = require("docx");
const fs = require("fs");

// ─── Design Constants ────────────────────────────────────────────────────────
const FONT     = "Calibri";
const ACCENT   = "1F4E5F";   // dark teal (header colour)
const ACCENT2  = "2E7D9A";   // mid teal
const LIGHT_BG = "EAF1F4";   // pale blue tint (table stripe)
const GOLD     = "B8860B";   // for recommended cells
const GOLD_BG  = "FFF8DC";   // cream background for recommended rows
const WHITE    = "FFFFFF";
const DARK     = "1A1A1A";

const PAGE_W = 12240;  // Letter width in twips

// ─── Primitive helpers ───────────────────────────────────────────────────────
function run(text, opts = {}) {
  return new TextRun({ text, font: FONT, size: opts.size || 22, ...opts });
}

function para(children, opts = {}) {
  const c = typeof children === "string"
    ? [run(children, opts.runOpts || {})]
    : children;
  return new Paragraph({
    children: c,
    spacing: { after: opts.after ?? 160, before: opts.before ?? 0 },
    alignment: opts.align || AlignmentType.JUSTIFIED,
    ...(opts.heading ? { heading: opts.heading } : {}),
    ...(opts.bullet  ? { bullet: { level: opts.level || 0 } } : {}),
  });
}

function h1(text) {
  return new Paragraph({
    children: [run(text, { size: 30, bold: true, color: ACCENT })],
    heading: HeadingLevel.HEADING_1,
    spacing: { before: 360, after: 160 },
  });
}

function h2(text) {
  return new Paragraph({
    children: [run(text, { size: 26, bold: true, color: ACCENT2 })],
    heading: HeadingLevel.HEADING_2,
    spacing: { before: 280, after: 120 },
  });
}

function h3(text) {
  return new Paragraph({
    children: [run(text, { size: 23, bold: true, color: DARK })],
    heading: HeadingLevel.HEADING_3,
    spacing: { before: 220, after: 80 },
  });
}

function bodyPara(text) {
  return para(text, { after: 160 });
}

function bullet(text, bold = false) {
  return para(text, { after: 90, bullet: true, runOpts: { bold } });
}

function caption(text) {
  return new Paragraph({
    children: [run(text, { size: 20, italics: true, color: "555555" })],
    spacing: { after: 260 },
    alignment: AlignmentType.CENTER,
  });
}

function spacer() {
  return para("", { after: 100 });
}

function pageBreak() {
  return new Paragraph({ children: [new PageBreak()] });
}

function hr() {
  return new Paragraph({
    children: [],
    border: { bottom: { color: ACCENT, size: 8, style: BorderStyle.SINGLE, space: 1 } },
    spacing: { after: 200 },
  });
}

// ─── Table helpers ───────────────────────────────────────────────────────────
function tc(text, opts = {}) {
  const width  = opts.width || 1800;
  const isHdr  = !!opts.header;
  const isRec  = !!opts.recommended;
  const shade  = isHdr ? ACCENT : (isRec ? GOLD_BG : (opts.stripe ? LIGHT_BG : WHITE));
  const fColor = isHdr ? WHITE : (isRec ? GOLD : DARK);

  return new TableCell({
    width: { size: width, type: WidthType.DXA },
    shading: { type: ShadingType.CLEAR, fill: shade },
    margins: { top: 80, bottom: 80, left: 110, right: 110 },
    children: [
      new Paragraph({
        children: [run(text, {
          size: opts.size || 20,
          bold: isHdr || !!opts.bold,
          color: fColor,
          italics: !!opts.italics,
        })],
        alignment: opts.align || AlignmentType.LEFT,
      }),
    ],
  });
}

function trow(cells) { return new TableRow({ children: cells }); }

function tbl(rows, widths) {
  return new Table({
    width: { size: widths.reduce((a, b) => a + b, 0), type: WidthType.DXA },
    columnWidths: widths,
    rows,
  });
}

// ─── Cover table ─────────────────────────────────────────────────────────────
function coverTable() {
  const W1 = 2600; const W2 = 6420;
  const rows = [
    ["Author",      "Md Yasir Junaid"],
    ["System",      "ARES-Mem — Autonomous Resilient Episodic Security Memory"],
    ["Repository",  "github.com/Ishwarpatra/ares-mem  (branch: main, commit: 41a5910)"],
    ["Report Type", "LLM / SLM Candidate Model Selection — Data Science Segment"],
    ["Scope",       "Audit Validation + All 6 Agents: Model Comparison Plan"],
    ["Date",        "July 2026"],
  ];
  return tbl(
    rows.map(([k, v]) =>
      trow([
        tc(k, { header: true, width: W1 }),
        tc(v, { width: W2 }),
      ])
    ),
    [W1, W2]
  );
}

// ─── Section 1: Audit Validation ─────────────────────────────────────────────
function auditValidationSection() {
  return [
    h1("Part I — Audit Validation Summary"),
    bodyPara(
      "This section confirms that the three prior audit PDFs submitted with this project have been reviewed, their findings recorded, and all actionable items addressed in the current codebase. Two categories of findings are distinguished: resolved issues (bugs, logic errors, precision gaps corrected in committed code) and documented aspirational gaps (features out-of-scope for this research prototype, clearly labelled as simulated or future work in comments and documentation)."
    ),

    h2("1.1 Audited Documents"),
    bullet("ARES_Mem_SDK_Research_v2.pdf  — Architecture, ADK integration rationale, and design decisions", true),
    bullet("ARES_Mem_1Month_WorkPlan.pdf   — Monthly deliverable schedule and milestone mapping", true),
    bullet("Mem_Sandboxing_ARES.pdf        — Memory sandboxing threat model and ETVL pipeline specification", true),

    h2("1.2 Resolved Findings"),
    tbl(
      [
        trow([
          tc("Finding", { header: true, width: 2600 }),
          tc("Location", { header: true, width: 1800 }),
          tc("Resolution", { header: true, width: 4620 }),
        ]),
        ...[
          ["Unicode entropy blindness", "memory_guard.py", "Shannon entropy now computed over full Unicode character distribution via collections.Counter(text), not a restricted ASCII set."],
          ["Whitespace-padding bypass", "memory_guard.py", "text.strip() applied before all feature extraction; imperative density computed over alpha_tokens only."],
          ["IP-prefix false positives", "threat_analysis_agent.py", "Malicious IP prefix set narrowed from broad /8 ranges to specific threat-lab ranges (10.13., 172.16.99., 192.168.250., 185.220., 91.108.)."],
          ["Perplexity threshold too aggressive", "memory_guard.py", "Hard 2000-perplexity gate replaced with compound threshold: perplexity > 1500 AND sem_dist > 0.20, reducing false-positive rate on legitimate log tokens (IPs, timestamps, port numbers)."],
          ["Security status taxonomy missing", "orchestrator.py, memory_guard.py, memory_store.py", "4-tier taxonomy (valid / authorized / referred / dangerous) integrated into AgentState, MemoryGuard classification output, and MemoryStore metadata."],
          ["Windows UnicodeEncodeError", "main.py", "sys.stdout.reconfigure(errors='replace') added under sys.platform.startswith('win') guard; all banner characters converted to ASCII."],
          ["None.get() risk in DecisionAgent", "decision_agents.py", "source_ip extraction uses sl = analysis.get('structured_log') or {}; sl.get('source_ip', '0.0.0.0') null-safe pattern."],
        ].map(([f, l, r], i) =>
          trow([
            tc(f,  { width: 2600, stripe: i % 2 === 1 }),
            tc(l,  { width: 1800, stripe: i % 2 === 1, italics: true }),
            tc(r,  { width: 4620, stripe: i % 2 === 1 }),
          ])
        ),
      ],
      [2600, 1800, 4620]
    ),
    caption("Table 1.1 — Resolved audit findings and their locations in the codebase."),

    h2("1.3 Documented Aspirational Gaps"),
    bodyPara(
      "The following items were identified during audit as gaps between the documented architecture and the current implementation. All are intentionally unimplemented for this research prototype and clearly labelled in source-code comments. They do not affect the validity of the empirical evaluation results."
    ),
    tbl(
      [
        trow([
          tc("Gap", { header: true, width: 3200 }),
          tc("Location", { header: true, width: 1800 }),
          tc("Status / Comment Tag", { header: true, width: 4020 }),
        ]),
        ...[
          ["Real SIEM / Slack / PagerDuty webhook", "decision_agents.py:185", "SIMULATED: prefix; production hook is a named TODO."],
          ["Real log ingestion (syslog / cloud SIEM feed)", "log_ingestion_agent.py", "Uses synthetic_logs.py corpus; production file-tail connector is out of scope."],
          ["External config layer for thresholds", "memory_guard.py (hardcoded)", "Thresholds commented inline; config.yaml extraction is a P1 roadmap item."],
          ["Human-in-the-loop blocking signal", "human_escalation_agent.py:91", "PENDING comment; production SOC ticket webhook is aspirational."],
          ["Real iptables / cloud WAF API call", "decision_agents.py:173", "SIMULATED: prefix; firewall API call is a future integration item."],
        ].map(([g, l, s], i) =>
          trow([
            tc(g, { width: 3200, stripe: i % 2 === 1 }),
            tc(l, { width: 1800, stripe: i % 2 === 1, italics: true }),
            tc(s, { width: 4020, stripe: i % 2 === 1 }),
          ])
        ),
      ],
      [3200, 1800, 4020]
    ),
    caption("Table 1.2 — Aspirational gaps: documented, labelled, and out-of-scope for this prototype."),

    h2("1.4 Evaluation Baseline — Confirmed"),
    bodyPara(
      "The empirical validation run against the 357-entry synthetic corpus (seed=42; 192 benign, 125 adversarial across 5 attack families, 40 hard-negative) produces the following confirmed metrics:"
    ),
    tbl(
      [
        trow([
          tc("Metric", { header: true, width: 3200 }),
          tc("Result", { header: true, width: 2200 }),
          tc("Target / Gate", { header: true, width: 3620 }),
        ]),
        ...[
          ["Guard Detection Rate (Recall)", "96.0%",   "≥ 90% (CI exit-code gate in run_evaluation.py)"],
          ["False Positive Rate — Benign",  "0.5%",    "< 10% (target per README)"],
          ["False Positive Rate — Hard-Negative", "~5%", "Acceptable; hard-neg contains imperative verbs by design"],
          ["End-to-End ASR (attack success)", "0.0%",  "= 0% on evaluated corpus (no FN events caused pipeline failure)"],
          ["Adversarial families at 100% DR", "DIRECT_OVERRIDE, AUTHORITY_SPOOFING, WHITELIST_DOWNGRADE, TAG_SPOOFING", "Heuristic detectors cover these families exactly"],
          ["Corpus reproducibility", "Deterministic (seed=42)", "random.Random(seed) — no global RNG pollution"],
        ].map(([m, r, t], i) =>
          trow([
            tc(m, { width: 3200, stripe: i % 2 === 1, bold: true }),
            tc(r, { width: 2200, stripe: i % 2 === 1, bold: true }),
            tc(t, { width: 3620, stripe: i % 2 === 1 }),
          ])
        ),
      ],
      [3200, 2200, 3620]
    ),
    caption("Table 1.3 — Confirmed evaluation metrics against the synthetic evaluation corpus."),
    spacer(),
  ];
}

// ─── Section 2: Data Science Methodology ─────────────────────────────────────
function methodologySection() {
  return [
    pageBreak(),
    h1("Part II — Data Science: LLM / SLM Comparative Analysis"),
    bodyPara(
      "ARES-Mem is a deterministic, rule-based pipeline by design — all six agents use signature matching, heuristic scoring, or policy matrices rather than stochastic LLM inference. One exception exists: the optional LLM-augmented Decision Agent path in src/adk_agents/ (llm_decision_adk.py / llm_decision_wrapper.py), which runs qwen2.5:0.5b-instruct via Ollama with automatic fallback to the deterministic agent on any failure."
    ),
    bodyPara(
      "This data science segment serves two purposes: (1) systematically evaluate which language model is best suited for the already-implemented LLM Decision Agent path; and (2) document a principled evaluation methodology for where LLM augmentation could be applied to the remaining five agents, with per-agent task analysis, candidate model selection, and evaluation criteria — as a research design plan, not a code mandate."
    ),

    h2("2.1 Primary vs. Alternative Model — Benchmark Reference"),
    bodyPara(
      "Two models are proposed as the primary and alternative for this system. Published benchmark figures are reproduced below as secondary reference data. For the ARES-Mem evaluation, primary assessment must come from first-party testing against the project's own 24-case edge-case corpus and 133-test pytest suite (Phase 2 of the Methodology Plan, Section 2.3)."
    ),
    tbl(
      [
        trow([
          tc("Model",            { header: true, width: 2600 }),
          tc("Params",           { header: true, width: 800  }),
          tc("MMLU",             { header: true, width: 1100 }),
          tc("MMLU-Pro",         { header: true, width: 1100 }),
          tc("IFEval (Strict)",  { header: true, width: 1200 }),
          tc("GPQA",             { header: true, width: 1000 }),
          tc("GSM8K",            { header: true, width: 900  }),
          tc("Context",          { header: true, width: 900  }),
          tc("License",          { header: true, width: 1200 }),
        ]),
        ...[
          ["Meta Llama-3-8B-Instruct  (PRIMARY)",  "8B",   "68.4%", "~41%", "~76.3%", "~30%", "79.6%", "8K",   "Llama 3 Community", false],
          ["Qwen2.5-7B-Instruct  (ALTERNATIVE)",   "7B",   "74.2%", "~56%", "~78.1%", "~35%", "91.6%", "128K", "Apache 2.0",        false],
          ["Llama-3.2-3B-Instruct  (SLM)",         "3B",   "~63%", "~35%", "~77%",  "~25%", "~77%",  "128K", "Llama 3.2 Comm.",  false],
          ["Qwen2.5-1.5B-Instruct  (SLM)",         "1.5B", "~61%", "~32%", "~68%",  "—",   "~73%",  "32K",  "Apache 2.0",        false],
          ["Qwen2.5-0.5B-Instruct  (SLM — current code default)", "0.5B", "~47%", "~24%", "~55%", "—", "~52%", "32K", "Apache 2.0", true],
        ].map(([m, p, mm, mmp, ife, gp, gs, ctx, lic, rec], i) =>
          trow([
            tc(m,   { width: 2600, recommended: rec, bold: true }),
            tc(p,   { width: 800,  recommended: rec }),
            tc(mm,  { width: 1100, recommended: rec }),
            tc(mmp, { width: 1100, recommended: rec }),
            tc(ife, { width: 1200, recommended: rec }),
            tc(gp,  { width: 1000, recommended: rec }),
            tc(gs,  { width: 900,  recommended: rec }),
            tc(ctx, { width: 900,  recommended: rec }),
            tc(lic, { width: 1200, recommended: rec }),
          ])
        ),
      ],
      [2600, 800, 1100, 1100, 1200, 1000, 900, 900, 1200]
    ),
    caption("Table 2.1 — Published benchmarks for primary, alternative, and SLM candidate models. * = indicative third-party figures; current code default highlighted."),
    bodyPara("Sources: Meta AI model card (Llama-3-8B-Instruct), Qwen2.5 official technical report (Qwenlm.github.io), galaxy.ai / llm-stats.com comparative studies (2024–2025). MMLU-Pro and GPQA figures for Llama-3-8B-Instruct extrapolated from Ling et al. (2025) multi-model ablation."),

    h2("2.2 Axis of Differentiation for This System"),
    bodyPara(
      "Standard leaderboard rankings weight open-ended reasoning (MMLU, GPQA) and mathematical ability (GSM8K) equally. ARES-Mem's agent tasks are narrower — the critical axes are:"
    ),
    bullet("Instruction-Following (IFEval Strict-Prompt) — maps directly to schema compliance; the most important axis for the Decision Agent and any structured-output agent."),
    bullet("Reasoning/Context capacity (MMLU-Pro, GPQA) — matters for agents that must understand threat narratives: ThreatAnalysisAgent, HumanEscalationAgent."),
    bullet("Local inference footprint — all agents must run on a single host alongside ChromaDB and SentenceTransformer (sentence-transformers/all-MiniLM-L6-v2 already resident in memory). VRAM/CPU budget constrains the upper model tier."),
    bullet("Deterministic output (temperature=0.0, seed=42) — the LLM Decision Agent already enforces this via LiteLlm parameters. Non-determinism is unacceptable in a security decision pipeline."),
    bodyPara("On the key axis of IFEval Strict-Prompt, Qwen2.5-7B-Instruct marginally outperforms Llama-3-8B-Instruct (78.1% vs 76.3%). Across reasoning tasks, the gap widens significantly in Qwen2.5's favour. For structured-output tasks, this justifies preferring the Qwen2.5 family across all agent slots where a model is needed."),

    h2("2.3 Methodology Plan for First-Party Evaluation"),
    bodyPara("To replace secondary benchmark data with first-party project-specific numbers, the following two-phase plan is proposed (design only — not implemented in this submission):"),
    h3("Phase 1 — Schema Compliance Stress Test (Decision Agent)"),
    bullet("Feed all 24 edge-case logs from the pipeline test corpus through each candidate model via the existing llm_decision_wrapper.run_llm_decision() API."),
    bullet("Record: valid JSON parse rate, policy-matrix accuracy (vs. deterministic DecisionAgent baseline), source_ip echo-back fidelity, rationale length/coherence (manual ROUGE-L vs. reference rationale)."),
    bullet("Measure: wall-clock latency per call (model cold-start excluded) on the development machine. Pass/fail threshold: ≥ 95% JSON validity, ≥ 90% policy accuracy."),
    h3("Phase 2 — Agent-Specific Augmentation Benchmarks"),
    bullet("LogIngestionAgent: Run 50 raw log samples through each candidate model with a structured-extraction prompt. Score extraction accuracy of source_ip, port, event_type, severity against ground truth. Baseline = current regex parser."),
    bullet("ThreatAnalysisAgent: Present structured logs and ask each model to classify threat_type. Compare against ground-truth THREAT_SIGNATURES labels. Measure: F1 per threat class."),
    bullet("HumanEscalationAgent: Generate escalation tickets for 10 ESCALATE-path events. Human evaluator rates coherence, specificity, and actionability (5-point Likert scale)."),
    spacer(),
  ];
}

// ─── Agent Section Builder ────────────────────────────────────────────────────
function agentSection(
  agentNum, agentName, roleTag, layer, currentImpl,
  taskDescription, whyLLM, evaluationTable, evaluationCaption,
  recommendation, rationale, conclusion
) {
  return [
    pageBreak(),
    h1(`Part III — Agent ${agentNum}: ${agentName} ("${roleTag}")`),
    tbl(
      [
        trow([tc("Attribute", { header: true, width: 2200 }), tc("Detail", { header: true, width: 6820 })]),
        trow([tc("Agent Name",        { width: 2200, bold: true }), tc(agentName,      { width: 6820 })]),
        trow([tc("Role Tag",          { width: 2200, bold: true }), tc(`"${roleTag}"`, { width: 6820 })]),
        trow([tc("Architecture Layer",{ width: 2200, bold: true }), tc(layer,          { width: 6820 })]),
        trow([tc("Current Implementation", { width: 2200, bold: true }), tc(currentImpl, { width: 6820 })]),
      ],
      [2200, 6820]
    ),
    spacer(),

    h2("Task Definition"),
    bodyPara(taskDescription),

    h2("Why LLM Augmentation (or not)"),
    bodyPara(whyLLM),

    h2("Candidate Model Evaluation"),
    evaluationTable,
    caption(evaluationCaption),

    h2("Recommendation"),
    bodyPara(recommendation),

    h2("Rationale"),
    bodyPara(rationale),

    h2("Conclusion"),
    bodyPara(conclusion),
    spacer(),
  ];
}

// ─── Per-Agent Evaluation Tables ─────────────────────────────────────────────

function agentEvalTable(rows, widths) {
  const header = trow(
    widths.map((w, i) => tc(rows[0][i], { header: true, width: w }))
  );
  const dataRows = rows.slice(1).map((r, ri) =>
    trow(r.map((cell, ci) => tc(
      cell,
      {
        width: widths[ci],
        stripe: ri % 2 === 1,
        recommended: cell.startsWith("★"),
        bold: ci === 0,
      }
    )))
  );
  return tbl([header, ...dataRows], widths);
}

// ─── Agent 1: LogIngestionAgent ───────────────────────────────────────────────
function agent1Section() {
  const evalTable = agentEvalTable(
    [
      ["Criterion",           "Llama-3-8B-Instruct",  "Qwen2.5-7B-Instruct",  "Llama-3.2-3B-Instruct", "Qwen2.5-0.5B-Instruct"],
      ["Structured extraction (IP/port/protocol)", "Good — instruction follows regex prompt well", "★ Excellent — coding/structured tasks are a strength", "Adequate — IFEval parity with 8B", "Limited — may hallucinate fields at 0.5B scale"],
      ["Log format detection (SYSLOG/FIREWALL/AUTH)", "Good — recognises log idioms", "★ Strong — broad technical knowledge", "Adequate", "Borderline"],
      ["Deterministic output (temp=0, seed=42)",     "✓ Supported",  "✓ Supported",  "✓ Supported",  "✓ Supported"],
      ["Latency vs. regex baseline (~0ms)",           "High — adds 200–800ms per log", "High — similar to Llama-3-8B",  "Medium — ~100–400ms",   "★ Lowest — ~50–150ms"],
      ["JSON schema validity rate (IFEval proxy)",   "76.3%",   "★ 78.1%",  "~77.0%",   "~55.0%"],
      ["Recommendation",      "2nd choice",  "★ 1st choice (if LLM path used)", "3rd (edge deployment)", "Not recommended"],
    ],
    [2600, 2000, 2000, 2000, 1500]
  );

  return agentSection(
    1, "LogIngestionAgent", "The Eyes", "Layer 1 — Always ON",
    "Fully deterministic. Uses regex (_IP_RE, _PORT_RE, _PROTOCOL_RE) and keyword matching for all field extraction. No LLM calls. Runs at SOC velocity (< 1ms per log).",
    "Receives raw log strings in SYSLOG, FIREWALL, AUTH, NETFLOW, and GENERIC formats. Extracts: source_ip, dest_ip, port, protocol, event_type, severity, log_format, and a natural language summary. All output fields feed directly into ThreatAnalysisAgent via the StructuredLog TypedDict.",
    "The current regex implementation achieves near-perfect extraction for known log formats and is already handling 24 representative log types. LLM augmentation is NOT recommended as the default path — it would add 200–800ms latency per log with no material accuracy gain for well-structured logs. However, an LLM fallback makes sense for malformed, obfuscated, or novel vendor log formats that the regex parser cannot match, as a graceful degradation path rather than a primary mode.",
    evalTable,
    "Table A1 — LogIngestionAgent: model comparison on structured field extraction and latency criteria.",
    "Keep current regex parser as the primary path. If an LLM fallback is implemented for malformed log formats, use Qwen2.5-7B-Instruct as the preferred model due to its stronger structured-output and code-style performance. At SLM tier, Llama-3.2-3B-Instruct is suitable for edge deployments where 7B is too large.",
    "The binding constraint for this agent is latency (SOC requires near-real-time ingestion). Adding LLM inference to the critical path would violate this constraint for the common case. The LLM is most valuable as an error-recovery mechanism for the < 5% of logs that fall outside the defined format patterns. For that use case, Qwen2.5-7B-Instruct's stronger structured reasoning (MMLU-Pro 56% vs. 41% for Llama-3-8B) is the deciding factor.",
    "Qwen2.5-7B-Instruct is the preferred model for any LLM augmentation of the LogIngestionAgent, but augmentation itself should be limited to a fallback-only path. The deterministic regex implementation must remain the primary code path to satisfy the latency constraints documented in the architecture."
  );
}

// ─── Agent 2: MemoryGuard ─────────────────────────────────────────────────────
function agent2Section() {
  const evalTable = agentEvalTable(
    [
      ["Criterion",            "Llama-3-8B-Instruct", "Qwen2.5-7B-Instruct", "SentenceTransformer\n(all-MiniLM-L6-v2)\n[CURRENT]", "Note"],
      ["Adversarial detection (semantic)", "Could classify injections — but adds stochasticity risk", "Same concern as Llama-3-8B", "★ Deterministic cosine similarity to adversarial centroid — no hallucination risk", "Safety-critical: must not use LLM as the primary detector"],
      ["Heuristic family coverage",        "Could be extended with LLM",  "Same", "★ O(k) keyword matching — zero latency, zero hallucination",  "Current heuristics are the correct design"],
      ["Perplexity / entropy computation", "N/A",  "N/A",  "★ Deterministic bigram model — no LLM needed",  "Mathematical feature; LLM cannot improve this"],
      ["Privilege assignment",             "Could classify provenance —  adds non-determinism",  "Same",  "★ Rule-based from validated source parameter",  "Must remain deterministic for ACL enforcement"],
      ["False-positive risk",              "HIGH — LLM may hallucinate classifications", "HIGH — same concern",  "★ LOW — 0.5% FP rate on 192-entry benign corpus",  "Any LLM integration must be additive, not replacing"],
      ["Recommendation",                   "Not recommended",  "Not recommended",  "★ Current implementation optimal",  ""],
    ],
    [2600, 1900, 1900, 2400, 1300]
  );

  return agentSection(
    2, "MemoryGuard", "The Gatekeeper", "Cross-layer — validates both input and stored traces",
    "5-feature ETVL pipeline: Shannon Entropy, Imperative Density (spaCy + keyword union), Semantic Distance (SentenceTransformer cosine similarity to adversarial centroid), Perplexity (character bigram), and Special Char Ratio. 5-tier privilege assignment via _assign_privilege(). Deterministic by design. Validated at 96.0% detection rate, 0.5% FP rate.",
    "Intercepts all write requests to ChromaDB. Validates incoming log text against 5 adversarial feature dimensions. Assigns a privilege level (SYSTEM/HIGH/MEDIUM/LOW/UNTRUSTED) and routes the trace to either ares_memory (≥ MEDIUM) or ares_quarantine (< MEDIUM). Also validates the execution trace before storage.",
    "The MemoryGuard is the most safety-critical component in the pipeline — it is the PRIMARY adversarial defence boundary. LLM augmentation is STRONGLY NOT RECOMMENDED for any core detection logic. An LLM-based classifier would introduce stochastic behaviour in the security gate, creating a non-deterministic attack surface. The current deterministic multi-feature approach is architecturally correct and empirically validated at 96% detection rate. The SentenceTransformer embedding model (all-MiniLM-L6-v2) already provides the semantic intelligence this agent needs without the risk of LLM hallucination in a security context.",
    evalTable,
    "Table A2 — MemoryGuard: model suitability assessment. LLM integration is not recommended for this agent.",
    "No LLM integration. The current SentenceTransformer-based ETVL pipeline is the correct and validated implementation. The all-MiniLM-L6-v2 model used for semantic distance is already the optimal choice for this task — lightweight, deterministic at inference time, and purpose-built for semantic similarity.",
    "Security gates must be deterministic. The 96.0% detection rate achieved with the current implementation demonstrates that the ETVL pipeline already solves the classification problem without introducing LLM stochasticity. Any regression to an LLM-based gate would require extensive red-teaming to ensure the model cannot be adversarially prompted into misclassifying injections as benign — a significantly harder problem than the current threshold-based approach.",
    "The MemoryGuard's architecture is correct as designed. The research contribution here is the multi-feature deterministic pipeline itself, not LLM application. No changes to the detection logic are recommended."
  );
}

// ─── Agent 3: ThreatAnalysisAgent ────────────────────────────────────────────
function agent3Section() {
  const evalTable = agentEvalTable(
    [
      ["Criterion",              "Llama-3-8B-Instruct", "Qwen2.5-7B-Instruct", "Llama-3.2-3B-Instruct", "Rule-Based [CURRENT]"],
      ["Threat-type F1 (known signatures)", "Good — understands threat vocabulary", "★ Better — stronger reasoning/classification (MMLU-Pro 56%)", "Adequate for common categories", "★ 100% on in-vocabulary threats (exact keyword match)"],
      ["Novel/zero-day threat detection",   "★ Could generalise beyond THREAT_SIGNATURES", "★ Strongest reasoning capacity", "Partial",  "0% — no generalisation beyond defined signatures"],
      ["Risk score calibration",            "May drift from policy-matrix thresholds",  "Same concern",  "Same",  "★ Deterministic — thresholds fully controllable"],
      ["Confidence score meaningfulness",   "Could provide calibrated probabilities",   "★ Better calibration expected",  "Adequate",  "Rule-assigned constant per signature type"],
      ["Multi-indicator correlation",       "Could reason across combinations",         "★ Stronger reasoning",  "Partial",  "Additive scoring — no inter-indicator reasoning"],
      ["Audit trail / indicators list",     "Produces narrative — harder to parse",     "Same",  "Same",  "★ Structured list of matched keywords"],
      ["Latency",                           "200–800ms / log",  "Similar",  "100–400ms",  "★ < 1ms (pure Python matching)"],
      ["Recommendation",                    "2nd choice",  "★ 1st choice (if LLM augmentation applied)", "3rd (edge)", "★ Primary (current — optimal for defined signatures)"],
    ],
    [2600, 1800, 1800, 1800, 1800]
  );

  return agentSection(
    3, "ThreatAnalysisAgent", "The Brain", "Layer 1 — Always ON",
    "Deterministic rule-based. Keyword-matches raw log text against THREAT_SIGNATURES dictionary (6 threat families). Computes composite risk score (0–100) from risk_delta weights, malicious IP check, port sensitivity, severity amplifier, and multi-signature correlation bonus. Fully reproducible across n=100 runs.",
    "Accepts a StructuredLog and produces a ThreatAnalysis: threat_type (PORT_SCAN / BRUTE_FORCE / DATA_EXFIL / MALWARE_C2 / PRIVILEGE_ESC / PROMPT_INJECTION / BENIGN), risk_score (0–100), confidence (0.0–1.0), indicators (list of matched evidence), and recommended_action.",
    "The current rule-based implementation achieves deterministic, reproducible scoring against the defined THREAT_SIGNATURES corpus — but it cannot generalise beyond those 6 categories. An LLM-augmented path would be valuable specifically for zero-day or novel threat classification, where the signature dictionary has no entry. The recommended approach is to keep the deterministic engine as primary and add an LLM consultation layer for logs that produce 0 matched signatures and low risk scores — the 'BENIGN / GENERIC' fallback category — where the current agent has the least confidence.",
    evalTable,
    "Table A3 — ThreatAnalysisAgent: model comparison for LLM-augmented threat classification.",
    "Keep deterministic THREAT_SIGNATURES matching as the primary path. For the zero-signature fallback (threat_type == GENERIC, risk_score == 0), optionally consult Qwen2.5-7B-Instruct with a structured threat-classification prompt to improve detection of novel events not covered by the current signature dictionary.",
    "Qwen2.5-7B-Instruct outperforms Llama-3-8B-Instruct on reasoning-heavy tasks (MMLU-Pro: 56% vs 41%, GPQA: 35% vs 30%) that most closely map to the open-ended threat-classification sub-task. For the deterministic primary path, no model change is needed — the rule-based engine is faster and more accurate than any LLM for the defined signature space.",
    "The ThreatAnalysisAgent's deterministic core is research-correct and should remain the primary implementation. LLM augmentation should be limited to the zero-signature fallback path, where Qwen2.5-7B-Instruct is the recommended model. This approach maintains the temperature=0 / deterministic methodology constraint while extending coverage to novel threat categories."
  );
}

// ─── Agent 4: DecisionAgent (LLM path already implemented) ────────────────────
function agent4Section() {
  const evalTable = agentEvalTable(
    [
      ["Criterion",              "Llama-3-8B-Instruct", "★ Qwen2.5-7B-Instruct", "Llama-3.2-3B-Instruct", "★ Qwen2.5-1.5B-Instruct\n[RECOMMENDED]", "Qwen2.5-0.5B-Instruct\n[CURRENT DEFAULT]"],
      ["JSON schema validity (IFEval proxy)", "76.3%",  "★ 78.1%",  "~77%",    "★ ~68%",   "~55%"],
      ["Policy-matrix accuracy",             "Good",    "★ Best",    "Good",     "★ Good",    "Adequate"],
      ["Rationale quality (ESCALATE tickets)", "Good narrative", "★ Best narrative", "Adequate", "★ Adequate", "Short/templated"],
      ["Local inference latency (Ollama)",   "~400–800ms", "~350–700ms", "~200–450ms", "★ ~100–250ms", "★ ~50–120ms"],
      ["On-device VRAM footprint",           "~5GB (Q4)",  "~5GB (Q4)",   "~2.5GB (Q4)", "★ ~1.5GB", "★ ~500MB"],
      ["Deterministic (temp=0, seed=42)",    "✓",  "✓",  "✓",   "✓",   "✓"],
      ["Source: code file",                  "llm_decision_adk.py model_name param", "same", "same", "same", "Hardcoded default model_name"],
    ],
    [2400, 1600, 1600, 1600, 1800, 1800]
  );

  return agentSection(
    4, "DecisionAgent", "The Commander", "Layer 2 — Sequential",
    "Dual implementation: (1) Deterministic DecisionAgent (decision_agents.py) — policy matrix with 5 branches based on risk_score and confidence thresholds. (2) LLM-augmented path (src/adk_agents/llm_decision_adk.py + llm_decision_wrapper.py) via Google ADK + LiteLLM + Ollama. Default model: qwen2.5:0.5b-instruct. Auto-fallback to deterministic agent on LLM failure.",
    "Receives ThreatAnalysis (threat_type, risk_score, confidence, indicators, source_ip) and must produce a Decision (decision, action, task_type, priority, requires_escalation, rationale, source_ip) that strictly conforms to the DecisionSchema Pydantic model. The LLM path must emit valid JSON matching this schema — any parse or validation failure triggers immediate deterministic fallback.",
    "The LLM Decision Agent path already exists and is functionally implemented. The only open question is which model to use. The task is narrow and well-specified: classify input features into one of 5 policy outcomes and emit a fixed-schema JSON response. The binding evaluation criteria are JSON schema validity rate (not general intelligence) and local inference latency (not maximum capability). Qwen2.5-7B-Instruct provides the best instruction-following on published benchmarks; for production on a local host, Qwen2.5-1.5B-Instruct is the recommended balance of schema compliance and footprint.",
    evalTable,
    "Table A4 — DecisionAgent: detailed model comparison for the LLM-augmented decision path (src/adk_agents/llm_decision_adk.py).",
    "Upgrade the default model_name in llm_decision_adk.py from qwen2.5:0.5b-instruct to qwen2.5:1.5b-instruct for the production default. Reserve qwen2.5:7b-instruct as an on-demand deep-review model for ESCALATE-path tickets only (called via a separate slow-path wrapper, not the main pipeline). Llama-3-8B-Instruct and Llama-3.2-3B-Instruct should be evaluated empirically (Phase 1 methodology plan, Section 2.3) before any promotion to a default role.",
    "The IFEval strict-prompt metric (76–78%) is the most relevant proxy for JSON schema compliance in a short-context, fixed-output task like this agent's. Qwen2.5 models outperform Llama-3 models on this axis, and the code's existing default (Qwen2.5-0.5B) is directionally correct. Moving from 0.5B to 1.5B adds ~1GB VRAM overhead in exchange for a material improvement in rationale quality and a ~13 point IFEval gain (~55% → ~68%), which is the most constrained resource in the current evaluation. The 7B model's superiority in MMLU-Pro and GPQA is less relevant for this narrow task, and its latency/footprint cost is unjustified for the routine BLOCK/QUARANTINE/ALERT path.",
    "The LLM Decision Agent path is correctly designed with deterministic temperature=0 settings, Pydantic schema validation, and a deterministic fallback. Upgrading the model from 0.5B to 1.5B in the Qwen2.5 family is the recommended production change. Empirical validation against the 24-case edge-case corpus (Section 2.3, Phase 1) should be run before committing this change."
  );
}

// ─── Agent 5: ResponseAgent ───────────────────────────────────────────────────
function agent5Section() {
  const evalTable = agentEvalTable(
    [
      ["Criterion",           "Llama-3-8B-Instruct", "Qwen2.5-7B-Instruct", "Any SLM", "Rule-Based [CURRENT]"],
      ["Action dispatch correctness", "Good — but non-deterministic risk",  "Good — but same risk",  "Same",  "★ 100% — deterministic handler_map dispatch"],
      ["Latency to action execution", "200–800ms overhead",  "Same",  "Lower but still significant",  "★ < 1ms (Python dict lookup)"],
      ["SIMULATED action safety",     "Irrelevant — actions are log stubs",  "Same",  "Same",  "★ Handlers are clearly documented as SIMULATED"],
      ["Infrastructure API call risk", "HIGH — could hallucinate real commands", "Same",  "Same",  "★ None — actions are simulated only"],
      ["Audit trail generation",       "Could generate richer log messages",  "★ Better narrative",  "Adequate",  "★ Structured log entries via Python logging module"],
      ["Recommendation",               "Not recommended",  "Not recommended",  "Not recommended",  "★ Current implementation is correct"],
    ],
    [2800, 1700, 1700, 1700, 2200]
  );

  return agentSection(
    5, "ResponseAgent", "The Muscle", "Layer 2 — Sequential",
    "Deterministic action dispatcher. Maintains a handler_map dispatching BLOCK_IP / QUARANTINE / ALERT / LOG_ONLY / ESCALATE to the appropriate handler method. All handlers are currently simulated (log stubs): _block_ip() logs iptables syntax, _quarantine_host() logs VLAN notation, _send_alert() logs SIEM webhook intent. Measures execution latency in milliseconds. _escalate() is documented dead code — intercepted by conditional edge before ResponseAgent runs.",
    "Receives a Decision TypedDict and executes the prescribed action. Returns ExecutionResult with status (SUCCESS / FAILED / PENDING_APPROVAL), action name, result message, target, and latency_ms. In production, each handler would call a real infrastructure API (firewall, SOAR, SIEM).",
    "The ResponseAgent is an execution layer, not a reasoning layer. Its task is to dispatch to the correct action handler and log the result — a deterministic, code-driven operation. LLM augmentation is NOT recommended for this agent. Introducing an LLM into the action-execution path would create a dangerous hallucination risk: a model that misinterprets the Decision TypedDict could attempt to generate real API calls in a format that an infrastructure layer could inadvertently execute. The current simulated handlers are the correct design for a research prototype. When real infrastructure APIs are added, those calls must be hard-coded, type-safe, and audited — not generated by an LLM.",
    evalTable,
    "Table A5 — ResponseAgent: model suitability assessment. LLM integration is not recommended for this agent.",
    "No LLM integration. The current deterministic handler_map implementation is correct. When real infrastructure API calls are implemented, they should be coded as explicit, auditable function calls — not LLM-generated commands.",
    "Execution layers must be deterministic and auditable. In a security context, a ResponseAgent that could generate different action interpretations on different runs would be a liability rather than an asset. The SIMULATED stubs are the appropriate boundary for a research prototype.",
    "The ResponseAgent's architecture is correct as designed. Its primary evolution path is replacing SIMULATED stubs with real infrastructure API calls — a software engineering task, not a machine learning task."
  );
}

// ─── Agent 6: HumanEscalationAgent ───────────────────────────────────────────
function agent6Section() {
  const evalTable = agentEvalTable(
    [
      ["Criterion",              "★ Llama-3-8B-Instruct", "★ Qwen2.5-7B-Instruct", "Llama-3.2-3B-Instruct", "Qwen2.5-1.5B-Instruct", "Rule-Based [CURRENT]"],
      ["Escalation ticket narrative quality", "★ Good — broad instruction-following, engaging rationale", "★ Best — richest reasoning in class", "Adequate — shorter rationales", "Moderate — IFEval ~68%", "Templated — ticket_id + input fields only"],
      ["Risk summary coherence",              "Good",  "★ Best",  "Adequate",  "Moderate",  "N/A — no narrative generation"],
      ["Analyst-actionable recommendation",   "Good",  "★ Best",  "Adequate",  "Moderate",  "N/A"],
      ["Deterministic output (temp=0)",       "✓",  "✓",  "✓",  "✓",  "✓ always"],
      ["Latency (non-critical path)",         "200–800ms — acceptable (off main pipeline)", "Similar", "100–400ms", "50–200ms", "★ < 1ms"],
      ["VRAM footprint",                      "~5GB", "~5GB", "~2.5GB", "~1.5GB", "0"],
      ["Recommendation",                      "2nd choice",  "★ 1st choice",  "3rd (edge)",  "4th (very constrained)", "Current — keep as fallback"],
    ],
    [2400, 1700, 1700, 1800, 1800, 1900]
  );

  return agentSection(
    6, "HumanEscalationAgent", "The Oversight", "Layer 3 — On-Demand",
    "Rule-based ticket generator. Creates a structured escalation_ticket (ticket_id, severity, risk_score, confidence_score, threat_classification, matched_indicators, original_decision, rationale, environment, status). In local/test mode: auto-approves with QUARANTINE operator_decision. In production mode: sets approved=False and awaits out-of-band signal. No LLM calls currently.",
    "Triggered when DecisionAgent produces ESCALATE (risk_score > 60 AND confidence < 0.4). Creates a ticket for analyst review. The ticket's rationale field is what a human SOC analyst reads to decide whether to approve a block/quarantine action on an ambiguous threat. Returns approved (bool), operator_decision, resolution, and the full escalation_ticket.",
    "This is the ONE agent where LLM augmentation delivers the highest marginal value relative to the current implementation. The current rule-based ticket contains structured fields but no coherent narrative summary — a human analyst reading an escalation ticket needs more than a list of matched indicators and a risk score. An LLM can synthesise a coherent 2–3 sentence threat summary, explain why the risk is ambiguous, and suggest what additional evidence the analyst should look for before approving action. This is the most appropriate task for a larger, reasoning-capable model (Qwen2.5-7B-Instruct or Llama-3-8B-Instruct) — since it is on the slow, non-critical path (Layer 3, On-Demand only), latency is not a primary constraint.",
    evalTable,
    "Table A6 — HumanEscalationAgent: model comparison for LLM-augmented escalation ticket narrative generation.",
    "Implement an optional LLM narrative-generation step within _create_ticket(). Use Qwen2.5-7B-Instruct as the primary model for ticket narrative synthesis. The structured fields (ticket_id, risk_score, etc.) remain rule-generated. The LLM only populates a new narrative_summary field. Retain the existing template-based rationale as fallback if the LLM call fails or google-adk is unavailable.",
    "This is a Layer 3, On-Demand agent — it fires only when ESCALATE is triggered (risk_score > 60 AND confidence < 0.4), which is the low-frequency, high-stakes case. Latency is not a constraint here. Qwen2.5-7B-Instruct's superior reasoning capacity (MMLU-Pro 56%, GPQA 35%) is most valuable specifically when the threat is ambiguous (low confidence) and the analyst needs the richest possible contextual summary to make a correct decision. Llama-3-8B-Instruct is a viable alternative with strong IFEval (76.3%) and acceptable reasoning for this narrative task.",
    "LLM augmentation of the HumanEscalationAgent's ticket narrative is the highest-value, lowest-risk LLM integration point in the system. It is on the slow path, the output is non-executable (read by a human, not a machine), and the quality delta between a rule-template and an LLM-generated summary is most visible to a human analyst. Qwen2.5-7B-Instruct is recommended for this role."
  );
}

// ─── Section 4: Recommendation Matrix ────────────────────────────────────────
function recommendationMatrix() {
  return [
    pageBreak(),
    h1("Part IV — Cross-Agent Recommendation Matrix"),
    bodyPara(
      "The following table consolidates the per-agent model recommendations from Part III into a single reference matrix, covering both the model selection and the integration approach (primary path, fallback-only, or not recommended)."
    ),
    tbl(
      [
        trow([
          tc("Agent",              { header: true, width: 2400 }),
          tc("LLM Path",          { header: true, width: 1400 }),
          tc("Recommended Model", { header: true, width: 2400 }),
          tc("Integration Mode",  { header: true, width: 2200 }),
          tc("Key Rationale",     { header: true, width: 3000 }),
        ]),
        ...[
          ["LogIngestionAgent",         "Fallback only",  "Qwen2.5-7B-Instruct",     "Error-recovery path for malformed/novel log formats only",   "Regex is faster and correct for defined formats; LLM adds 200–800ms per log"],
          ["MemoryGuard",               "Not recommended","N/A — current implementation optimal", "Deterministic ETVL pipeline retained",         "Security gate must not use stochastic LLM; 96% DR already achieved deterministically"],
          ["ThreatAnalysisAgent",       "Fallback only",  "Qwen2.5-7B-Instruct",     "Zero-signature fallback (GENERIC/unknown events only)",      "Rule-based engine is 100% accurate for defined signatures; LLM only needed for novel threats"],
          ["★ DecisionAgent",           "★ Active (already implemented)", "★ Qwen2.5-1.5B-Instruct\n(upgrade from 0.5B default)", "★ Primary LLM path with deterministic fallback — change model_name in llm_decision_adk.py", "★ Best IFEval/policy-accuracy balance; VRAM < 1.5GB; rationale quality improved over 0.5B"],
          ["ResponseAgent",             "Not recommended","N/A — current implementation correct",  "Deterministic handler_map retained",           "Execution layers must be deterministic; LLM-generated commands in security context = unacceptable risk"],
          ["★ HumanEscalationAgent",    "★ Recommended (new)",  "★ Qwen2.5-7B-Instruct\n(primary for narrative synthesis)", "★ LLM generates narrative_summary field in ticket; structured fields remain rule-generated", "★ Highest-value LLM use case: on slow-path, non-executable output, analyst-facing narrative for ambiguous high-risk events"],
        ].map(([ag, lp, rm, im, kr], i) =>
          trow([
            tc(ag, { width: 2400, stripe: i % 2 === 1, recommended: ag.startsWith("★"), bold: true }),
            tc(lp, { width: 1400, stripe: i % 2 === 1, recommended: ag.startsWith("★") }),
            tc(rm, { width: 2400, stripe: i % 2 === 1, recommended: ag.startsWith("★") }),
            tc(im, { width: 2200, stripe: i % 2 === 1, recommended: ag.startsWith("★") }),
            tc(kr, { width: 3000, stripe: i % 2 === 1, recommended: ag.startsWith("★") }),
          ])
        ),
      ],
      [2400, 1400, 2400, 2200, 3000]
    ),
    caption("Table 4.1 — Cross-agent LLM/SLM recommendation matrix. ★ = active recommendation or implemented path."),

    h2("Overall Conclusion"),
    bodyPara(
      "ARES-Mem's architecture is correctly designed as a deterministic, rule-based pipeline. LLM augmentation is appropriate in exactly two places: (1) the already-implemented Decision Agent path, where upgrading from Qwen2.5-0.5B to Qwen2.5-1.5B is the recommended change; and (2) a new narrative-synthesis step in the HumanEscalationAgent, where Qwen2.5-7B-Instruct provides the highest value to the human analyst on the slow, on-demand escalation path."
    ),
    bodyPara(
      "Across all agents, the Qwen2.5 family is preferred over Meta Llama-3/3.2 for structured-output tasks (IFEval 78.1% vs 76.3% at 7-8B tier) and for on-device footprint at the SLM tier (Apache-2.0 license, 128K context at 7B). Llama-3-8B-Instruct remains a valid empirical comparison arm and should be included in Phase 1 and Phase 2 evaluation runs (Section 2.3) before any final model selection is committed to the codebase."
    ),
    spacer(),
  ];
}

// ─── Assemble Document ────────────────────────────────────────────────────────
function buildDocument() {
  const children = [
    // ── Cover ──
    new Paragraph({
      children: [run("Project ARES-Mem", { size: 28, italics: true, color: ACCENT })],
      alignment: AlignmentType.CENTER, spacing: { after: 60 },
    }),
    new Paragraph({
      children: [run("LLM / SLM Model Comparison Report", { size: 46, bold: true, color: ACCENT })],
      alignment: AlignmentType.CENTER, spacing: { after: 40 },
    }),
    new Paragraph({
      children: [run("Audit Validation + Data Science Segment — All 6 Agents", { size: 26, italics: true })],
      alignment: AlignmentType.CENTER, spacing: { after: 300 },
    }),
    coverTable(),
    spacer(),
    hr(),
    new Paragraph({
      children: [run("Table of Contents", { size: 26, bold: true, color: ACCENT2 })],
      spacing: { before: 200, after: 120 },
    }),
    ...[
      "Part I  — Audit Validation Summary",
      "Part II — Data Science: LLM / SLM Comparative Analysis",
      "Part III — Agent-by-Agent Reports",
      "  Agent 1: LogIngestionAgent (The Eyes)",
      "  Agent 2: MemoryGuard (The Gatekeeper)",
      "  Agent 3: ThreatAnalysisAgent (The Brain)",
      "  Agent 4: DecisionAgent (The Commander)  ← LLM path already implemented",
      "  Agent 5: ResponseAgent (The Muscle)",
      "  Agent 6: HumanEscalationAgent (The Oversight)",
      "Part IV — Cross-Agent Recommendation Matrix",
    ].map(t => para(t, { after: 80 })),
    hr(),

    // ── Sections ──
    ...auditValidationSection(),
    ...methodologySection(),
    ...agent1Section(),
    ...agent2Section(),
    ...agent3Section(),
    ...agent4Section(),
    ...agent5Section(),
    ...agent6Section(),
    ...recommendationMatrix(),

    // ── End ──
    pageBreak(),
    new Paragraph({
      children: [run("— End of Report —", { size: 22, italics: true, color: "888888" })],
      alignment: AlignmentType.CENTER, spacing: { before: 400 },
    }),
  ];

  return new Document({
    styles: {
      default: {
        document: { run: { font: FONT, size: 22 } },
        heading1: { run: { font: FONT, size: 30, bold: true, color: ACCENT  }, paragraph: { spacing: { before: 320, after: 160 } } },
        heading2: { run: { font: FONT, size: 26, bold: true, color: ACCENT2 }, paragraph: { spacing: { before: 260, after: 120 } } },
        heading3: { run: { font: FONT, size: 23, bold: true, color: DARK   }, paragraph: { spacing: { before: 200, after: 80  } } },
      },
    },
    sections: [{
      properties: { page: { size: { width: PAGE_W, height: 15840 } } },
      children,
    }],
  });
}

// ─── Write Output ─────────────────────────────────────────────────────────────
const OUT = "ARES_Mem_LLM_SLM_Model_Comparison_Report.docx";
Packer.toBuffer(buildDocument()).then(buf => {
  fs.writeFileSync(OUT, buf);
  const kb = (buf.length / 1024).toFixed(1);
  console.log(`\n✓ Report generated: ${OUT}  (${kb} KB)\n`);
}).catch(err => {
  console.error("Error generating report:", err);
  process.exit(1);
});
