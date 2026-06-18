# Project ARES-Mem

**Autonomous Resilient Episodic Security Memory — Production-Grade Multi-Agent Cybersecurity Defense System**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![LangGraph](https://img.shields.io/badge/orchestration-LangGraph-green.svg)](https://github.com/langchain-ai/langgraph)
[![ChromaDB](https://img.shields.io/badge/vector--db-ChromaDB-purple.svg)](https://www.trychroma.com/)
[![Docker](https://img.shields.io/badge/deployment-Docker-blue.svg)](https://www.docker.com/)

---

## System Architecture

```
┌────────────────────────────────────────────────────────────┐
│                  ARES-Mem LangGraph State Machine           │
│                                                            │
│  [ingest] → [analyze] → [decide] ─────────────────────→ [secure_memory] → END
│                             │                    ↑
│                             ├─ ESCALATE → [human_escalation] ─→ [execute_response]
│                             ├─ LOG_ONLY ──────────────────────────────────────────↗
│                             └─ BLOCK/QUARANTINE/ALERT → [execute_response] ──────↗
└────────────────────────────────────────────────────────────┘

Memory Guard ETVL Pipeline:
  Raw Trace → [Entropy] → [Imperative Density] → [Semantic Distance] → [Perplexity] → Privilege Tag
                                                                               ↓
                                                          ares_memory (≥MEDIUM) | ares_quarantine (<MEDIUM)
```

### Agents

| Agent | Role | Layer |
|---|---|---|
| `LogIngestionAgent` | Parses raw logs into structured events | 1 (Always-ON) |
| `ThreatAnalysisAgent` | Scores risk (0–100) deterministically | 1 (Always-ON) |
| `DecisionAgent` | Policy matrix evaluation | 2 (Sequential) |
| `ResponseAgent` | Executes defensive actions | 2 (Sequential) |
| `HumanEscalationAgent` | Analyst review for ambiguous threats | 3 (On-Demand) |
| `MemoryGuard` | ETVL adversarial filtration middleware | Cross-layer |

### 5-Tier Privilege System

| Level | Label | Description |
|---|---|---|
| 5 | SYSTEM | Immutable system policies |
| 4 | HIGH | Verified agent reasoning |
| 3 | MEDIUM | Internal operational data |
| 2 | LOW | External unverified data |
| 1 | UNTRUSTED | Known adversarial / quarantined |

---

## Quick Start

### Local (no Docker)

```bash
# 1. Create and activate virtual environment
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Linux/macOS

# 2. Install dependencies
pip install -r requirements.txt

# 3. Download spaCy model (optional — graceful fallback if unavailable)
python -m spacy download en_core_web_sm

# 4. Copy environment template
copy .env.example .env        # Windows
# cp .env.example .env        # Linux/macOS

# 5. Run the pipeline
python src/main.py

# 6. Run the test suite
pytest tests/ --verbose --tb=short
```

### Docker (Production)

```bash
# Build and start all services
docker compose up --build

# ChromaDB starts first → health check passes → pytest runs → main.py executes
```

---

## Running Tests

```bash
# Full test suite with coverage
pytest tests/ --verbose --cov=src --cov-report=term-missing

# ASR adversarial simulation only
pytest tests/test_adversarial_asr.py -v -s

# Memory Guard unit tests only
pytest tests/test_memory_guard.py -v

# Agent unit tests only
pytest tests/test_agents.py -v

# Orchestrator integration tests only
pytest tests/test_orchestrator.py -v
```

### Expected Results

```
tests/test_memory_guard.py      ✓ 25 tests — All feature extraction validated
tests/test_agents.py            ✓ 37 tests — All agents deterministic
tests/test_memory_store.py      ✓ 15 tests — ACL routing verified
tests/test_orchestrator.py      ✓ 13 tests — Full pipeline end-to-end
tests/test_adversarial_asr.py   ✓ 14 tests — Adversarial ASR testing
tests/test_evaluation.py        ✓ 29 tests — Evaluation metrics verified
```

---

## Security Features

### Memory Guard Feature Matrix

| Feature | Method | Threshold | Action |
|---|---|---|---|
| Semantic Distance | Cosine similarity to 15-seed adversarial centroid | > 0.48 | QUARANTINE |
| Imperative Density | POS-tagging / keyword heuristic | > 0.25 | QUARANTINE |
| Perplexity | Character-level bigram model | > 2000 | QUARANTINE |
| Shannon Entropy | Byte-level entropy | > 5.0 | Privilege downgrade |
| Provenance Hops | Chain-of-custody depth | External + hops | Trust decay |

### Memory Collections

- `ares_memory` — Validated traces (privilege ≥ MEDIUM)
- `ares_quarantine` — Flagged traces (privilege < MEDIUM) — read-only audit

---

## Project Structure

```
ares-mem/
├── dataset/                       # Synthetic corpus definition & types
│   ├── corpus_types.py
│   └── synthetic_corpus.py
├── eval/                          # Evaluation harness & metrics
│   ├── metrics.py
│   ├── run_evaluation.py
│   └── results/                   # Generated evaluation reports
├── src/
│   ├── base.py                    # BaseAgent abstract class
│   ├── models.py                  # TypedDicts + THREAT_SIGNATURES
│   ├── log_ingestion_agent.py     # E-layer parser (The Eyes)
│   ├── threat_analysis_agent.py   # Risk scoring (The Brain)
│   ├── decision_agents.py         # Policy + response (The Commander + Muscle)
│   ├── response_agents.py         # Re-export alias
│   ├── human_escalation_agent.py  # Oversight (The Oversight)
│   ├── memory_guard.py            # ETVL filtration (The Gatekeeper)
│   ├── memory_store.py            # ChromaDB + ACL retrieval
│   ├── orchestrator.py            # LangGraph StateGraph
│   ├── synthetic_logs.py          # Log corpus for testing
│   └── main.py                    # Production entry point
├── tests/
│   ├── conftest.py                # Shared fixtures
│   ├── test_memory_guard.py       # Feature extraction unit tests
│   ├── test_agents.py             # Agent unit tests
│   ├── test_memory_store.py       # ACL and routing tests
│   ├── test_orchestrator.py       # End-to-end integration tests
│   ├── test_adversarial_asr.py    # Adversarial ASR simulation
│   └── test_evaluation.py         # Evaluation module tests
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
└── .env.example
```

---

## Methodological Constraints (Research Compliance)

1. **LLM Stochasticity** — All agents use deterministic rule-based logic (temperature=0 equivalent). No external LLM API calls are required for core functionality.

2. **Latency Overhead** — The `ResponseAgent` and `main.py` both measure and report per-action latency in milliseconds. The Memory Guard's feature extraction pipeline latency is tracked via `BaseAgent.run()`.

3. **Data Provenance Spoofing** — Tag spoofing is addressed by the `TestPrivilegeEscalationAttempts` test class. Privilege assignment is based on the validated `source` parameter (set by the trusted ingestion layer), not on log content.
