# Project ARES-Mem

**Autonomous Resilient Episodic Security Memory** — a multi-agent cybersecurity defense system using LangGraph orchestration, ChromaDB vector memory sandboxing, and NLP-based adversarial payload detection.

---

## Architecture

```
Raw Log
   │
   ▼
[LogIngestionAgent]   — sanitises, structures
   │
   ▼
[ThreatAnalysisAgent] — LLM risk scoring (GPT-4o)
   │
   ▼
[DecisionAgent]       — policy-table decision (LLM)
   │
   ├── LOG_ONLY        → MemoryGuard → Analytics
   ├── MANUAL_REVIEW   → Human Review Node → MemoryGuard → Analytics
   └── (else)          → ResponseAgent → MemoryGuard → Analytics
```

### MemoryGuard (Memory Sandboxing)
Assigns a **trust tier** to every execution trace using three signals:

| Feature | Description | Threshold |
|---|---|---|
| `semantic_distance` | Cosine similarity to adversarial centroid (17-sample corpus) | > 0.55 |
| `imperative_density` | Ratio of command verbs to total tokens | > 0.30 |
| `entropy` | Shannon entropy — detects obfuscated payloads | > 5.20 bits |

Tiers: `verified_internal` → `medium_internal` → `untrusted_external`

---

## Setup

### Prerequisites
- Python ≥ 3.11
- `OPENAI_API_KEY` set (or your OpenAI-compatible endpoint)

```bash
# 1. Clone
git clone https://github.com/Ishwarpatra/ares-mem.git
cd ares-mem

# 2. Create venv
python -m venv .venv
.venv\Scripts\activate   # Windows
# source .venv/bin/activate  # Linux/Mac

# 3. Install dependencies
pip install -r requirements.txt
python -m spacy download en_core_web_sm

# 4. Configure environment
cp .env.example .env
# Edit .env and set OPENAI_API_KEY
```

---

## Running

```bash
# Run the full pipeline with a test log
python src/orchestrator.py

# Run memory guard + store integration test
python src/test_phase_3.py

# Run agent pipeline integration test
python src/test_agents.py
```

---

## Docker

```bash
# Build
docker build -t ares-mem .

# Run with environment file
docker run --env-file .env ares-mem

# Or use docker-compose (includes ChromaDB service)
docker-compose up
```

---

## Testing

```bash
# Run all tests
pytest src/

# Run with verbose output
pytest src/ -v
```

---

## Environment Variables

See [`.env.example`](.env.example) for full documentation.

| Variable | Required | Description |
|---|---|---|
| `OPENAI_API_KEY` | ✅ | OpenAI API key for LLM agents |
| `OPENAI_BASE_URL` | ❌ | Custom endpoint (Azure / proxy) |
| `OPENSANDBOX_API_KEY` | ❌ | OpenSandbox SDK integration |
| `GOOGLE_API_KEY` | ❌ | Google ADK integration |
| `CHROMA_HOST` / `CHROMA_PORT` | ❌ | Remote ChromaDB (defaults to local) |

---

## Project Structure

```
ares-mem/
├── src/
│   ├── orchestrator.py       # LangGraph pipeline (entry point)
│   ├── ingestion_agent.py    # Log sanitisation & structuring
│   ├── threat_agent.py       # LLM-based risk scoring
│   ├── decision_agent.py     # LLM-based policy decision
│   ├── response_agent.py     # Simulated defensive action
│   ├── memory_guard.py       # NLP feature extraction & trust tier
│   ├── memory_store.py       # ChromaDB vector store + sandbox retrieval
│   ├── analytics_agent.py    # matplotlib/pandas graph generation
│   ├── opensandbox_service.py# OpenSandbox SDK wrapper
│   ├── google_adk_service.py # Google ADK wrapper
│   ├── test_agents.py        # Agent pipeline integration tests
│   ├── test_integrations.py  # SDK integration tests
│   └── test_phase_3.py       # MemoryGuard + MemoryStore tests
├── .env.example
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── setup.py
```
