"""
tests/conftest.py — Shared pytest fixtures for ARES-Mem test suite.

Provides reusable test fixtures for all test modules:
  - memory_guard_instance: pre-initialized MemoryGuard (SentenceTransformer cached)
  - memory_store_instance: isolated in-memory ChromaDB store per test
  - sample_logs: representative benign/threat log strings
  - adversarial_logs: prompt injection payloads for ASR testing
"""
import sys
import os
import pytest

# Ensure src/ is on path for all test modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from memory_guard import MemoryGuard
from memory_store import MemoryStore
from synthetic_logs import (
    BENIGN_LOGS,
    BRUTE_FORCE_LOGS,
    PORT_SCAN_LOGS,
    DATA_EXFIL_LOGS,
    MALWARE_C2_LOGS,
    PROMPT_INJECTION_LOGS,
)


# ── Module-scoped MemoryGuard (expensive SentenceTransformer init) ────────────
@pytest.fixture(scope="module")
def memory_guard_instance() -> MemoryGuard:
    """Shared MemoryGuard instance (model loaded once per test module)."""
    return MemoryGuard()


# ── Function-scoped MemoryStore (fresh isolated DB per test) ─────────────────
@pytest.fixture()
def memory_store_instance(tmp_path) -> MemoryStore:
    """
    Fresh MemoryStore with ephemeral local ChromaDB per test function.
    Uses tmp_path to ensure isolation between tests.
    """
    store = MemoryStore(path=str(tmp_path / "test_chroma"))
    return store


# ── Log corpus fixtures ───────────────────────────────────────────────────────
@pytest.fixture(scope="session")
def sample_logs():
    """Representative logs from each category."""
    return {
        "benign":      BENIGN_LOGS[0],
        "brute_force": BRUTE_FORCE_LOGS[3],
        "port_scan":   PORT_SCAN_LOGS[1],
        "data_exfil":  DATA_EXFIL_LOGS[0],
        "malware_c2":  MALWARE_C2_LOGS[0],
    }


@pytest.fixture(scope="session")
def adversarial_logs():
    """All 10 prompt injection payloads."""
    return PROMPT_INJECTION_LOGS


@pytest.fixture(scope="session")
def benign_logs():
    """Benign log corpus for false-positive testing."""
    return BENIGN_LOGS
