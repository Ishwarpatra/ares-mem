import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
import json

from src.service import app
from src.orchestrator import get_agent_registry, AgentRegistry
from config.settings import load_settings, Settings
from src.memory_store import MemoryStore

client = TestClient(app)
API_KEY = "internal-key-456"
HEADERS = {"X-API-KEY": API_KEY}

def test_pydantic_settings():
    """Phase 1c: Verify Pydantic settings load and validate correctly."""
    settings = load_settings()
    assert isinstance(settings, Settings)
    assert settings.app_name == "ARES-Mem API"
    assert settings.decision_agent.block_threshold == 80
    assert settings.logging.level == "INFO"

def test_pydantic_validation_error():
    """Phase 1c: Verify Pydantic throws on invalid data."""
    with pytest.raises(ValidationError):
        Settings(logging={"level": "INVALID_LEVEL"})

def test_dependency_injection_registry():
    """Phase 1a: Verify AgentRegistry singleton behaves correctly."""
    registry1 = get_agent_registry()
    registry2 = get_agent_registry()
    assert registry1 is registry2  # Should be lru_cached singleton
    
    # Check registration
    registry1.register("test_agent", {"foo": "bar"})
    assert registry2.get("test_agent") == {"foo": "bar"}

def test_health_endpoints():
    """Phase 1d: Verify /health, /live, /ready endpoints."""
    # /live
    resp = client.get("/live")
    assert resp.status_code == 200
    assert resp.json() == {"status": "alive"}
    
    # /health
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert "version" in data
    assert "checks" in data
    assert data["checks"]["coordination_engine"] == "ok"

def test_standardized_responses():
    """Quick Wins: Verify ErrorResponse and SuccessResponse formats."""
    # Test unauthenticated error
    resp = client.get("/metrics")
    assert resp.status_code == 403
    data = resp.json()
    assert data["status"] == "error"
    assert data["code"] == "AUTH_REQUIRED"
    
    # Test valid success response
    resp = client.get("/metrics", headers=HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert "data" in data
    assert "pipeline" in data["data"]

def test_chromadb_upsert_fix():
    """Phase 1b: Verify multiple ingestions don't crash ChromaDB due to duplicate IDs."""
    log = "Suspicious login attempt from unknown IP 10.0.0.5"
    payload = {"log": log, "id": "fixed-id-123"}
    
    # Ingest 1
    resp1 = client.post("/ingest", json=payload, headers=HEADERS)
    assert resp1.status_code == 200
    
    # Ingest 2 (Should use .upsert() and not crash!)
    resp2 = client.post("/ingest", json=payload, headers=HEADERS)
    assert resp2.status_code == 200
    
    assert resp1.json()["data"]["status"] == "processed"
    assert resp2.json()["data"]["status"] == "processed"
