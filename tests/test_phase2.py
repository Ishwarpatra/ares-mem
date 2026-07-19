import pytest
from fastapi.testclient import TestClient
import uuid
import os
import time

from src.service import app

client = TestClient(app)
API_KEY = "internal-key-456"
HEADERS = {"X-API-KEY": API_KEY}

def test_full_pipeline_with_tracing_and_audit():
    """Phase 2 Integration: Tests Tracing, Audit Logging, and Notifications."""
    # 1. Provide a specific Trace ID
    req_id = f"test-trace-{uuid.uuid4().hex[:8]}"
    headers = {**HEADERS, "X-Request-ID": req_id}
    
    # 2. Trigger ingestion (this exercises the full ARES pipeline)
    log = "Suspicious network scan from 192.168.1.100"
    payload = {"log": log}
    
    resp = client.post("/ingest", json=payload, headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    
    # Verify tracing propagated to response
    assert resp.headers.get("x-request-id") == req_id
    
    # 3. Verify Audit Log was generated for this request ID
    time.sleep(0.1) # Small delay for async audit
    audit_resp = client.get(f"/audit/events", headers=HEADERS)
    assert audit_resp.status_code == 200
    events = audit_resp.json()["events"]
    
    # We should find at least one event with our request_id
    matching_events = [e for e in events if e.get("request_id") == req_id]
    assert len(matching_events) > 0, "Audit log did not record the event with request_id"
    
def test_rate_limiting_integration():
    """Phase 2 Integration: Verify rate limits are active on endpoints."""
    # We can't easily exhaust the 1000/hr limit in tests quickly without a mock, 
    # but we can verify the limit headers are present.
    resp = client.get("/health")
    assert resp.status_code == 200
    
    resp = client.get("/settings", headers=HEADERS)
    assert resp.status_code == 200
    assert "x-ratelimit-limit" in resp.headers

def test_settings_api_integration():
    """Phase 2 Integration: Verify settings API is active and functional."""
    resp = client.get("/settings", headers=HEADERS)
    assert resp.status_code == 200
    assert resp.json()["data"]["app_name"] == "ARES-Mem API"
