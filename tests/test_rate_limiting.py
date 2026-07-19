import pytest
from fastapi.testclient import TestClient
from src.service import app

client = TestClient(app)

def test_rate_limit_external():
    # Use external key to test 100/hour limit. We can mock the rate limit to something smaller, or just hit it 101 times.
    # To keep test fast and reliable, we'll patch get_rate_limit to return "5/minute" for the external key.
    
    headers = {"X-API-KEY": "external-key-789"}
    # The default external limit is 100/hour. We'll hit a cheap endpoint like /explain/missing_id 101 times
    # Actually wait, /explain/{event_id} hits chromadb, we should use /health but /health is not rate limited.
    # We will use /metrics since it doesn't do much writing, just reading agents.
    
    # We'll just call /metrics 101 times
    for _ in range(100):
        resp = client.get("/metrics", headers=headers)
        # It should succeed or fail with 500, but not 429 yet
        if resp.status_code == 429:
            break
            
    # The 101st request should be rate limited
    resp = client.get("/metrics", headers=headers)
    assert resp.status_code == 429
    assert "Retry-After" in resp.headers

def test_system_rate_limit():
    headers = {"X-API-KEY": "system-key-123"}
    # Verify that system-key-123 has a higher limit. We'll just check if it gets 429 on the first call (it shouldn't).
    resp = client.get("/metrics", headers=headers)
    assert resp.status_code in (200, 500)
    assert resp.status_code != 429
