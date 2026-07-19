import pytest
from fastapi.testclient import TestClient
from src.service import app
import os
import yaml

client = TestClient(app)

@pytest.fixture
def auth_headers():
    return {"X-API-KEY": "internal-key-456"}

def test_get_settings(auth_headers):
    response = client.get("/settings", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "data" in data
    assert "memory_guard" in data["data"]
    assert "decision_agent" in data["data"]

def test_patch_settings(auth_headers, tmp_path):
    # Set config path to a temp file
    config_file = tmp_path / "settings.yaml"
    os.environ["ARES_CONFIG_PATH"] = str(config_file)
    
    # 1. Update settings
    payload = {
        "memory_guard": {
            "sem_dist_threshold": 0.55
        },
        "logging": {
            "level": "DEBUG"
        }
    }
    
    response = client.patch("/settings", headers=auth_headers, json=payload)
    assert response.status_code == 200
    data = response.json()["data"]
    
    # 2. Verify returned settings reflect changes
    assert data["memory_guard"]["sem_dist_threshold"] == 0.55
    assert data["logging"]["level"] == "DEBUG"
    
    # 3. Verify YAML was written
    assert os.path.exists(config_file)
    with open(config_file, "r") as f:
        saved_config = yaml.safe_load(f)
    
    assert saved_config["memory_guard"]["sem_dist_threshold"] == 0.55
    assert saved_config["logging"]["level"] == "DEBUG"
    
    # Reset env
    del os.environ["ARES_CONFIG_PATH"]

def test_patch_settings_invalid(auth_headers):
    payload = {
        "memory_guard": {
            "sem_dist_threshold": 2.5  # Invalid, must be <= 1.0
        }
    }
    response = client.patch("/settings", headers=auth_headers, json=payload)
    assert response.status_code == 400
    assert "Validation" in response.json()["message"] or "Invalid settings payload" in response.json()["message"]
