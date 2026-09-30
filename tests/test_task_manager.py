import pytest
import os
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_public_system_health():
    """Verify system health endpoint returns populated metrics, specs, and task manager processes."""
    response = client.get("/health/public")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "resources" in data
    assert "cpu_percent" in data["resources"]
    assert "memory_percent" in data["resources"]
    assert "system" in data
    assert "os" in data["system"]
    assert "processor" in data["system"]
    assert "processes" in data
    assert "total_count" in data["processes"]
    assert data["processes"]["total_count"] > 0
    assert "all_processes" in data["processes"]
    assert len(data["processes"]["all_processes"]) > 0


def test_task_manager_processes_endpoint():
    """Verify /health/processes endpoint supports sorting, filtering, and pagination."""
    # Login as admin
    login_res = client.post("/auth/login", json={"username": "Ashwin_gowda1", "password": "Ashwin@gowda1234"})
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Fetch top processes by CPU
    res = client.get("/health/processes?limit=20&sort_by=cpu&order=desc", headers=headers)
    assert res.status_code == 200
    pdata = res.json()
    assert "processes" in pdata
    assert "total_matching" in pdata
    assert len(pdata["processes"]) > 0

    first = pdata["processes"][0]
    assert "pid" in first
    assert "name" in first
    assert "cpu" in first
    assert "memory_mb" in first

    # Search for python
    sres = client.get("/health/processes?search=python", headers=headers)
    assert sres.status_code == 200
    sdata = sres.json()
    for p in sdata["processes"]:
        assert "python" in p["name"].lower() or "python" in str(p["pid"])


def test_kill_process_security_safeguards():
    """Verify critical system processes (PID <= 4) and server self-kill are blocked."""
    login_res = client.post("/auth/login", json={"username": "Ashwin_gowda1", "password": "Ashwin@gowda1234"})
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Attempt to kill PID 0 (System Idle) or PID 4 (System)
    r4 = client.post("/health/processes/4/kill", headers=headers)
    assert r4.status_code == 400
    assert "Cannot terminate" in r4.json()["detail"]

    r0 = client.post("/health/processes/0/kill", headers=headers)
    assert r0.status_code == 400

    # Attempt to kill server PID
    current_pid = os.getpid()
    r_self = client.post(f"/health/processes/{current_pid}/kill", headers=headers)
    assert r_self.status_code == 400
    assert "ThreatShield server process" in r_self.json()["detail"]


def test_kill_nonexistent_process():
    """Verify terminating a non-existent PID returns 404."""
    login_res = client.post("/auth/login", json={"username": "Ashwin_gowda1", "password": "Ashwin@gowda1234"})
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 999999 should not exist
    r = client.post("/health/processes/999999/kill", headers=headers)
    assert r.status_code == 404
