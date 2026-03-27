from __future__ import annotations

import os
import pytest
from fastapi.testclient import TestClient

from wardenhub_coordinator.app import app
from wardenhub_coordinator import app as app_module


@pytest.fixture
def client(tmp_path, monkeypatch):
    """TestClient with a temp config that uses a tmp db path."""
    config_file = tmp_path / "coordinator.yaml"
    db_file = tmp_path / "test.db"
    config_file.write_text(
        f"coordinator:\n"
        f"  host: '0.0.0.0'\n"
        f"  port: 8080\n"
        f"  db_path: '{db_file}'\n"
        f"pushgateway:\n"
        f"  url: 'http://localhost:9091'\n"
        f"  cleanup_threshold: '6h'\n"
        f"schedule:\n"
        f"  interval: '3h'\n"
    )
    monkeypatch.setenv("WARDENHUB_CONFIG", str(config_file))

    # Also stub out the scheduler so tests don't start background jobs
    import wardenhub_coordinator.scheduler as sched_module
    from apscheduler.schedulers.asyncio import AsyncIOScheduler

    stub_scheduler = AsyncIOScheduler()
    monkeypatch.setattr(sched_module, "_scheduler", stub_scheduler)

    with TestClient(app, raise_server_exceptions=True) as c:
        yield c

    app_module._db = None


def test_health_returns_ok(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "version" in data


def test_register_agent(client):
    payload = {
        "hostname": "test-host",
        "ip": "192.168.1.10",
        "providers": ["lynis", "network"],
        "findings_summary": {"critical": 0, "warning": 3, "info": 5},
        "last_run": "2026-03-27T06:00:00Z",
        "version": "0.1.0",
    }
    resp = client.post("/api/register", json=payload)
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_register_then_status(client):
    payload = {
        "hostname": "test-host",
        "ip": "192.168.1.10",
        "providers": ["lynis"],
        "findings_summary": {"critical": 1, "warning": 2, "info": 0},
        "last_run": "2026-03-27T06:00:00Z",
        "version": "0.1.0",
    }
    client.post("/api/register", json=payload)

    resp = client.get("/api/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert data["agents"][0]["hostname"] == "test-host"


def test_register_invalid_payload(client):
    resp = client.post("/api/register", json={"hostname": "missing-fields"})
    assert resp.status_code == 422


def test_get_findings_empty(client):
    resp = client.get("/api/findings")
    assert resp.status_code == 200
    data = resp.json()
    assert data["totals"]["critical"] == 0


def test_get_findings_aggregated(client):
    for i in range(2):
        payload = {
            "hostname": f"host-{i}",
            "ip": f"192.168.1.{10 + i}",
            "providers": ["lynis"],
            "findings_summary": {"critical": 1, "warning": 2, "info": 3},
            "last_run": "2026-03-27T06:00:00Z",
            "version": "0.1.0",
        }
        client.post("/api/register", json=payload)

    resp = client.get("/api/findings")
    assert resp.status_code == 200
    data = resp.json()
    assert data["totals"]["critical"] == 2
    assert data["totals"]["warning"] == 4
    assert len(data["per_host"]) == 2


def test_register_updates_existing_agent(client):
    payload = {
        "hostname": "test-host",
        "ip": "192.168.1.10",
        "providers": ["lynis"],
        "findings_summary": {"critical": 0, "warning": 1, "info": 0},
        "last_run": "2026-03-27T06:00:00Z",
        "version": "0.1.0",
    }
    client.post("/api/register", json=payload)

    # Update with new findings
    payload["findings_summary"] = {"critical": 2, "warning": 0, "info": 0}
    payload["last_run"] = "2026-03-27T09:00:00Z"
    client.post("/api/register", json=payload)

    resp = client.get("/api/status")
    data = resp.json()
    assert data["total"] == 1  # still only one agent
    assert data["agents"][0]["findings_critical"] == 2
