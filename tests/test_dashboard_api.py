"""
Unit and API Integration Tests for Flask Web Dashboard.
"""

import pytest
from dashboard.app import app
from core.ids_service import IDSService


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_index_page(client):
    """Kiem tra trang chu Dashboard tra ve HTTP 200 va co tieu de PBL4."""
    res = client.get("/")
    assert res.status_code == 200
    assert b"PBL4 NIDS" in res.data
    assert b"throughputChart" in res.data


def test_api_status(client):
    """Kiem tra endpoint /api/status tra ve day du thong tin telemetry."""
    res = client.get("/api/status")
    assert res.status_code == 200
    data = res.get_json()
    assert "status" in data
    assert "stats" in data
    assert "total" in data["stats"]
    assert "alerts" in data
    assert "throughput_history" in data


def test_api_interfaces(client):
    """Kiem tra endpoint /api/interfaces tra ve danh sach interface."""
    res = client.get("/api/interfaces")
    assert res.status_code == 200
    data = res.get_json()
    assert "interfaces" in data
    assert len(data["interfaces"]) > 0
    # Loopback phai xuat hien
    assert any(i["is_loopback"] for i in data["interfaces"])


def test_api_alerts_and_logs(client):
    """Kiem tra endpoint /api/alerts va /api/logs."""
    res_alerts = client.get("/api/alerts?severity=ALL")
    assert res_alerts.status_code == 200
    assert "alerts" in res_alerts.get_json()

    res_logs = client.get("/api/logs?level=ALL")
    assert res_logs.status_code == 200
    assert "logs" in res_logs.get_json()


def test_api_storage_stats(client):
    """Kiem tra endpoint /api/storage."""
    res = client.get("/api/storage")
    assert res.status_code == 200
    data = res.get_json()
    assert "total_size_mb" in data
    assert "retention_days" in data


def test_api_simulate_validation(client):
    """Kiem tra validation cua endpoint /api/simulate."""
    # Che do khong hop le -> 400
    res_bad = client.post("/api/simulate", json={"mode": "invalid_mode"})
    assert res_bad.status_code == 400

    # Che do normal -> 200
    res_ok = client.post("/api/simulate", json={"mode": "normal"})
    assert res_ok.status_code == 200
    assert res_ok.get_json()["success"] is True


def test_api_start_and_stop_lifecycle(client):
    """Kiem tra vong doi Start va Stop qua API."""
    service = IDSService.get_instance()
    
    # 1. Start IDS
    res_start = client.post("/api/control/start", json={})
    assert res_start.status_code in [200, 400]  # Co the 400 neu dang chay
    
    # 2. Stop IDS
    res_stop = client.post("/api/control/stop")
    assert res_stop.status_code == 200
    assert res_stop.get_json()["success"] is True
    assert service.sniffer.status in ["STOPPED", "STOPPING"]
