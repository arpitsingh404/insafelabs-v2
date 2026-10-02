"""Tests for the newly wired features: Threat Map data, Alerts feed data,
Scheduled Monitors CRUD + run-now."""
import os
import time
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")
if not BASE_URL:
    with open("/app/frontend/.env") as f:
        for ln in f:
            if ln.startswith("REACT_APP_BACKEND_URL="):
                BASE_URL = ln.split("=", 1)[1].strip().rstrip("/")

API = f"{BASE_URL}/api"


# ---------- Dashboard stats: threat_points + alerts keys ----------
def test_dashboard_stats_has_threat_and_alerts_keys():
    r = requests.get(f"{API}/dashboard/stats", timeout=30)
    assert r.status_code == 200, r.text
    data = r.json()
    assert "threat_points" in data
    assert "alerts" in data
    assert isinstance(data["threat_points"], list)
    assert isinstance(data["alerts"], list)


# ---------- Scanner schedules: list ----------
def test_list_schedules():
    r = requests.get(f"{API}/scanner/schedules", timeout=15)
    assert r.status_code == 200
    assert isinstance(r.json(), list)


# ---------- Scanner alerts: list ----------
def test_list_alerts():
    r = requests.get(f"{API}/scanner/alerts", timeout=15)
    assert r.status_code == 200
    assert isinstance(r.json(), list)


# ---------- Create schedule ----------
@pytest.fixture(scope="module")
def created_schedule():
    payload = {"target": "TEST_example.com", "interval": "daily"}
    r = requests.post(f"{API}/scanner/schedules", json=payload, timeout=15)
    assert r.status_code == 200, r.text
    doc = r.json()
    assert doc["target"] == payload["target"]
    assert doc["interval"] == "daily"
    assert doc["id"]
    yield doc
    # cleanup
    requests.delete(f"{API}/scanner/schedules/{doc['id']}", timeout=15)


def test_create_and_visible_in_list(created_schedule):
    sid = created_schedule["id"]
    r = requests.get(f"{API}/scanner/schedules", timeout=15)
    ids = [s["id"] for s in r.json()]
    assert sid in ids


def test_invalid_interval_rejected():
    r = requests.post(f"{API}/scanner/schedules",
                      json={"target": "example.com", "interval": "bogus"}, timeout=15)
    assert r.status_code == 400


# ---------- Run now: use example.com — real scan takes 20-60s ----------
def test_run_schedule_now(created_schedule):
    sid = created_schedule["id"]
    # switch target to example.com for a fast real scan
    r = requests.post(f"{API}/scanner/schedules/{sid}/run", timeout=180)
    assert r.status_code == 200, r.text
    data = r.json()
    assert "scan_id" in data
    assert "finding_count" in data
    assert "new_findings" in data
    assert isinstance(data["new_findings"], list)
    # verify last_finding_count updated in list
    r2 = requests.get(f"{API}/scanner/schedules", timeout=15)
    doc = next((s for s in r2.json() if s["id"] == sid), None)
    assert doc and doc.get("last_finding_count") == data["finding_count"]


# ---------- Delete ----------
def test_delete_schedule_removes_it():
    payload = {"target": "TEST_delete_me.com", "interval": "hourly"}
    r = requests.post(f"{API}/scanner/schedules", json=payload, timeout=15)
    sid = r.json()["id"]
    d = requests.delete(f"{API}/scanner/schedules/{sid}", timeout=15)
    assert d.status_code == 200
    lst = requests.get(f"{API}/scanner/schedules", timeout=15).json()
    assert sid not in [s["id"] for s in lst]


def test_delete_nonexistent_404():
    r = requests.delete(f"{API}/scanner/schedules/does-not-exist", timeout=15)
    assert r.status_code == 404
