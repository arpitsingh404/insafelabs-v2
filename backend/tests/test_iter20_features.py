"""Iteration 20: Live ticker findings + drilldowns + branded operation report."""
import os
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL") or open("/app/frontend/.env").read().split("REACT_APP_BACKEND_URL=")[1].split("\n")[0].strip()
BASE_URL = BASE_URL.rstrip("/")
API = f"{BASE_URL}/api"

TINY_PNG = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="


# ---- Dashboard Findings ----
def test_dashboard_findings_all():
    r = requests.get(f"{API}/dashboard/findings", timeout=30)
    assert r.status_code == 200, r.text
    data = r.json()
    for k in ["total", "count", "counts", "findings"]:
        assert k in data, f"missing key {k}"
    for k in ["critical", "high", "medium", "low", "info"]:
        assert k in data["counts"]
    assert data["total"] == sum(data["counts"].values()) or data["total"] >= 0
    if data["findings"]:
        f0 = data["findings"][0]
        for k in ["title", "severity", "cvss", "host"]:
            assert k in f0, f"finding missing {k}: {f0}"


def test_dashboard_findings_severity_filter_high():
    r = requests.get(f"{API}/dashboard/findings", params={"severity": "high"}, timeout=30)
    assert r.status_code == 200
    data = r.json()
    assert data["count"] == data["counts"]["high"]
    for f in data["findings"]:
        assert f["severity"] == "high"


def test_dashboard_findings_unknown_severity():
    r = requests.get(f"{API}/dashboard/findings", params={"severity": "zzz"}, timeout=30)
    assert r.status_code == 200
    data = r.json()
    assert data["count"] == 0
    assert data["findings"] == []


# ---- Operation Report ----
def _get_recon_id():
    r = requests.get(f"{API}/offensive/operation/sources", timeout=30)
    if r.status_code == 200:
        recons = (r.json() or {}).get("recon", [])
        if recons:
            return recons[0].get("id")
    return None


def test_operation_report_with_logo_and_notes():
    rid = _get_recon_id()
    assert rid, "no recon id available"
    body = {
        "title": "TEST_Op",
        "operator": "tester",
        "recon_ids": [rid],
        "network_ids": [],
        "binary_ids": [],
        "cover_notes": "Test cover notes for iter20",
        "logo": TINY_PNG,
    }
    r = requests.post(f"{API}/offensive/operation/report", json=body, timeout=60)
    assert r.status_code == 200, r.text
    assert r.headers.get("content-type", "").startswith("application/pdf")
    assert r.content[:4] == b"%PDF"


def test_operation_report_without_logo_notes():
    rid = _get_recon_id()
    assert rid
    body = {"title": "TEST_Op2", "operator": "tester", "recon_ids": [rid], "network_ids": [], "binary_ids": []}
    r = requests.post(f"{API}/offensive/operation/report", json=body, timeout=60)
    assert r.status_code == 200
    assert r.content[:4] == b"%PDF"


def test_operation_report_empty_selection_400():
    body = {"title": "TEST_Empty", "operator": "tester", "recon_ids": [], "network_ids": [], "binary_ids": []}
    r = requests.post(f"{API}/offensive/operation/report", json=body, timeout=30)
    assert r.status_code == 400
