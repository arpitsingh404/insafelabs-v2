"""Iteration 22 — Bug Bounty Engine (/api/bugbounty/*) end-to-end backend tests."""
import os
import time
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")
if not BASE_URL:
    with open("/app/frontend/.env") as f:
        for line in f:
            if line.startswith("REACT_APP_BACKEND_URL="):
                BASE_URL = line.split("=", 1)[1].strip().rstrip("/")


API = f"{BASE_URL}/api"


@pytest.fixture(scope="module")
def scan_id():
    r = requests.post(f"{API}/bugbounty/scan", json={"target": "example.com"}, timeout=30)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["status"] == "queued"
    assert d["target"] == "example.com"
    assert "id" in d
    return d["id"]


def test_invalid_target_returns_400():
    r = requests.post(f"{API}/bugbounty/scan", json={"target": "notadomain"}, timeout=15)
    assert r.status_code == 400, r.text
    r2 = requests.post(f"{API}/bugbounty/scan", json={"target": "has space.com"}, timeout=15)
    assert r2.status_code == 400


def test_start_scan_returns_queued(scan_id):
    assert scan_id  # fixture validated


def test_scan_reaches_done(scan_id):
    """Poll scan doc until status='done' (up to ~150s)."""
    deadline = time.time() + 150
    last = None
    while time.time() < deadline:
        r = requests.get(f"{API}/bugbounty/scan/{scan_id}", timeout=20)
        assert r.status_code == 200
        last = r.json()
        if last.get("status") in ("done", "error"):
            break
        time.sleep(4)
    assert last is not None
    assert last.get("status") == "done", f"Final status={last.get('status')} stage={last.get('stage')} err={last.get('error')}"
    # structure checks
    assert isinstance(last.get("subdomains"), list)
    assert isinstance(last.get("live_hosts"), list)
    assert isinstance(last.get("findings"), list)
    counts = last.get("counts") or {}
    for k in ("critical", "high", "medium", "low", "info"):
        assert k in counts
    assert "sub_count" in last and "live_count" in last and "finding_count" in last
    js = last.get("js_recon") or {}
    assert "endpoints" in js and "secrets" in js
    # live_host fields
    if last["live_hosts"]:
        h = last["live_hosts"][0]
        for k in ("host", "status", "title", "server", "tech", "waf"):
            assert k in h
    # finding fields
    if last["findings"]:
        f = last["findings"][0]
        for k in ("id", "host", "type", "severity", "cvss", "title", "detail", "evidence", "remediation"):
            assert k in f


def test_list_scans_contains_scan(scan_id):
    r = requests.get(f"{API}/bugbounty/scans", timeout=15)
    assert r.status_code == 200
    d = r.json()
    assert "scans" in d and isinstance(d["scans"], list)
    ids = [s["id"] for s in d["scans"]]
    assert scan_id in ids


def test_ai_report_markdown(scan_id):
    r = requests.post(f"{API}/bugbounty/report/{scan_id}", timeout=120)
    assert r.status_code == 200, r.text
    d = r.json()
    assert "markdown" in d
    assert isinstance(d["markdown"], str)
    assert len(d["markdown"]) > 200


def test_report_pdf(scan_id):
    r = requests.get(f"{API}/bugbounty/report/{scan_id}/pdf", timeout=60)
    assert r.status_code == 200
    assert "application/pdf" in r.headers.get("content-type", "")
    assert r.content[:4] == b"%PDF"


def test_scan_not_found():
    r = requests.get(f"{API}/bugbounty/scan/does-not-exist-xyz", timeout=15)
    assert r.status_code == 404
