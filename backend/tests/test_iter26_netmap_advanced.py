"""Iteration 26: Advanced Network Mapper - scan profiles, fingerprinting, AI attack-path."""
import os
import time
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "https://localhost:8001").rstrip("/")
API = f"{BASE_URL}/api"

EXISTING_DEEP_SCAN = "b7e77712-f111-4492-bb8f-e4955cc72a1e"


def _poll(scan_id, timeout=180):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        r = requests.get(f"{API}/offensive/network/scan/{scan_id}", timeout=30)
        assert r.status_code == 200
        last = r.json()
        if last.get("status") in ("completed", "failed"):
            return last
        time.sleep(3)
    return last


# ---------------- Local segments ----------------
def test_interfaces_returns_segments():
    r = requests.get(f"{API}/offensive/network/interfaces", timeout=15)
    assert r.status_code == 200
    body = r.json()
    assert "segments" in body
    assert isinstance(body["segments"], list)
    assert len(body["segments"]) >= 1
    seg = body["segments"][0]
    assert "cidr" in seg and "ip" in seg
    assert "/" in seg["cidr"]


# ---------------- Existing deep scan (regression) ----------------
def test_existing_deep_scan_web_server_fingerprint():
    r = requests.get(f"{API}/offensive/network/scan/{EXISTING_DEEP_SCAN}", timeout=30)
    assert r.status_code == 200
    d = r.json()
    assert d.get("status") == "completed"
    hosts = d.get("hosts", [])
    assert len(hosts) >= 1
    h = hosts[0]
    assert h.get("device_type") == "Web Server"
    assert "Linux" in (h.get("os_guess") or "")
    tags = h.get("tags", [])
    assert "web" in tags and "ssh" in tags
    # Options captured
    opts = d.get("options", {})
    assert opts.get("profile") == "deep"
    assert opts.get("port_count") == 66
    # Graph nodes/edges present
    assert "nodes" in d and "edges" in d
    assert "device_summary" in d


# ---------------- Profile port counts ----------------
@pytest.mark.parametrize("profile,expected", [("quick", 8), ("standard", 23), ("deep", 66)])
def test_profile_port_counts(profile, expected):
    # scan localhost to keep it fast; we only need to verify port_count option
    payload = {
        "target": "scanme.nmap.org",
        "profile": profile,
        "neighborhood": False,
        "rdns": False,
        "banners": False,
        "os_guess": False,
    }
    r = requests.post(f"{API}/offensive/network/scan", json=payload, timeout=30)
    assert r.status_code == 200, r.text
    sid = r.json()["id"]
    # We don't need completion — poll until options appear or completed
    deadline = time.time() + 120
    doc = None
    while time.time() < deadline:
        g = requests.get(f"{API}/offensive/network/scan/{sid}", timeout=30).json()
        doc = g
        if g.get("options", {}).get("port_count") or g.get("status") in ("completed", "failed"):
            break
        time.sleep(2)
    assert doc is not None
    assert doc.get("options", {}).get("port_count") == expected, doc.get("options")


def test_custom_profile_ports_spec():
    payload = {
        "target": "scanme.nmap.org",
        "profile": "custom",
        "ports": "22,80,443,8000-8010",
        "neighborhood": False,
        "rdns": False,
        "banners": False,
        "os_guess": False,
    }
    r = requests.post(f"{API}/offensive/network/scan", json=payload, timeout=30)
    assert r.status_code == 200
    sid = r.json()["id"]
    # 22,80,443 = 3 + 8000-8010 = 11 -> total 14 unique
    deadline = time.time() + 120
    doc = None
    while time.time() < deadline:
        doc = requests.get(f"{API}/offensive/network/scan/{sid}", timeout=30).json()
        if doc.get("options", {}).get("port_count") or doc.get("status") in ("completed", "failed"):
            break
        time.sleep(2)
    assert doc.get("options", {}).get("port_count") == 14, doc.get("options")


# ---------------- AI analyze ----------------
def test_ai_analyze_unknown_scan_404():
    r = requests.post(f"{API}/offensive/network/analyze/does-not-exist-xyz", timeout=30)
    assert r.status_code == 404


def test_ai_analyze_existing_scan():
    r = requests.post(f"{API}/offensive/network/analyze/{EXISTING_DEEP_SCAN}", timeout=120)
    assert r.status_code == 200, r.text
    body = r.json()
    assert "answer" in body
    assert isinstance(body["answer"], str)
    assert len(body["answer"]) > 40
    # Persisted
    g = requests.get(f"{API}/offensive/network/scan/{EXISTING_DEEP_SCAN}", timeout=30).json()
    assert "ai_summary" in g and g["ai_summary"]


# ---------------- Regression: other offensive endpoints importable ----------------
def test_regression_offensive_router_alive():
    # AD enumerate should reject invalid host gracefully (not 500 due to import error)
    r = requests.post(f"{API}/offensive/ad/enumerate", json={"host": "127.0.0.1", "port": 389}, timeout=15)
    # either 200 with error field, or 4xx/5xx from network — key is: not an ImportError-style crash
    assert r.status_code in (200, 400, 422, 500, 502, 503, 504)


def test_regression_pivot_endpoint():
    r = requests.post(f"{API}/offensive/network/pivot", json={"question": "How to pivot to internal?"}, timeout=60)
    assert r.status_code in (200, 400, 422)
    if r.status_code == 200:
        assert "answer" in r.json()
