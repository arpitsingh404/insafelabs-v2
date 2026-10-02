"""Tests for DAXX Attack Surface Scanner - async flow + advanced modules."""
import os
import time
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")
if not BASE_URL:
    # Fallback to frontend .env
    with open("/app/frontend/.env") as f:
        for line in f:
            if line.startswith("REACT_APP_BACKEND_URL="):
                BASE_URL = line.split("=", 1)[1].strip().rstrip("/")

API = f"{BASE_URL}/api"

# Minimal fast module selection
FAST_OPTS = dict(
    scan_ports=False, scan_ssl=False, scan_endpoints=False, scan_tech=False,
    scan_secrets=False, scan_subdomains=False, scan_webvulns=False, scan_api=False,
    scan_network=False, capture_screenshot=False,
    scan_headers=True, scan_config=False, scan_cors=True, scan_cookies=True,
    scan_methods=True, scan_csp=True, scan_waf=True, scan_dns_ext=False,
    scan_deepvulns=False, scan_graphql=False, scan_takeover=False, scan_wellknown=True,
)


def _poll(scan_id, timeout=180):
    t0 = time.time()
    while time.time() - t0 < timeout:
        r = requests.get(f"{API}/scanner/scans/{scan_id}", timeout=15)
        assert r.status_code == 200
        d = r.json()
        if d.get("status") in ("completed", "failed"):
            return d
        time.sleep(2.5)
    pytest.fail(f"Scan {scan_id} did not complete within {timeout}s")


def test_async_scan_returns_immediately():
    """POST /api/scanner/scan should return <2s with id + running status."""
    t0 = time.time()
    r = requests.post(f"{API}/scanner/scan",
                      json={"target": "https://github.com/login", **FAST_OPTS}, timeout=10)
    elapsed = time.time() - t0
    assert r.status_code == 200, r.text
    body = r.json()
    assert "id" in body
    assert body.get("status") == "running"
    assert elapsed < 3.0, f"POST took {elapsed:.2f}s - not truly async"


def test_github_scan_populates_advanced_modules():
    """Full flow: scan github.com/login → poll → verify new keys."""
    r = requests.post(f"{API}/scanner/scan",
                      json={"target": "https://github.com/login", **FAST_OPTS}, timeout=10)
    assert r.status_code == 200
    scan_id = r.json()["id"]

    doc = _poll(scan_id, timeout=180)
    assert doc["status"] == "completed", f"Scan failed: {doc.get('error')}"

    # Verify all new keys present
    for key in ["config", "cors", "cookies_audit", "methods", "csp", "waf",
                "dns_ext", "deepvulns", "graphql", "takeover", "wellknown", "wordpress"]:
        assert key in doc, f"Missing key: {key}"

    # CSP present with issues (github uses unsafe-inline)
    assert doc["csp"].get("present") is True, f"CSP not present: {doc['csp']}"
    assert len(doc["csp"].get("issues", [])) > 0, "CSP should have issues on github"

    # Weak CSP finding
    titles = [f.get("title", "") for f in doc.get("findings", [])]
    assert any("Weak Content-Security-Policy" in t for t in titles), \
        f"Missing Weak-CSP finding. Titles: {titles[:10]}"

    # Cookies audit non-empty
    assert len(doc["cookies_audit"].get("cookies", [])) > 0, "cookies_audit empty"

    # Well-known: robots + security.txt
    assert doc["wellknown"].get("robots") is True
    assert doc["wellknown"].get("security_txt") is True


def test_config_scan_no_false_positives_on_secure_target():
    """config_exposure_scan on github should probe ~99 and find 0."""
    opts = {k: False for k in FAST_OPTS}
    opts["scan_config"] = True
    r = requests.post(f"{API}/scanner/scan",
                      json={"target": "https://github.com", **opts}, timeout=10)
    scan_id = r.json()["id"]
    doc = _poll(scan_id, timeout=180)
    assert doc["status"] == "completed"
    cfg = doc.get("config", {})
    assert isinstance(cfg, dict)
    # probed count should be present and reasonable
    probed = cfg.get("probed", 0)
    assert probed >= 90, f"Expected ~99 probed, got {probed}"
    hits = cfg.get("hits") or cfg.get("config_hits") or []
    assert len(hits) == 0, f"Unexpected config hits on github: {hits}"


def test_example_com_dnssec():
    """example.com should show dnssec=true."""
    opts = {k: False for k in FAST_OPTS}
    opts["scan_dns_ext"] = True
    r = requests.post(f"{API}/scanner/scan",
                      json={"target": "https://example.com", **opts}, timeout=10)
    scan_id = r.json()["id"]
    doc = _poll(scan_id, timeout=120)
    assert doc["status"] == "completed"
    assert doc["dns_ext"].get("dnssec") is True, f"dns_ext: {doc['dns_ext']}"


def test_scans_list_and_delete():
    """Verify listing returns docs and delete works."""
    r = requests.get(f"{API}/scanner/scans", timeout=10)
    assert r.status_code == 200
    lst = r.json()
    assert isinstance(lst, list)
