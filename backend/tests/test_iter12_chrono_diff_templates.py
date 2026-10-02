"""Iteration 12 tests: livefeed, template engine (no FP on github),
scan diff, PDF with new modules, async scan regression."""
import os
import time
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL").rstrip("/")
API = BASE_URL + "/api"

# For fast UI-oriented scans, disable heavy modules
FAST_OPTS = {
    "scan_subdomains": False,
    "scan_network": False,
    "scan_ports": False,
    "capture_screenshot": False,
    "scan_ssl": True,
    "scan_headers": True,
    "scan_endpoints": False,
    "scan_tech": True,
    "scan_secrets": False,
    "scan_webvulns": False,
    "scan_api": False,
    "scan_config": False,
    "scan_cors": True,
    "scan_cookies": True,
    "scan_methods": True,
    "scan_csp": True,
    "scan_waf": True,
    "scan_dns_ext": False,
    "scan_deepvulns": False,
    "scan_graphql": False,
    "scan_takeover": False,
    "scan_wellknown": True,
    "scan_templates": True,
}


def _wait_complete(scan_id, timeout=300):
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = requests.get(f"{API}/scanner/scans/{scan_id}", timeout=15)
        if r.status_code == 200:
            d = r.json()
            if d.get("status") in ("completed", "failed"):
                return d
        time.sleep(3)
    pytest.fail(f"Scan {scan_id} did not complete in {timeout}s")


# ----- Livefeed -----
def test_livefeed_shape():
    r = requests.get(f"{API}/dashboard/livefeed", timeout=20)
    assert r.status_code == 200
    data = r.json()
    assert "lines" in data and "scan_count" in data
    assert isinstance(data["lines"], list)
    assert isinstance(data["scan_count"], int)
    # each line should have t + m
    for line in data["lines"][:5]:
        assert "t" in line and "m" in line


# ----- Async scan regression -----
@pytest.fixture(scope="module")
def gh_scan():
    r = requests.post(f"{API}/scanner/scan",
                      json={"target": "https://github.com", **FAST_OPTS}, timeout=20)
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "running"
    assert "id" in body
    doc = _wait_complete(body["id"], timeout=300)
    assert doc["status"] == "completed"
    return doc


def test_async_scan_returns_running_immediately():
    t = time.time()
    r = requests.post(f"{API}/scanner/scan",
                      json={"target": "https://example.com", **FAST_OPTS}, timeout=15)
    elapsed = time.time() - t
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "running"
    assert elapsed < 5, f"Async scan blocked for {elapsed}s"


def test_scan_has_templates_key(gh_scan):
    assert "templates" in gh_scan
    tpl = gh_scan["templates"]
    assert "matched" in tpl
    assert "total_templates" in tpl
    assert "match_count" in tpl
    assert tpl["total_templates"] >= 40


def test_templates_zero_false_positive_on_github(gh_scan):
    tpl = gh_scan.get("templates") or {}
    matched = tpl.get("matched") or []
    # Github.com should not trigger prometheus/phpinfo/actuator/etc.
    fp_ids = {"phpinfo", "prometheus", "actuator-env", "adminer", "ds-store",
              "phpmyadmin", "traefik", "portainer", "django-debug",
              "kubernetes-dash", "docker-registry"}
    hits = [m["id"] for m in matched if m.get("id") in fp_ids]
    assert not hits, f"False positives on github.com: {hits}"


# ----- Diff endpoint -----
def test_diff_endpoint(gh_scan):
    # Second scan of same target
    r = requests.post(f"{API}/scanner/scan",
                      json={"target": "https://github.com", **FAST_OPTS}, timeout=20)
    assert r.status_code == 200
    id_b = r.json()["id"]
    _wait_complete(id_b, timeout=300)
    id_a = gh_scan["id"]

    d = requests.get(f"{API}/scanner/diff", params={"a": id_a, "b": id_b}, timeout=30)
    assert d.status_code == 200
    data = d.json()
    assert "a" in data and "b" in data
    assert "added" in data and isinstance(data["added"], list)
    assert "removed" in data and isinstance(data["removed"], list)
    assert "common_count" in data
    assert "risk_delta" in data
    assert "finding_delta" in data


def test_diff_404_on_missing_scan():
    r = requests.get(f"{API}/scanner/diff", params={"a": "missing-a", "b": "missing-b"}, timeout=15)
    assert r.status_code == 404


# ----- PDF with new sections -----
def test_pdf_report_valid(gh_scan):
    r = requests.get(f"{API}/scanner/scans/{gh_scan['id']}/report", timeout=90)
    assert r.status_code == 200
    assert r.headers.get("content-type", "").startswith("application/pdf")
    body = r.content
    assert body.startswith(b"%PDF-"), "PDF header missing"
    # end marker (may have trailing whitespace/newlines)
    assert b"%%EOF" in body[-1024:], "PDF EOF marker missing"
