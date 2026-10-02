"""Iteration 23 — Bug Bounty API Discovery + JSON/Postman export tests."""
import json
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

# reuse the already-completed httpbin.org scan from main-agent verification
EXISTING_SCAN_ID = "79b18530-7afb-4f43-a41c-65553a5a7cb3"


@pytest.fixture(scope="module")
def scan_id():
    """Use existing completed scan if available; otherwise start a fresh one and poll."""
    r = requests.get(f"{API}/bugbounty/scan/{EXISTING_SCAN_ID}", timeout=15)
    if r.status_code == 200 and r.json().get("status") == "done":
        return EXISTING_SCAN_ID
    # fallback: kick off a fresh petstore scan (smaller, ~21 endpoints)
    s = requests.post(f"{API}/bugbounty/scan", json={"target": "petstore.swagger.io"}, timeout=30)
    assert s.status_code == 200, s.text
    sid = s.json()["id"]
    deadline = time.time() + 240
    while time.time() < deadline:
        p = requests.get(f"{API}/bugbounty/scan/{sid}", timeout=20).json()
        if p.get("status") in ("done", "error"):
            break
        time.sleep(5)
    return sid


# ---------- Scan document: API discovery fields ----------
def test_scan_has_api_discovery_fields(scan_id):
    d = requests.get(f"{API}/bugbounty/scan/{scan_id}", timeout=20).json()
    assert d.get("status") == "done", f"stage={d.get('stage')} err={d.get('error')}"
    assert "api_count" in d and isinstance(d["api_count"], int) and d["api_count"] > 0
    assert isinstance(d.get("api_specs"), list) and len(d["api_specs"]) >= 1
    assert all(s.startswith("http") for s in d["api_specs"])
    inv = d.get("api_inventory")
    assert isinstance(inv, list) and len(inv) == d["api_count"]
    for ep in inv[:5]:
        for k in ("method", "url", "source", "is_json", "auth", "params", "summary"):
            assert k in ep, f"missing key {k} in endpoint {ep}"
        assert ep["method"] in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")
        assert ep["url"].startswith("http")


def test_stage_stepper_includes_api_recon(scan_id):
    # The completed scan should have progressed through api_recon; final stage=done
    d = requests.get(f"{API}/bugbounty/scan/{scan_id}", timeout=20).json()
    assert d.get("stage") == "done"
    assert d.get("progress") in (100, 99, 98) or d.get("progress") >= 88


# ---------- Export: JSON ----------
def test_export_apis_json(scan_id):
    r = requests.get(f"{API}/bugbounty/export/{scan_id}/apis", timeout=30)
    assert r.status_code == 200
    assert "application/json" in r.headers.get("content-type", "")
    cd = r.headers.get("content-disposition", "")
    assert "attachment" in cd
    assert "insafelabs-apis-" in cd
    body = r.json()
    for k in ("target", "generated", "count", "specs", "endpoints"):
        assert k in body
    assert body["count"] == len(body["endpoints"]) > 0
    assert body["target"] in cd  # e.g. httpbin.org appears in filename


def test_export_apis_json_404():
    r = requests.get(f"{API}/bugbounty/export/does-not-exist-xyz/apis", timeout=15)
    assert r.status_code == 404


# ---------- Export: Postman ----------
def test_export_postman(scan_id):
    r = requests.get(f"{API}/bugbounty/export/{scan_id}/postman", timeout=30)
    assert r.status_code == 200
    assert "application/json" in r.headers.get("content-type", "")
    cd = r.headers.get("content-disposition", "")
    assert "attachment" in cd
    assert "insafelabs-postman-" in cd
    coll = r.json()
    assert "info" in coll and "name" in coll["info"]
    assert "schema" in coll["info"] and "v2.1.0" in coll["info"]["schema"]
    assert isinstance(coll["item"], list) and len(coll["item"]) > 0
    item = coll["item"][0]
    assert "name" in item and "request" in item
    req = item["request"]
    assert req["method"] in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")
    assert "url" in req and "raw" in req["url"]


def test_export_postman_404():
    r = requests.get(f"{API}/bugbounty/export/does-not-exist-xyz/postman", timeout=15)
    assert r.status_code == 404
