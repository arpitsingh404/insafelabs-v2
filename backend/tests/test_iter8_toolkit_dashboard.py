"""Iteration 8 tests: enriched dashboard/stats + toolkit (cve, dns)."""
import os
import time

import pytest
import requests

def _load_url():
    v = os.environ.get("REACT_APP_BACKEND_URL")
    if not v:
        try:
            with open("/app/frontend/.env") as f:
                for ln in f:
                    if ln.startswith("REACT_APP_BACKEND_URL="):
                        v = ln.split("=", 1)[1].strip()
                        break
        except Exception:
            pass
    return (v or "").rstrip("/")

BASE_URL = _load_url()
API = f"{BASE_URL}/api"


@pytest.fixture(scope="module")
def client():
    s = requests.Session()
    s.headers.update({"Content-Type": "application/json"})
    return s


# ---- Dashboard stats enriched ----
class TestDashboardStats:
    def test_stats_returns_new_keys(self, client):
        r = client.get(f"{API}/dashboard/stats", timeout=30)
        assert r.status_code == 200, r.text
        d = r.json()
        for k in ["osint_lookups", "apk_scans", "cloud_scans", "monitors_active",
                  "avg_risk", "top_targets", "risk_trend", "activity"]:
            assert k in d, f"missing {k}"
        assert isinstance(d["top_targets"], list)
        assert isinstance(d["risk_trend"], list) and len(d["risk_trend"]) == 14
        for pt in d["risk_trend"]:
            assert "date" in pt and "findings" in pt and "scans" in pt
        assert isinstance(d["activity"], list)
        assert isinstance(d["avg_risk"], int)


# ---- Toolkit CVE ----
class TestToolkitCVE:
    def test_cve_search_log4j(self, client):
        r = client.post(f"{API}/toolkit/cve", json={"keyword": "log4j", "limit": 5}, timeout=40)
        assert r.status_code == 200, r.text
        d = r.json()
        assert "total" in d and "results" in d
        assert isinstance(d["results"], list)
        if d["results"]:
            item = d["results"][0]
            for k in ["id", "description", "severity", "url"]:
                assert k in item

    def test_cve_short_keyword_rejected(self, client):
        time.sleep(2)  # avoid NVD rate limit
        r = client.post(f"{API}/toolkit/cve", json={"keyword": "a", "limit": 5}, timeout=40)
        assert r.status_code in (400, 422)


# ---- Toolkit DNS ----
class TestToolkitDNS:
    def test_dns_github(self, client):
        r = client.post(f"{API}/toolkit/dns", json={"domain": "github.com"}, timeout=60)
        assert r.status_code == 200, r.text
        d = r.json()
        # Recon lib returns a dict; should contain some DNS records
        assert isinstance(d, dict)
        assert d.get("domain") == "github.com"
        # Common fields likely present
        keys = set(d.keys())
        # accept either 'records' object or flat 'a', 'mx' etc.
        assert keys & {"records", "a", "mx", "ns", "txt", "dns"}, f"unexpected keys: {keys}"

    def test_dns_invalid(self, client):
        r = client.post(f"{API}/toolkit/dns", json={"domain": "x"}, timeout=15)
        assert r.status_code in (400, 422)
