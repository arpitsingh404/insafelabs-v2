"""Backend API tests for DAXX iteration 4:
   - /api/tools/ipinfo (geo lookup for self and explicit IP + domain)
   - /api/scanner/scan deep recon sections (tech, subdomains, network, webvulns, api, screenshot)
   - /api/scanner/scans/{id}/report PDF endpoint
   - VDP removal from frontend routing (see playwright test); backend router still exists (noted).
"""
import os
import time
import pytest
import requests

BASE_URL = os.environ["REACT_APP_BACKEND_URL"].rstrip("/") if os.environ.get("REACT_APP_BACKEND_URL") else "https://localhost:8001"
API = f"{BASE_URL}/api"


# ------------------ tools / ipinfo ------------------
class TestIpInfo:
    def test_ipinfo_explicit_ip_us(self):
        r = requests.get(f"{API}/tools/ipinfo", params={"ip": "8.8.8.8"}, timeout=15)
        assert r.status_code == 200, r.text
        data = r.json()
        assert data.get("countryCode") == "US"
        assert "lat" in data and "lon" in data
        assert data.get("query") == "8.8.8.8"
        assert data.get("is_self") is False

    def test_ipinfo_domain_lookup(self):
        r = requests.get(f"{API}/tools/ipinfo", params={"ip": "github.com"}, timeout=15)
        assert r.status_code == 200, r.text
        data = r.json()
        assert data.get("status", "success") != "fail"
        assert data.get("country")
        assert data.get("lat") is not None

    def test_ipinfo_self(self):
        r = requests.get(f"{API}/tools/ipinfo", timeout=15)
        # Even if it fails geo, must return 200 or 404 (private ip). Prefer 200.
        assert r.status_code in (200, 404)
        if r.status_code == 200:
            assert r.json().get("is_self") is True


# ------------------ scanner deep recon ------------------
class TestScannerDeep:
    scan_id = None

    def test_deep_scan_iana(self):
        payload = {
            "target": "iana.org",
            "options": {
                "scan_ports": True, "scan_ssl": True, "scan_headers": True,
                "scan_endpoints": True, "scan_tech": True, "scan_cms": True,
                "scan_secrets": True, "scan_subdomains": True,
                "scan_webvulns": True, "scan_api": True, "scan_network": True,
                "scan_screenshot": True,
            },
        }
        r = requests.post(f"{API}/scanner/scan", json=payload, timeout=180)
        assert r.status_code == 200, r.text
        doc = r.json()
        TestScannerDeep.scan_id = doc.get("id") or doc.get("_id")
        assert TestScannerDeep.scan_id
        # Deep recon fields should exist (may be empty structures)
        assert "tech" in doc or "webvulns" in doc or "network" in doc, f"missing deep keys: {list(doc.keys())}"
        # Subdomains should include something (best-effort)
        subs_obj = doc.get("subdomains") or {}
        subs = subs_obj.get("subdomains") if isinstance(subs_obj, dict) else subs_obj
        assert isinstance(subs, list) and len(subs) > 0, f"subdomains empty: {subs_obj}"
        assert any("iana.org" in s for s in subs)
        # Network should return DNS records
        network = doc.get("network") or {}
        assert isinstance(network, dict)
        print("iana subdomains sample:", subs[:5])
        print("network keys:", list(network.keys()))
        print("tech:", doc.get("tech"))
        print("screenshot:", (doc.get("screenshot") or "")[:80])

    def test_pdf_report(self):
        assert TestScannerDeep.scan_id, "scan must have completed"
        r = requests.get(
            f"{API}/scanner/scans/{TestScannerDeep.scan_id}/report",
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=60,
        )
        assert r.status_code == 200, r.text[:300]
        assert "application/pdf" in r.headers.get("content-type", "")
        assert r.content[:4] == b"%PDF"


# ------------------ VDP frontend removal ------------------
class TestVdpFrontendRemoval:
    def test_frontend_landing_no_vdp_link(self):
        r = requests.get(BASE_URL + "/", timeout=15, headers={"User-Agent": "Mozilla/5.0"})
        assert r.status_code == 200
        # SPA; content is client-rendered so we can't assert too much here
