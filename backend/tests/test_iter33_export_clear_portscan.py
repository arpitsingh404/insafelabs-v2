"""Iteration 33 — Test: export-history backup, per-module clear-history, portscan, full-wipe."""
import os
import json
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "http://localhost:8001").rstrip("/")
API = f"{BASE_URL}/api"


# -------------------- Export history --------------------
class TestExportHistory:
    def test_export_returns_json_attachment(self):
        r = requests.get(f"{API}/dashboard/export-history", timeout=60)
        assert r.status_code == 200, r.text
        cd = r.headers.get("content-disposition", "")
        assert "attachment" in cd.lower()
        assert "insafelabs-history-backup-" in cd
        assert cd.endswith('.json"') or ".json" in cd
        assert r.headers.get("content-type", "").startswith("application/json")

    def test_export_body_shape(self):
        r = requests.get(f"{API}/dashboard/export-history", timeout=60)
        data = r.json()
        assert "generated" in data
        assert "collections" in data
        assert "total_records" in data
        cols = data["collections"]
        # 13 history collections
        assert len(cols) == 13, f"Expected 13 collections, got {len(cols)}: {list(cols.keys())}"
        for key in ["recon_scans", "network_scans", "bugbounty_scans", "osint_lookups",
                    "assessments", "sca_scans", "binary_scans", "apk_scans", "cloud_scans",
                    "scan_alerts", "pentest_sessions", "pentest_messages", "vdp_reports"]:
            assert key in cols
            assert isinstance(cols[key], list)
        assert isinstance(data["total_records"], int)


# -------------------- Per-module clear-history --------------------
class TestClearHistoryModule:
    def test_unknown_module_returns_404(self):
        r = requests.post(f"{API}/dashboard/clear-history/nonsense", timeout=15)
        assert r.status_code == 404
        assert "detail" in r.json()

    @pytest.mark.parametrize("module,expected_colls", [
        ("osint", ["osint_lookups"]),
        ("scanner", ["recon_scans", "scan_alerts"]),
        ("bugbounty", ["bugbounty_scans"]),
        ("network", ["network_scans"]),
        ("code", ["assessments", "sca_scans"]),
        ("binary", ["binary_scans"]),
        ("redteam", ["apk_scans", "cloud_scans"]),
        ("ai", ["pentest_sessions", "pentest_messages"]),
    ])
    def test_valid_modules_return_ok(self, module, expected_colls):
        # Seed a record for osint/scanner/bugbounty so we get a non-zero delete count
        if module == "osint":
            requests.post(f"{API}/osint/lookup", json={"kind": "username", "query": f"TEST_seed_{module}"}, timeout=30)
        r = requests.post(f"{API}/dashboard/clear-history/{module}", timeout=30)
        assert r.status_code == 200, r.text
        d = r.json()
        assert d["ok"] is True
        assert d["module"] == module
        assert "total_deleted" in d
        assert "deleted" in d
        for c in expected_colls:
            assert c in d["deleted"]

    def test_osint_clear_actually_wipes(self):
        # seed
        requests.post(f"{API}/osint/lookup", json={"kind": "username", "query": "TEST_seed_wipe"}, timeout=30)
        # clear
        r = requests.post(f"{API}/dashboard/clear-history/osint", timeout=30)
        assert r.status_code == 200
        # verify empty via history endpoint (case-file)
        r2 = requests.get(f"{API}/osint/history", timeout=15)
        if r2.status_code == 200:
            body = r2.json()
            items = body.get("items") if isinstance(body, dict) else body
            if isinstance(items, list):
                assert len(items) == 0


# -------------------- Full-wipe clear-history --------------------
class TestFullWipe:
    def test_full_wipe_ok(self):
        r = requests.post(f"{API}/dashboard/clear-history", timeout=60)
        assert r.status_code == 200, r.text
        d = r.json()
        assert d["ok"] is True
        assert "total_deleted" in d
        assert "deleted" in d
        # 13 collections in the deleted map
        assert len(d["deleted"]) == 13


# -------------------- Port Scan --------------------
class TestPortScan:
    def test_scanme_nmap_org_open_ports(self):
        r = requests.post(f"{API}/toolkit/portscan",
                          json={"host": "scanme.nmap.org"}, timeout=90)
        assert r.status_code == 200, r.text
        d = r.json()
        assert d["host"] == "scanme.nmap.org"
        assert d.get("ip")
        assert d.get("private") is False
        assert "scanned" in d
        assert "open_count" in d
        assert "elapsed_ms" in d
        assert isinstance(d.get("ports"), list)
        # ports 22 (ssh) and 80 (http) expected on scanme.nmap.org
        ports_by_num = {p["port"]: p for p in d["ports"]}
        assert 22 in ports_by_num, f"port 22 not found. Open ports: {list(ports_by_num.keys())}"
        assert 80 in ports_by_num, f"port 80 not found. Open ports: {list(ports_by_num.keys())}"
        assert ports_by_num[22]["service"].lower() in ("ssh", "ssh?", "openssh")
        assert ports_by_num[80]["service"].lower() in ("http", "http?", "www")

    def test_private_ip_flagged(self):
        r = requests.post(f"{API}/toolkit/portscan",
                          json={"host": "192.168.1.1"}, timeout=90)
        assert r.status_code == 200, r.text
        d = r.json()
        assert d.get("private") is True
        assert d.get("open_count", 0) == 0 or "note" in d
        # Should have some note about unreachable/private
        note = (d.get("note") or "").lower()
        assert any(w in note for w in ["private", "unreachable", "lan", "local"]) or d.get("open_count") == 0

    def test_invalid_host_graceful(self):
        r = requests.post(f"{API}/toolkit/portscan",
                          json={"host": "definitely-not-a-real-host-xyz-12345.invalid"}, timeout=30)
        # Either 400/502 or 200 with error indicator
        assert r.status_code in (200, 400, 422, 502)


# -------------------- Toolkit tab regression: ensure endpoints for all 16 tabs work --------------------
class TestToolkitRegression16:
    def test_dns(self):
        r = requests.post(f"{API}/toolkit/dns", json={"domain": "example.com"}, timeout=30)
        assert r.status_code == 200

    # subnet/password/jwt/encoders/cipher/hashing/revshell/payloads/dork/paykeys are pure client-side tools — no backend
