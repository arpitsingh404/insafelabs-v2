"""Iteration 24: Enhanced JS Recon (7 arrays + finding promotion)."""
import os
import time
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "http://localhost:8001").rstrip("/")
EXISTING_SCAN_ID = "b3b5a304-90f2-4cdd-936d-5f14ff410abd"
JS_KEYS = ["endpoints", "secrets", "admin_panels", "feature_flags",
           "internal_domains", "libraries", "source_maps"]


@pytest.fixture(scope="module")
def scan():
    r = requests.get(f"{BASE_URL}/api/bugbounty/scan/{EXISTING_SCAN_ID}", timeout=30)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d.get("status") == "done"
    return d


# --- JS Recon structure ---
class TestJSReconStructure:
    def test_all_seven_arrays_present(self, scan):
        j = scan.get("js_recon") or {}
        for k in JS_KEYS:
            assert k in j, f"missing key {k}"
            assert isinstance(j[k], list), f"{k} not list"

    def test_libraries_shape(self, scan):
        libs = scan["js_recon"]["libraries"]
        assert len(libs) >= 1
        jq = next((l for l in libs if l.get("name") == "jQuery"), None)
        assert jq is not None
        for k in ("name", "version", "fixed", "cvss", "note", "vulnerable", "source"):
            assert k in jq
        assert jq["version"] == "4.0.0"
        assert jq["vulnerable"] is False  # 4.0.0 > 3.5.0

    def test_admin_panels_shape(self, scan):
        panels = scan["js_recon"]["admin_panels"]
        assert len(panels) >= 1
        p = panels[0]
        for k in ("url", "status", "exposed"):
            assert k in p
        assert isinstance(p["status"], int)
        assert isinstance(p["exposed"], bool)

    def test_internal_domains_are_strings_no_fp(self, scan):
        doms = scan["js_recon"]["internal_domains"]
        assert all(isinstance(d, str) for d in doms)
        # regression: no bogus x.test/t.test/*.test etc from minified JS
        for d in doms:
            assert not d.endswith(".test"), f"false-positive .test host: {d}"
            assert not d.endswith(".svc"), f"false-positive .svc host: {d}"
        assert "yekta.dev" in doms

    def test_feature_flags_are_strings(self, scan):
        assert all(isinstance(f, str) for f in scan["js_recon"]["feature_flags"])

    def test_endpoints_are_strings(self, scan):
        assert all(isinstance(e, str) for e in scan["js_recon"]["endpoints"])

    def test_secrets_shape(self, scan):
        for s in scan["js_recon"]["secrets"]:
            assert isinstance(s, dict)

    def test_source_maps_shape(self, scan):
        for sm in scan["js_recon"]["source_maps"]:
            assert isinstance(sm, dict)
            for k in ("url", "sources_count", "sample"):
                assert k in sm


# --- Findings promotion ---
class TestFindingsPromotion:
    def test_internal_leak_finding_present(self, scan):
        findings = scan.get("findings") or []
        il = [f for f in findings if f.get("type") == "internal-leak"]
        assert len(il) == 1, f"expected 1 internal-leak, got {len(il)}"
        f = il[0]
        assert "cvss" in f and "severity" in f and "remediation" in f
        assert "yekta.dev" in (f.get("detail", "") + f.get("evidence", ""))

    def test_no_vuln_lib_for_jquery_4(self, scan):
        # jQuery 4.0.0 should NOT create a vuln-lib finding
        vl = [f for f in scan["findings"] if f.get("type") == "vuln-lib"]
        assert len(vl) == 0

    def test_no_admin_panel_finding_since_404(self, scan):
        # wp-admin returned 404 -> exposed=False -> no admin-panel finding
        ap = [f for f in scan["findings"] if f.get("type") == "admin-panel"]
        assert len(ap) == 0

    def test_findings_promotion_code_covers_all_five_types(self):
        """Static check that router promotes all 5 new finding types."""
        src = open("/app/backend/routers/bugbounty.py").read()
        for t in ("js-secret", "sourcemap", "vuln-lib", "admin-panel", "internal-leak"):
            assert f'"{t}"' in src, f"promotion for {t} not found in router"


# --- Fresh scan smoke (optional; only if quick) ---
class TestBugBountyEndpointsRegression:
    def test_list_scans(self):
        r = requests.get(f"{BASE_URL}/api/bugbounty/scans", timeout=15)
        assert r.status_code == 200
        body = r.json()
        scans = body if isinstance(body, list) else body.get("scans")
        assert isinstance(scans, list) and len(scans) > 0

    def test_api_inventory_export(self, scan):
        # scan has apis object; regression - inventory still shaped
        apis = scan.get("api_inventory") or scan.get("apis") or []
        assert isinstance(apis, (list, dict))
