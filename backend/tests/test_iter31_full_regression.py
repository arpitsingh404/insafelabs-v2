"""
Iteration 31: Full regression sweep across Bug Bounty, Network Mapper,
Assessments (code-review), and cross-cutting endpoints referenced in the
review request. Uses external BASE_URL via REACT_APP_BACKEND_URL.
"""
import os, time, json, pytest, requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL").rstrip("/")
API = f"{BASE_URL}/api"


# ---------------------- Bug Bounty ----------------------
class TestBugBounty:
    scan_id = None
    scan_id_2 = None

    def test_start_scan_httpbin(self):
        r = requests.post(f"{API}/bugbounty/scan",
                          json={"target": "httpbin.org", "scope": ["httpbin.org"]},
                          timeout=30)
        assert r.status_code == 200, r.text
        j = r.json()
        assert "id" in j
        TestBugBounty.scan_id = j["id"]

    def test_poll_scan_done(self):
        assert TestBugBounty.scan_id
        deadline = time.time() + 180
        status = None
        while time.time() < deadline:
            r = requests.get(f"{API}/bugbounty/scan/{TestBugBounty.scan_id}", timeout=30)
            assert r.status_code == 200
            j = r.json()
            status = j.get("status")
            if status in ("done", "error", "completed", "finished"):
                break
            time.sleep(4)
        assert status in ("done", "completed", "finished"), f"final status={status}"
        assert j.get("api_count", 0) >= 0
        # Should include api_inventory / api_specs keys (may be empty on httpbin)
        assert "api_inventory" in j or "api_specs" in j or "apis" in j

    def test_export_apis_json(self):
        r = requests.get(f"{API}/bugbounty/export/{TestBugBounty.scan_id}/apis", timeout=30)
        assert r.status_code == 200
        # should be JSON
        assert "application/json" in r.headers.get("content-type", "").lower() or r.text.strip().startswith(("{", "["))

    def test_export_postman(self):
        r = requests.get(f"{API}/bugbounty/export/{TestBugBounty.scan_id}/postman", timeout=30)
        assert r.status_code == 200
        try:
            j = r.json()
            assert "info" in j and "item" in j
        except Exception:
            pytest.fail("postman export not JSON")

    def test_export_sources_maybe_404(self):
        r = requests.get(f"{API}/bugbounty/export/{TestBugBounty.scan_id}/sources", timeout=30)
        # Either 200 zip or 404 no maps
        assert r.status_code in (200, 404)

    def test_second_scan_and_diff(self):
        r = requests.post(f"{API}/bugbounty/scan",
                          json={"target": "httpbin.org", "scope": ["httpbin.org"]}, timeout=30)
        assert r.status_code == 200
        TestBugBounty.scan_id_2 = r.json()["id"]
        deadline = time.time() + 180
        while time.time() < deadline:
            r = requests.get(f"{API}/bugbounty/scan/{TestBugBounty.scan_id_2}", timeout=30)
            if r.json().get("status") in ("done", "completed", "finished"):
                break
            time.sleep(4)
        j = r.json()
        # diff may be in field 'diff' or endpoint
        # Try known diff endpoint pattern
        candidates = [
            f"{API}/bugbounty/scan/{TestBugBounty.scan_id_2}/diff",
            f"{API}/bugbounty/diff/{TestBugBounty.scan_id_2}",
        ]
        got = None
        for u in candidates:
            rr = requests.get(u, timeout=15)
            if rr.status_code == 200:
                got = rr.json(); break
        # diff might be embedded in scan result
        assert got is not None or "diff" in j or "diff_summary" in j


# ---------------------- Network Mapper ----------------------
class TestNetworkMapper:
    scan_id = None

    def test_interfaces(self):
        r = requests.get(f"{API}/offensive/network/interfaces", timeout=15)
        assert r.status_code == 200
        j = r.json()
        assert isinstance(j, (list, dict))

    def test_scan_scanme(self):
        payload = {"target": "scanme.nmap.org", "profile": "quick",
                   "neighborhood": False, "os_guess": True, "banners": True, "rdns": True}
        r = requests.post(f"{API}/offensive/network/scan", json=payload, timeout=30)
        assert r.status_code == 200, r.text
        TestNetworkMapper.scan_id = r.json().get("id") or r.json().get("scan_id")
        assert TestNetworkMapper.scan_id
        deadline = time.time() + 180
        while time.time() < deadline:
            rr = requests.get(f"{API}/offensive/network/scan/{TestNetworkMapper.scan_id}", timeout=30)
            if rr.status_code == 200 and rr.json().get("status") in ("done", "completed", "finished"):
                j = rr.json(); break
            time.sleep(4)
        else:
            pytest.fail("network scan did not complete")
        assert "hosts" in j or "results" in j

    def test_analyze_ai(self):
        assert TestNetworkMapper.scan_id
        r = requests.post(f"{API}/offensive/network/analyze/{TestNetworkMapper.scan_id}", timeout=90)
        assert r.status_code == 200
        j = r.json()
        # AI text field
        assert any(k in j for k in ("analysis", "ai", "attack_path", "text", "output", "answer"))


# ---------------------- Assessments (Code Review) ----------------------
class TestAssessments:
    aid = None

    def test_unknown_module_400(self):
        r = requests.post(f"{API}/assessments/run", json={"module": "no-such", "inputs": {}}, timeout=15)
        assert r.status_code == 400

    def test_code_review_small(self):
        payload = {"module": "code-review",
                   "inputs": {"code": "def add(a,b):\n    return a+b\n", "language": "python"}}
        r = requests.post(f"{API}/assessments/run", json=payload, timeout=120)
        assert r.status_code == 200, r.text
        j = r.json()
        TestAssessments.aid = j.get("id") or j.get("_id")
        assert TestAssessments.aid
        assert "findings" in j or "result" in j

    def test_truncation_large(self):
        big = "print('x')\n" * 20000  # ~200k chars
        payload = {"module": "code-review", "inputs": {"code": big, "language": "python"}}
        r = requests.post(f"{API}/assessments/run", json=payload, timeout=180)
        assert r.status_code == 200

    def test_list_filter(self):
        r = requests.get(f"{API}/assessments?module=code-review", timeout=15)
        assert r.status_code == 200
        j = r.json()
        assert isinstance(j, list)
        # no mongo _id leak
        for item in j[:5]:
            assert "_id" not in item

    def test_get_and_delete(self):
        assert TestAssessments.aid
        r = requests.get(f"{API}/assessments/{TestAssessments.aid}", timeout=15)
        assert r.status_code == 200
        d = requests.delete(f"{API}/assessments/{TestAssessments.aid}", timeout=15)
        assert d.status_code in (200, 204)
        r2 = requests.get(f"{API}/assessments/{TestAssessments.aid}", timeout=15)
        assert r2.status_code == 404
