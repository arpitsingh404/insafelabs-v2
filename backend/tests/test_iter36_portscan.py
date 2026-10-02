"""Iteration 36 - Port Scan (RustScan-style) backend tests."""
import os
import time
import pytest
import requests
from dotenv import load_dotenv

load_dotenv("/app/frontend/.env")
BASE_URL = os.environ.get("REACT_APP_BACKEND_URL").rstrip("/")
API = f"{BASE_URL}/api"

HOST = "scanme.nmap.org"


def _start(payload):
    return requests.post(f"{API}/toolkit/portscan/start", json=payload, timeout=20)


def _poll(job_id, want_status="done", max_wait=60, interval=0.7):
    deadline = time.time() + max_wait
    last = None
    while time.time() < deadline:
        r = requests.get(f"{API}/toolkit/portscan/status/{job_id}", timeout=10)
        assert r.status_code == 200, r.text
        last = r.json()
        if last.get("status") in ("done", "cancelled", "error"):
            if want_status is None or last["status"] == want_status:
                return last
            return last
        time.sleep(interval)
    return last


class TestPortScanLifecycle:
    def test_start_top100_and_complete(self):
        r = _start({"host": HOST, "profile": "top100"})
        assert r.status_code == 200, r.text
        data = r.json()
        assert "id" in data
        assert data["total"] in (99, 100), f"expected ~100 ports, got {data['total']}"
        assert data.get("ip")
        assert data.get("host") == HOST
        job_id = data["id"]

        final = _poll(job_id, want_status="done", max_wait=90)
        assert final["status"] == "done", f"final status: {final}"
        assert 22 in final["open"], f"port 22 missing in {final['open']}"
        assert 80 in final["open"], f"port 80 missing in {final['open']}"
        assert final["open_count"] >= 2

        # Deep probe entries
        ports = {p["port"]: p for p in final.get("ports", [])}
        assert 22 in ports
        assert 80 in ports
        ssh = ports[22]
        # ssh service or banner
        assert (ssh.get("service") or "").lower().startswith("ssh") or "SSH" in (ssh.get("banner") or "")
        http = ports[80]
        title = (http.get("title") or "").lower()
        server = (http.get("server") or "")
        assert "scanme" in title or "Apache" in server or (http.get("service") or "").lower() == "http"

        # host_info
        hi = final.get("host_info") or {}
        # rDNS may be None; but usually resolves. Non-fatal.
        # At minimum expect key existence
        assert isinstance(hi, dict)


class TestPortScanStatusNotFound:
    def test_unknown_job_id_404(self):
        r = requests.get(f"{API}/toolkit/portscan/status/does-not-exist-xyz", timeout=10)
        assert r.status_code == 404


class TestPortScanProfiles:
    def test_quick_profile(self):
        r = _start({"host": HOST, "profile": "quick"})
        assert r.status_code == 200
        d = r.json()
        assert 20 <= d["total"] <= 50, f"quick total: {d['total']}"

    def test_top1000_profile(self):
        r = _start({"host": HOST, "profile": "top1000"})
        assert r.status_code == 200
        d = r.json()
        assert d["total"] == 1000

    def test_full_profile_starts(self):
        r = _start({"host": HOST, "profile": "full"})
        assert r.status_code == 200
        d = r.json()
        assert d["total"] == 65535
        # verify status endpoint works and shows progress (don't wait for completion)
        time.sleep(2.0)
        s = requests.get(f"{API}/toolkit/portscan/status/{d['id']}", timeout=10)
        assert s.status_code == 200
        sj = s.json()
        assert sj["status"] in ("running", "done")
        assert sj["total"] == 65535
        # cancel to free resources
        requests.post(f"{API}/toolkit/portscan/cancel/{d['id']}", timeout=10)

    def test_custom_profile_ports(self):
        ports = "22,80,443,8000-8010"
        # 3 + 11 = 14
        r = _start({"host": HOST, "profile": "custom", "ports": ports})
        assert r.status_code == 200
        d = r.json()
        assert d["total"] == 14, f"expected 14, got {d['total']}"
        final = _poll(d["id"], want_status="done", max_wait=60)
        assert final["status"] == "done"
        assert 22 in final["open"]
        assert 80 in final["open"]


class TestPortScanCancel:
    def test_cancel_full_scan(self):
        r = _start({"host": HOST, "profile": "full"})
        assert r.status_code == 200
        job_id = r.json()["id"]
        time.sleep(1.0)
        c = requests.post(f"{API}/toolkit/portscan/cancel/{job_id}", timeout=10)
        assert c.status_code == 200
        # poll until cancelled
        deadline = time.time() + 30
        final = None
        while time.time() < deadline:
            s = requests.get(f"{API}/toolkit/portscan/status/{job_id}", timeout=10).json()
            if s["status"] in ("cancelled", "done"):
                final = s
                break
            time.sleep(0.7)
        assert final is not None
        assert final["status"] == "cancelled", f"expected cancelled, got {final['status']}"


class TestPortScanInvalidHost:
    def test_invalid_host(self):
        r = _start({"host": "notarealhost.invalid", "profile": "quick"})
        # Expect graceful 400
        assert r.status_code == 400, f"expected 400, got {r.status_code}: {r.text}"


class TestToolkitRegression:
    """Smoke check that other toolkit endpoints still respond."""

    def test_toolkit_endpoints_reachable(self):
        # A few sanity endpoints. We don't validate deep behavior - just non-5xx.
        checks = [
            ("POST", "/toolkit/encode", {"input": "hello", "algo": "base64"}),
            ("POST", "/toolkit/hash", {"input": "hello", "algo": "sha256"}),
            ("POST", "/toolkit/password/generate", {"length": 16}),
        ]
        for method, path, body in checks:
            url = f"{API}{path}"
            r = requests.request(method, url, json=body, timeout=15)
            # allow 200/400/404 but never 500
            assert r.status_code < 500, f"{path} -> {r.status_code}: {r.text[:200]}"
