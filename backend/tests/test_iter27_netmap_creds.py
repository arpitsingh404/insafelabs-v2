"""Iter27 — Default creds & access panel for Network Mapper.

Covers:
 - unit-level _fingerprint / _device_access mapping for cameras, routers, exposed DBs
 - live e2e scan of scanme.nmap.org includes host.access with web creds + hydra ssh cmd
 - regression: pivot & AD endpoints still importable
"""
import os
import sys
import time
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL").rstrip("/")
API = f"{BASE_URL}/api"

# make backend importable for unit-level tests
sys.path.insert(0, "/app/backend")
from routers import offensive as off  # noqa: E402


# ----------------------------- unit tests ---------------------------------
class TestFingerprintAccess:
    def test_hikvision_camera(self):
        services = [
            {"port": 80, "service": "HTTP", "banner": "App-webs Hikvision-Webs"},
            {"port": 554, "service": "RTSP", "banner": ""},
        ]
        fp = off._fingerprint(services, "")
        assert fp["device_type"] == "IP Camera / NVR"
        assert fp["vendor"] == "Hikvision"

        acc = off._device_access("1.2.3.4", services, fp["device_type"], fp["vendor"])
        pairs = [(c["user"], c["pass"]) for c in acc["creds"]]
        # First two should be admin/12345 and admin/ (empty)
        assert pairs[0] == ("admin", "12345")
        assert ("admin", "") in pairs[:4]
        rtsps = [a["url"] for a in acc["access"] if a["type"] == "RTSP"]
        assert any("rtsp://1.2.3.4:554/Streaming/Channels/101" in u for u in rtsps)
        cmds = " ".join(acc["commands"])
        assert "ffplay" in cmds and "rtsp" in cmds
        assert "hydra -s 554" in cmds and "rtsp://1.2.3.4" in cmds

    def test_dahua_camera(self):
        services = [
            {"port": 80, "service": "HTTP", "banner": "Dahua DVR web"},
            {"port": 554, "service": "RTSP", "banner": ""},
        ]
        fp = off._fingerprint(services, "")
        assert fp["vendor"] == "Dahua"
        acc = off._device_access("1.1.1.1", services, fp["device_type"], "Dahua")
        pairs = [(c["user"], c["pass"]) for c in acc["creds"]]
        assert ("admin", "admin") in pairs
        assert ("888888", "888888") in pairs
        assert any("/cam/realmonitor" in a["url"] for a in acc["access"] if a["type"] == "RTSP")

    def test_mongodb_no_auth_note(self):
        services = [{"port": 27017, "service": "MongoDB", "banner": ""}]
        fp = off._fingerprint(services, "")
        acc = off._device_access("9.9.9.9", services, fp["device_type"], fp.get("vendor"))
        joined = " ".join(acc["notes"])
        assert "NO authentication" in joined
        assert "mongosh" in joined and "9.9.9.9:27017" in joined

    def test_mikrotik_router(self):
        services = [{"port": 80, "service": "HTTP", "banner": "RouterOS Mikrotik"}]
        fp = off._fingerprint(services, "")
        assert fp["device_type"] == "Router / Firewall"
        assert fp["vendor"] == "Mikrotik"
        acc = off._device_access("2.2.2.2", services, fp["device_type"], "Mikrotik")
        pairs = [(c["user"], c["pass"]) for c in acc["creds"]]
        assert ("admin", "") in pairs


# ------------------------- live e2e via scanme -----------------------------
class TestScanmeAccess:
    def test_scanme_has_access_object(self):
        r = requests.post(f"{API}/offensive/network/scan",
                          json={"target": "scanme.nmap.org", "profile": "quick",
                                "banners": True, "os_guess": True, "rdns": True},
                          timeout=30)
        assert r.status_code == 200, r.text
        scan_id = r.json()["id"]

        # poll up to 90s
        doc = None
        for _ in range(45):
            g = requests.get(f"{API}/offensive/network/scan/{scan_id}", timeout=15)
            assert g.status_code == 200
            doc = g.json()
            if doc.get("status") == "completed":
                break
            time.sleep(2)
        assert doc and doc.get("status") == "completed", f"scan didn't finish: {doc}"

        hosts = doc.get("hosts") or []
        assert hosts, "no live hosts"
        for h in hosts:
            assert "access" in h and isinstance(h["access"], dict)
            assert "creds" in h["access"] and "access" in h["access"] and "commands" in h["access"]

        h0 = hosts[0]
        acc = h0["access"]
        # Web UI URL
        urls = [a["url"] for a in acc["access"]]
        assert any(u.startswith("http://") and h0["ip"] in u for u in urls), f"no web UI url: {urls}"
        # default web creds
        pairs = [(c["user"], c["pass"]) for c in acc["creds"]]
        assert ("admin", "admin") in pairs
        assert ("admin", "password") in pairs
        assert ("admin", "") in pairs
        # ssh hydra command
        cmds = " ".join(acc["commands"])
        assert "hydra" in cmds and "ssh://" in cmds


# ------------------------- regression checks -------------------------------
class TestRegression:
    def test_ad_and_re_routes_registered(self):
        # importable and router has expected paths
        paths = {r.path for r in off.router.routes}
        for p in ("/offensive/ad/enumerate", "/offensive/smb/enumerate",
                  "/offensive/network/scan", "/offensive/binary/analyze",
                  "/offensive/network/pivot"):
            assert p in paths, f"missing route {p}"

    def test_interfaces_endpoint(self):
        r = requests.get(f"{API}/offensive/network/interfaces", timeout=15)
        assert r.status_code == 200
        assert "segments" in r.json()
