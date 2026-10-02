"""Backend tests: AD Enum, Network Scan/Pivot, Binary RE."""
import os
import time
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL").rstrip("/")
API = f"{BASE_URL}/api"


# ---------------- AD ----------------
class TestAD:
    def test_ad_enumerate_public_ldap(self):
        r = requests.post(f"{API}/offensive/ad/enumerate",
                          json={"host": "ldap.forumsys.com", "port": 389}, timeout=45)
        assert r.status_code == 200, r.text
        d = r.json()
        assert d.get("reachable") is True
        assert d.get("bound") is True
        ncs = d.get("naming_contexts") or []
        assert any("dc=example,dc=com" in n.lower() for n in ncs), f"naming_contexts={ncs}"
        assert isinstance(d.get("notes"), list)

    def test_ad_enumerate_unreachable(self):
        r = requests.post(f"{API}/offensive/ad/enumerate",
                          json={"host": "10.255.255.1", "port": 389}, timeout=45)
        assert r.status_code == 200, r.text
        d = r.json()
        assert "reachable" in d and "bound" in d
        # should have an error string, no crash
        assert d.get("bound") is False

    def test_ad_advise(self):
        r = requests.post(f"{API}/offensive/ad/advise",
                          json={"question": "I have a low-priv domain user, whats my privesc path?"},
                          timeout=90)
        assert r.status_code == 200, r.text
        assert (r.json().get("answer") or "").strip()


# ---------------- Network ----------------
class TestNetwork:
    def _poll(self, scan_id, timeout=75):
        deadline = time.time() + timeout
        last = None
        while time.time() < deadline:
            r = requests.get(f"{API}/offensive/network/scan/{scan_id}", timeout=15)
            assert r.status_code == 200, r.text
            last = r.json()
            if last.get("status") in ("completed", "failed"):
                return last
            time.sleep(2.5)
        return last

    def test_network_scan_scanme(self):
        r = requests.post(f"{API}/offensive/network/scan",
                          json={"target": "scanme.nmap.org"}, timeout=15)
        assert r.status_code == 200
        j = r.json()
        assert j["status"] == "running"
        assert "id" in j
        doc = self._poll(j["id"])
        assert doc and doc.get("status") == "completed", doc
        assert doc.get("hosts_up", 0) >= 1
        assert isinstance(doc.get("nodes"), list) and len(doc["nodes"]) >= 3
        assert isinstance(doc.get("edges"), list)
        svcs = []
        for h in doc.get("hosts", []):
            svcs += [s.get("port") for s in h.get("services", [])]
        assert 22 in svcs and 80 in svcs, f"svcs={svcs}"

    def test_network_scan_cidr(self):
        r = requests.post(f"{API}/offensive/network/scan",
                          json={"target": "45.33.32.156/30"}, timeout=15)
        assert r.status_code == 200
        j = r.json()
        doc = self._poll(j["id"], timeout=120)
        assert doc.get("status") == "completed", doc

    def test_pivot_advise(self):
        r = requests.post(f"{API}/offensive/network/pivot",
                          json={"scenario": "foothold on 10.0.0.5 need to reach 10.0.1.0/24"},
                          timeout=90)
        assert r.status_code == 200, r.text
        assert (r.json().get("answer") or "").strip()


# ---------------- Binary RE ----------------
class TestBinary:
    def test_binary_elf(self):
        with open("/bin/ls", "rb") as f:
            files = {"file": ("ls", f, "application/octet-stream")}
            r = requests.post(f"{API}/offensive/binary/analyze", files=files, timeout=120)
        assert r.status_code == 200, r.text
        d = r.json()
        assert d.get("format") == "ELF"
        assert d.get("elf") and isinstance(d["elf"].get("imports"), list)
        assert "arch" in d["elf"] and "bits" in d["elf"]
        assert isinstance(d.get("suspicious_apis"), list)
        v = d.get("verdict") or {}
        assert "level" in v and "score" in v and "reasons" in v
        assert d.get("sha256") and d.get("entropy") is not None
        assert d.get("ai_summary")  # not None

    def test_binary_text(self):
        files = {"file": ("hello.txt", b"hello world this is text", "text/plain")}
        r = requests.post(f"{API}/offensive/binary/analyze", files=files, timeout=90)
        assert r.status_code == 200, r.text
        d = r.json()
        assert d.get("format") == "raw/data"
