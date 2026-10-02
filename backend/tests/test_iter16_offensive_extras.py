"""Backend tests iter16: BloodHound export, SMB enum, Binary PDF report, AD enumerate regression."""
import io
import os
import json
import zipfile
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL").rstrip("/")
API = f"{BASE_URL}/api"


# --------------- BloodHound export ---------------
class TestBloodHound:
    def test_bloodhound_public_ldap(self):
        r = requests.post(f"{API}/offensive/ad/bloodhound",
                          json={"host": "ldap.forumsys.com", "port": 389}, timeout=60)
        assert r.status_code == 200, r.text
        assert r.headers.get("content-type", "").startswith("application/zip"), r.headers
        content = r.content
        assert content[:2] == b"PK", "Not a zip"
        zf = zipfile.ZipFile(io.BytesIO(content))
        names = set(zf.namelist())
        expected = {"users.json", "groups.json", "computers.json", "domains.json"}
        assert expected.issubset(names), f"names={names}"
        for name in expected:
            data = json.loads(zf.read(name))
            assert "meta" in data and "data" in data, f"{name} missing keys"
            meta = data["meta"]
            assert meta.get("version") == 4, f"{name} meta={meta}"
            assert "type" in meta and "count" in meta
            assert isinstance(data["data"], list)

    def test_bloodhound_unreachable(self):
        r = requests.post(f"{API}/offensive/ad/bloodhound",
                          json={"host": "10.255.255.1", "port": 389}, timeout=45)
        # Graceful failure -> 400 per contract
        assert r.status_code == 400, f"expected 400 got {r.status_code}: {r.text[:200]}"


# --------------- AD enumerate regression (SID/domain fields) ---------------
class TestADRegression:
    def test_ad_enumerate_has_new_fields(self):
        r = requests.post(f"{API}/offensive/ad/enumerate",
                          json={"host": "ldap.forumsys.com", "port": 389}, timeout=45)
        assert r.status_code == 200, r.text
        d = r.json()
        assert d.get("reachable") is True
        assert d.get("bound") is True
        # New fields should exist (may be None for non-AD LDAP)
        assert "domain_fqdn" in d, f"keys={list(d.keys())}"
        assert "domain_sid" in d, f"keys={list(d.keys())}"


# --------------- SMB enum ---------------
class TestSMB:
    def test_smb_scanme_graceful(self):
        r = requests.post(f"{API}/offensive/smb/enumerate",
                          json={"host": "scanme.nmap.org"}, timeout=45)
        assert r.status_code == 200, r.text
        d = r.json()
        assert d.get("connected") is False
        # Should have an error string; no crash
        err = d.get("error") or ""
        assert isinstance(err, str) and len(err) > 0, f"doc={d}"


# --------------- Binary PDF report ---------------
class TestBinaryReport:
    def test_binary_report_pdf(self):
        payload = {
            "filename": "ls",
            "format": "ELF",
            "size_kb": 138.2,
            "entropy": 6.12,
            "sha256": "a" * 64,
            "pe": {"machine": "x86_64"},
            "verdict": {"level": "low", "label": "benign", "score": 5,
                        "reasons": ["standard libc imports", "no packed sections"]},
            "suspicious_apis": ["system", "execve"],
            "urls": ["https://example.com"],
            "ips": ["1.2.3.4"],
            "secrets": [],
            "ai_summary": "Standard GNU coreutils ls binary; no red flags."
        }
        r = requests.post(f"{API}/offensive/binary/report", json=payload, timeout=45)
        assert r.status_code == 200, r.text
        assert r.headers.get("content-type", "").startswith("application/pdf"), r.headers
        assert r.content[:4] == b"%PDF", r.content[:20]
        assert len(r.content) > 500
