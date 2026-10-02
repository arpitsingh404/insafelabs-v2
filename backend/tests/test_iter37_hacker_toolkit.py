"""Iteration 37 - Advanced Hacker Toolkit endpoint tests."""
import os
import time
import hmac
import hashlib
import base64
import json
import pytest
import requests

def _load_backend_url():
    v = os.environ.get("REACT_APP_BACKEND_URL")
    if not v:
        try:
            with open("/app/frontend/.env") as f:
                for line in f:
                    if line.startswith("REACT_APP_BACKEND_URL="):
                        v = line.split("=", 1)[1].strip()
                        break
        except Exception:
            pass
    return v.rstrip("/")

BASE_URL = _load_backend_url()
API = f"{BASE_URL}/api/toolkit"


@pytest.fixture(scope="module")
def s():
    ses = requests.Session()
    ses.headers.update({"Content-Type": "application/json"})
    return ses


# --------- Directory Bruteforcer (job-based) ---------
class TestDirScan:
    def test_dirscan_flow(self, s):
        r = s.post(f"{API}/dirscan/start", json={"url": "https://github.com"}, timeout=30)
        assert r.status_code == 200, r.text
        d = r.json()
        assert "id" in d and "total" in d and "base" in d
        jid = d["id"]

        # Poll for up to ~40s
        final = None
        for _ in range(40):
            time.sleep(1)
            rs = s.get(f"{API}/dirscan/status/{jid}", timeout=15)
            assert rs.status_code == 200
            js = rs.json()
            assert {"status", "done", "total", "found", "found_count"}.issubset(js.keys())
            if js["status"] in ("done", "cancelled", "error"):
                final = js
                break
        assert final is not None, "dirscan did not finish in time"
        assert final["status"] == "done"
        assert isinstance(final["found"], list)

    def test_dirscan_status_unknown_id(self, s):
        r = s.get(f"{API}/dirscan/status/nonexistent-id-xyz", timeout=10)
        assert r.status_code == 404

    def test_dirscan_cancel(self, s):
        r = s.post(f"{API}/dirscan/start", json={"url": "https://example.com"}, timeout=15)
        assert r.status_code == 200
        jid = r.json()["id"]
        c = s.post(f"{API}/dirscan/cancel/{jid}", timeout=10)
        assert c.status_code == 200


# --------- Web Tech & WAF Fingerprint ---------
class TestFingerprint:
    def test_wordpress_org(self, s):
        r = s.post(f"{API}/fingerprint", json={"url": "https://wordpress.org"}, timeout=30)
        assert r.status_code == 200, r.text
        d = r.json()
        techs = [t.get("name", "").lower() for t in d.get("tech", d.get("technologies", []))]
        # accept either shape
        joined = json.dumps(d).lower()
        assert "wordpress" in joined
        # server field commonly present
        assert "server" in d or "headers" in d

    def test_github_no_magento_false_positive(self, s):
        r = s.post(f"{API}/fingerprint", json={"url": "https://github.com"}, timeout=30)
        assert r.status_code == 200
        joined = json.dumps(r.json()).lower()
        assert "magento" not in joined

    def test_cloudflare_waf(self, s):
        r = s.post(f"{API}/fingerprint", json={"url": "https://www.cloudflare.com"}, timeout=30)
        assert r.status_code == 200
        joined = json.dumps(r.json()).lower()
        assert "cloudflare" in joined


# --------- Email/DNS Security Recon ---------
class TestEmailDns:
    def test_google_com(self, s):
        r = s.post(f"{API}/email-dns", json={"domain": "google.com"}, timeout=30)
        assert r.status_code == 200, r.text
        d = r.json()
        blob = json.dumps(d).lower()
        assert "v=spf1" in blob
        assert "reject" in blob  # DMARC p=reject
        assert d.get("spoofable") in (False, None)

    def test_no_records_spoofable(self, s):
        # A random domain unlikely to have SPF/DMARC
        r = s.post(f"{API}/email-dns", json={"domain": "example.com"}, timeout=30)
        assert r.status_code == 200
        d = r.json()
        assert "issues" in d


# --------- CORS Misconfig ---------
class TestCors:
    def test_example_not_vulnerable(self, s):
        r = s.post(f"{API}/cors-test", json={"url": "https://example.com"}, timeout=30)
        assert r.status_code == 200, r.text
        d = r.json()
        assert d.get("vulnerable") in (False, None)
        assert isinstance(d.get("tests", []), list)
        assert len(d.get("tests", [])) >= 3


# --------- GraphQL Introspection ---------
class TestGraphQL:
    def test_countries_enabled(self, s):
        r = s.post(f"{API}/graphql", json={"url": "https://countries.trevorblades.com/graphql"}, timeout=45)
        assert r.status_code == 200, r.text
        d = r.json()
        assert d.get("introspection_enabled") is True
        assert d.get("query_type", "").lower() == "query"
        types = d.get("types") or d.get("type_names") or []
        assert isinstance(types, list) and len(types) >= 5

    def test_non_graphql_disabled(self, s):
        r = s.post(f"{API}/graphql", json={"url": "https://example.com"}, timeout=30)
        assert r.status_code == 200
        d = r.json()
        assert d.get("introspection_enabled") in (False, None)


# --------- Subdomain Takeover ---------
class TestTakeover:
    def test_example_com(self, s):
        r = s.post(f"{API}/takeover", json={"host": "example.com"}, timeout=30)
        assert r.status_code == 200, r.text
        d = r.json()
        assert d.get("vulnerable") in (False, None)
        assert "cnames" in d
        assert isinstance(d["cnames"], list)


# --------- JWT Secret Brute Force ---------
def _b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def _make_jwt(payload, secret, alg="HS256"):
    header = {"alg": alg, "typ": "JWT"}
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing = f"{h}.{p}".encode()
    if alg == "none":
        return f"{h}.{p}."
    sig = hmac.new(secret.encode(), signing, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url(sig)}"


class TestJwtCrack:
    def test_weak_secret_cracked(self, s):
        token = _make_jwt({"user": "admin"}, "secret")
        r = s.post(f"{API}/jwt-crack", json={"token": token}, timeout=120)
        assert r.status_code == 200, r.text
        d = r.json()
        assert d.get("secret") == "secret" or d.get("cracked") == "secret"

    def test_alg_none(self, s):
        token = _make_jwt({"user": "admin"}, "", alg="none")
        r = s.post(f"{API}/jwt-crack", json={"token": token}, timeout=30)
        assert r.status_code == 200
        joined = json.dumps(r.json()).lower()
        assert "none" in joined

    def test_strong_secret_not_found(self, s):
        token = _make_jwt({"user": "admin"}, "kJ39dl@aB!7xQ_zPq2v9WmnR4tYuIeOpAsDfGhJk")
        r = s.post(f"{API}/jwt-crack", json={"token": token}, timeout=120)
        assert r.status_code == 200
        d = r.json()
        assert d.get("secret") in (None, "", False) and d.get("cracked") in (None, "", False, "not found")


# --------- Regression: older toolkit endpoints ---------
class TestRegression:
    def test_portscan_start(self, s):
        r = s.post(f"{API}/portscan/start", json={"host": "scanme.nmap.org", "profile": "top100"}, timeout=15)
        assert r.status_code == 200, r.text
        assert "id" in r.json()

    def test_subdomain_enum(self, s):
        r = s.post(f"{API}/subdomain-enum", json={"domain": "example.com"}, timeout=30)
        assert r.status_code == 200

    def test_http_request(self, s):
        r = s.post(f"{API}/http-request", json={"method": "GET", "url": "https://example.com", "headers": "", "body": ""}, timeout=20)
        assert r.status_code == 200

    def test_hash_crack(self, s):
        # md5 of "password"
        r = s.post(f"{API}/hash-crack", json={"hash": "5f4dcc3b5aa765d61d8327deb882cf99"}, timeout=60)
        assert r.status_code == 200
