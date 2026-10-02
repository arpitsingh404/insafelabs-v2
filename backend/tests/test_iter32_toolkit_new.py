"""Iteration 32: Test 6 new Toolkit tools — hash-crack + http-inspect backend endpoints."""
import os
import hashlib
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "http://localhost:8001").rstrip("/")
API = f"{BASE_URL}/api"


# -------------------- Hash Crack --------------------
class TestHashCrack:
    def test_md5_password_cracked(self):
        r = requests.post(f"{API}/toolkit/hash-crack",
                          json={"hash": "5f4dcc3b5aa765d61d8327deb882cf99"}, timeout=30)
        assert r.status_code == 200, r.text
        d = r.json()
        assert d["cracked"] == "password"
        assert d["cracked_algo"] == "MD5"
        assert "MD5" in d["candidates"]
        assert "NTLM" in d["candidates"]

    def test_ntlm_password_cracked(self):
        r = requests.post(f"{API}/toolkit/hash-crack",
                          json={"hash": "8846f7eaee8fb117ad06bdd830b7586c"}, timeout=30)
        assert r.status_code == 200
        d = r.json()
        assert d["cracked"] == "password"
        assert d["cracked_algo"] == "NTLM"

    def test_sha256_common_word_cracked(self):
        h = hashlib.sha256(b"admin").hexdigest()
        r = requests.post(f"{API}/toolkit/hash-crack", json={"hash": h}, timeout=30)
        assert r.status_code == 200
        d = r.json()
        assert d["cracked"] == "admin"
        assert d["cracked_algo"] == "SHA256"
        assert "SHA-256" in d["candidates"]

    def test_bcrypt_identified_not_crackable(self):
        # valid bcrypt format (60 chars total: $2b$12$ + 53 chars)
        bcrypt_hash = "$2b$12$KIXQvJ8vN9x7Ry5Zc4rJ1eN6P0Kp9Q3L2M8sT7W6Y5xR4A3H2G1FO"
        r = requests.post(f"{API}/toolkit/hash-crack", json={"hash": bcrypt_hash}, timeout=30)
        assert r.status_code == 200
        d = r.json()
        assert d["crackable"] is False
        assert any("bcrypt" in c for c in d["candidates"])
        assert d["cracked"] is None

    def test_random_uncrackable(self):
        # random-ish MD5-length hex, not in wordlist
        r = requests.post(f"{API}/toolkit/hash-crack",
                          json={"hash": "deadbeefcafebabe1234567890abcdef"}, timeout=30)
        assert r.status_code == 200
        d = r.json()
        assert d["cracked"] is None
        assert d["crackable"] is True

    def test_extra_wordlist_honored(self):
        # hash of a made-up unique word — should only crack when extra wordlist supplied
        pw = "SuperUniqueTestWord42"
        h = hashlib.md5(pw.encode()).hexdigest()
        # without wordlist
        r1 = requests.post(f"{API}/toolkit/hash-crack", json={"hash": h}, timeout=30)
        assert r1.json()["cracked"] is None
        # with wordlist
        r2 = requests.post(f"{API}/toolkit/hash-crack",
                           json={"hash": h, "wordlist": f"foo\n{pw}\nbar"}, timeout=30)
        d2 = r2.json()
        assert d2["cracked"] == pw
        assert d2["wordlist_size"] > d2["tried"] - 5  # extras included

    def test_short_hash_error(self):
        r = requests.post(f"{API}/toolkit/hash-crack", json={"hash": "ab"}, timeout=15)
        assert r.status_code == 422  # min_length=3 pydantic


# -------------------- HTTP + TLS Inspect --------------------
class TestHttpInspect:
    def test_github_grade_and_tls(self):
        r = requests.post(f"{API}/toolkit/http-inspect",
                          json={"url": "github.com"}, timeout=60)
        assert r.status_code == 200, r.text
        d = r.json()
        assert d["status"] in (200, 301, 302)
        sec = d["security"]
        assert sec["grade"] in ("A", "A+", "B", "C")  # github is well-configured
        assert isinstance(sec["present"], list)
        assert isinstance(sec["missing"], list)
        tls = d["tls"]
        assert "issuer" in tls
        assert "valid_to" in tls
        assert isinstance(tls.get("sans"), list)
        assert "headers" in d

    def test_http_plain_no_tls(self):
        # explicit http:// - TLS should show error 'not an HTTPS URL'
        r = requests.post(f"{API}/toolkit/http-inspect",
                          json={"url": "http://neverssl.com"}, timeout=45)
        # Either 200 or 502; if 200 should have tls error
        if r.status_code == 200:
            d = r.json()
            assert "error" in d["tls"]

    def test_invalid_domain_graceful(self):
        r = requests.post(f"{API}/toolkit/http-inspect",
                          json={"url": "definitely-not-a-real-domain-xyz-12345.invalid"}, timeout=30)
        # Should be 502 with a message (not a 500)
        assert r.status_code in (502, 400)
        assert "detail" in r.json()


# -------------------- Regression on existing endpoints --------------------
class TestToolkitRegression:
    def test_cve_still_works(self):
        r = requests.post(f"{API}/toolkit/cve",
                          json={"keyword": "openssl", "limit": 3}, timeout=45)
        # Either 200 or 429 (NVD rate limit) — both acceptable
        assert r.status_code in (200, 429)

    def test_dns_still_works(self):
        r = requests.post(f"{API}/toolkit/dns",
                          json={"domain": "example.com"}, timeout=45)
        assert r.status_code == 200
        d = r.json()
        assert d.get("domain") == "example.com"
