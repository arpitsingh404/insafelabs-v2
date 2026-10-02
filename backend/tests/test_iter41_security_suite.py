"""Iter 41 — Security Suite & AI Auto-Triage backend tests.

Covers:
- Login telemetry (previous_login on success)
- Brute-force lockout Retry-After header on 429
- AI Auto-Triage endpoint (POST /api/bugbounty/triage/{scan_id})
"""
import os
import time
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/") or \
    "https://localhost:8001"
API = f"{BASE_URL}/api"
PASSWORD = "333221"
SCAN_ID = "test-triage-1"


def _clear_lockout():
    """Best-effort clear of login_attempts via mongosh."""
    os.system('mongosh test_database --quiet --eval "db.login_attempts.deleteMany({})" >/dev/null 2>&1')


@pytest.fixture(scope="module", autouse=True)
def _module_cleanup():
    _clear_lockout()
    yield
    _clear_lockout()


# ---------------- Login Telemetry ----------------
class TestLoginTelemetry:
    def test_login_returns_previous_login_object(self):
        _clear_lockout()
        # First login sets baseline
        r1 = requests.post(f"{API}/auth/login", json={"password": PASSWORD}, timeout=10)
        assert r1.status_code == 200, r1.text
        d1 = r1.json()
        assert "token" in d1
        assert "previous_login" in d1
        assert set(d1["previous_login"].keys()) >= {"at", "ip"}

        # Second login should show a non-null previous_login (from first)
        time.sleep(0.5)
        r2 = requests.post(f"{API}/auth/login", json={"password": PASSWORD}, timeout=10)
        assert r2.status_code == 200
        d2 = r2.json()
        assert d2["previous_login"]["at"] is not None
        assert d2["previous_login"]["ip"] is not None


# ---------------- Brute Force Lockout ----------------
class TestBruteForceLockout:
    def test_wrong_password_shows_attempts_left_then_locks(self):
        _clear_lockout()
        for i in range(1, 5):
            r = requests.post(f"{API}/auth/login", json={"password": "wrong"}, timeout=10)
            assert r.status_code == 401
            body = r.json()
            detail = body.get("detail", "")
            assert "attempt" in detail.lower()
        # 5th attempt should trigger 429 with Retry-After header
        r5 = requests.post(f"{API}/auth/login", json={"password": "wrong"}, timeout=10)
        assert r5.status_code == 429
        assert "Retry-After" in r5.headers or "retry-after" in {k.lower(): v for k, v in r5.headers.items()}
        # Case insensitive check
        headers_lc = {k.lower(): v for k, v in r5.headers.items()}
        ra = headers_lc.get("retry-after")
        assert ra is not None
        assert int(ra) > 0 and int(ra) <= 15 * 60 + 5

        # Subsequent attempts during lockout also 429
        r6 = requests.post(f"{API}/auth/login", json={"password": PASSWORD}, timeout=10)
        assert r6.status_code == 429
        _clear_lockout()


# ---------------- AI Triage ----------------
class TestAITriage:
    def _auth_token(self):
        _clear_lockout()
        r = requests.post(f"{API}/auth/login", json={"password": PASSWORD}, timeout=10)
        assert r.status_code == 200
        return r.json()["token"]

    def test_triage_returns_verdicts_and_summary(self):
        token = self._auth_token()
        r = requests.post(f"{API}/bugbounty/triage/{SCAN_ID}",
                          headers={"Authorization": f"Bearer {token}"}, timeout=60)
        assert r.status_code == 200, r.text
        data = r.json()
        assert "triaged" in data
        assert "summary" in data
        assert isinstance(data["triaged"], list)
        assert len(data["triaged"]) >= 1
        for v in data["triaged"]:
            assert v["verdict"] in ("confirmed", "likely", "false_positive")
            assert 0 <= int(v["confidence"]) <= 100
            assert "reason" in v
            assert "duplicate_of" in v
        s = data["summary"]
        for k in ("total", "confirmed", "likely", "false_positives", "duplicates", "unique"):
            assert k in s, f"missing {k}"
        assert s["total"] == len(data["triaged"])

    def test_triage_scan_not_found(self):
        token = self._auth_token()
        r = requests.post(f"{API}/bugbounty/triage/does-not-exist-xyz",
                          headers={"Authorization": f"Bearer {token}"}, timeout=15)
        assert r.status_code == 404
