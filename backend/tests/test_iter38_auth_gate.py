"""Iteration 38 - JWT single-password auth gate regression.

Verifies:
 - POST /api/auth/login (correct/incorrect passwords)
 - GET  /api/auth/me    (with/without Bearer token)
 - Representative protected endpoints across every router group:
     * 401 without token
     * 200 (or non-401) with Bearer token
 - ?token= query-string fallback works on protected GETs
"""
import os
import pytest
import requests

def _load_backend_url():
    v = os.environ.get("REACT_APP_BACKEND_URL")
    if v:
        return v.rstrip("/")
    env_path = "/app/frontend/.env"
    if os.path.exists(env_path):
        with open(env_path) as f:
            for line in f:
                if line.startswith("REACT_APP_BACKEND_URL="):
                    return line.split("=", 1)[1].strip().rstrip("/")
    raise RuntimeError("REACT_APP_BACKEND_URL not found")

BASE_URL = _load_backend_url()
PASSWORD = "333221"


# ---------- helpers ----------
@pytest.fixture(scope="module")
def token():
    r = requests.post(
        f"{BASE_URL}/api/auth/login",
        json={"password": PASSWORD},
        timeout=15,
    )
    assert r.status_code == 200, f"login failed: {r.status_code} {r.text}"
    data = r.json()
    assert data.get("token_type") == "bearer"
    assert isinstance(data.get("token"), str) and len(data["token"]) > 20
    return data["token"]


@pytest.fixture(scope="module")
def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


# ---------- /api/auth/login ----------
class TestAuthLogin:
    def test_login_wrong_password_401(self):
        r = requests.post(
            f"{BASE_URL}/api/auth/login",
            json={"password": "wrong-code"},
            timeout=15,
        )
        assert r.status_code == 401
        assert r.json().get("detail") == "Incorrect access code"

    def test_login_correct_password_200(self, token):
        assert token  # fixture already asserts shape

    def test_login_empty_password_401(self):
        r = requests.post(
            f"{BASE_URL}/api/auth/login",
            json={"password": ""},
            timeout=15,
        )
        assert r.status_code == 401


# ---------- /api/auth/me ----------
class TestAuthMe:
    def test_me_without_token_401(self):
        r = requests.get(f"{BASE_URL}/api/auth/me", timeout=15)
        assert r.status_code == 401

    def test_me_with_token_200(self, auth_headers):
        r = requests.get(f"{BASE_URL}/api/auth/me", headers=auth_headers, timeout=15)
        assert r.status_code == 200
        body = r.json()
        assert body.get("authenticated") is True

    def test_me_with_bad_token_401(self):
        r = requests.get(
            f"{BASE_URL}/api/auth/me",
            headers={"Authorization": "Bearer not-a-real-jwt"},
            timeout=15,
        )
        assert r.status_code == 401


# ---------- Protected endpoints regression ----------
# One representative GET per router group. All must 401 without token,
# and return non-401 (ideally 200) with token.
PROTECTED_ENDPOINTS = [
    "/api/dashboard/stats",
    "/api/dashboard/livefeed",
    "/api/tools/ipinfo",
    "/api/scanner/scans",
    "/api/osint/history",
    "/api/bugbounty/scans",
    "/api/toolkit/imei/history",
    "/api/offensive/network/interfaces",
    "/api/redteam/apk/scans",
    "/api/assessments",
    "/api/sca/scans",
    "/api/pentest/sessions",
]


@pytest.mark.parametrize("path", PROTECTED_ENDPOINTS)
def test_protected_endpoint_without_token_401(path):
    r = requests.get(f"{BASE_URL}{path}", timeout=20)
    assert r.status_code == 401, f"{path} expected 401 got {r.status_code}"


@pytest.mark.parametrize("path", PROTECTED_ENDPOINTS)
def test_protected_endpoint_with_token_not_401(path, auth_headers):
    r = requests.get(f"{BASE_URL}{path}", headers=auth_headers, timeout=30)
    # Some endpoints may return 404 if resource path variant, but MUST NOT be 401/403.
    assert r.status_code not in (401, 403), (
        f"{path} auth broken: {r.status_code} {r.text[:200]}"
    )


# ---------- ?token= query fallback ----------
class TestTokenQueryFallback:
    def test_dashboard_stats_via_query_token(self, token):
        r = requests.get(
            f"{BASE_URL}/api/dashboard/stats", params={"token": token}, timeout=20
        )
        assert r.status_code == 200, f"query token auth failed: {r.status_code} {r.text[:200]}"

    def test_dashboard_stats_via_query_token_invalid_401(self):
        r = requests.get(
            f"{BASE_URL}/api/dashboard/stats",
            params={"token": "junk"},
            timeout=15,
        )
        assert r.status_code == 401

    def test_scanner_report_query_token_not_401(self, token):
        """Scanner PDF report — with a random id we expect 404 (not 401)."""
        r = requests.get(
            f"{BASE_URL}/api/scanner/scans/nonexistent-id-xyz/report",
            params={"token": token},
            timeout=20,
        )
        assert r.status_code != 401, (
            f"scanner report should authenticate via query token, got 401"
        )


# ---------- Sanity: root ----------
def test_root():
    r = requests.get(f"{BASE_URL}/api/", timeout=10)
    assert r.status_code == 200
    assert r.json().get("status") == "ok"
