"""Security-hardening regression tests.

Run against a LIVE local backend (default http://127.0.0.1:8001):

    backend\\venv\\Scripts\\python.exe -m pytest backend/tests/test_security_hardening.py -n0 -q

These assert the fixes from the audit: auth is fail-closed, SSRF to
loopback/metadata is blocked, and unconfigured integrations degrade gracefully.
"""
import os
import pathlib

import pytest
import requests

ROOT = pathlib.Path(__file__).resolve().parents[1]  # backend/


def _load_env():
    """Read backend/.env so MONGO_URL / DB_NAME / ADMIN_PASSWORD are available."""
    envf = ROOT / ".env"
    if not envf.exists():
        return
    for line in envf.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


_load_env()

BASE = (os.environ.get("REACT_APP_BACKEND_URL") or "http://127.0.0.1:8001").rstrip("/")
PASSWORD = os.environ.get("ADMIN_PASSWORD", "333221")


def _clear_login_attempts():
    try:
        from pymongo import MongoClient

        client = MongoClient(os.environ.get("MONGO_URL", "mongodb://localhost:27017"), serverSelectionTimeoutMS=3000)
        client[os.environ.get("DB_NAME", "insafelabs")].login_attempts.delete_many({})
        client.close()
    except Exception:
        pass


@pytest.fixture(scope="module")
def token():
    _clear_login_attempts()
    r = requests.post(f"{BASE}/api/auth/login", json={"password": PASSWORD}, timeout=10)
    r.raise_for_status()
    return r.json()["token"]


@pytest.fixture(scope="module")
def auth(token):
    return {"Authorization": f"Bearer {token}"}


def test_backend_is_up():
    r = requests.get(f"{BASE}/api/", timeout=10)
    assert r.status_code == 200
    assert r.json().get("status") == "ok"


def test_protected_route_requires_auth():
    assert requests.get(f"{BASE}/api/dashboard/stats", timeout=10).status_code == 401


def test_token_query_fallback_not_accepted(token):
    r = requests.get(f"{BASE}/api/dashboard/stats", params={"token": token}, timeout=10)
    assert r.status_code == 401


def test_valid_token_works(auth):
    r = requests.get(f"{BASE}/api/dashboard/stats", headers=auth, timeout=10)
    assert r.status_code == 200
    assert "total_findings" in r.json()


def test_empty_password_rejected():
    _clear_login_attempts()
    r = requests.post(f"{BASE}/api/auth/login", json={"password": ""}, timeout=10)
    assert r.status_code in (401, 429)
    _clear_login_attempts()


def test_nosql_object_password_rejected():
    r = requests.post(f"{BASE}/api/auth/login", json={"password": {"$ne": None}}, timeout=10)
    assert r.status_code == 422


def test_ssrf_loopback_respects_private_setting(auth):
    """Loopback is blocked unless ALLOW_PRIVATE_TARGETS=1 (then it is allowed)."""
    import os
    allow = os.environ.get("ALLOW_PRIVATE_TARGETS", "").strip().lower() in ("1", "true", "yes")
    r = requests.post(f"{BASE}/api/toolkit/http-inspect", json={"url": "http://127.0.0.1:8001/api/"}, headers=auth, timeout=20)
    if allow:
        assert r.status_code == 200, r.text
    else:
        assert r.status_code == 400, r.text


def test_ssrf_metadata_always_blocked(auth):
    """Cloud-metadata / link-local must ALWAYS be blocked, even with private targets allowed."""
    r = requests.post(f"{BASE}/api/toolkit/http-inspect", json={"url": "http://169.254.169.254/latest/meta-data/"}, headers=auth, timeout=20)
    assert r.status_code == 400, r.text


def test_ssrf_file_scheme_blocked(auth):
    r = requests.post(f"{BASE}/api/toolkit/http-request", json={"method": "GET", "url": "file:///etc/passwd", "headers": "", "body": ""}, headers=auth, timeout=20)
    assert r.status_code in (400, 422), r.text


def test_imei_endpoints_degrade_gracefully(auth):
    acc = requests.get(f"{BASE}/api/toolkit/imei/account", headers=auth, timeout=15)
    assert acc.status_code == 200
    body = acc.json()
    assert body.get("configured") is False or body.get("balance") is not None

    svc = requests.get(f"{BASE}/api/toolkit/imei/services", headers=auth, timeout=15)
    assert svc.status_code == 200
    assert isinstance(svc.json(), list)
