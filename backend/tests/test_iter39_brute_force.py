"""Iteration 39 - Brute-force lockout on POST /api/auth/login + regression.

Flow:
  1. Wipe login_attempts collection (fresh state).
  2. 4 wrong attempts → each returns 401 with 'N attempt(s) left' decrementing.
  3. 5th wrong attempt → 429 lockout message.
  4. Even with correct pw while locked → 429.
  5. Wipe again → correct pw → 200 with {token, token_type}.
  6. Regression: /api/dashboard/stats and /api/tools/ipinfo work with token, 401 without.
"""
import os
import re
import pytest
import requests
from pymongo import MongoClient


def _load_env(key, path):
    with open(path) as f:
        for line in f:
            if line.startswith(key + "="):
                return line.split("=", 1)[1].strip().strip('"')
    raise RuntimeError(f"{key} not in {path}")


BASE_URL = _load_env("REACT_APP_BACKEND_URL", "/app/frontend/.env").rstrip("/")
MONGO_URL = _load_env("MONGO_URL", "/app/backend/.env")
DB_NAME = _load_env("DB_NAME", "/app/backend/.env")
PASSWORD = "333221"


def _wipe_attempts():
    client = MongoClient(MONGO_URL)
    client[DB_NAME]["login_attempts"].delete_many({})
    client.close()


@pytest.fixture(autouse=True)
def _clean_attempts():
    _wipe_attempts()
    yield
    _wipe_attempts()


class TestBruteForceLockout:
    def test_four_wrong_then_lockout_on_fifth(self):
        expected_left = [4, 3, 2, 1]
        for i, left in enumerate(expected_left, start=1):
            r = requests.post(f"{BASE_URL}/api/auth/login",
                              json={"password": "wrong"}, timeout=15)
            assert r.status_code == 401, f"attempt {i}: {r.status_code} {r.text}"
            detail = r.json().get("detail", "")
            assert "Incorrect access code" in detail, detail
            m = re.search(r"(\d+)\s+attempt", detail)
            assert m, f"no attempts-left in message: {detail}"
            assert int(m.group(1)) == left, f"attempt {i} expected {left} left, got: {detail}"

        # 5th wrong = lockout
        r = requests.post(f"{BASE_URL}/api/auth/login",
                          json={"password": "wrong"}, timeout=15)
        assert r.status_code == 429, f"5th attempt should lock: {r.status_code} {r.text}"
        assert "locked" in r.json().get("detail", "").lower()

        # correct pw while locked = still 429
        r = requests.post(f"{BASE_URL}/api/auth/login",
                          json={"password": PASSWORD}, timeout=15)
        assert r.status_code == 429, f"correct pw during lockout: {r.status_code} {r.text}"
        assert "locked" in r.json().get("detail", "").lower()

    def test_correct_password_success_and_clears_counter(self):
        # 2 wrong first
        for _ in range(2):
            r = requests.post(f"{BASE_URL}/api/auth/login",
                              json={"password": "wrong"}, timeout=15)
            assert r.status_code == 401
        # Now correct
        r = requests.post(f"{BASE_URL}/api/auth/login",
                          json={"password": PASSWORD}, timeout=15)
        assert r.status_code == 200
        data = r.json()
        assert data.get("token_type") == "bearer"
        assert isinstance(data.get("token"), str) and len(data["token"]) > 20

        # Counter cleared → 4 more wrong should still leave 1 attempt left (fresh counter)
        r = requests.post(f"{BASE_URL}/api/auth/login",
                          json={"password": "wrong"}, timeout=15)
        assert r.status_code == 401
        detail = r.json().get("detail", "")
        m = re.search(r"(\d+)\s+attempt", detail)
        assert m and int(m.group(1)) == 4, f"counter not cleared after success: {detail}"


class TestProtectedEndpointRegression:
    def test_dashboard_stats_no_token_401(self):
        r = requests.get(f"{BASE_URL}/api/dashboard/stats", timeout=15)
        assert r.status_code == 401

    def test_tools_ipinfo_no_token_401(self):
        r = requests.get(f"{BASE_URL}/api/tools/ipinfo", timeout=15)
        assert r.status_code == 401

    def test_dashboard_stats_with_token_200(self):
        tok = requests.post(f"{BASE_URL}/api/auth/login",
                            json={"password": PASSWORD}, timeout=15).json()["token"]
        r = requests.get(f"{BASE_URL}/api/dashboard/stats",
                         headers={"Authorization": f"Bearer {tok}"}, timeout=20)
        assert r.status_code == 200, r.text[:200]

    def test_tools_ipinfo_with_token_200(self):
        tok = requests.post(f"{BASE_URL}/api/auth/login",
                            json={"password": PASSWORD}, timeout=15).json()["token"]
        r = requests.get(f"{BASE_URL}/api/tools/ipinfo",
                         headers={"Authorization": f"Bearer {tok}"}, timeout=20)
        assert r.status_code == 200, r.text[:200]
