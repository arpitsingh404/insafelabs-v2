"""Iteration 9 regression: IMEI history/account + OSINT IMEI + OSINT Email redesign."""
import os
import time
import pytest
import requests
from dotenv import load_dotenv

load_dotenv("/app/frontend/.env")
BASE = os.environ["REACT_APP_BACKEND_URL"].rstrip("/")
API = f"{BASE}/api"
IMEI = "356166091795616"


# -------- Toolkit: IMEI account (token balance chip) --------
def test_imei_account():
    r = requests.get(f"{API}/toolkit/imei/account", timeout=30)
    assert r.status_code == 200, r.text
    d = r.json()
    assert "balance" in d and "pricing_level" in d and "username" in d
    assert isinstance(d["balance"], (int, float))


# -------- Toolkit: IMEI history panel --------
def test_imei_history():
    r = requests.get(f"{API}/toolkit/imei/history", timeout=30)
    assert r.status_code == 200, r.text
    d = r.json()
    assert "count" in d and "results" in d
    assert isinstance(d["results"], list)
    if d["results"]:
        row = d["results"][0]
        for k in ("id", "imei", "service", "status", "created_at", "result"):
            assert k in row, f"missing key {k}"


# -------- Toolkit IMEI basic (service 0, instant) --------
def test_imei_basic_check():
    r = requests.post(f"{API}/toolkit/imei", json={"imei": IMEI, "service_id": 0}, timeout=60)
    assert r.status_code == 200, r.text
    d = r.json()
    # Result has brand_name/model
    result = d.get("result") or d
    # Accept either {result:{...}} or flat
    brand = (result.get("brand_name") or result.get("brand") or "").lower()
    assert "apple" in brand or "apple" in str(d).lower()


# -------- Toolkit IMEI async: Blacklist Premium (service 28) --------
@pytest.mark.slow
def test_imei_blacklist_premium_async():
    r = requests.post(f"{API}/toolkit/imei", json={"imei": IMEI, "service_id": 28}, timeout=90)
    assert r.status_code == 200, r.text
    d = r.json()
    # Expect a Done status eventually with blacklist_status/device_is_clean
    result = d.get("result") or {}
    status = (d.get("status") or "").lower()
    # Either finished with result, or async accepted (id present)
    assert status == "done" or result or d.get("id"), f"unexpected async payload: {d}"
    if result:
        assert ("blacklist_status" in result) or ("device_is_clean" in result), f"no blacklist keys: {result}"


# -------- OSINT: POST /osint/imei saves lookup with kind='imei' --------
def test_osint_imei_saved():
    r = requests.post(f"{API}/osint/imei", json={"imei": IMEI, "service_id": 0}, timeout=60)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d.get("kind") == "imei"
    assert d.get("query") == IMEI
    assert "id" in d and "result" in d
    lookup_id = d["id"]

    # Appears in history
    r2 = requests.get(f"{API}/osint/history", timeout=30)
    assert r2.status_code == 200
    hist = r2.json()
    ids = [x.get("id") for x in hist]
    assert lookup_id in ids


# -------- OSINT: Email redesign backend still returns expected shape --------
def test_osint_email_shape():
    r = requests.post(f"{API}/osint/email", json={"email": "beau@dodgycoder.net"}, timeout=45)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d.get("kind") == "email"
    res = d.get("result") or {}
    assert "gravatar" in res and "mail" in res and "candidate_profiles" in res
    m = res["mail"]
    for k in ("mx", "a", "spf", "provider"):
        assert k in m
    assert "domain" in res and "derived_username" in res
