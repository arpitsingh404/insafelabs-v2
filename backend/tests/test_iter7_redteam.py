"""Iteration 7 backend tests: Red Team Ops (advisor/phishing/cloud/apk), OSINT dossier PDF."""
import os
import io
import pytest
import requests

def _load_url():
    v = os.environ.get("REACT_APP_BACKEND_URL")
    if not v:
        try:
            with open("/app/frontend/.env") as f:
                for ln in f:
                    if ln.startswith("REACT_APP_BACKEND_URL="):
                        v = ln.split("=", 1)[1].strip()
                        break
        except Exception:
            pass
    return (v or "").rstrip("/")

BASE_URL = _load_url()
API = f"{BASE_URL}/api"


@pytest.fixture(scope="module")
def s():
    sess = requests.Session()
    sess.headers.update({"Content-Type": "application/json"})
    return sess


# --- RED TEAM: Advisor ---
def test_advisor(s):
    r = s.post(f"{API}/redteam/advisor",
               json={"domain": "cloud-attacks", "question": "How to assess S3 misconfigurations?"},
               timeout=60)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d.get("domain") == "cloud-attacks"
    assert isinstance(d.get("answer"), str) and len(d["answer"]) > 40


# --- RED TEAM: Phishing ---
def test_phishing(s):
    r = s.post(f"{API}/redteam/phishing",
               json={"scenario": "IT Support", "company": "Acme", "role": "Employee", "difficulty": "medium"},
               timeout=60)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d.get("subject")
    assert d.get("body_text", "").startswith("[SIMULATION")
    assert isinstance(d.get("red_flags"), list) and len(d["red_flags"]) >= 1


# --- RED TEAM: Cloud (flaws.cloud) ---
def test_cloud_flaws(s):
    r = s.post(f"{API}/redteam/cloud", json={"target": "flaws.cloud"}, timeout=45)
    assert r.status_code == 200, r.text
    d = r.json()
    checks = d.get("checks") or []
    aws = next((c for c in checks if c.get("provider") == "AWS S3"), None)
    assert aws is not None, checks
    assert aws.get("state") == "PUBLIC LISTING", aws
    assert isinstance(d.get("findings"), list) and len(d["findings"]) >= 1


# --- RED TEAM: APK URL analysis ---
APK_URL = "https://github.com/appium/appium/raw/master/packages/appium/sample-code/apps/ApiDemos-debug.apk"


def test_apk_url(s):
    r = s.post(f"{API}/redteam/apk/url", json={"apk_url": APK_URL}, timeout=120)
    assert r.status_code == 200, r.text
    d = r.json()
    app = d.get("app") or {}
    assert app.get("package") == "io.appium.android.apis", app
    assert d.get("flags", {}).get("debuggable") is True
    assert isinstance(d.get("findings"), list) and len(d["findings"]) >= 1


def test_apk_scans_history(s):
    r = s.get(f"{API}/redteam/apk/scans", timeout=15)
    assert r.status_code == 200
    assert isinstance(r.json(), list)


# --- OSINT: Dossier PDF ---
def test_osint_dossier(s):
    # ensure at least one lookup exists
    s.post(f"{API}/osint/email", json={"email": "test@example.com"}, timeout=30)
    r = s.post(f"{API}/osint/report", json={"lookup_ids": []}, timeout=60)
    assert r.status_code == 200, r.text
    ct = r.headers.get("content-type", "")
    assert "pdf" in ct.lower()
    assert r.content[:4] == b"%PDF"
    assert len(r.content) > 500
