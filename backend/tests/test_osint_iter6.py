"""Iteration 6: OSINT endpoints + threat map refresh + PDF report."""
import os
import time
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "https://localhost:8001").rstrip("/")
API = f"{BASE_URL}/api"


@pytest.fixture(scope="module")
def s():
    sess = requests.Session()
    sess.headers.update({"Content-Type": "application/json"})
    return sess


# ---------- OSINT EMAIL ----------
def test_osint_email(s):
    r = s.post(f"{API}/osint/email", json={"email": "beau@dodgycoder.net"}, timeout=90)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["kind"] == "email"
    res = d["result"]
    assert "mail" in res and "provider" in res["mail"]
    assert "gravatar" in res
    assert isinstance(res.get("candidate_profiles"), list) and len(res["candidate_profiles"]) >= 4
    assert "ai_summary" in res
    # AI can occasionally be empty; log
    print("ai_summary len:", len(res.get("ai_summary") or ""))


def test_osint_email_invalid(s):
    r = s.post(f"{API}/osint/email", json={"email": "notanemail"}, timeout=15)
    assert r.status_code == 400


# ---------- OSINT PHONE ----------
def test_osint_phone_us(s):
    r = s.post(f"{API}/osint/phone", json={"phone": "+14155552671"}, timeout=15)
    assert r.status_code == 200, r.text
    res = r.json()["result"]
    assert res["valid"] is True
    assert "San Francisco" in (res.get("region") or "")
    assert res["formats"]["e164"] == "+14155552671"
    assert isinstance(res.get("timezones"), list) and len(res["timezones"]) >= 1


def test_osint_phone_in(s):
    r = s.post(f"{API}/osint/phone", json={"phone": "9820098200", "region": "IN"}, timeout=15)
    assert r.status_code == 200, r.text
    res = r.json()["result"]
    assert res["valid"] is True
    assert res["country_code"] == "+91"


# ---------- OSINT IMAGE ----------
def test_osint_image(s):
    url = "https://raw.githubusercontent.com/ianare/exif-samples/master/jpg/gps/DSCN0010.jpg"
    r = s.post(f"{API}/osint/image", json={"image_url": url}, timeout=120)
    assert r.status_code == 200, r.text
    res = r.json()["result"]
    assert res["metadata"]["format"] in ("JPEG", "JPG")
    exif = res.get("exif") or {}
    assert "NIKON" in (exif.get("Make") or "").upper()
    assert "COOLPIX" in (exif.get("Model") or "").upper()
    gps = res.get("gps")
    assert gps and gps.get("lat") and gps.get("lon") and gps.get("maps_url")
    print("ai_analysis len:", len(res.get("ai_analysis") or ""))


# ---------- OSINT USERNAME ----------
def test_osint_username(s):
    r = s.post(f"{API}/osint/username", json={"username": "torvalds"}, timeout=90)
    assert r.status_code == 200, r.text
    res = r.json()["result"]
    assert res["username"] == "torvalds"
    assert res["checked"] >= 14
    assert isinstance(res["results"], list) and len(res["results"]) >= 14
    # GitHub should be found
    gh = next((x for x in res["results"] if x["site"] == "GitHub"), None)
    assert gh and gh["status"] == "found"


def test_osint_username_invalid(s):
    r = s.post(f"{API}/osint/username", json={"username": "bad name!!"}, timeout=10)
    assert r.status_code == 400


# ---------- HISTORY ----------
def test_osint_history_and_delete(s):
    r = s.get(f"{API}/osint/history", timeout=15)
    assert r.status_code == 200
    hist = r.json()
    assert isinstance(hist, list) and len(hist) >= 1
    lid = hist[0]["id"]
    d = s.delete(f"{API}/osint/history/{lid}", timeout=15)
    assert d.status_code == 200
    # Deleting again -> 404
    d2 = s.delete(f"{API}/osint/history/{lid}", timeout=10)
    assert d2.status_code == 404


# ---------- DASHBOARD STATS (threat map) ----------
def test_dashboard_stats(s):
    r = s.get(f"{API}/dashboard/stats", timeout=20)
    assert r.status_code == 200, r.text
    d = r.json()
    assert "threat_points" in d
    assert "alerts" in d


# ---------- SCANNER PDF ----------
def test_scanner_pdf_report(s):
    # Trigger a scan
    # Try to reuse an existing completed scan first
    lst = s.get(f"{API}/scanner/scans", timeout=30)
    scan_id = None
    if lst.status_code == 200:
        for item in lst.json():
            if item.get("id"):
                scan_id = item["id"]
                break
    if not scan_id:
        r = s.post(f"{API}/scanner/scan", json={
            "target": "example.com",
            "checks": {"tls": True, "headers": True, "dns": True, "endpoints": True, "snapshot": False}
        }, timeout=180)
        assert r.status_code == 200, r.text
        scan_id = r.json().get("id") or r.json().get("scan_id")
    assert scan_id
    # get PDF
    p = s.get(f"{API}/scanner/scans/{scan_id}/report", timeout=90)
    assert p.status_code == 200, p.text[:200]
    assert "application/pdf" in p.headers.get("content-type", "").lower()
    assert len(p.content) > 500
    assert p.content[:4] == b"%PDF"
