"""Iter17: Operation Report + Voice/Gesture backend tests.

Covers:
 - GET /api/offensive/operation/sources structure
 - POST /api/offensive/operation/report -> real PDF
 - POST /api/offensive/operation/report empty -> 400
 - POST /api/offensive/binary/analyze persists into binaries[]
"""
import io
import os
import pytest
import requests

BASE = os.environ["REACT_APP_BACKEND_URL"].rstrip("/")
API = f"{BASE}/api"


@pytest.fixture(scope="module")
def sources():
    r = requests.get(f"{API}/offensive/operation/sources", timeout=30)
    assert r.status_code == 200, r.text
    return r.json()


def test_sources_structure(sources):
    for k in ("recon", "network", "binaries"):
        assert k in sources and isinstance(sources[k], list)
    if sources["recon"]:
        r0 = sources["recon"][0]
        for f in ("id", "risk_score", "posture", "finding_count"):
            assert f in r0, f"recon missing {f}"
        assert "host" in r0 or "target" in r0
    if sources["network"]:
        n0 = sources["network"][0]
        for f in ("id", "target", "hosts_up", "scanned"):
            assert f in n0, f"network missing {f}"
    for b in sources["binaries"]:
        for f in ("id", "filename", "format", "verdict"):
            assert f in b, f"binary missing {f}"


def test_report_valid_returns_pdf(sources):
    if not sources["recon"] and not sources["network"]:
        pytest.skip("no data to build report from")
    payload = {
        "title": "TEST_iter17 dossier",
        "operator": "T1",
        "recon_ids": [sources["recon"][0]["id"]] if sources["recon"] else [],
        "network_ids": [sources["network"][0]["id"]] if sources["network"] else [],
        "binary_ids": [],
    }
    r = requests.post(f"{API}/offensive/operation/report", json=payload, timeout=60)
    assert r.status_code == 200, r.text
    assert r.headers.get("content-type", "").startswith("application/pdf")
    assert r.content[:5] == b"%PDF-"
    assert len(r.content) > 1000


def test_report_empty_returns_400():
    r = requests.post(
        f"{API}/offensive/operation/report",
        json={"recon_ids": [], "network_ids": [], "binary_ids": []},
        timeout=30,
    )
    assert r.status_code == 400
    body = r.json()
    assert "detail" in body and isinstance(body["detail"], str) and len(body["detail"]) > 0


def test_binary_analyze_persists():
    before = requests.get(f"{API}/offensive/operation/sources", timeout=30).json()
    before_count = len(before["binaries"])

    # Craft a tiny fake ELF
    elf = b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 56 + b"suspicious_test_bin\x00"
    files = {"file": ("TEST_tiny.elf", io.BytesIO(elf), "application/octet-stream")}
    r = requests.post(f"{API}/offensive/binary/analyze", files=files, timeout=90)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("format") in ("ELF", "raw/data")
    assert "id" in body and "verdict" in body

    after = requests.get(f"{API}/offensive/operation/sources", timeout=30).json()
    after_count = len(after["binaries"])
    assert after_count == before_count + 1, f"binary not persisted: {before_count} -> {after_count}"
    # The newly inserted binary should now be selectable in a report
    new_id = body["id"]
    assert any(b["id"] == new_id for b in after["binaries"])

    # And a report with just this binary should render a PDF
    r2 = requests.post(
        f"{API}/offensive/operation/report",
        json={"binary_ids": [new_id], "recon_ids": [], "network_ids": []},
        timeout=60,
    )
    assert r2.status_code == 200
    assert r2.content[:5] == b"%PDF-"
