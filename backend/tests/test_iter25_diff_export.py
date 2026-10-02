"""Tests for Recon Diff + Source Recon Export (iteration 25)."""
import os
import io
import json
import zipfile
import requests
import pytest

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL").rstrip("/") + "/api"
SCAN_WITH_DIFF = "82b420a5-a17a-41ca-81fe-1b3db1f04a7b"
BASELINE = "b3b5a304-90f2-4cdd-936d-5f14ff410abd"


# ------------------ Recon Diff ------------------
def test_scan_detail_has_diff_object():
    r = requests.get(f"{BASE_URL}/bugbounty/scan/{SCAN_WITH_DIFF}", timeout=30)
    assert r.status_code == 200, r.text
    data = r.json()
    diff = data.get("diff")
    assert diff is not None, "Expected diff object on scan detail"
    assert diff["baseline_id"] == BASELINE
    counts = diff["counts"]
    for k in ("new_subdomains", "removed_subdomains", "new_hosts", "new_apis", "new_libraries"):
        assert k in counts
    assert counts["new_apis"] == 4, f"Expected new_apis=4, got {counts['new_apis']}"
    # Lists exist
    for k in ("new_subdomains", "removed_subdomains", "new_hosts", "new_apis", "new_libraries"):
        assert isinstance(diff[k], list)


def test_scans_list_excludes_diff():
    r = requests.get(f"{BASE_URL}/bugbounty/scans", timeout=30)
    assert r.status_code == 200
    payload = r.json()
    scans = payload["scans"] if isinstance(payload, dict) else payload
    assert isinstance(scans, list) and len(scans) > 0
    for s in scans:
        assert "diff" not in s, "list_scans must exclude 'diff' field"


def test_baseline_scan_diff_null():
    r = requests.get(f"{BASE_URL}/bugbounty/scan/{BASELINE}", timeout=30)
    assert r.status_code == 200
    assert r.json().get("diff") is None


# ------------------ Source Export ------------------
def test_export_sources_zip_ok():
    r = requests.get(f"{BASE_URL}/bugbounty/export/{SCAN_WITH_DIFF}/sources", timeout=120)
    assert r.status_code == 200, r.text[:500]
    assert r.headers.get("content-type", "").startswith("application/zip")
    cd = r.headers.get("content-disposition", "")
    assert "attachment" in cd and "insafelabs-sources-" in cd and ".zip" in cd

    zf = zipfile.ZipFile(io.BytesIO(r.content))
    names = zf.namelist()
    assert "MANIFEST.json" in names
    assert "README.txt" in names
    # ~43 entries expected
    assert len(names) >= 40, f"Expected ~43 entries, got {len(names)}"

    manifest = json.loads(zf.read("MANIFEST.json"))
    assert "maps" in manifest and len(manifest["maps"]) >= 1
    m0 = manifest["maps"][0]
    assert m0.get("files_reconstructed", 0) > 0

    # Path traversal neutralised
    for n in names:
        assert not n.startswith("/"), f"Absolute path leak: {n}"
        assert "../" not in n and "..\\" not in n, f"Traversal in entry: {n}"


def test_export_sources_404_for_missing_scan():
    r = requests.get(f"{BASE_URL}/bugbounty/export/nonexistent-id-xyz/sources", timeout=15)
    assert r.status_code == 404


def test_export_sources_404_for_scan_without_maps():
    # baseline scan should not have injected source_maps
    r = requests.get(f"{BASE_URL}/bugbounty/export/{BASELINE}/sources", timeout=30)
    assert r.status_code == 404
