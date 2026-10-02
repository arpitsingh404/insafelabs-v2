"""
Backend regression tests for the Secure Code Review module + assessments CRUD.
Covers: run with code-review module, unknown module 400, large-code truncation (100k+),
list filter by module, get by id, delete.
"""
import os
import pytest
import requests

BASE = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")
if not BASE:
    # Fallback to local when running inside container
    BASE = "http://localhost:8001"

API = f"{BASE}/api"


@pytest.fixture(scope="module")
def sess():
    s = requests.Session()
    s.headers.update({"Content-Type": "application/json"})
    return s


VULN_CODE = """
import os, pickle, sqlite3
def login(user, pw):
    q = "SELECT * FROM users WHERE u='" + user + "' AND p='" + pw + "'"
    sqlite3.connect('a.db').execute(q)
    os.system("logger " + user)
    return pickle.loads(open('/tmp/x','rb').read())
API_KEY = "demo-hardcoded-key-please-rotate"
"""


class TestCodeReviewAssessment:
    created_id = None

    def test_unknown_module_returns_400(self, sess):
        r = sess.post(f"{API}/assessments/run",
                      json={"module": "does-not-exist", "inputs": {"code": "x"}}, timeout=30)
        assert r.status_code == 400
        assert "Unknown module" in r.json().get("detail", "")

    def test_run_code_review_small(self, sess):
        r = sess.post(f"{API}/assessments/run",
                      json={"module": "code-review",
                            "inputs": {"code": VULN_CODE, "language": "python"}},
                      timeout=120)
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["module"] == "code-review"
        assert isinstance(data.get("findings"), list)
        assert data["finding_count"] == len(data["findings"])
        assert data["finding_count"] >= 1, "expected AI to return findings for vuln code"
        assert data["posture"] in ("critical", "high", "medium", "low")
        assert 0 <= data["risk_score"] <= 100
        assert data["id"]
        assert data["ref"].startswith("InsafeLabs-")
        # sanity on first finding
        f0 = data["findings"][0]
        for k in ("title", "severity", "description"):
            assert k in f0
        TestCodeReviewAssessment.created_id = data["id"]

    def test_run_code_review_large_input_truncated(self, sess):
        big = VULN_CODE + ("\n# padding line ABCDEFGH " * 6000)  # ~ >150k
        assert len(big) > 100_000
        r = sess.post(f"{API}/assessments/run",
                      json={"module": "code-review",
                            "inputs": {"code": big, "language": "python"}},
                      timeout=180)
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["finding_count"] >= 1

    def test_list_filter_by_module(self, sess):
        r = sess.get(f"{API}/assessments", params={"module": "code-review"}, timeout=30)
        assert r.status_code == 200
        docs = r.json()
        assert isinstance(docs, list)
        assert all(d["module"] == "code-review" for d in docs)
        assert any(d["id"] == TestCodeReviewAssessment.created_id for d in docs)
        # Ensure _id was stripped
        assert all("_id" not in d for d in docs)

    def test_get_assessment_full(self, sess):
        aid = TestCodeReviewAssessment.created_id
        r = sess.get(f"{API}/assessments/{aid}", timeout=30)
        assert r.status_code == 200
        doc = r.json()
        assert doc["id"] == aid
        assert "findings" in doc
        assert "_id" not in doc

    def test_get_assessment_404(self, sess):
        r = sess.get(f"{API}/assessments/does-not-exist-xyz", timeout=30)
        assert r.status_code == 404

    def test_delete_assessment(self, sess):
        aid = TestCodeReviewAssessment.created_id
        r = sess.delete(f"{API}/assessments/{aid}", timeout=30)
        assert r.status_code == 200
        # Now GET should 404
        r2 = sess.get(f"{API}/assessments/{aid}", timeout=30)
        assert r2.status_code == 404

    def test_delete_assessment_404(self, sess):
        r = sess.delete(f"{API}/assessments/nope-nope", timeout=30)
        assert r.status_code == 404
