"""Iteration 35 backend tests: subdomain-enum, http-request builder."""
import os
import pytest
import requests

def _load_url():
    url = os.environ.get('REACT_APP_BACKEND_URL')
    if not url:
        try:
            with open('/app/frontend/.env') as f:
                for line in f:
                    if line.startswith('REACT_APP_BACKEND_URL='):
                        url = line.split('=', 1)[1].strip()
                        break
        except Exception:
            pass
    return url.rstrip('/')

BASE_URL = _load_url()
API = f"{BASE_URL}/api"


# --- Subdomain Enumerator ---
class TestSubdomainEnum:
    def test_subdomain_enum_github(self):
        r = requests.post(f"{API}/toolkit/subdomain-enum", json={"domain": "github.com"}, timeout=60)
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["domain"] == "github.com"
        assert data["checked"] >= 100
        assert data["found_count"] >= 1
        assert isinstance(data["found"], list)
        assert "elapsed_ms" in data
        # Structure of found rows
        if data["found"]:
            row = data["found"][0]
            assert "subdomain" in row and "ips" in row
            assert isinstance(row["ips"], list)

    def test_subdomain_enum_invalid(self):
        r = requests.post(f"{API}/toolkit/subdomain-enum", json={"domain": "notadomain"}, timeout=30)
        # backend should reject invalid input with 400
        assert r.status_code in (400, 422), f"Expected 400/422, got {r.status_code}: {r.text}"

    def test_subdomain_enum_missing_domain(self):
        r = requests.post(f"{API}/toolkit/subdomain-enum", json={}, timeout=15)
        assert r.status_code in (400, 422)


# --- HTTP Request Builder ---
class TestHttpRequestBuilder:
    def test_http_get_example(self):
        r = requests.post(f"{API}/toolkit/http-request", json={
            "method": "GET",
            "url": "https://example.com",
            "headers": "",
            "body": ""
        }, timeout=30)
        assert r.status_code == 200, r.text
        data = r.json()
        assert data.get("status") == 200
        assert "text/html" in (data.get("content_type") or "").lower()
        assert data.get("size_bytes", 0) > 0
        assert "body" in data
        assert isinstance(data.get("headers"), (dict, list))

    def test_http_post_with_headers_and_body(self):
        payload = {
            "method": "POST",
            "url": "https://httpbin.org/post",
            "headers": "X-Test: insafelabs\nContent-Type: application/json",
            "body": '{"hello":"world"}'
        }
        r = requests.post(f"{API}/toolkit/http-request", json=payload, timeout=30)
        # httpbin may fail from sandbox; accept 200 or 502-ish handled response
        assert r.status_code in (200, 502), r.text
        if r.status_code == 200:
            data = r.json()
            assert "status" in data

    def test_http_unreachable_url(self):
        r = requests.post(f"{API}/toolkit/http-request", json={
            "method": "GET",
            "url": "http://definitely-not-a-real-domain-xyz-12345.invalid",
            "headers": "",
            "body": ""
        }, timeout=30)
        # Must not 500 or crash; expect graceful 502/400
        assert r.status_code in (400, 502), f"Expected graceful error, got {r.status_code}: {r.text[:200]}"

    def test_http_body_truncated(self):
        # example.com body < 24000 so just verify field exists & is string
        r = requests.post(f"{API}/toolkit/http-request", json={
            "method": "GET", "url": "https://example.com", "headers": "", "body": ""
        }, timeout=30)
        assert r.status_code == 200
        assert isinstance(r.json().get("body"), str)
