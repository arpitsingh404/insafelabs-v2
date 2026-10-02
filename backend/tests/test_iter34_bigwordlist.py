"""Tests for iteration 34 — Hash Cracker big wordlist (~157,865 rockyou-style)."""
import hashlib
import os
import time

import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL").rstrip("/")
HASH_URL = f"{BASE_URL}/api/toolkit/hash-crack"

EXPECTED_WORDLIST_SIZE = 157865


def _post(hash_value: str, wordlist: str = ""):
    r = requests.post(HASH_URL, json={"hash": hash_value, "wordlist": wordlist}, timeout=60)
    assert r.status_code == 200, f"HTTP {r.status_code}: {r.text[:200]}"
    return r.json()


@pytest.mark.parametrize(
    "plain,algo",
    [
        ("Summer2024", "md5"),
        ("letmein123", "sha256"),
        ("P@ssw0rd", "md5"),
        ("dragon1", "sha1"),
    ],
)
def test_crack_new_passwords(plain, algo):
    h = hashlib.new(algo, plain.encode()).hexdigest()
    t0 = time.time()
    data = _post(h)
    elapsed = time.time() - t0
    assert data["wordlist_size"] == EXPECTED_WORDLIST_SIZE, data["wordlist_size"]
    assert data["cracked"] == plain, f"cracked={data.get('cracked')} for {plain}"
    assert data["cracked_algo"] == algo.upper()
    assert data["crackable"] is True
    print(f"OK {plain}/{algo} in {elapsed:.2f}s tried={data['tried']}")


def test_uncrackable_random_sha256_fast():
    # Random-ish hex not in wordlist
    h = hashlib.sha256(b"zzz_not_in_wordlist_" + os.urandom(16).hex().encode()).hexdigest()
    t0 = time.time()
    data = _post(h)
    elapsed = time.time() - t0
    assert data["cracked"] is None
    assert data["tried"] == EXPECTED_WORDLIST_SIZE
    assert data["wordlist_size"] == EXPECTED_WORDLIST_SIZE
    assert elapsed < 4.0, f"too slow: {elapsed:.2f}s"
    print(f"OK uncrackable sha256 in {elapsed:.2f}s")


def test_bcrypt_identified_not_crackable():
    bcrypt_hash = "$2b$12$KIXQKw3JiK1e0Z1qhL9lQeIHZQmYyq3PZeRj0.aXKMGxsQxWlKKKm"
    data = _post(bcrypt_hash)
    assert data["crackable"] is False
    assert data["cracked"] is None
    assert any("bcrypt" in c.lower() for c in data["candidates"])


def test_ntlm_password_cracks():
    data = _post("8846f7eaee8fb117ad06bdd830b7586c")
    # NTLM(password) — password is in COMMON list so should crack quickly
    assert data["cracked"] == "password"
    assert data["cracked_algo"] in ("NTLM", "MD5")
    assert data["wordlist_size"] == EXPECTED_WORDLIST_SIZE


def test_wordlist_size_matches():
    # Any known crack call reports the size
    h = hashlib.md5(b"password").hexdigest()
    data = _post(h)
    assert data["wordlist_size"] == EXPECTED_WORDLIST_SIZE
