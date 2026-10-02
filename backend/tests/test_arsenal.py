"""Arsenal runner safety tests (no external tools required)."""
import asyncio
import sys

import pytest
from fastapi import HTTPException

from routers import arsenal


def test_target_validation_rejects_dangerous_input():
    bad = ["-oN evil.txt", "example.com; whoami", "a b", "a|b", "$(id)", "a`id`", "a&b", "a>b", "a'quote"]
    for t in bad:
        with pytest.raises(HTTPException):
            arsenal._validate_target(t, "host")


def test_target_validation_accepts_hosts_and_cidr():
    assert arsenal._validate_target("example.com", "host") == "example.com"
    assert arsenal._validate_target("10.0.0.0/24", "host") == "10.0.0.0/24"
    assert arsenal._validate_target("127.0.0.1", "host") == "127.0.0.1"
    assert arsenal._validate_target("https://example.com/a?b=1", "url").startswith("https://")


def test_target_validation_requires_url_scheme():
    with pytest.raises(HTTPException):
        arsenal._validate_target("example.com", "url")


def test_catalog_has_expected_tools():
    ids = {t["id"] for t in arsenal.CATALOG}
    for expected in ["nmap", "masscan", "zap", "burp", "nikto", "nuclei", "sqlmap", "metasploit",
                     "tshark", "nessus", "openvas", "john", "hashcat", "aircrack",
                     "gobuster", "ffuf", "amass", "httpx", "subfinder", "wfuzz"]:
        assert expected in ids, f"missing {expected}"


def test_runner_is_shell_free(monkeypatch):
    """The runner must exec an argv array (never a shell string) and substitute the target."""
    fake = {
        "id": "faketool", "name": "Fake", "category": "Test", "binaries": ["x"],
        "mode": "cli", "runnable": True, "targetType": "host",
        "profiles": [{"id": "p", "args": ["-c", "print('ARSENAL_RUN_OK')", "{target}"]}],
    }
    monkeypatch.setattr(arsenal, "CATALOG", [fake])
    monkeypatch.setattr(arsenal, "_resolve", lambda tool, dirs=None: ("fake", sys.executable, "test 1.0"))

    res = asyncio.run(arsenal.run(arsenal.RunBody(id="faketool", profile="p", target="example.com")))
    assert "ARSENAL_RUN_OK" in res["output"]
    assert res["argv"] == ["fake", "-c", "print('ARSENAL_RUN_OK')", "example.com"]
    assert res["exit_code"] == 0


def test_runner_blocks_non_runnable(monkeypatch):
    fake = {"id": "gui", "name": "GUI", "category": "Test", "binaries": ["x"],
            "mode": "gui", "runnable": False, "targetType": "host", "profiles": []}
    monkeypatch.setattr(arsenal, "CATALOG", [fake])
    with pytest.raises(HTTPException) as e:
        asyncio.run(arsenal.run(arsenal.RunBody(id="gui", target="example.com")))
    assert e.value.status_code == 400
