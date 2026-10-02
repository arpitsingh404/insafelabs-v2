"""Outbound URL guard.

The toolkit exposes several "fetch this URL" helpers. Without validation those
become a general-purpose SSRF proxy into the host's network (loopback services,
cloud metadata at 169.254.169.254, docker API, etc.). This module centralises
the check.

Set ALLOW_PRIVATE_TARGETS=1 in the environment to intentionally allow
loopback / private-range targets (e.g. scanning your own LAN).
"""
import ipaddress
import os
import socket
from urllib.parse import urlparse

from fastapi import HTTPException

ALLOW_PRIVATE = os.environ.get("ALLOW_PRIVATE_TARGETS", "").strip().lower() in ("1", "true", "yes")

# Cloud metadata / well-known internal-only hostnames that must never be reachable.
BLOCKED_HOSTS = {
    "metadata.google.internal",
    "metadata.goog",
    "metadata",
    "instance-data",
}


def guard_url(url: str, *, allow_private: bool | None = None) -> str:
    """Validate an outbound URL, raising HTTP 400 when the target is unsafe.

    Blocks non-http(s) schemes, known metadata hostnames, and — unless
    ALLOW_PRIVATE_TARGETS=1 (or allow_private=True) — loopback, private,
    link-local, reserved and multicast addresses (IPv4 & IPv6).
    """
    if not isinstance(url, str) or not url.strip():
        raise HTTPException(status_code=400, detail="A target URL is required")

    raw = url.strip()
    parsed = urlparse(raw if "://" in raw else "http://" + raw)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(status_code=400, detail=f"Unsupported URL scheme '{parsed.scheme}' — only http/https allowed")

    host = parsed.hostname
    if not host:
        raise HTTPException(status_code=400, detail="Invalid target host")

    if host.lower().rstrip(".") in BLOCKED_HOSTS:
        raise HTTPException(status_code=400, detail="Blocked target host (cloud metadata)")

    allow_priv = ALLOW_PRIVATE if allow_private is None else allow_private
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise HTTPException(status_code=400, detail=f"Could not resolve host '{host}'")

    for info in infos:
        ip = info[4][0]
        try:
            addr = ipaddress.ip_address(ip.split("%")[0])
        except ValueError:
            continue
        # ALWAYS blocked, even when private targets are allowed: link-local
        # (includes cloud metadata 169.254.169.254 / fe80::), multicast, unspecified.
        if addr.is_link_local or addr.is_multicast or addr.is_unspecified:
            raise HTTPException(status_code=400, detail=f"Blocked target address {ip} (link-local/reserved)")
        if addr.is_reserved and not (addr.is_loopback or addr.is_private):
            raise HTTPException(status_code=400, detail=f"Blocked target address {ip} (reserved)")
        # loopback / private (LAN) — allowed only when explicitly enabled
        if (addr.is_loopback or addr.is_private) and not allow_priv:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Blocked target address {ip} (loopback/private). "
                    "Internal targets are disabled — set ALLOW_PRIVATE_TARGETS=1 to permit them."
                ),
            )
    return raw
