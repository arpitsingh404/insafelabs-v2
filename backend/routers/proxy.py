"""Proxy checker + proxy-chain tester (proxychains-style).

* /proxy/test  — test each proxy individually against a target URL.
* /proxy/chain — open a REAL multi-hop tunnel: each hop CONNECT-tunnels to the
  next proxy, the last hop tunnels to the target, then we send the request
  and report per-hop status + the response.

Only http/https proxies can be chained (CONNECT); socks proxies are tested
individually, not chained.
"""
import base64
import socket
import ssl
import time
from urllib.parse import urlparse

import requests
import urllib3
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from netguard import guard_url

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

router = APIRouter(prefix="/proxy", tags=["proxy"])
MAX_HOPS = 8


class ChainInput(BaseModel):
    proxies: list[str] = Field(default_factory=list)
    target: str = "https://api.ipify.org"
    timeout: float = 12


def _parse(p):
    q = (p or "").strip()
    if not q:
        return None
    if "://" not in q:
        q = "http://" + q
    u = urlparse(q)
    if not u.hostname:
        return None
    scheme = u.scheme.lower()
    default_port = 1080 if scheme.startswith("socks") else 8080
    return {"scheme": scheme, "host": u.hostname, "port": u.port or default_port,
            "user": u.username, "pass": u.password, "raw": p.strip()}


def _proxy_url(pr):
    auth = f"{pr['user']}:{pr['pass']}@" if pr["user"] else ""
    return f"{pr['scheme']}://{auth}{pr['host']}:{pr['port']}"


def _test_one(pr, target, timeout):
    purl = _proxy_url(pr)
    t0 = time.time()
    try:
        r = requests.get(target, proxies={"http": purl, "https": purl}, timeout=timeout, verify=False)
        body = (r.text or "").strip()
        return {"ok": True, "status": r.status_code, "elapsed_ms": int((time.time() - t0) * 1000),
                "exit_ip": body[:60] if "ip" in target else None, "body": body[:120]}
    except Exception as e:
        return {"ok": False, "error": str(e)[:160], "elapsed_ms": int((time.time() - t0) * 1000)}


def _tunnel(sock, host, port, via_pr, timeout):
    """Send an HTTP CONNECT request on `sock` (talking to proxy `via_pr`) to reach host:port."""
    req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
    if via_pr and via_pr.get("user"):
        tok = base64.b64encode(f"{via_pr['user']}:{via_pr['pass']}".encode()).decode()
        req += f"Proxy-Authorization: Basic {tok}\r\n"
    req += "Proxy-Connection: keep-alive\r\n\r\n"
    sock.sendall(req.encode())
    buf = b""
    sock.settimeout(timeout)
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        if len(buf) > 65536:
            break
    head = buf.split(b"\r\n\r\n", 1)[0].decode("latin-1", "ignore")
    status_line = head.split("\r\n", 1)[0] if head else ""
    if " 200 " not in status_line:
        raise RuntimeError(f"CONNECT refused: {status_line[:100] or 'no response'}")
    return sock, (buf.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in buf else b"")


def _chain(proxies, target, timeout):
    u = urlparse(target if "://" in target else "https://" + target)
    if u.scheme not in ("http", "https"):
        raise HTTPException(status_code=400, detail="Target must be http/https")
    guard_url(target)
    thost, tport = u.hostname, (u.port or (443 if u.scheme == "https" else 80))
    tpath = u.path or "/"
    if u.query:
        tpath += "?" + u.query

    hops = []
    # open a socket to the first proxy
    first = proxies[0]
    s = socket.create_connection((first["host"], first["port"]), timeout=timeout)
    hops.append({"hop": 0, "proxy": first["raw"], "status": "connected"})

    leftover = b""
    for i in range(1, len(proxies)):
        nxt = proxies[i]
        try:
            s, _ = _tunnel(s, nxt["host"], nxt["port"], proxies[i - 1], timeout)
            hops.append({"hop": i, "proxy": nxt["raw"], "status": "tunneled"})
        except Exception as e:
            hops.append({"hop": i, "proxy": nxt["raw"], "status": "failed", "error": str(e)[:140]})
            try:
                s.close()
            except Exception:
                pass
            return {"ok": False, "hops": hops, "target": target}

    # final tunnel to the target through the last proxy
    try:
        s, leftover = _tunnel(s, thost, tport, proxies[-1], timeout)
    except Exception as e:
        hops.append({"hop": len(proxies), "proxy": f"{thost}:{tport}", "status": "failed", "error": str(e)[:140]})
        try:
            s.close()
        except Exception:
            pass
        return {"ok": False, "hops": hops, "target": target}

    try:
        if u.scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=thost)
        req = (f"GET {tpath} HTTP/1.1\r\nHost: {thost}\r\nUser-Agent: InsafeLabs-ProxyChain/1.0\r\n"
               f"Accept: */*\r\nConnection: close\r\n\r\n")
        s.sendall(req.encode())
        data = leftover
        s.settimeout(timeout)
        try:
            while len(data) < 65536:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        text = data.decode("utf-8", "ignore")
        status_line = text.split("\r\n", 1)[0] if text else ""
        body = text.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in text else ""
        hops.append({"hop": len(proxies), "proxy": f"{thost}:{tport}", "status": "connected"})
        return {"ok": True, "hops": hops, "target": target, "status_line": status_line,
                "exit_ip": body.strip()[:60] if "ip" in target else None, "body": body[:300]}
    finally:
        try:
            s.close()
        except Exception:
            pass


@router.post("/test")
async def test(body: ChainInput):
    tgt = body.target or "https://api.ipify.org"
    guard_url(tgt)
    results = []
    for raw in body.proxies[:MAX_HOPS]:
        pr = _parse(raw)
        if not pr:
            results.append({"proxy": raw, "ok": False, "error": "invalid proxy"})
            continue
        if pr["scheme"].startswith("socks"):
            results.append({"proxy": raw, "ok": False, "error": "SOCKS test needs PySocks (not installed); use http(s) proxies"})
            continue
        r = _test_one(pr, tgt, body.timeout)
        results.append({"proxy": raw, **r})
    return {"target": tgt, "results": results}


@router.post("/chain")
async def chain(body: ChainInput):
    if not body.proxies:
        raise HTTPException(status_code=400, detail="Provide at least one proxy (host:port)")
    proxies = [_parse(p) for p in body.proxies[:MAX_HOPS]]
    if any(p is None for p in proxies):
        raise HTTPException(status_code=400, detail="One or more proxies are invalid")
    socks = [p["raw"] for p in proxies if p["scheme"].startswith("socks")]
    if socks:
        raise HTTPException(status_code=400, detail=f"SOCKS proxies cannot be chained here: {', '.join(socks)}")
    return _chain(proxies, body.target or "https://api.ipify.org", body.timeout)
