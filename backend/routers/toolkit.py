"""InsafeLabs Hacker Toolkit — CVE search (NVD) + DNS/WHOIS lookup + IMEI info
+ hash identify/crack + HTTP header & TLS certificate inspector. Authorized use only."""
import asyncio
import os
import re
import ssl
import socket
import struct
import hashlib
import hmac
import json
import base64
import ipaddress
import uuid as _uuid
import time as _time
from pathlib import Path
from datetime import datetime, timezone

import requests
import urllib3
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

import recon_lib
from netguard import guard_url

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
router = APIRouter(prefix="/toolkit", tags=["toolkit"])

UA = {"User-Agent": "InsafeLabs-Toolkit/1.0 (authorized security assessment)"}
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
IMEI_BASE = "https://dash.imei.info/api"


def _sev_from_score(s):
    try:
        s = float(s)
    except Exception:
        return "info"
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    if s > 0:
        return "low"
    return "info"


class CveInput(BaseModel):
    keyword: str = Field(min_length=2)
    limit: int = 15


def _cve_search(keyword: str, limit: int) -> dict:
    limit = max(1, min(limit, 30))
    try:
        r = requests.get(NVD, params={"keywordSearch": keyword, "resultsPerPage": limit},
                         timeout=25, headers=UA)
        if r.status_code in (403, 429):
            raise HTTPException(status_code=429, detail="NVD rate limit hit (5 requests / 30s without an API key). Wait ~30s and retry.")
        data = r.json()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"CVE database unavailable: {str(e)[:100]}")
    out = []
    for v in data.get("vulnerabilities", []):
        c = v.get("cve", {})
        desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
        metrics = c.get("metrics", {})
        cvss, sev, vector = None, None, None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                md = metrics[key][0]
                cd = md.get("cvssData", {})
                cvss = cd.get("baseScore")
                sev = (cd.get("baseSeverity") or md.get("baseSeverity") or "").lower()
                vector = cd.get("vectorString")
                break
        out.append({
            "id": c.get("id"), "description": desc[:420],
            "cvss": cvss, "severity": sev or _sev_from_score(cvss or 0),
            "vector": vector, "published": (c.get("published") or "")[:10],
            "url": f"https://nvd.nist.gov/vuln/detail/{c.get('id')}",
        })
    out.sort(key=lambda x: (x["cvss"] or 0), reverse=True)
    return {"keyword": keyword, "total": data.get("totalResults", len(out)), "results": out}


@router.post("/cve")
async def cve(data: CveInput):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _cve_search, data.keyword, data.limit)


class DnsInput(BaseModel):
    domain: str = Field(min_length=3)


@router.post("/dns")
async def dns(data: DnsInput):
    domain = data.domain.strip().replace("http://", "").replace("https://", "").split("/")[0]
    loop = asyncio.get_event_loop()
    result, findings = await loop.run_in_executor(None, recon_lib.network_recon, domain)
    result["domain"] = domain
    result["findings"] = findings
    return result


# ---------------------------------------------------------------------------
# IMEI info (imei.info API v5)
# ---------------------------------------------------------------------------
class ImeiInput(BaseModel):
    imei: str = Field(min_length=6)
    service_id: int = 0


def _imei_configured() -> bool:
    return bool(os.environ.get("IMEI_INFO_API_KEY"))


def _imei_key():
    key = os.environ.get("IMEI_INFO_API_KEY")
    if not key:
        raise HTTPException(status_code=503, detail="IMEI lookup is not configured (set IMEI_INFO_API_KEY)")
    return key


def _imei_check(imei: str, service_id: int) -> dict:
    import time
    key = _imei_key()
    imei = imei.strip().replace(" ", "").replace("-", "")
    if not imei.isdigit() or not (14 <= len(imei) <= 16):
        raise HTTPException(status_code=400, detail="IMEI must be 14-16 digits")
    try:
        r = requests.get(f"{IMEI_BASE}/check/{service_id}/",
                         params={"API_KEY": key, "imei": imei},
                         headers={"accept": "application/json"}, timeout=45)
        data = r.json() if r.content else {}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"IMEI service unavailable: {str(e)[:120]}")
    if r.status_code >= 400:
        detail = data.get("detail") or data.get("error") or data.get("message") or str(data)[:200]
        raise HTTPException(status_code=(r.status_code if r.status_code < 500 else 502),
                            detail=f"IMEI check failed: {detail}")
    # Async services return a history_id/ulid and no result yet — poll for the result.
    hid = data.get("history_id") or data.get("id")
    if not data.get("result") and hid:
        for _ in range(10):
            time.sleep(3)
            try:
                pr = requests.get(f"{IMEI_BASE}/search_history/{hid}/",
                                  params={"API_KEY": key}, headers={"accept": "application/json"}, timeout=30)
                if pr.status_code == 200:
                    pdata = pr.json()
                    data = pdata
                    if pdata.get("status") == "Done" or pdata.get("result"):
                        return pdata
            except Exception:
                break
    return data


def _imei_services() -> list:
    key = _imei_key()
    try:
        r = requests.get(f"{IMEI_BASE}/service/services/", params={"API_KEY": key},
                         headers={"accept": "application/json"}, timeout=30)
        svcs = r.json()
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"IMEI services unavailable: {str(e)[:120]}")
    if not isinstance(svcs, list):
        return []
    out = [{"id": s.get("id"), "name": s.get("name"),
            "brand": s.get("brand") or [], "price": s.get("price")}
           for s in svcs if s.get("show_button")]
    out.sort(key=lambda x: (0 if x.get("id") == 0 else 1, str(x.get("name") or "")))
    return out


@router.post("/imei")
async def imei(data: ImeiInput):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _imei_check, data.imei, data.service_id)


@router.get("/imei/services")
async def imei_services():
    if not _imei_configured():
        return []
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _imei_services)


def _imei_history() -> dict:
    key = _imei_key()
    try:
        r = requests.get(f"{IMEI_BASE}/search_history/", params={"API_KEY": key},
                         headers={"accept": "application/json"}, timeout=30)
        data = r.json()
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"IMEI history unavailable: {str(e)[:120]}")
    out = []
    for it in (data.get("results") or []):
        res = it.get("result") or {}
        out.append({
            "id": it.get("id"), "imei": it.get("imei"),
            "service": it.get("service"), "service_id": it.get("service_id"),
            "status": it.get("status"), "created_at": it.get("created_at"),
            "price": it.get("token_request_price"),
            "brand": res.get("brand_name") or res.get("manufacturer"),
            "model": res.get("model") or res.get("model_name"),
            "result": res,
        })
    return {"count": data.get("count", len(out)), "results": out}


@router.get("/imei/history")
async def imei_history():
    if not _imei_configured():
        return {"count": 0, "results": [], "configured": False}
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _imei_history)


def _imei_account() -> dict:
    key = _imei_key()
    try:
        r = requests.get(f"{IMEI_BASE}/account/account/", params={"API_KEY": key},
                         headers={"accept": "application/json"}, timeout=20)
        d = r.json()
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"IMEI account unavailable: {str(e)[:120]}")
    return {"balance": d.get("balance"), "pricing_level": d.get("pricing_level"),
            "username": d.get("username")}


@router.get("/imei/account")
async def imei_account():
    if not _imei_configured():
        return {"balance": None, "pricing_level": None, "username": None, "configured": False}
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _imei_account)



# ===========================================================================
# HASH IDENTIFIER + CRACKER (built-in wordlist; MD5/SHA/NTLM)
# ===========================================================================
def _md4(data: bytes) -> bytes:
    """Pure-python MD4 (OpenSSL 3 drops md4) — used for NTLM hashing."""
    def lrot(x, n):
        x &= 0xFFFFFFFF
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
    msg = bytearray(data)
    orig = (8 * len(data)) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", orig)
    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    for off in range(0, len(msg), 64):
        X = list(struct.unpack("<16I", msg[off:off + 64]))
        aa, bb, cc, dd = a, b, c, d
        for i in [0, 4, 8, 12]:
            a = lrot(a + ((b & c) | (~b & d)) + X[i], 3)
            d = lrot(d + ((a & b) | (~a & c)) + X[i + 1], 7)
            c = lrot(c + ((d & a) | (~d & b)) + X[i + 2], 11)
            b = lrot(b + ((c & d) | (~c & a)) + X[i + 3], 19)
        for i in [0, 1, 2, 3]:
            a = lrot(a + ((b & c) | (b & d) | (c & d)) + X[i] + 0x5A827999, 3)
            d = lrot(d + ((a & b) | (a & c) | (b & c)) + X[i + 4] + 0x5A827999, 5)
            c = lrot(c + ((d & a) | (d & b) | (a & b)) + X[i + 8] + 0x5A827999, 9)
            b = lrot(b + ((c & d) | (c & a) | (d & a)) + X[i + 12] + 0x5A827999, 13)
        for i in [0, 2, 1, 3]:
            a = lrot(a + (b ^ c ^ d) + X[i] + 0x6ED9EBA1, 3)
            d = lrot(d + (a ^ b ^ c) + X[i + 8] + 0x6ED9EBA1, 9)
            c = lrot(c + (d ^ a ^ b) + X[i + 4] + 0x6ED9EBA1, 11)
            b = lrot(b + (c ^ d ^ a) + X[i + 12] + 0x6ED9EBA1, 15)
        a = (a + aa) & 0xFFFFFFFF
        b = (b + bb) & 0xFFFFFFFF
        c = (c + cc) & 0xFFFFFFFF
        d = (d + dd) & 0xFFFFFFFF
    return struct.pack("<4I", a, b, c, d)


def _ntlm(pw: str) -> str:
    return _md4(pw.encode("utf-16le")).hex()


# compact common-password wordlist (top leaks + keyboard walks) for demo cracking
COMMON_PASSWORDS = [
    "123456", "password", "123456789", "12345678", "12345", "1234567", "1234567890",
    "qwerty", "abc123", "111111", "123123", "password1", "1234", "iloveyou", "000000",
    "admin", "welcome", "monkey", "dragon", "letmein", "football", "654321", "!@#$%^&*",
    "master", "666666", "qwertyuiop", "123321", "mustang", "shadow", "michael", "superman",
    "696969", "batman", "trustno1", "hello", "charlie", "aa123456", "donald", "password123",
    "qwerty123", "1q2w3e4r", "zxcvbnm", "asdfghjkl", "1qaz2wsx", "sunshine", "princess",
    "login", "starwars", "121212", "flower", "hottie", "loveme", "zaq1zaq1", "passw0rd",
    "root", "toor", "test", "guest", "changeme", "secret", "administrator", "P@ssw0rd",
    "Welcome1", "Password1", "abcd1234", "a1b2c3", "qazwsx", "ninja", "azerty", "123qwe",
    "computer", "michelle", "jessica", "pepper", "daniel", "andrew", "joshua", "summer",
    "love", "ashley", "nicole", "chelsea", "biteme", "matthew", "access", "yankees",
    "987654321", "google", "maverick", "cheese", "hunter", "ranger", "buster", "thomas",
    "robert", "soccer", "hockey", "killer", "george", "sexy", "andrea", "purple",
    "amanda", "jordan", "cameron", "secret1", "freedom", "ginger", "willie", "letmein123",
]


def _load_big_wordlist():
    """Load the bundled rockyou-style list (~158k), fall back to the small builtin."""
    p = Path(__file__).resolve().parent.parent / "wordlists" / "rockyou_lite.txt"
    if p.exists():
        try:
            words = [w for w in p.read_text(encoding="utf-8", errors="ignore").splitlines() if w]
            if words:
                return words
        except Exception:
            pass
    return list(COMMON_PASSWORDS)


BIG_WORDLIST = _load_big_wordlist()
SLOW_ALGO_CAP = 40000  # pure-python md4/ntlm is slow — cap candidates for those algos
SLOW_ALGOS = {"ntlm", "md4"}


def _identify_hash(h: str):
    h = (h or "").strip()
    out = []
    if re.fullmatch(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}", h):
        return h, [{"name": "bcrypt", "crackable": False}]
    if h.startswith("$argon2"):
        return h, [{"name": "Argon2", "crackable": False}]
    if h.startswith("$6$"):
        return h, [{"name": "sha512crypt (Unix)", "crackable": False}]
    if h.startswith("$5$"):
        return h, [{"name": "sha256crypt (Unix)", "crackable": False}]
    if h.startswith("$1$"):
        return h, [{"name": "md5crypt (Unix)", "crackable": False}]
    if not re.fullmatch(r"[a-fA-F0-9]+", h):
        return h, [{"name": "Unknown (non-hex)", "crackable": False}]
    n = len(h)
    tbl = {
        32: [("MD5", "md5"), ("NTLM", "ntlm"), ("MD4", "md4"), ("LM", None)],
        40: [("SHA-1", "sha1")],
        56: [("SHA-224", "sha224")],
        64: [("SHA-256", "sha256")],
        96: [("SHA-384", "sha384")],
        128: [("SHA-512", "sha512")],
    }
    for nm, algo in tbl.get(n, []):
        out.append({"name": nm, "algo": algo, "crackable": algo is not None})
    if not out:
        out.append({"name": f"Unknown ({n}-char hex)", "crackable": False})
    return h.lower(), out


def _digest(algo: str, pw: str) -> str:
    if algo == "ntlm":
        return _ntlm(pw)
    if algo == "md4":
        return _md4(pw.encode()).hex()
    return hashlib.new(algo, pw.encode()).hexdigest()


def _crack_hash(h: str, extra: str = "") -> dict:
    target, kinds = _identify_hash(h)
    algos = [k["algo"] for k in kinds if k.get("crackable") and k.get("algo")]
    # user-supplied words first, then the big bundled list
    words = []
    seen = set()
    for w in (extra or "").replace(",", "\n").split("\n"):
        w = w.strip()
        if w and w not in seen:
            seen.add(w)
            words.append(w)
    user_count = len(words)
    words.extend(BIG_WORDLIST)

    fast = [a for a in algos if a not in SLOW_ALGOS]
    slow = [a for a in algos if a in SLOW_ALGOS]
    cracked = None
    used_algo = None
    tried = 0
    if algos:
        for i, pw in enumerate(words):
            tried += 1
            for algo in fast:
                if hashlib.new(algo, pw.encode()).hexdigest() == target:
                    cracked, used_algo = pw, algo
                    break
            if cracked:
                break
            # pure-python md4/ntlm only on the first N candidates (perf guard)
            if slow and (i < user_count or i < SLOW_ALGO_CAP):
                for algo in slow:
                    try:
                        if _digest(algo, pw) == target:
                            cracked, used_algo = pw, algo
                            break
                    except Exception:
                        continue
                if cracked:
                    break
    return {
        "input": h.strip(), "candidates": [k["name"] for k in kinds],
        "crackable": bool(algos), "wordlist_size": len(words), "tried": tried,
        "cracked": cracked, "cracked_algo": used_algo.upper() if used_algo else None,
    }


class HashInput(BaseModel):
    hash: str = Field(min_length=3, max_length=200)
    wordlist: str = Field(default="", max_length=100_000)


@router.post("/hash-crack")
async def hash_crack(data: HashInput):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _crack_hash, data.hash, data.wordlist)


# ===========================================================================
# HTTP HEADER + TLS CERTIFICATE INSPECTOR
# ===========================================================================
SEC_HEADERS = {
    "strict-transport-security": "HSTS (transport security)",
    "content-security-policy": "Content-Security-Policy",
    "x-frame-options": "X-Frame-Options (clickjacking)",
    "x-content-type-options": "X-Content-Type-Options (MIME sniffing)",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}


def _tls_cert(host: str, port: int = 443) -> dict:
    try:
        from cryptography import x509
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                proto = ssock.version()
                cipher = ssock.cipher()
        cert = x509.load_der_x509_certificate(der)

        def _name(n):
            try:
                return n.rfc4514_string()
            except Exception:
                return str(n)
        try:
            sans = [g.value for g in cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)]
        except Exception:
            sans = []
        na = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=timezone.utc)
        nb = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.replace(tzinfo=timezone.utc)
        days_left = (na - datetime.now(timezone.utc)).days
        return {
            "subject": _name(cert.subject), "issuer": _name(cert.issuer),
            "valid_from": nb.isoformat()[:10], "valid_to": na.isoformat()[:10],
            "days_left": days_left, "expired": days_left < 0,
            "serial": format(cert.serial_number, "x"),
            "sans": sans[:40], "tls_version": proto,
            "cipher": cipher[0] if cipher else None,
            "self_signed": cert.subject == cert.issuer,
        }
    except Exception as e:
        return {"error": str(e)[:160]}


def _http_inspect(url: str) -> dict:
    url = (url or "").strip()
    if not re.match(r"^https?://", url):
        url = "https://" + url
    guard_url(url)
    host = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0]
    is_https = url.lower().startswith("https")
    try:
        r = requests.get(url, timeout=20, headers=UA, allow_redirects=True, verify=False)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Request failed: {str(e)[:140]}")
    headers = {k: v for k, v in r.headers.items()}
    lower = {k.lower(): v for k, v in headers.items()}
    present, missing = [], []
    for k, label in SEC_HEADERS.items():
        (present if k in lower else missing).append(label)
    score = len(present)
    grade = ["F", "F", "D", "C", "B", "A", "A+"][min(score, 6)]
    chain = [{"url": h.url, "status": h.status_code} for h in r.history]
    return {
        "url": url, "final_url": r.url, "status": r.status_code,
        "elapsed_ms": int(r.elapsed.total_seconds() * 1000),
        "server": lower.get("server"), "powered_by": lower.get("x-powered-by"),
        "content_type": lower.get("content-type"),
        "headers": headers, "redirect_chain": chain,
        "security": {"present": present, "missing": missing, "score": score, "grade": grade},
        "tls": _tls_cert(host) if is_https else {"error": "not an HTTPS URL"},
    }


class HttpInput(BaseModel):
    url: str = Field(min_length=3, max_length=2048)


@router.post("/http-inspect")
async def http_inspect(data: HttpInput):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _http_inspect, data.url)


# ===========================================================================
# QUICK PORT + SERVICE SCANNER (nmap-style, top ~35 ports)
# ===========================================================================
SCAN_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    443: "https", 445: "microsoft-ds", 465: "smtps", 587: "submission",
    993: "imaps", 995: "pop3s", 1433: "ms-sql", 1521: "oracle", 1723: "pptp",
    2049: "nfs", 2375: "docker", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5601: "kibana", 5900: "vnc", 6379: "redis", 8000: "http-alt", 8080: "http-proxy",
    8443: "https-alt", 8888: "http-alt", 9200: "elasticsearch", 11211: "memcached",
    27017: "mongodb",
}
TLS_SCAN_PORTS = {443, 8443, 993, 995, 465, 990}
HTTP_SCAN_PORTS = {80, 8080, 8000, 8888}


async def _probe_port(ip: str, port: int, timeout: float = 1.5):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
    except Exception:
        return None
    banner = ""
    try:
        if port in HTTP_SCAN_PORTS:
            writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
            await writer.drain()
        if port not in TLS_SCAN_PORTS:
            data = await asyncio.wait_for(reader.read(160), timeout=0.9)
            banner = data.decode("latin-1", "ignore").strip().split("\r\n")[0][:120]
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
        except Exception:
            pass
    return {"port": port, "service": SCAN_PORTS.get(port, "unknown"), "banner": banner}


async def _port_scan(host: str) -> dict:
    host = (host or "").strip().replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    if not host:
        raise HTTPException(status_code=400, detail="Enter a host or IP")
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        raise HTTPException(status_code=400, detail=f"Could not resolve '{host}'")
    try:
        is_private = ipaddress.ip_address(ip).is_private
    except Exception:
        is_private = False
    sem = asyncio.Semaphore(60)

    async def guarded(p):
        async with sem:
            return await _probe_port(ip, p)

    t0 = _time.time()
    results = await asyncio.gather(*[guarded(p) for p in SCAN_PORTS])
    open_ports = sorted([r for r in results if r], key=lambda x: x["port"])
    return {
        "host": host, "ip": ip, "private": is_private,
        "scanned": len(SCAN_PORTS), "open_count": len(open_ports),
        "elapsed_ms": int((_time.time() - t0) * 1000), "ports": open_ports,
        "note": "This IP is in a private/LAN range — unreachable from the cloud engine (results may be empty)." if is_private else None,
    }


class PortScanInput(BaseModel):
    host: str = Field(min_length=3, max_length=253)


@router.post("/portscan")
async def portscan(data: PortScanInput):
    return await _port_scan(data.host)



# ===========================================================================
# SUBDOMAIN ENUMERATOR (DNS resolution of a common-subdomain wordlist)
# ===========================================================================
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "pop3", "imap", "ns1", "ns2",
    "ns", "dns", "api", "dev", "staging", "stage", "test", "uat", "qa", "prod",
    "production", "portal", "admin", "blog", "shop", "store", "vpn", "remote",
    "m", "mobile", "app", "apps", "cdn", "static", "assets", "img", "images",
    "docs", "doc", "support", "help", "status", "git", "gitlab", "github",
    "jenkins", "ci", "jira", "confluence", "cpanel", "whm", "webdisk",
    "autodiscover", "secure", "payment", "pay", "beta", "demo", "cloud",
    "dashboard", "panel", "monitor", "monitoring", "grafana", "kibana",
    "prometheus", "db", "database", "mysql", "redis", "mongo", "postgres",
    "internal", "intranet", "corp", "office", "auth", "sso", "login", "account",
    "accounts", "news", "forum", "community", "wiki", "cms", "media", "video",
    "stream", "chat", "mx", "mx1", "mx2", "email", "proxy", "gateway", "gw",
    "router", "fw", "firewall", "backup", "old", "new", "sandbox", "v1", "v2",
    "v3", "graphql", "ws", "socket", "live", "edge", "origin", "download",
    "downloads", "files", "file", "upload", "uploads", "s3", "storage", "data",
    "analytics", "stats", "track", "ads", "beta1", "test1", "test2", "demo1",
    "web", "web1", "web2", "server", "host", "cpu", "vps", "cloudflare",
    "kubernetes", "k8s", "docker", "registry", "nexus", "artifactory",
]


async def _subdomain_enum(domain: str) -> dict:
    domain = (domain or "").strip().lower().replace("http://", "").replace("https://", "").split("/")[0]
    if not domain or "." not in domain:
        raise HTTPException(status_code=400, detail="Enter a valid domain, e.g. example.com")
    loop = asyncio.get_event_loop()
    sem = asyncio.Semaphore(60)

    async def resolve(sub):
        host = f"{sub}.{domain}"
        async with sem:
            try:
                infos = await asyncio.wait_for(loop.getaddrinfo(host, None), timeout=4)
                ips = sorted({i[4][0] for i in infos})
                return {"subdomain": host, "ips": ips[:6]}
            except Exception:
                return None

    t0 = _time.time()
    results = await asyncio.gather(*[resolve(s) for s in COMMON_SUBDOMAINS])
    found = sorted([r for r in results if r], key=lambda x: x["subdomain"])
    return {
        "domain": domain, "checked": len(COMMON_SUBDOMAINS),
        "found_count": len(found), "elapsed_ms": int((_time.time() - t0) * 1000),
        "found": found,
    }


class SubdomainInput(BaseModel):
    domain: str = Field(min_length=3, max_length=253)


@router.post("/subdomain-enum")
async def subdomain_enum(data: SubdomainInput):
    return await _subdomain_enum(data.domain)


# ===========================================================================
# HTTP REQUEST BUILDER / REPLAY (mini curl / Postman)
# ===========================================================================
def _parse_headers(raw: str) -> dict:
    out = {}
    for line in (raw or "").split("\n"):
        line = line.strip()
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        if k.strip():
            out[k.strip()] = v.strip()
    return out


def _http_request(method: str, url: str, headers_raw: str, body: str) -> dict:
    url = (url or "").strip()
    if not re.match(r"^https?://", url):
        url = "https://" + url
    guard_url(url)
    method = (method or "GET").upper()
    if method not in {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}:
        raise HTTPException(status_code=400, detail="Unsupported method")
    headers = {**UA, **_parse_headers(headers_raw)}
    try:
        r = requests.request(
            method, url, headers=headers, data=(body.encode() if body else None),
            timeout=25, verify=False, allow_redirects=True,
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Request failed: {str(e)[:160]}")
    text = r.text if r.text else ""
    truncated = len(text) > 24000
    return {
        "method": method, "url": url, "final_url": r.url,
        "status": r.status_code, "reason": r.reason,
        "elapsed_ms": int(r.elapsed.total_seconds() * 1000),
        "size_bytes": len(r.content),
        "content_type": r.headers.get("Content-Type"),
        "headers": {k: v for k, v in r.headers.items()},
        "redirects": [h.status_code for h in r.history],
        "body": text[:24000], "truncated": truncated,
    }


class HttpReqInput(BaseModel):
    method: str = "GET"
    url: str = Field(min_length=3, max_length=2048)
    headers: str = ""
    body: str = ""


@router.post("/http-request")
async def http_request(data: HttpReqInput):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _http_request, data.method, data.url, data.headers, data.body)



# ===========================================================================
# RUSTSCAN-STYLE FAST SCANNER — 2-phase (fast connect sweep -> deep probe),
# background job with live progress, port profiles, risk flags & host intel.
# ===========================================================================

TOP_100_PORTS = [
    7, 20, 21, 22, 23, 25, 26, 53, 67, 68, 69, 80, 81, 88, 110, 111, 113, 119,
    123, 135, 137, 138, 139, 143, 161, 162, 179, 199, 389, 427, 443, 444, 445,
    465, 500, 512, 513, 514, 515, 543, 544, 548, 554, 587, 631, 636, 646, 873,
    990, 993, 995, 1025, 1080, 1099, 1194, 1433, 1434, 1521, 1723, 1900, 2049,
    2082, 2083, 2181, 2375, 2376, 3128, 3268, 3306, 3389, 3690, 4444, 4786,
    5000, 5060, 5432, 5601, 5900, 5901, 5985, 6379, 6443, 7001, 8000, 8008,
    8080, 8081, 8088, 8443, 8888, 9000, 9090, 9200, 9300, 10000, 11211, 27017,
    27018, 50000,
]

# port -> (service, severity, reason)
RISKY_PORTS = {
    21: ("FTP", "MEDIUM", "Cleartext auth; anonymous login often enabled"),
    23: ("Telnet", "CRITICAL", "Cleartext remote shell — should be disabled"),
    69: ("TFTP", "HIGH", "No auth file transfer"),
    111: ("RPCbind", "MEDIUM", "Portmapper info leak"),
    135: ("MSRPC", "MEDIUM", "Windows RPC exposure"),
    139: ("NetBIOS", "MEDIUM", "Legacy Windows share exposure"),
    445: ("SMB", "HIGH", "SMB exposed — EternalBlue / share access risk"),
    161: ("SNMP", "MEDIUM", "Default community strings ('public')"),
    512: ("rexec", "HIGH", "Legacy r-service, cleartext"),
    513: ("rlogin", "HIGH", "Legacy r-service, cleartext"),
    514: ("rshell", "HIGH", "Legacy r-service, cleartext"),
    1433: ("MSSQL", "HIGH", "Database exposed to network"),
    1521: ("Oracle", "HIGH", "Database exposed to network"),
    2049: ("NFS", "HIGH", "Network file share exposure"),
    2375: ("Docker API", "CRITICAL", "Unauthenticated Docker = host RCE"),
    2376: ("Docker TLS", "HIGH", "Docker API exposed"),
    3306: ("MySQL", "HIGH", "Database exposed to network"),
    3389: ("RDP", "HIGH", "BlueKeep / brute-force target"),
    5432: ("PostgreSQL", "HIGH", "Database exposed to network"),
    5900: ("VNC", "HIGH", "Remote desktop exposure"),
    5901: ("VNC", "HIGH", "Remote desktop exposure"),
    6379: ("Redis", "CRITICAL", "Often no auth — RCE / data exposure"),
    9200: ("Elasticsearch", "HIGH", "Often no auth — data exposure"),
    9300: ("Elasticsearch", "HIGH", "Cluster transport exposed"),
    11211: ("Memcached", "HIGH", "No auth + DDoS amplification"),
    27017: ("MongoDB", "CRITICAL", "Often no auth — data exposure"),
    27018: ("MongoDB", "CRITICAL", "Often no auth — data exposure"),
    50000: ("SAP/DB2", "MEDIUM", "Enterprise service exposed"),
    4444: ("Metasploit?", "MEDIUM", "Common backdoor / handler port"),
    23424: ("Unknown", "LOW", "Unusual open port — investigate"),
}

_PORTSCAN_JOBS = {}


def _parse_ports(spec: str):
    out = set()
    for part in (spec or "").replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part:
            try:
                a, b = part.split("-", 1)
                a, b = int(a), int(b)
                for p in range(max(1, min(a, b)), min(65535, max(a, b)) + 1):
                    out.add(p)
            except Exception:
                continue
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    out.add(p)
            except Exception:
                continue
    return sorted(out)


def _ports_for_profile(profile: str, spec: str):
    if profile == "quick":
        return sorted(SCAN_PORTS.keys())
    if profile == "top100":
        return sorted(set(TOP_100_PORTS))
    if profile == "top1000":
        return list(range(1, 1001))
    if profile == "full":
        return list(range(1, 65536))
    return _parse_ports(spec) or sorted(SCAN_PORTS.keys())


async def _connect_open(ip, port, timeout):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=0.3)
        except Exception:
            pass
        return True
    except Exception:
        return False


def _deep_probe(ip, port):
    service = SCAN_PORTS.get(port) or (RISKY_PORTS.get(port, (None,))[0]) or "unknown"
    banner, title, server = "", "", ""
    try:
        s = socket.socket()
        s.settimeout(1.4)
        s.connect((ip, port))
        if port in HTTP_SCAN_PORTS:
            s.sendall(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
        if port not in TLS_SCAN_PORTS:
            data = s.recv(2048).decode("latin-1", "ignore")
            banner = data.strip().split("\r\n")[0][:120]
            ms = re.search(r"(?im)^server:\s*(.+)$", data)
            server = ms.group(1).strip()[:80] if ms else ""
            mt = re.search(r"(?is)<title[^>]*>(.*?)</title>", data)
            title = re.sub(r"\s+", " ", mt.group(1)).strip()[:100] if mt else ""
        s.close()
    except Exception:
        pass
    if port in TLS_SCAN_PORTS and port in (443, 8443):
        try:
            r = requests.get(f"https://{ip}:{port}/", timeout=4, verify=False, headers=UA)
            server = (r.headers.get("Server") or server)[:80]
            mt = re.search(r"(?is)<title[^>]*>(.*?)</title>", r.text or "")
            if mt:
                title = re.sub(r"\s+", " ", mt.group(1)).strip()[:100]
        except Exception:
            pass
    risk = RISKY_PORTS.get(port)
    return {
        "port": port, "service": service, "banner": banner, "title": title, "server": server,
        "risk": ({"severity": risk[1], "reason": risk[2]} if risk else None),
    }


def _host_intel(ip):
    info = {"rdns": None, "org": None, "country": None, "asn": None}
    try:
        info["rdns"] = socket.gethostbyaddr(ip)[0]
    except Exception:
        pass
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,isp,org,as", timeout=5)
        d = r.json()
        if d.get("status") == "success":
            info["org"] = d.get("org") or d.get("isp")
            info["country"] = d.get("country")
            info["asn"] = d.get("as")
    except Exception:
        pass
    return info


async def _run_portscan(job):
    ip = job["ip"]
    ports = job.pop("_ports")
    job["_t0"] = _time.time()
    loop = asyncio.get_event_loop()
    job["host_info"] = await loop.run_in_executor(None, _host_intel, ip)

    sem = asyncio.Semaphore(500)
    open_ports = []
    done = 0

    async def probe(p):
        nonlocal done
        async with sem:
            ok = await _connect_open(ip, p, 0.7)
        done += 1
        job["done"] = done
        if ok:
            open_ports.append(p)
            job["open"] = sorted(open_ports)
        return ok

    CHUNK = 2000
    for i in range(0, len(ports), CHUNK):
        if job.get("cancel"):
            break
        await asyncio.gather(*[probe(p) for p in ports[i:i + CHUNK]])

    job["phase"] = "deep"
    op = sorted(open_ports)
    results = await asyncio.gather(*[loop.run_in_executor(None, _deep_probe, ip, p) for p in op]) if op else []
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    results.sort(key=lambda r: (order.get(r["risk"]["severity"], 9) if r["risk"] else 8, r["port"]))
    job["ports"] = results
    job["open_count"] = len(op)
    job["risk_count"] = sum(1 for r in results if r["risk"])
    job["elapsed_ms"] = int((_time.time() - job["_t0"]) * 1000)
    job["status"] = "cancelled" if job.get("cancel") else "done"


class ScanStartInput(BaseModel):
    host: str = Field(min_length=3, max_length=253)
    profile: str = "quick"
    ports: str = ""


@router.post("/portscan/start")
async def portscan_start(data: ScanStartInput):
    host = data.host.strip().replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    if not host:
        raise HTTPException(status_code=400, detail="Enter a host or IP")
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        raise HTTPException(status_code=400, detail=f"Could not resolve '{host}'")
    ports = _ports_for_profile(data.profile, data.ports)
    if not ports:
        raise HTTPException(status_code=400, detail="No valid ports to scan")
    try:
        private = ipaddress.ip_address(ip).is_private
    except Exception:
        private = False
    if len(_PORTSCAN_JOBS) > 20:
        for k in list(_PORTSCAN_JOBS.keys())[:-15]:
            old = _PORTSCAN_JOBS.pop(k, None)
            if old and old.get("_task"):
                old["_task"].cancel()
    jid = _uuid.uuid4().hex[:12]
    job = {
        "id": jid, "host": host, "ip": ip, "private": private, "profile": data.profile,
        "total": len(ports), "done": 0, "open": [], "ports": [], "status": "running",
        "phase": "sweep", "cancel": False, "_ports": ports,
        "note": "Private/LAN IP — unreachable from the cloud engine." if private else None,
    }
    _PORTSCAN_JOBS[jid] = job
    job["_task"] = asyncio.create_task(_run_portscan(job))
    return {"id": jid, "total": len(ports), "ip": ip, "host": host, "private": private, "note": job["note"]}


@router.get("/portscan/status/{jid}")
async def portscan_status(jid: str):
    job = _PORTSCAN_JOBS.get(jid)
    if not job:
        raise HTTPException(status_code=404, detail="scan not found")
    return {k: v for k, v in job.items() if not k.startswith("_")}


@router.post("/portscan/cancel/{jid}")
async def portscan_cancel(jid: str):
    job = _PORTSCAN_JOBS.get(jid)
    if not job:
        raise HTTPException(status_code=404, detail="scan not found")
    job["cancel"] = True
    return {"ok": True}



# ===========================================================================
# DNS-over-HTTPS helper (shared by DNS / email / takeover tools)
# ===========================================================================
def _doh(name, rtype):
    try:
        r = requests.get("https://dns.google/resolve", params={"name": name, "type": rtype}, timeout=8)
        return r.json()
    except Exception:
        return {}


def _doh_data(name, rtype, want_type=None):
    ans = _doh(name, rtype).get("Answer", []) or []
    out = []
    for a in ans:
        if want_type is None or a.get("type") == want_type:
            out.append(a.get("data", "").strip().strip('"'))
    return out


# ===========================================================================
# a) DIRECTORY / FILE BRUTEFORCER (mini gobuster) — background job
# ===========================================================================
DIR_WORDLIST = [
    "admin", "administrator", "login", "wp-admin", "wp-login.php", "dashboard",
    "portal", "cpanel", "phpmyadmin", "adminer", "manager", "console", "panel",
    "api", "api/v1", "api/v2", "graphql", "graphiql", "swagger", "swagger-ui",
    "openapi.json", "swagger.json", "docs", "redoc", "rest", "soap",
    ".git", ".git/config", ".git/HEAD", ".svn", ".hg", ".env", ".env.local",
    ".env.production", "config", "config.php", "configuration.php", "settings.py",
    "web.config", "app.config", "database.yml", "wp-config.php", "wp-config.php.bak",
    "backup", "backups", "backup.zip", "backup.sql", "backup.tar.gz", "db.sql",
    "dump.sql", "database.sql", "old", "old.zip", "site.zip", "www.zip", "test.php",
    "info.php", "phpinfo.php", "debug", "test", "tests", "tmp", "temp", "uploads",
    "upload", "files", "file", "download", "downloads", "images", "img", "assets",
    "static", "media", "js", "css", "includes", "inc", "lib", "vendor", "node_modules",
    "server-status", "server-info", "status", "health", "healthz", "metrics",
    "actuator", "actuator/health", "actuator/env", "jenkins", "jira", "gitlab",
    "user", "users", "account", "accounts", "profile", "register", "signup",
    "signin", "logout", "password", "reset", "forgot", "auth", "oauth", "sso",
    "robots.txt", "sitemap.xml", ".htaccess", ".htpasswd", "crossdomain.xml",
    "security.txt", ".well-known/security.txt", "readme.md", "README.md", "CHANGELOG.md",
    "LICENSE", "composer.json", "package.json", "yarn.lock", "Gemfile", "Dockerfile",
    "docker-compose.yml", ".dockerignore", ".gitignore", ".gitlab-ci.yml", ".travis.yml",
    "cgi-bin", "shell", "cmd", "c99.php", "webshell.php", "adminer.php",
    "private", "secret", "secrets", "internal", "staging", "dev", "beta",
    "billing", "invoice", "invoices", "reports", "report", "export", "import",
    "settings", "setup", "install", "installer", "update", "upgrade", "migrate",
    "log", "logs", "error.log", "access.log", "debug.log", "app.log",
]


def _dir_status_class(code):
    if code in (200, 204): return ("HIGH", "accessible")
    if code in (301, 302, 307, 308): return ("LOW", "redirect")
    if code in (401, 403): return ("MEDIUM", "protected (exists)")
    if code == 500: return ("MEDIUM", "server error")
    return (None, str(code))


_DIRSCAN_JOBS = {}


def _probe_path(base, path, baseline):
    url = base + "/" + path
    try:
        r = requests.get(url, timeout=8, verify=False, allow_redirects=False, headers=UA)
    except Exception:
        return None
    code = r.status_code
    if code == 404:
        return None
    size = len(r.content)
    # soft-404 filter: if 200 and matches baseline size closely, skip
    if code == 200 and baseline and abs(size - baseline) < 32:
        return None
    sev, note = _dir_status_class(code)
    return {"path": "/" + path, "status": code, "size": size,
            "location": r.headers.get("Location", "")[:200], "severity": sev, "note": note}


async def _run_dirscan(job):
    base = job["base"]
    job["_t0"] = _time.time()
    loop = asyncio.get_event_loop()
    # baseline (random path) to fingerprint soft-404
    baseline = None
    try:
        rnd = await loop.run_in_executor(None, lambda: requests.get(base + "/insafe_" + _uuid.uuid4().hex[:10], timeout=8, verify=False, allow_redirects=False, headers=UA))
        if rnd.status_code == 200:
            baseline = len(rnd.content)
    except Exception:
        pass
    words = DIR_WORDLIST
    found = []
    done = 0
    sem = asyncio.Semaphore(30)

    async def one(p):
        nonlocal done
        async with sem:
            r = await loop.run_in_executor(None, _probe_path, base, p, baseline)
        done += 1
        job["done"] = done
        if r:
            found.append(r)
            job["found"] = sorted(found, key=lambda x: x["path"])
        return r

    for i in range(0, len(words), 60):
        if job.get("cancel"):
            break
        await asyncio.gather(*[one(p) for p in words[i:i + 60]])
    job["found_count"] = len(found)
    job["elapsed_ms"] = int((_time.time() - job["_t0"]) * 1000)
    job["status"] = "cancelled" if job.get("cancel") else "done"


class DirScanInput(BaseModel):
    url: str = Field(min_length=3, max_length=2048)


@router.post("/dirscan/start")
async def dirscan_start(data: DirScanInput):
    base = data.url.strip().rstrip("/")
    if not re.match(r"^https?://", base):
        base = "https://" + base
    guard_url(base)
    if len(_DIRSCAN_JOBS) > 20:
        for k in list(_DIRSCAN_JOBS.keys())[:-15]:
            old = _DIRSCAN_JOBS.pop(k, None)
            if old and old.get("_task"):
                old["_task"].cancel()
    jid = _uuid.uuid4().hex[:12]
    job = {"id": jid, "base": base, "total": len(DIR_WORDLIST), "done": 0,
           "found": [], "found_count": 0, "status": "running", "cancel": False}
    _DIRSCAN_JOBS[jid] = job
    job["_task"] = asyncio.create_task(_run_dirscan(job))
    return {"id": jid, "total": len(DIR_WORDLIST), "base": base}


@router.get("/dirscan/status/{jid}")
async def dirscan_status(jid: str):
    job = _DIRSCAN_JOBS.get(jid)
    if not job:
        raise HTTPException(status_code=404, detail="scan not found")
    return {k: v for k, v in job.items() if not k.startswith("_")}


@router.post("/dirscan/cancel/{jid}")
async def dirscan_cancel(jid: str):
    job = _DIRSCAN_JOBS.get(jid)
    if not job:
        raise HTTPException(status_code=404, detail="scan not found")
    job["cancel"] = True
    return {"ok": True}


# ===========================================================================
# b) WEB TECH & WAF FINGERPRINT
# ===========================================================================
WAF_SIGS = [
    ("Cloudflare", ["cf-ray", "cf-cache-status", "__cfduid", "cf-request-id"], ["cloudflare"]),
    ("Akamai", ["akamai", "x-akamai", "akamaighost"], ["akamai"]),
    ("Sucuri", ["x-sucuri-id", "x-sucuri-cache"], ["sucuri"]),
    ("Imperva/Incapsula", ["x-iinfo", "incap_ses", "visid_incap"], ["incapsula"]),
    ("AWS CloudFront/WAF", ["x-amz-cf-id", "x-amzn-requestid", "x-amz-cf-pop"], ["cloudfront", "awselb"]),
    ("Fastly", ["x-served-by", "x-fastly"], ["fastly"]),
    ("F5 BIG-IP", ["bigipserver", "x-waf-event"], ["big-ip"]),
    ("Barracuda", ["barra_counter_session"], ["barracuda"]),
    ("Wordfence", [], ["wordfence"]),
]
TECH_SIGS = [
    ("WordPress", "cms", ["/wp-content/", "/wp-includes/", "wp-json", "wp-embed"]),
    ("Drupal", "cms", ["drupal.settings", "/sites/default/files", "x-drupal", "x-generator: drupal"]),
    ("Joomla", "cms", ["/media/jui/", "com_content", "/media/system/js/", "joomla!"]),
    ("Magento", "cms", ["/skin/frontend/", "/mage/cookies.js", "var blank_url", "/static/frontend/"]),
    ("Shopify", "cms", ["cdn.shopify.com", "shopify.theme"]),
    ("Ghost", "cms", ["ghost-sdk", "content=\"ghost"]),
    ("Django", "framework", ["csrfmiddlewaretoken", "__admin_media_prefix__", "csrftoken"]),
    ("Laravel", "framework", ["laravel_session", "xsrf-token"]),
    ("Ruby on Rails", "framework", ["x-runtime", "csrf-param", "authenticity_token"]),
    ("Express", "framework", ["x-powered-by: express"]),
    ("ASP.NET", "framework", ["x-aspnet-version", "__viewstate", "x-aspnetmvc-version"]),
    ("Next.js", "framework", ["__next_data__", "/_next/static", "x-nextjs"]),
    ("Nuxt.js", "framework", ["__nuxt__", "/_nuxt/"]),
    ("React", "js", ["_reactroot", "react-dom", "/react@", "react.production.min"]),
    ("Vue.js", "js", ["data-v-", "__vue__", "vue.runtime"]),
    ("Angular", "js", ["ng-version", "ng-app=", "angular.min.js"]),
    ("jQuery", "js", ["jquery.min.js", "/jquery-", "jquery.js"]),
    ("Bootstrap", "js", ["bootstrap.min.css", "bootstrap.css"]),
    ("PHP", "language", ["x-powered-by: php", "phpsessid"]),
    ("Nginx", "server", ["server: nginx"]),
    ("Apache", "server", ["server: apache"]),
    ("IIS", "server", ["server: microsoft-iis"]),
    ("LiteSpeed", "server", ["server: litespeed"]),
    ("OpenResty", "server", ["server: openresty"]),
    ("Varnish", "server", ["via: varnish", "x-varnish"]),
    ("Google Analytics", "analytics", ["google-analytics.com", "gtag(", "googletagmanager"]),
]


def _web_fingerprint(url):
    url = url.strip()
    if not re.match(r"^https?://", url):
        url = "https://" + url
    guard_url(url)
    try:
        r = requests.get(url, timeout=15, verify=False, allow_redirects=True, headers=UA)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Request failed: {str(e)[:140]}")
    hdr_str = "\n".join(f"{k}: {v}" for k, v in r.headers.items()).lower()
    cookies = "; ".join(r.cookies.keys()).lower()
    body = (r.text or "")[:60000].lower()
    hay = hdr_str + "\n" + cookies + "\n" + body

    waf = []
    for name, hs, bs in WAF_SIGS:
        if any(s in hdr_str or s in cookies for s in hs) or any(s in hay for s in bs):
            waf.append(name)
    tech = []
    seen = set()
    for name, cat, sigs in TECH_SIGS:
        if name in seen:
            continue
        for s in sigs:
            if s in hay:
                tech.append({"name": name, "category": cat, "evidence": s[:40]})
                seen.add(name)
                break
    gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', r.text or "", re.I)
    return {
        "url": url, "final_url": r.url, "status": r.status_code,
        "server": r.headers.get("Server"), "powered_by": r.headers.get("X-Powered-By"),
        "generator": gen.group(1)[:80] if gen else None,
        "waf": sorted(set(waf)), "tech": tech,
    }


class UrlInput(BaseModel):
    url: str = Field(min_length=3, max_length=2048)


@router.post("/fingerprint")
async def fingerprint(data: UrlInput):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _web_fingerprint, data.url)


# ===========================================================================
# c) EMAIL / DNS SECURITY RECON (SPF, DKIM, DMARC, MX, CAA, DNSSEC)
# ===========================================================================
DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "k2", "mail", "dkim", "s1", "s2", "smtp", "mandrill", "mxvault"]


def _email_dns(domain):
    domain = domain.strip().lower().replace("http://", "").replace("https://", "").split("/")[0]
    txt = _doh_data(domain, "TXT", 16)
    spf = [t for t in txt if t.lower().startswith("v=spf1")]
    dmarc_txt = [t for t in _doh_data("_dmarc." + domain, "TXT", 16) if "v=dmarc1" in t.lower()]
    dmarc_policy = None
    if dmarc_txt:
        m = re.search(r"p=(\w+)", dmarc_txt[0])
        dmarc_policy = m.group(1) if m else None
    dkim = {}
    for sel in DKIM_SELECTORS:
        recs = _doh_data(f"{sel}._domainkey.{domain}", "TXT", 16)
        for rec in recs:
            if "v=dkim1" in rec.lower() or "p=" in rec:
                dkim[sel] = rec[:100]
                break
    mx = _doh_data(domain, "MX", 15)
    caa = _doh_data(domain, "CAA", 257)
    dnssec = bool(_doh(domain, "DS").get("Answer"))

    issues = []
    if not spf:
        issues.append({"check": "SPF", "severity": "HIGH", "detail": "No SPF record — anyone can spoof mail from this domain"})
    elif any("+all" in s.lower() or " ?all" in s.lower() for s in spf):
        issues.append({"check": "SPF", "severity": "MEDIUM", "detail": "Weak SPF (+all/?all) allows spoofing"})
    if not dmarc_txt:
        issues.append({"check": "DMARC", "severity": "HIGH", "detail": "No DMARC policy — no protection against spoofing"})
    elif dmarc_policy in ("none", None):
        issues.append({"check": "DMARC", "severity": "MEDIUM", "detail": "DMARC p=none — monitoring only, not enforced"})
    if not dkim:
        issues.append({"check": "DKIM", "severity": "MEDIUM", "detail": "No DKIM found on common selectors"})
    if not dnssec:
        issues.append({"check": "DNSSEC", "severity": "LOW", "detail": "DNSSEC not enabled"})
    if not caa:
        issues.append({"check": "CAA", "severity": "LOW", "detail": "No CAA record — any CA can issue certs"})
    spoofable = not spf or not dmarc_txt or dmarc_policy in ("none", None)
    return {
        "domain": domain, "spf": spf, "dmarc": dmarc_txt, "dmarc_policy": dmarc_policy,
        "dkim": dkim, "mx": mx, "caa": caa, "dnssec": dnssec,
        "spoofable": spoofable, "issues": issues,
    }


class DomainInput(BaseModel):
    domain: str = Field(min_length=3, max_length=253)


@router.post("/email-dns")
async def email_dns(data: DomainInput):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _email_dns, data.domain)


# ===========================================================================
# d) CORS MISCONFIGURATION TESTER
# ===========================================================================
def _cors_test(url):
    url = url.strip()
    if not re.match(r"^https?://", url):
        url = "https://" + url
    guard_url(url)
    host = re.sub(r"^https?://", "", url).split("/")[0]
    tests = [
        ("arbitrary origin", "https://evil-insafelabs.com"),
        ("null origin", "null"),
        ("subdomain trick", f"https://{host}.evil-insafelabs.com"),
        ("prefix trick", f"https://evil{host}"),
    ]
    results = []
    findings = []
    for label, origin in tests:
        try:
            r = requests.get(url, timeout=12, verify=False, headers={**UA, "Origin": origin}, allow_redirects=True)
        except Exception:
            results.append({"test": label, "origin": origin, "error": True})
            continue
        acao = r.headers.get("Access-Control-Allow-Origin")
        acac = r.headers.get("Access-Control-Allow-Credentials")
        row = {"test": label, "origin": origin, "acao": acao, "acac": acac}
        results.append(row)
        if acao == origin and origin != "https://" + host:
            sev = "CRITICAL" if (acac or "").lower() == "true" else "HIGH"
            findings.append({"severity": sev, "detail": f"Reflects arbitrary Origin '{origin}'" + (" WITH credentials" if (acac or '').lower() == 'true' else "")})
        elif acao == "null" and origin == "null":
            findings.append({"severity": "HIGH", "detail": "Trusts 'null' origin (sandboxed iframe / data URI bypass)"})
    if not findings:
        # informational: wildcard
        try:
            r = requests.get(url, timeout=10, verify=False, headers=UA)
            if r.headers.get("Access-Control-Allow-Origin") == "*":
                findings.append({"severity": "LOW", "detail": "ACAO: * (wildcard) — fine unless it serves sensitive data"})
        except Exception:
            pass
    return {"url": url, "vulnerable": any(f["severity"] in ("CRITICAL", "HIGH") for f in findings), "findings": findings, "tests": results}


@router.post("/cors-test")
async def cors_test(data: UrlInput):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _cors_test, data.url)


# ===========================================================================
# e) JWT SECRET BRUTE-FORCE (HS256/384/512) + alg=none detection
# ===========================================================================
def _b64url_json(seg):
    seg += "=" * (-len(seg) % 4)
    return json.loads(base64.urlsafe_b64decode(seg.encode()))


def _jwt_crack(token, extra):
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise HTTPException(status_code=400, detail="Not a JWT (expected 3 dot-separated parts)")
    try:
        header = _b64url_json(parts[0])
        payload = _b64url_json(parts[1])
    except Exception:
        raise HTTPException(status_code=400, detail="Could not decode JWT header/payload")
    alg = str(header.get("alg", ""))
    result = {"header": header, "payload": payload, "alg": alg, "cracked": None}
    if alg.lower() == "none":
        result["alg_none_vuln"] = True
        result["crackable"] = False
        return result
    algmap = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
    h = algmap.get(alg.upper())
    if not h:
        result["crackable"] = False
        result["note"] = f"{alg} is not HMAC — secret brute-force only applies to HS256/384/512"
        return result
    signing_input = (parts[0] + "." + parts[1]).encode()
    sig = parts[2]
    words = []
    seen = set()
    for w in (extra or "").replace(",", "\n").split("\n"):
        w = w.strip()
        if w and w not in seen:
            seen.add(w)
            words.append(w)
    words.extend(BIG_WORDLIST)
    cracked = None
    tried = 0
    for w in words:
        tried += 1
        calc = base64.urlsafe_b64encode(hmac.new(w.encode(), signing_input, h).digest()).rstrip(b"=").decode()
        if calc == sig:
            cracked = w
            break
    result.update({"crackable": True, "cracked": cracked, "tried": tried, "wordlist_size": len(words)})
    return result


class JwtCrackInput(BaseModel):
    token: str = Field(min_length=10, max_length=8192)
    wordlist: str = Field(default="", max_length=100_000)


@router.post("/jwt-crack")
async def jwt_crack(data: JwtCrackInput):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _jwt_crack, data.token, data.wordlist)


# ===========================================================================
# f) GRAPHQL INTROSPECTION DUMPER
# ===========================================================================
_INTROSPECT_Q = "query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind } } }"


def _graphql(url):
    url = url.strip()
    if not re.match(r"^https?://", url):
        url = "https://" + url
    guard_url(url)
    schema = None
    status = None
    try:
        r = requests.post(url, json={"query": _INTROSPECT_Q}, timeout=15, verify=False, headers={**UA, "Content-Type": "application/json"})
        status = r.status_code
        schema = (r.json().get("data") or {}).get("__schema")
    except Exception:
        pass
    if not schema:
        try:
            r = requests.get(url, params={"query": _INTROSPECT_Q}, timeout=15, verify=False, headers=UA)
            status = status or r.status_code
            schema = (r.json().get("data") or {}).get("__schema")
        except Exception:
            pass
    if not schema:
        return {"url": url, "status": status, "introspection_enabled": False,
                "note": "Introspection disabled or not a GraphQL endpoint"}
    types = [t["name"] for t in schema.get("types", []) if not str(t.get("name", "")).startswith("__")]
    return {
        "url": url, "status": status, "introspection_enabled": True,
        "query_type": (schema.get("queryType") or {}).get("name"),
        "mutation_type": (schema.get("mutationType") or {}).get("name"),
        "subscription_type": (schema.get("subscriptionType") or {}).get("name"),
        "type_count": len(types), "types": sorted(types)[:120],
    }


@router.post("/graphql")
async def graphql_introspect(data: UrlInput):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _graphql, data.url)


# ===========================================================================
# g) SUBDOMAIN TAKEOVER CHECK
# ===========================================================================
TAKEOVER_FINGERPRINTS = [
    ("GitHub Pages", "github.io", "there isn't a github pages site here"),
    ("Heroku", "herokuapp.com", "no such app"),
    ("AWS S3", "amazonaws.com", "nosuchbucket"),
    ("AWS S3", "amazonaws.com", "the specified bucket does not exist"),
    ("Shopify", "myshopify.com", "sorry, this shop is currently unavailable"),
    ("Fastly", "fastly.net", "fastly error: unknown domain"),
    ("Ghost", "ghost.io", "the thing you were looking for is no longer here"),
    ("Surge.sh", "surge.sh", "project not found"),
    ("Bitbucket", "bitbucket.io", "repository not found"),
    ("Pantheon", "pantheonsite.io", "the gods are wise"),
    ("Tumblr", "domains.tumblr.com", "there's nothing here"),
    ("WordPress", "wordpress.com", "do you want to register"),
    ("Zendesk", "zendesk.com", "help center closed"),
    ("Readthedocs", "readthedocs.io", "unknown to readthedocs"),
    ("Netlify", "netlify.app", "not found - request id"),
    ("Cargo", "cargocollective.com", "404 not found"),
    ("Unbounce", "unbounce.com", "the requested url was not found on this server"),
]


def _takeover(host):
    host = host.strip().lower().replace("http://", "").replace("https://", "").split("/")[0]
    guard_url(f"https://{host}/")
    cnames = _doh_data(host, "CNAME", 5)
    body = ""
    fetched = None
    for scheme in ("https", "http"):
        try:
            r = requests.get(f"{scheme}://{host}/", timeout=10, verify=False, headers=UA, allow_redirects=True)
            body = (r.text or "")[:8000].lower()
            fetched = r.status_code
            break
        except Exception:
            continue
    matches = []
    for service, cn, fp in TAKEOVER_FINGERPRINTS:
        cname_hit = any(cn in c.lower() for c in cnames)
        body_hit = fp in body
        if body_hit or (cname_hit and body_hit):
            matches.append({"service": service, "cname_match": cname_hit, "fingerprint": fp})
        elif cname_hit:
            matches.append({"service": service, "cname_match": True, "fingerprint": None, "note": "CNAME points to this service — verify the resource is claimed"})
    vulnerable = any(m.get("fingerprint") for m in matches)
    return {
        "host": host, "cnames": cnames, "http_status": fetched,
        "vulnerable": vulnerable, "matches": matches,
        "note": None if cnames else "No CNAME — direct takeover unlikely (checks target dangling CNAMEs)",
    }


class HostInput(BaseModel):
    host: str = Field(min_length=3, max_length=253)


@router.post("/takeover")
async def takeover(data: HostInput):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _takeover, data.host)

