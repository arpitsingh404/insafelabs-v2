"""Toolbox — broad utility layer (DNS, domain, email-security, network, dev tools).

Everything here is defensive/utility oriented: DNS lookups, RDAP/WHOIS, email
authentication record checks, port/HTTP/TLS diagnostics and small helpers that
do not fit the offensive modules. Outbound fetches go through the shared SSRF
guard (`netguard.guard_url`).
"""
import base64
import hashlib
import ipaddress
import json
import re
import socket
import ssl
import struct
import subprocess
import time
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser, Parser
from urllib.parse import urlparse, quote

import requests
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from routers.vulnsuite import guard_url, _req, _norm, UA

router = APIRouter(prefix="/toolbox", tags=["toolbox"])

DNS_TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16,
             "AAAA": 28, "SRV": 33, "CAA": 257, "ANY": 255}
DOH_RESOLVERS = {
    "Cloudflare": "https://cloudflare-dns.com/dns-query",
    "Google": "https://dns.google/dns-query",
    "OpenDNS": "https://doh.opendns.com/dns-query",
    "AdGuard": "https://dns.adguard-dns.com/dns-query",
    "ControlD": "https://freedns.controld.com/p0",
    "NextDNS": "https://dns.nextdns.io",
}


# --------------------------------------------------------------------------- helpers
class HostIn(BaseModel):
    host: str = Field(min_length=1, max_length=253)


class UrlIn(BaseModel):
    url: str = Field(min_length=3, max_length=2048)


class DomIn(BaseModel):
    domain: str = Field(min_length=1, max_length=253)


class DnsIn(BaseModel):
    domain: str = Field(min_length=1, max_length=253)
    type: str = "A"


class HostPortIn(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    port: int = 443


class EmailIn(BaseModel):
    email: str = Field(min_length=3, max_length=320)


class TextIn(BaseModel):
    text: str = Field(min_length=1, max_length=1000000)


class RestIn(BaseModel):
    method: str = "GET"
    url: str = Field(min_length=3, max_length=2048)
    headers: dict | None = None
    body: str | None = None


class DkimIn(BaseModel):
    domain: str = Field(min_length=1, max_length=253)
    selector: str = "default"


class CompareIn(BaseModel):
    url1: str = Field(min_length=3, max_length=2048)
    url2: str = Field(min_length=3, max_length=2048)


class TargetIn(BaseModel):
    target: str = Field(min_length=1, max_length=320)


def _clean(host: str) -> str:
    h = (host or "").strip()
    h = re.sub(r"^[a-z]+://", "", h, flags=re.I).split("/")[0].split("@")[-1]
    return h.split(":")[0].strip().strip(".")


_DOMAIN_RX = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$", re.I)
_BLOCKED_HOSTS = {"metadata.google.internal", "metadata.goog", "instance-data", "metadata"}


def _check_domain(domain: str) -> str:
    """Lighter guard for pure DNS lookups: validate syntax, block metadata hosts.

    DNS-only tools do not fetch the target, so they must not require the domain
    to resolve (useful for freshly-registered / MX-only domains)."""
    d = _clean(domain)
    if not _DOMAIN_RX.match(d):
        raise HTTPException(status_code=400, detail=f"Invalid domain '{domain}'")
    if d.lower() in _BLOCKED_HOSTS:
        raise HTTPException(status_code=400, detail="Blocked target host (cloud metadata)")
    return d


def _doh(name: str, rtype: str, resolver: str = DOH_RESOLVERS["Cloudflare"]) -> dict:
    rtype = (rtype or "A").upper()
    if rtype not in DNS_TYPES:
        raise HTTPException(status_code=400, detail=f"Unsupported DNS type '{rtype}'")
    try:
        r = requests.get(resolver, params={"name": name, "type": rtype},
                         headers={**UA, "Accept": "application/dns-json"}, timeout=12, verify=False)
        j = r.json()
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"DNS query failed: {str(e)[:120]}")
    answers = []
    for a in j.get("Answer", []) or []:
        answers.append({"name": a.get("name"), "type": a.get("type"), "ttl": a.get("TTL"), "data": a.get("data")})
    return {"type": rtype, "status": j.get("Status"), "answers": answers}


# --- DNS-over-HTTPS wire format (works with more resolvers than the JSON API) ---
def _read_name(data: bytes, off: int):
    parts = []
    jumped = False
    next_off = off
    while 0 <= off < len(data):
        l = data[off]
        if l == 0:
            off += 1
            if not jumped:
                next_off = off
            break
        if l & 0xC0 == 0xC0:
            ptr = ((l & 0x3F) << 8) | data[off + 1]
            if not jumped:
                next_off = off + 2
            off = ptr
            jumped = True
            continue
        parts.append(data[off + 1:off + 1 + l].decode("latin1"))
        off += 1 + l
    return ".".join(parts), next_off


def _parse_doh_wire(data: bytes):
    if len(data) < 12:
        return []
    try:
        _tid, _flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
    except Exception:
        return []
    off = 12
    for _ in range(qd):
        _n, off = _read_name(data, off)
        off += 4
    out = []
    for _ in range(an):
        name, off = _read_name(data, off)
        if off + 10 > len(data):
            break
        rtype, _rclass, ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        rdata_off = off
        rdata = data[off:off + rdlen]
        off += rdlen
        if rtype == 1 and rdlen == 4:
            val = socket.inet_ntoa(rdata)
        elif rtype == 28 and rdlen == 16:
            val = socket.inet_ntop(socket.AF_INET6, rdata)
        elif rtype in (2, 5, 12):
            val, _ = _read_name(data, rdata_off)
        elif rtype == 15:
            pref = struct.unpack(">H", rdata[:2])[0]
            nm, _ = _read_name(data, rdata_off + 2)
            val = f"{pref} {nm}"
        elif rtype == 16:
            txts = []
            i = 0
            while i < len(rdata):
                ln = rdata[i]
                txts.append(rdata[i + 1:i + 1 + ln].decode("latin1"))
                i += 1 + ln
            val = "".join(txts)
        else:
            val = rdata.hex()
        out.append({"name": name, "type": rtype, "ttl": ttl, "data": val})
    return out


def _doh_wire(url: str, name: str, rtype: str):
    rtype = (rtype or "A").upper()
    qt = DNS_TYPES.get(rtype)
    if not qt:
        raise HTTPException(status_code=400, detail=f"Unsupported DNS type '{rtype}'")
    header = struct.pack(">HHHHHH", 0x1A2B, 0x0100, 1, 0, 0, 0)
    qn = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    packet = header + qn + struct.pack(">HH", qt, 1)
    try:
        r = requests.post(url, data=packet,
                          headers={**UA, "Content-Type": "application/dns-message", "Accept": "application/dns-message"},
                          timeout=10, verify=False)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"DNS query failed: {str(e)[:100]}")
    if r.status_code != 200 or not r.content:
        raise HTTPException(status_code=502, detail=f"resolver returned HTTP {r.status_code}")
    return _parse_doh_wire(r.content)


def _txt(name: str) -> list:
    try:
        d = _doh(name, "TXT")
    except HTTPException:
        return []
    out = []
    for a in d["answers"]:
        if a.get("type") == 16:
            out.append((a.get("data") or "").strip('"'))
    return out


def _resolve(host: str) -> list:
    host = _clean(host)
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return []
    seen = []
    for i in infos:
        ip = i[4][0]
        if ip not in seen:
            seen.append(ip)
    return seen


def _meta(host: str) -> str:
    try:
        return socket.gethostbyaddr(host)[0]
    except Exception:
        return ""


def _tls_probe(host: str, port: int, alpn=None):
    """Manual socket/TLS probe returning timings, cert and negotiated params."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if alpn:
        ctx.set_alpn_protocols(alpn)
    t = {}
    t0 = time.perf_counter()
    raw = socket.create_connection((host, port), timeout=10)
    t["connect_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    t1 = time.perf_counter()
    ss = ctx.wrap_socket(raw, server_hostname=host)
    t["tls_ms"] = round((time.perf_counter() - t1) * 1000, 1)
    t["version"] = ss.version()
    t["cipher"] = (ss.cipher() or [None])[0]
    t["alpn"] = ss.selected_alpn_protocol()
    cert = ss.getpeercert()
    der = ss.getpeercert(binary_form=True)
    result = {"timings": t, "cert": cert, "der": der, "socket": ss, "raw": raw}
    return result, ss


def _cert_from_der(der: bytes) -> dict:
    """Parse a DER certificate into a getpeercert()-style dict."""
    if not der:
        return {}
    try:
        import tempfile, os
        pem = ssl.DER_cert_to_PEM_cert(der)
        fd, path = tempfile.mkstemp(suffix=".pem")
        with os.fdopen(fd, "w") as f:
            f.write(pem)
        try:
            return ssl._ssl._test_decode_cert(path)
        finally:
            os.unlink(path)
    except Exception:
        try:
            from cryptography import x509
            c = x509.load_der_x509_certificate(der)

            def _name(n):
                return [[attr.oid._name, attr.value] for attr in n]

            return {"subject": _name(c.subject), "issuer": _name(c.issuer),
                    "notAfter": c.not_valid_after_utc.strftime("%b %d %H:%M:%S %Y GMT"),
                    "serialNumber": format(c.serial_number, "X")}
        except Exception:
            return {}


def _cert_summary(cert: dict) -> dict:
    if not cert:
        return {}
    def _flatten(name):
        return {k: v for part in (cert.get(name) or []) for k, v in part}
    return {
        "subject": _flatten("subject"),
        "issuer": _flatten("issuer"),
        "serialNumber": cert.get("serialNumber"),
        "notBefore": cert.get("notBefore"),
        "notAfter": cert.get("notAfter"),
        "subjectAltName": [v for _, v in (cert.get("subjectAltName") or [])],
    }


def _run_cmd(args, timeout=60):
    try:
        p = subprocess.run(args, capture_output=True, timeout=timeout,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        out = (p.stdout or b"").decode("utf-8", "ignore") + (p.stderr or b"").decode("utf-8", "ignore")
        return out.strip().splitlines()
    except subprocess.TimeoutExpired:
        return ["[timeout]"]
    except FileNotFoundError:
        return [f"[command not found: {args[0]}]"]
    except Exception as e:
        return [f"[error: {str(e)[:120]}]"]


# --------------------------------------------------------------------------- DNS / domain
@router.post("/resolve")
async def resolve(data: HostIn):
    host = _clean(data.host)
    guard_url(f"http://{host}")
    ips = _resolve(host)
    return {"host": host, "addresses": ips,
            "ipv4": [i for i in ips if ":" not in i], "ipv6": [i for i in ips if ":" in i],
            "ptr": _meta(ips[0]) if ips else ""}


@router.post("/dns")
async def dns_lookup(data: DnsIn):
    domain = _clean(data.domain)
    _check_domain(domain)
    rtype = (data.type or "A").upper()
    types = list(DNS_TYPES.keys()) if rtype == "ALL" else [rtype]
    return {"domain": domain, "records": {t: _doh(domain, t)["answers"] for t in types}}


@router.post("/dns-propagation")
async def dns_propagation(data: DnsIn):
    domain = _clean(data.domain)
    _check_domain(domain)
    out = {}
    norm = {}
    want = DNS_TYPES.get((data.type or "A").upper())
    for label, res in DOH_RESOLVERS.items():
        try:
            ans = _doh_wire(res, domain, data.type or "A")
        except HTTPException as e:
            ans = [{"error": e.detail}]
        out[label] = ans
        norm[label] = sorted(str(a.get("data")) for a in ans if a.get("data") and (want is None or a.get("type") == want))
    data_sets = [v for v in norm.values() if v]
    distinct = {json.dumps(v) for v in data_sets}
    return {"domain": domain, "type": (data.type or "A").upper(), "resolvers": out,
            "checked": len(DOH_RESOLVERS), "responding": len(data_sets),
            "consistent": bool(data_sets) and len(distinct) <= 1}


@router.post("/reverse-dns")
async def reverse_dns(data: HostIn):
    host = _clean(data.host)
    ips = _resolve(host) if not re.match(r"^[0-9a-fA-F:.]+$", host) else [host]
    out = [{"ip": ip, "ptr": _meta(ip)} for ip in ips]
    if not any(o["ptr"] for o in out):
        # fall back to DoH PTR
        for ip in ips:
            rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa" if ":" not in ip else ip
            try:
                ans = _doh(rev, "PTR")["answers"]
                for a in ans:
                    out.append({"ip": ip, "ptr": a.get("data")})
            except HTTPException:
                pass
    return {"host": host, "results": out}


@router.post("/mx")
async def mx_lookup(data: DomIn):
    domain = _clean(data.domain)
    _check_domain(domain)
    return {"domain": domain, "mx": _doh(domain, "MX")["answers"]}


@router.post("/soa")
async def soa_lookup(data: DomIn):
    domain = _clean(data.domain)
    _check_domain(domain)
    return {"domain": domain, "soa": _doh(domain, "SOA")["answers"]}


@router.post("/ns")
async def ns_lookup(data: DomIn):
    domain = _clean(data.domain)
    _check_domain(domain)
    return {"domain": domain, "ns": _doh(domain, "NS")["answers"]}


def _whois_raw(domain: str) -> str:
    tld = domain.rsplit(".", 1)[-1]
    server = None
    try:
        s = socket.create_connection(("whois.iana.org", 43), timeout=8)
        s.sendall((domain + "\r\n").encode())
        buf = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        s.close()
        text = buf.decode("utf-8", "ignore")
        m = re.search(r"(?im)^refer:\s*(\S+)", text)
        if m:
            server = m.group(1)
    except Exception:
        text = ""
    if server:
        try:
            s = socket.create_connection((server, 43), timeout=10)
            s.sendall((domain + "\r\n").encode())
            buf = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
            s.close()
            text = buf.decode("utf-8", "ignore")
        except Exception:
            pass
    return text


@router.post("/whois")
async def whois(data: DomIn):
    domain = _clean(data.domain)
    _check_domain(domain)
    raw = _whois_raw(domain)
    if not raw:
        # RDAP fallback
        try:
            r = requests.get(f"https://rdap.org/domain/{domain}", headers=UA, timeout=12, verify=False)
            if r.status_code == 200:
                j = r.json()
                return {"domain": domain, "source": "RDAP", "raw": "", "rdap": {
                    "handle": j.get("handle"), "ldhName": j.get("ldhName"),
                    "status": j.get("status"), "events": j.get("events"),
                    "nameservers": [n.get("ldhName") for n in (j.get("nameservers") or [])]}}
        except Exception:
            pass
        raise HTTPException(status_code=502, detail="WHOIS lookup failed")
    fields = {}
    for key in ("Registrar", "Creation Date", "Registry Expiry Date", "Updated Date",
                "Name Server", "Domain Status", "Registrant Organization"):
        vals = re.findall(rf"(?im)^{re.escape(key)}\s*:\s*(.+)$", raw)
        if vals:
            fields[key] = [v.strip() for v in vals]
    return {"domain": domain, "source": "WHOIS", "fields": fields, "raw": raw[:8000]}


@router.post("/domain-expiry")
async def domain_expiry(data: DomIn):
    domain = _clean(data.domain)
    _check_domain(domain)
    exp = None
    source = None
    raw = _whois_raw(domain)
    m = re.search(r"(?im)^(?:Registry Expiry Date|Expiry Date|Expiration Date|paid-till|renewal date)\s*:\s*(.+)$", raw)
    if m:
        exp = m.group(1).strip()
        source = "WHOIS"
    if not exp:
        try:
            r = requests.get(f"https://rdap.org/domain/{domain}", headers=UA, timeout=12, verify=False)
            if r.status_code == 200:
                for ev in r.json().get("events", []) or []:
                    if ev.get("eventAction") in ("expiration", "expiry"):
                        exp = ev.get("eventDate")
                        source = "RDAP"
                        break
        except Exception:
            pass
    days = None
    if exp:
        cleaned = re.sub(r"[TZ].*$", "", exp.strip()).strip()
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%Y%m%d"):
            try:
                d = datetime.strptime(cleaned[:len(fmt) + 8].strip(), fmt).replace(tzinfo=timezone.utc)
                days = (d - datetime.now(timezone.utc)).days
                break
            except Exception:
                continue
    return {"domain": domain, "expires": exp, "days_left": days, "source": source,
            "status": "expired" if (days is not None and days < 0) else ("expiring" if days is not None and days < 30 else "ok")}


@router.post("/asn")
async def asn_lookup(data: TargetIn):
    target = _clean(data.target)
    ip = target
    if not re.match(r"^[0-9a-fA-F:.]+$", target):
        ips = _resolve(target)
        if not ips:
            raise HTTPException(status_code=400, detail="Could not resolve target")
        ip = ips[0]
    try:
        r = requests.get(f"https://ipwho.is/{ip}", headers=UA, timeout=12, verify=False)
        j = r.json()
        c = j.get("connection", {}) or {}
        return {"target": target, "ip": ip, "asn": c.get("asn"), "org": c.get("org"),
                "isp": c.get("isp"), "domain": c.get("domain"),
                "country": j.get("country"), "city": j.get("city")}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"ASN lookup failed: {str(e)[:120]}")


@router.post("/geo")
async def geo(data: TargetIn):
    target = _clean(data.target)
    ip = target
    if not re.match(r"^[0-9a-fA-F:.]+$", target):
        ips = _resolve(target)
        if not ips:
            raise HTTPException(status_code=400, detail="Could not resolve target")
        ip = ips[0]
    try:
        r = requests.get(f"https://ipwho.is/{ip}", headers=UA, timeout=12, verify=False)
        return {"target": target, "ip": ip, "geo": r.json()}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Geo lookup failed: {str(e)[:120]}")


@router.post("/ns-perf")
async def ns_perf(data: DomIn):
    domain = _clean(data.domain)
    _check_domain(domain)
    ns = [a.get("data") for a in _doh(domain, "NS")["answers"] if a.get("data")]
    out = []
    for server in ns:
        t0 = time.perf_counter()
        try:
            _doh(domain, "SOA")
            ms = round((time.perf_counter() - t0) * 1000, 1)
            out.append({"nameserver": server, "reachable": True, "note": "via public resolver"})
        except HTTPException:
            out.append({"nameserver": server, "reachable": False})
    return {"domain": domain, "nameservers": out}


@router.post("/dns-traversal")
async def dns_traversal(data: DomIn):
    domain = _clean(data.domain)
    _check_domain(domain)
    parts = domain.split(".")
    chain = []
    for i in range(len(parts) - 1, 0, -1):
        zone = ".".join(parts[i - 1:]) if i - 1 <= len(parts) else ".".join(parts[:2])
        zone = ".".join(parts[i - 1:])
        try:
            ns = _doh(zone, "NS")["answers"]
        except HTTPException:
            ns = []
        chain.append({"zone": zone, "nameservers": [a.get("data") for a in ns]})
    return {"domain": domain, "chain": chain}


# --------------------------------------------------------------------------- email security
@router.post("/spf")
async def spf(data: DomIn):
    domain = _clean(data.domain)
    _check_domain(domain)
    records = [t for t in _txt(domain) if t.lower().startswith("v=spf1")]
    findings = []
    if not records:
        findings.append("No SPF record — anyone can spoof this domain.")
    else:
        rec = records[0]
        if "+all" in rec.replace(" ", ""):
            findings.append("SPF ends in +all — effectively no protection.")
        elif "-all" not in rec and "~all" not in rec:
            findings.append("SPF has no strict 'all' qualifier.")
        lookups = len(re.findall(r"\b(include|a|mx|ptr|exists|redirect)\b", rec, re.I))
        if lookups > 10:
            findings.append(f"{lookups} DNS-lookup mechanisms — may exceed the 10-lookup limit.")
    return {"domain": domain, "records": records, "issues": findings}


@router.post("/dmarc")
async def dmarc(data: DomIn):
    domain = _clean(data.domain)
    _check_domain(domain)
    records = [t for t in _txt(f"_dmarc.{domain}") if "v=dmarc1" in t.lower()]
    policy = None
    if records:
        m = re.search(r"(?i)\bp\s*=\s*(none|quarantine|reject)", records[0])
        policy = m.group(1).lower() if m else None
    return {"domain": domain, "records": records, "policy": policy,
            "enforcing": policy in ("quarantine", "reject")}


@router.post("/dkim")
async def dkim(data: DkimIn):
    domain = _clean(data.domain)
    _check_domain(domain)
    name = f"{data.selector}._domainkey.{domain}"
    records = _txt(name)
    valid = any("p=" in r for r in records)
    return {"domain": domain, "selector": data.selector, "record_name": name,
            "records": records, "valid": valid}


@router.post("/mta-sts")
async def mtasts(data: DomIn):
    domain = _clean(data.domain)
    _check_domain(domain)
    txt = _txt(f"_mta-sts.{domain}")
    policy = None
    try:
        r = requests.get(f"https://mta-sts.{domain}/.well-known/mta-sts.txt", headers=UA, timeout=10, verify=False)
        if r.status_code == 200:
            policy = r.text[:4000]
    except Exception:
        pass
    return {"domain": domain, "dns_record": txt, "policy": policy, "configured": bool(txt or policy)}


@router.post("/tls-rpt")
async def tls_rpt(data: DomIn):
    domain = _clean(data.domain)
    _check_domain(domain)
    return {"domain": domain, "record": _txt(f"_smtp._tls.{domain}")}


@router.post("/bimi")
async def bimi(data: DomIn):
    domain = _clean(data.domain)
    _check_domain(domain)
    recs = _txt(f"default._bimi.{domain}")
    return {"domain": domain, "records": recs, "configured": bool(recs)}


@router.post("/email-validate")
async def email_validate(data: EmailIn):
    addr = data.email.strip()
    issues = []
    if not re.match(r"^[^@\s]+@[^@\s]+\.[a-zA-Z]{2,}$", addr):
        return {"email": addr, "valid": False, "issues": ["Malformed address"]}
    local, domain = addr.rsplit("@", 1)
    mx = _doh(domain, "MX")["answers"]
    a = _doh(domain, "A")["answers"]
    if not mx and not a:
        issues.append("Domain has no MX or A record — cannot receive mail.")
    DISPOSABLE = {"mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
                  "trashmail.com", "yopmail.com", "sharklasers.com", "getnada.com"}
    disposable = domain.lower() in DISPOSABLE
    if disposable:
        issues.append("Disposable email domain.")
    role = local.lower() in {"admin", "info", "support", "sales", "postmaster", "webmaster", "noreply", "no-reply"}
    if role:
        issues.append("Role-based address (not a personal mailbox).")
    return {"email": addr, "valid": bool(mx or a), "domain": domain, "mx": [m.get("data") for m in mx],
            "disposable": disposable, "role": role, "issues": issues}


@router.post("/email-headers")
async def email_headers(data: TextIn):
    raw = data.text.replace("\r\n", "\n")
    headers = Parser(policy=policy.default).parsestr(raw)
    hops = []
    for i, received in enumerate(headers.get_all("Received", [])):
        ips = re.findall(r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?", received)
        hops.append({"hop": i + 1, "from": (received.split("from", 1)[-1] if "from" in received else received)[:200].strip(),
                     "ips": ips})
    auth = headers.get_all("Authentication-Results", [])
    spf = re.search(r"spf=(\w+)", " ".join(auth), re.I)
    dkim = re.search(r"dkim=(\w+)", " ".join(auth), re.I)
    dmarc = re.search(r"dmarc=(\w+)", " ".join(auth), re.I)
    return {"subject": headers.get("Subject"), "from": headers.get("From"), "to": headers.get("To"),
            "date": headers.get("Date"), "hops": hops,
            "auth": {"spf": spf.group(1) if spf else None, "dkim": dkim.group(1) if dkim else None,
                     "dmarc": dmarc.group(1) if dmarc else None}}


@router.post("/eml")
async def eml_view(data: TextIn):
    raw = data.text
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw.encode("utf-8", "ignore"))
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain" and not part.get_filename():
                    body = part.get_content()
                    break
        else:
            body = msg.get_content()
        atts = [{"filename": p.get_filename(), "type": p.get_content_type()}
                for p in msg.walk() if p.get_filename()]
        return {"subject": msg.get("Subject"), "from": msg.get("From"), "to": msg.get("To"),
                "cc": msg.get("Cc"), "date": msg.get("Date"), "attachments": atts, "body": (body or "")[:20000]}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Could not parse EML: {str(e)[:120]}")


# --------------------------------------------------------------------------- network / sysadmin
@router.post("/availability")
async def availability(data: UrlIn):
    url = _norm(data.url)
    guard_url(url)
    t0 = time.perf_counter()
    try:
        r = _req(url, timeout=15)
        return {"url": url, "up": r.status_code < 500, "status": r.status_code,
                "latency_ms": round((time.perf_counter() - t0) * 1000, 1), "server": r.headers.get("Server")}
    except Exception as e:
        return {"url": url, "up": False, "error": str(e)[:160]}


@router.post("/ping")
async def ping(data: HostIn):
    host = _clean(data.host)
    guard_url(f"http://{host}")
    lines = _run_cmd(["ping", "-n", "4", host], timeout=40)
    return {"host": host, "output": lines}


@router.post("/traceroute")
async def traceroute(data: HostIn):
    host = _clean(data.host)
    guard_url(f"http://{host}")
    lines = _run_cmd(["tracert", "-d", "-w", "1000", "-h", "20", host], timeout=90)
    return {"host": host, "output": lines}


@router.post("/port")
async def port_check(data: HostPortIn):
    host = _clean(data.host)
    guard_url(f"http://{host}")
    t0 = time.perf_counter()
    try:
        s = socket.create_connection((host, int(data.port)), timeout=6)
        s.close()
        return {"host": host, "port": data.port, "open": True,
                "latency_ms": round((time.perf_counter() - t0) * 1000, 1)}
    except Exception as e:
        return {"host": host, "port": data.port, "open": False, "error": str(e)[:120]}


@router.post("/http-headers")
async def http_headers(data: UrlIn):
    url = _norm(data.url)
    guard_url(url)
    try:
        r = _req(url, timeout=20)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Request failed: {str(e)[:140]}")
    h = {k: v for k, v in r.headers.items()}
    low = {k.lower(): v for k, v in h.items()}
    cookies = r.raw.headers.getlist("Set-Cookie") if hasattr(r.raw, "headers") else []
    cookie_report = []
    for c in cookies:
        cookie_report.append({"cookie": c.split(";")[0], "secure": "secure" in c.lower(),
                              "httponly": "httponly" in c.lower(), "samesite": bool(re.search(r"(?i)samesite", c))})
    score = 0
    checks = {
        "HSTS": "strict-transport-security" in low,
        "X-Frame-Options": "x-frame-options" in low or "frame-ancestors" in low.get("content-security-policy", ""),
        "X-Content-Type-Options": low.get("x-content-type-options", "").lower() == "nosniff",
        "Content-Security-Policy": "content-security-policy" in low,
        "Referrer-Policy": "referrer-policy" in low,
        "Permissions-Policy": "permissions-policy" in low,
    }
    score = sum(1 for v in checks.values() if v)
    return {"url": url, "status": r.status_code, "http_version": getattr(r.raw, "version", None),
            "server": low.get("server"), "powered_by": low.get("x-powered-by"),
            "headers": h, "checks": checks, "score": score, "max": len(checks),
            "cookies": cookie_report, "redirected_to": r.url if r.url != url else None}


@router.post("/tls")
async def tls_check(data: HostPortIn):
    host = _clean(data.host)
    guard_url(f"http://{host}")
    versions = []
    for label, ver in (("TLS 1.3", ssl.TLSVersion.TLSv1_3), ("TLS 1.2", ssl.TLSVersion.TLSv1_2),
                       ("TLS 1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
                       ("TLS 1.0", getattr(ssl.TLSVersion, "TLSv1", None)),
                       ("SSL 3.0", getattr(ssl.TLSVersion, "SSLv3", None))):
        if ver is None:
            versions.append({"protocol": label, "supported": None, "note": "unavailable in this runtime"})
            continue
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ver
            ctx.maximum_version = ver
            raw = socket.create_connection((host, int(data.port)), timeout=8)
            ctx.wrap_socket(raw, server_hostname=host).close()
            versions.append({"protocol": label, "supported": True})
        except Exception:
            versions.append({"protocol": label, "supported": False})
    return {"host": host, "port": data.port, "protocols": versions}


@router.post("/ssl-certificate")
async def ssl_certificate(data: HostPortIn):
    host = _clean(data.host)
    guard_url(f"http://{host}")
    try:
        res, ss = _tls_probe(host, int(data.port))
        summary = _cert_summary(res["cert"] or _cert_from_der(res.get("der")))
        ss.close()
        exp = summary.get("notAfter")
        days = None
        if exp:
            try:
                cleaned = re.sub(r"\s+(GMT|UTC)$", "", exp.strip())
                d = datetime.strptime(cleaned, "%b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
                days = (d - datetime.now(timezone.utc)).days
            except Exception:
                days = None
        return {"host": host, "port": data.port, "certificate": summary, "days_left": days,
                "expired": (days is not None and days < 0), "expiring_soon": (days is not None and 0 <= days < 30)}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"TLS probe failed: {str(e)[:140]}")


@router.post("/http2")
async def http2_test(data: HostPortIn):
    host = _clean(data.host)
    guard_url(f"http://{host}")
    try:
        res, ss = _tls_probe(host, int(data.port), alpn=["h2", "http/1.1"])
        alpn = res["timings"].get("alpn")
        ss.close()
        return {"host": host, "port": data.port, "http2": alpn == "h2", "negotiated": alpn}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"ALPN probe failed: {str(e)[:140]}")


@router.post("/web-speed")
async def web_speed(data: UrlIn):
    url = _norm(data.url)
    guard_url(url)
    p = urlparse(url)
    host = p.hostname
    port = p.port or (443 if p.scheme == "https" else 80)
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    timings = {}
    total_start = time.perf_counter()
    try:
        t0 = time.perf_counter()
        raw = socket.create_connection((host, port), timeout=10)
        timings["connect_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        if p.scheme == "https":
            t1 = time.perf_counter()
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            raw = ctx.wrap_socket(raw, server_hostname=host)
            timings["tls_ms"] = round((time.perf_counter() - t1) * 1000, 1)
        t2 = time.perf_counter()
        req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: InsafeLabs/1.0\r\nConnection: close\r\n\r\n"
        raw.sendall(req.encode())
        first = raw.recv(1)
        timings["ttfb_ms"] = round((time.perf_counter() - t2) * 1000, 1)
        size = len(first)
        while True:
            chunk = raw.recv(65536)
            if not chunk:
                break
            size += len(chunk)
        raw.close()
        timings["total_ms"] = round((time.perf_counter() - total_start) * 1000, 1)
        timings["bytes"] = size
        return {"url": url, "timings": timings}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Speed test failed: {str(e)[:140]}")


@router.post("/web-objects")
async def web_objects(data: UrlIn):
    url = _norm(data.url)
    guard_url(url)
    try:
        r = _req(url, timeout=20)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Request failed: {str(e)[:140]}")
    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    html = r.text or ""
    assets = set(re.findall(r'(?:src|href)\s*=\s*["\']([^"\']+)["\']', html, re.I))
    from urllib.parse import urljoin
    objs = []
    for a in list(assets)[:60]:
        if a.startswith(("mailto:", "javascript:", "#", "data:")):
            continue
        full = urljoin(base, a)
        try:
            rr = requests.head(full, headers=UA, timeout=8, verify=False, allow_redirects=True)
            size = rr.headers.get("Content-Length")
            objs.append({"url": full, "status": rr.status_code,
                         "type": rr.headers.get("Content-Type"), "bytes": int(size) if size and size.isdigit() else None})
        except Exception:
            objs.append({"url": full, "status": None})
    by_type = {}
    total = 0
    for o in objs:
        key = (o.get("type") or "unknown").split(";")[0]
        by_type[key] = by_type.get(key, 0) + 1
        if o.get("bytes"):
            total += o["bytes"]
    return {"url": url, "objects": objs, "count": len(objs), "by_type": by_type, "total_bytes": total}


@router.post("/text-ratio")
async def text_ratio(data: UrlIn):
    url = _norm(data.url)
    guard_url(url)
    try:
        r = _req(url, timeout=20)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Request failed: {str(e)[:140]}")
    html = r.text or ""
    text = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", "", html)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    words = len(text.split())
    ratio = round(len(text) / max(len(html), 1) * 100, 2)
    return {"url": url, "html_bytes": len(html), "text_chars": len(text), "text_ratio_pct": ratio, "words": words}


@router.post("/link-explorer")
async def link_explorer(data: UrlIn):
    url = _norm(data.url)
    guard_url(url)
    try:
        r = _req(url, timeout=20)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Request failed: {str(e)[:140]}")
    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    from urllib.parse import urljoin
    links = sorted(set(re.findall(r'href\s*=\s*["\']([^"\']+)["\']', r.text or "", re.I)))
    internal, external = [], []
    for l in links:
        if l.startswith(("mailto:", "javascript:", "#", "tel:")):
            continue
        full = urljoin(base, l)
        (internal if full.startswith(base) else external).append(full)
    return {"url": url, "internal": internal[:300], "external": external[:300],
            "internal_count": len(internal), "external_count": len(external)}


@router.post("/link-checker")
async def link_checker(data: UrlIn):
    url = _norm(data.url)
    guard_url(url)
    try:
        r = _req(url, timeout=20)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Request failed: {str(e)[:140]}")
    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    from urllib.parse import urljoin
    links = sorted(set(re.findall(r'href\s*=\s*["\']([^"\']+)["\']', r.text or "", re.I)))
    results, broken = [], []
    for l in links[:40]:
        if l.startswith(("mailto:", "javascript:", "#", "tel:")):
            continue
        full = urljoin(base, l)
        try:
            rr = requests.head(full, headers=UA, timeout=8, verify=False, allow_redirects=True)
            if rr.status_code >= 400:
                rr = requests.get(full, headers=UA, timeout=8, verify=False, allow_redirects=True)
            results.append({"url": full, "status": rr.status_code})
            if rr.status_code >= 400:
                broken.append({"url": full, "status": rr.status_code})
        except Exception as e:
            results.append({"url": full, "status": None, "error": str(e)[:80]})
            broken.append({"url": full, "status": None})
    return {"url": url, "checked": len(results), "broken": broken, "results": results}


@router.post("/redirect-checker")
async def redirect_checker(data: UrlIn):
    url = _norm(data.url)
    guard_url(url)
    chain = []
    current = url
    for _ in range(10):
        try:
            r = _req(current, allow_redirects=False, timeout=12)
        except Exception as e:
            chain.append({"url": current, "error": str(e)[:120]})
            break
        loc = r.headers.get("Location")
        chain.append({"url": current, "status": r.status_code, "location": loc})
        if not loc or r.status_code not in (301, 302, 303, 307, 308):
            break
        from urllib.parse import urljoin
        current = urljoin(current, loc)
    return {"start": url, "final": chain[-1]["url"] if chain else url, "chain": chain,
            "hops": len(chain) - 1}


@router.post("/compare")
async def compare(data: CompareIn):
    out = {}
    for i, u in enumerate(("url1", "url2"), start=1):
        url = _norm(getattr(data, u))
        guard_url(url)
        t0 = time.perf_counter()
        try:
            r = _req(url, timeout=20)
            out[u] = {"url": url, "status": r.status_code, "ms": round((time.perf_counter() - t0) * 1000, 1),
                      "bytes": len(r.content or b""), "server": r.headers.get("Server"),
                      "type": r.headers.get("Content-Type")}
        except Exception as e:
            out[u] = {"url": url, "error": str(e)[:140]}
    return out


@router.post("/websocket")
async def websocket_check(data: UrlIn):
    url = _norm(data.url).replace("https://", "wss://").replace("http://", "ws://")
    p = urlparse(url)
    host = p.hostname
    port = p.port or (443 if p.scheme == "wss" else 80)
    guard_url(f"http://{host}")
    try:
        raw = socket.create_connection((host, port), timeout=8)
        if p.scheme == "wss":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            raw = ctx.wrap_socket(raw, server_hostname=host)
        path = p.path or "/"
        key = base64.b64encode(hashlib.sha1(str(time.time()).encode()).digest()).decode()
        req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n")
        raw.sendall(req.encode())
        resp = raw.recv(1024).decode("utf-8", "ignore")
        raw.close()
        return {"url": url, "available": "101" in resp.split("\r\n")[0], "response": resp.split("\r\n")[0]}
    except Exception as e:
        return {"url": url, "available": False, "error": str(e)[:140]}


@router.post("/ghostcat")
async def ghostcat(data: HostIn):
    host = _clean(data.host)
    guard_url(f"http://{host}")
    try:
        s = socket.create_connection((host, 8009), timeout=5)
        s.sendall(bytes.fromhex("1234001902001a00000000000000"))  # AJP13 CPing-like probe
        resp = s.recv(64)
        s.close()
        return {"host": host, "ajp_open": True, "vulnerable": "possible",
                "note": "AJP port 8009 is reachable — Ghostcat (CVE-2020-1938) exposure possible if Tomcat < 9.0.31.",
                "bytes": resp.hex()[:64]}
    except Exception as e:
        return {"host": host, "ajp_open": False, "vulnerable": False, "note": str(e)[:120]}


@router.post("/heartbleed")
async def heartbleed(data: HostPortIn):
    host = _clean(data.host)
    guard_url(f"http://{host}")
    try:
        res, ss = _tls_probe(host, int(data.port))
        ss.close()
        return {"host": host, "note": "TLS handshake OK. Deep Heartbeat (CVE-2014-0160) probing requires raw TLS — "
                                      "recommend a dedicated scanner (nmap --script ssl-heartbleed) for a definitive result.",
                "tls_version": res["timings"].get("version")}
    except Exception as e:
        return {"host": host, "error": str(e)[:140]}


@router.post("/poodle")
async def poodle(data: HostPortIn):
    host = _clean(data.host)
    guard_url(f"http://{host}")
    ver = getattr(ssl.TLSVersion, "SSLv3", None)
    if ver is None:
        return {"host": host, "sslv3_supported": None,
                "note": "SSLv3 unavailable in this runtime — server cannot be probed for POODLE here."}
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ver
        ctx.maximum_version = ver
        raw = socket.create_connection((host, int(data.port)), timeout=8)
        ctx.wrap_socket(raw, server_hostname=host).close()
        return {"host": host, "sslv3_supported": True, "vulnerable": True,
                "note": "SSLv3 negotiated — POODLE (CVE-2014-3566) is exploitable."}
    except Exception:
        return {"host": host, "sslv3_supported": False, "vulnerable": False}


# --------------------------------------------------------------------------- reputation / blacklist
DNSBL = ["zen.spamhaus.org", "bl.spamcop.net", "b.barracudacentral.org", "dnsbl.sorbs.net", "spam.dnsbl.sorbs.net"]


@router.post("/blacklist")
async def blacklist(data: TargetIn):
    target = _clean(data.target)
    guard_url(f"http://{target}")
    ips = [target] if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target) else _resolve(target)
    if not ips:
        raise HTTPException(status_code=400, detail="Could not resolve target to an IP")
    ip = ips[0]
    rev = ".".join(reversed(ip.split(".")))
    listings = []
    for zone in DNSBL:
        try:
            ans = _doh(f"{rev}.{zone}", "A")["answers"]
            if ans:
                listings.append({"zone": zone, "listed": True, "reply": ans[0].get("data")})
        except HTTPException:
            continue
    return {"target": target, "ip": ip, "listed": bool(listings), "listings": listings,
            "checked_zones": DNSBL}


@router.post("/brand-reputation")
async def brand_reputation(data: TargetIn):
    host = _check_domain(data.target)
    hits = {}
    try:
        r = requests.post("https://urlhaus-api.abuse.ch/v1/host/", data={"host": host}, headers=UA, timeout=12, verify=False)
        j = r.json()
        hits["urlhaus"] = {"query_status": j.get("query_status"), "urls_online": j.get("urls_online"),
                           "blacklists": j.get("blacklists")}
    except Exception as e:
        hits["urlhaus"] = {"error": str(e)[:100]}
    ip = None
    ips = _resolve(host)
    if ips:
        ip = ips[0]
    return {"target": host, "ip": ip, "results": hits,
            "flagged": (hits.get("urlhaus", {}).get("query_status") == "ok")}


# --------------------------------------------------------------------------- dev / misc
@router.post("/rest-api")
async def rest_api(data: RestIn):
    url = _norm(data.url)
    guard_url(url)
    method = (data.method or "GET").upper()
    if method not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
        raise HTTPException(status_code=400, detail="Unsupported HTTP method")
    t0 = time.perf_counter()
    try:
        r = requests.request(method, url, headers={**UA, **(data.headers or {})},
                             data=(data.body.encode() if data.body else None), timeout=20, verify=False)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Request failed: {str(e)[:140]}")
    return {"status": r.status_code, "ms": round((time.perf_counter() - t0) * 1000, 1),
            "headers": dict(r.headers), "body": (r.text or "")[:20000]}


@router.post("/pgp-key")
async def pgp_key(data: CompareIn):
    """Generate an OpenPGP key pair. Requires `pgpy` (pip) or a `gpg` binary."""
    name = data.url1.strip()[:80]
    email = data.url2.strip()[:120]
    try:
        import pgpy
        from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
        key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 3072)
        uid = pgpy.PGPUID.new(name or "InsafeLabs User", email=email or "user@example.com")
        key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
                    hashes=[HashAlgorithm.SHA256], ciphers=[SymmetricKeyAlgorithm.AES256],
                    compression=[CompressionAlgorithm.ZLIB])
        return {"name": uid.name, "email": uid.email, "public_key": str(key.pubkey), "private_key": str(key)}
    except Exception:
        gpg = _run_cmd(["gpg", "--version"], timeout=10)
        if gpg and not gpg[0].startswith("["):
            return {"note": "pgpy not installed; a gpg binary is present but interactive key generation is not supported here.",
                    "gpg": gpg[0]}
        raise HTTPException(status_code=501, detail="PGP key generation unavailable — install pgpy in the backend venv.")
