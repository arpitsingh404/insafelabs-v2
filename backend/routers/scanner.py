import asyncio
import socket
import ssl
import uuid
import json
import io
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
from fastapi import APIRouter, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, Field

from db import db
import ai
import recon_lib
import recon_advanced
import recon_templates

router = APIRouter(prefix="/scanner", tags=["scanner"])

UA = {"User-Agent": "InsafeLabs-Scanner/1.0 (authorized security assessment)"}

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-alt",
    8443: "HTTPS-alt", 27017: "MongoDB", 9200: "Elasticsearch",
    5900: "VNC", 11211: "Memcached",
}

# (cvss, message) for a port being exposed to the internet
PORT_RISK = {
    23: (9.1, "Telnet exposes credentials in cleartext"),
    6379: (8.6, "Redis is exposed (frequently unauthenticated)"),
    445: (8.1, "SMB file-sharing is exposed"),
    3306: (7.5, "MySQL database port is exposed to the internet"),
    5432: (7.5, "PostgreSQL database port is exposed"),
    27017: (7.5, "MongoDB is exposed to the internet"),
    9200: (7.5, "Elasticsearch is exposed without a proxy"),
    11211: (7.5, "Memcached is exposed to the internet"),
    5900: (7.5, "VNC remote desktop is exposed"),
    3389: (6.5, "RDP is exposed to the internet"),
    21: (5.3, "FTP is exposed and often uses cleartext auth"),
    25: (3.1, "SMTP is exposed"),
    22: (2.0, "SSH is reachable (informational — ensure key-only auth)"),
}

PATHS = [
    "/admin", "/administrator", "/login", "/wp-admin", "/wp-login.php",
    "/.git/config", "/.git/HEAD", "/.env", "/.svn/entries", "/config.php",
    "/backup", "/backup.zip", "/backup.sql", "/db.sql", "/dump.sql",
    "/phpmyadmin", "/api", "/api/v1", "/swagger", "/swagger-ui.html",
    "/actuator", "/actuator/health", "/console", "/dashboard", "/debug",
    "/server-status", "/.htaccess", "/robots.txt", "/sitemap.xml",
    "/.well-known/security.txt", "/uploads/", "/old/", "/dev/", "/test/",
    "/.DS_Store", "/web.config",
]

SECURITY_HEADERS = {
    "Content-Security-Policy": (4.3, "Missing Content-Security-Policy allows XSS / data-injection to be more impactful"),
    "Strict-Transport-Security": (4.3, "Missing HSTS allows protocol-downgrade / SSL-strip attacks"),
    "X-Frame-Options": (4.3, "Missing X-Frame-Options enables clickjacking"),
    "X-Content-Type-Options": (3.1, "Missing X-Content-Type-Options enables MIME-sniffing"),
    "Referrer-Policy": (2.0, "Missing Referrer-Policy may leak URLs to third parties"),
    "Permissions-Policy": (2.0, "Missing Permissions-Policy leaves browser features unrestricted"),
    "X-XSS-Protection": (2.0, "Missing X-XSS-Protection (legacy browsers)"),
}


class ScanInput(BaseModel):
    target: str = Field(min_length=3)
    scan_ports: bool = True
    scan_ssl: bool = True
    scan_headers: bool = True
    scan_endpoints: bool = True
    scan_tech: bool = True
    scan_secrets: bool = True
    scan_subdomains: bool = True
    scan_webvulns: bool = True
    scan_api: bool = True
    scan_network: bool = True
    capture_screenshot: bool = True
    # Advanced modules
    scan_config: bool = True
    scan_cors: bool = True
    scan_cookies: bool = True
    scan_methods: bool = True
    scan_csp: bool = True
    scan_waf: bool = True
    scan_dns_ext: bool = True
    scan_deepvulns: bool = True
    scan_graphql: bool = True
    scan_takeover: bool = True
    scan_wellknown: bool = True
    scan_templates: bool = True
    scan_content: bool = True


def severity_from_cvss(cvss: float) -> str:
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0:
        return "low"
    return "info"


def normalize_target(target: str):
    t = target.strip()
    if not t.startswith("http://") and not t.startswith("https://"):
        t = "https://" + t
    p = urlparse(t)
    host = p.hostname
    scheme = p.scheme
    base = f"{scheme}://{p.netloc}"
    return host, base, scheme


async def _check_port(host, port, timeout=3.0):
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=1)
        except Exception:
            pass
        return True
    except Exception:
        return False


async def scan_ports(host):
    ports = list(COMMON_PORTS.keys())
    results = await asyncio.gather(*[_check_port(host, p) for p in ports])
    return [{"port": p, "service": COMMON_PORTS[p], "state": "open"}
            for p, ok in zip(ports, results) if ok]


def _ssl_info(host, port=443):
    info = {"host": host, "port": port}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=7) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
                info["tls_version"] = ss.version()
                info["cipher"] = ss.cipher()[0]
                info["valid"] = True
                na = cert.get("notAfter")
                nb = cert.get("notBefore")
                info["not_after"] = na
                info["not_before"] = nb
                info["issuer"] = {k: v for t in cert.get("issuer", []) for (k, v) in t}
                info["subject"] = {k: v for t in cert.get("subject", []) for (k, v) in t}
                try:
                    exp = datetime.strptime(na, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    info["days_to_expiry"] = (exp - datetime.now(timezone.utc)).days
                except Exception:
                    info["days_to_expiry"] = None
        return info
    except ssl.SSLCertVerificationError as e:
        info["valid"] = False
        info["verify_error"] = str(e)[:200]
        try:
            c2 = ssl._create_unverified_context()
            with socket.create_connection((host, port), timeout=7) as sock:
                with c2.wrap_socket(sock, server_hostname=host) as ss:
                    info["tls_version"] = ss.version()
                    info["cipher"] = ss.cipher()[0]
        except Exception as e2:
            info["error"] = str(e2)[:150]
        return info
    except Exception as e:
        return {"host": host, "port": port, "reachable": False, "error": str(e)[:200]}


def _headers(url):
    try:
        r = requests.get(url, timeout=8, allow_redirects=True, headers=UA)
        present = {h: r.headers.get(h) for h in SECURITY_HEADERS}
        return {
            "status": r.status_code,
            "final_url": str(r.url),
            "server": r.headers.get("Server"),
            "x_powered_by": r.headers.get("X-Powered-By"),
            "security_headers": present,
        }
    except Exception as e:
        return {"reachable": False, "error": str(e)[:200]}


def _enum(base):
    def one(path):
        try:
            r = requests.get(base.rstrip("/") + path, timeout=6, allow_redirects=False, headers=UA)
            if r.status_code in (200, 201, 204, 301, 302, 307, 308, 401, 403):
                return {"path": path, "status": r.status_code, "length": len(r.content)}
        except Exception:
            return None
        return None

    found = []
    with ThreadPoolExecutor(max_workers=12) as ex:
        for res in ex.map(one, PATHS):
            if res:
                found.append(res)
    return found


def _endpoint_finding(entry):
    path = entry["path"].lower()
    status = entry["status"]
    accessible = status in (200, 201, 204, 301, 302, 307, 308)
    if (".git" in path or ".svn" in path) and accessible:
        return (8.6, "Exposed version-control metadata — source code / secrets disclosure")
    if ".env" in path and accessible:
        return (9.1, "Exposed environment file — likely credential / secret leakage")
    if (path.endswith(".sql") or "backup" in path or path.endswith(".zip") or "dump" in path) and accessible:
        return (7.5, "Exposed backup / database file")
    if ".ds_store" in path and accessible:
        return (5.3, "Exposed .DS_Store reveals directory structure")
    if "web.config" in path and accessible:
        return (6.5, "Exposed web.config may reveal configuration/secrets")
    if any(k in path for k in ["phpmyadmin", "actuator", "console", "swagger", "wp-admin", "wp-login"]):
        return (6.5 if accessible else 3.1, "Sensitive management/admin endpoint reachable")
    if any(k in path for k in ["/admin", "administrator", "dashboard", "/api", "/debug", "server-status"]):
        return (5.3 if accessible else 2.0, "Sensitive endpoint reachable")
    return None


def build_findings(host, base, ports, ssl_res, headers_res, endpoints):
    findings = []

    def add(title, cvss, category, evidence, recommendation, component=""):
        findings.append({
            "title": title, "cvss": round(cvss, 1), "severity": severity_from_cvss(cvss),
            "category": category, "component": component, "evidence": evidence,
            "recommendation": recommendation,
        })

    # Ports
    for p in ports or []:
        risk = PORT_RISK.get(p["port"])
        if risk:
            cvss, msg = risk
            add(f"Exposed service: {p['service']} (port {p['port']})", cvss,
                "Network Exposure / CWE-284", f"{host}:{p['port']} is OPEN — {msg}",
                f"Restrict port {p['port']} via firewall/security-group; expose only via VPN or a hardened gateway.",
                p["service"])

    # SSL/TLS
    if ssl_res and ssl_res.get("reachable") is not False:
        ver = ssl_res.get("tls_version")
        cipher = (ssl_res.get("cipher") or "").upper()
        dte = ssl_res.get("days_to_expiry")
        if ssl_res.get("valid") is False:
            add("TLS certificate validation failed", 6.5, "Cryptographic Failures / CWE-295",
                ssl_res.get("verify_error", "Certificate could not be validated"),
                "Install a valid certificate from a trusted CA matching the hostname.", "TLS")
        if dte is not None and dte < 0:
            add("TLS certificate expired", 7.5, "Cryptographic Failures / CWE-298",
                f"Certificate expired {abs(dte)} day(s) ago (notAfter {ssl_res.get('not_after')}).",
                "Renew the TLS certificate immediately and automate renewal.", "TLS")
        elif dte is not None and dte <= 15:
            add("TLS certificate expiring soon", 4.0, "Cryptographic Failures",
                f"Certificate expires in {dte} day(s).", "Renew before expiry; automate with ACME/Let's Encrypt.", "TLS")
        if ver in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            add(f"Weak TLS protocol negotiated ({ver})", 7.4, "Cryptographic Failures / CWE-327",
                f"Server negotiated deprecated {ver}.", "Disable TLS < 1.2; prefer TLS 1.3.", "TLS")
        if any(w in cipher for w in ["RC4", "3DES", "DES", "NULL", "MD5", "EXPORT"]):
            add("Weak cipher suite in use", 5.9, "Cryptographic Failures / CWE-327",
                f"Negotiated cipher: {ssl_res.get('cipher')}", "Disable weak ciphers; use AEAD suites (AES-GCM/ChaCha20).", "TLS")

    # Headers
    if headers_res and headers_res.get("reachable") is not False:
        sh = headers_res.get("security_headers", {})
        is_https = str(headers_res.get("final_url", "")).startswith("https")
        for header, (cvss, msg) in SECURITY_HEADERS.items():
            if header == "Strict-Transport-Security" and not is_https:
                continue
            if not sh.get(header):
                add(f"Missing security header: {header}", cvss, "Security Misconfiguration / CWE-16",
                    msg, f"Add the `{header}` response header.", "HTTP")
        if headers_res.get("server") and any(c.isdigit() for c in str(headers_res.get("server"))):
            add("Server software version disclosed", 3.1, "Security Misconfiguration / CWE-200",
                f"Server header: {headers_res.get('server')}", "Suppress version banners in the Server header.",
                str(headers_res.get("server")))

    # Endpoints
    for e in endpoints or []:
        r = _endpoint_finding(e)
        if r:
            cvss, msg = r
            add(f"Exposed endpoint: {e['path']} (HTTP {e['status']})", cvss,
                "Sensitive Data Exposure / CWE-538", f"{base}{e['path']} returned HTTP {e['status']} ({e['length']} bytes) — {msg}",
                "Restrict, authenticate or remove the exposed path.", "HTTP")

    return findings


async def ai_enrich(host, ports, ssl_res, headers_res, endpoints):
    """Best-effort AI: executive summary + CVE findings from detected banners."""
    context = {
        "host": host,
        "open_ports": [f"{p['port']}/{p['service']}" for p in (ports or [])],
        "server": (headers_res or {}).get("server"),
        "x_powered_by": (headers_res or {}).get("x_powered_by"),
        "tls_version": (ssl_res or {}).get("tls_version"),
        "exposed_paths": [e["path"] for e in (endpoints or [])],
    }
    system = (
        "You are InsafeLabs, a senior penetration tester writing a client report. Given raw scan data, "
        "return STRICT JSON only: {\"executive_summary\": string (3-5 sentences, professional), "
        "\"cve_findings\": [{\"title\": str, \"cvss\": number, \"category\": str, \"component\": str, "
        "\"evidence\": str, \"recommendation\": str}]}. In cve_findings, list any well-known CVEs that "
        "plausibly affect the disclosed server/software banners (cite the CVE id in the title). If no "
        "banner/version is disclosed, return an empty cve_findings array. Do not invent versions."
    )
    try:
        raw = await ai.complete("scanner", system, json.dumps(context))
        parsed = ai.parse_json(raw)
        return parsed.get("executive_summary", ""), parsed.get("cve_findings", []) or []
    except Exception:
        return "", []


def _grade(score):
    return "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 55 else "E" if score >= 40 else "F"


def build_scorecard(ssl_res, headers_res, net_data, cookie_data, cors_data, secrets_data, config_data, content_data):
    """Synthesize an A–F security scorecard from data already collected (no extra network)."""
    cats = []

    def add(name, score):
        s = max(0, min(100, int(round(score))))
        cats.append({"category": name, "score": s, "grade": _grade(s)})

    try:
        if ssl_res and ssl_res.get("valid") is not None:
            s = 100
            if not ssl_res.get("valid"):
                s -= 55
            v = ssl_res.get("tls_version") or ""
            if "1.0" in v or "1.1" in v:
                s -= 30
            d = ssl_res.get("days_to_expiry")
            if isinstance(d, (int, float)) and d < 15:
                s -= 20
            add("TLS / Certificate", s)
    except Exception:
        pass
    try:
        sh = (headers_res or {}).get("security_headers") if isinstance(headers_res, dict) else None
        if isinstance(sh, dict) and sh:
            present = sum(1 for x in sh.values() if x)
            add("HTTP Security Headers", present / len(sh) * 100)
    except Exception:
        pass
    try:
        if net_data and (net_data.get("records") or net_data.get("spf") is not None):
            s = 100
            if not net_data.get("spf"):
                s -= 35
            elif not net_data.get("spf_enforced"):
                s -= 12
            if not net_data.get("dmarc"):
                s -= 30
            elif net_data.get("dmarc_policy") in (None, "none"):
                s -= 15
            if not net_data.get("dkim"):
                s -= 15
            add("Email Anti-Spoofing", s)
    except Exception:
        pass
    try:
        cks = (cookie_data or {}).get("cookies") or []
        if cks:
            good = sum(1 for c in cks if c.get("secure") and c.get("httponly") and c.get("samesite"))
            add("Cookie Security", good / len(cks) * 100)
    except Exception:
        pass
    try:
        if cors_data and ("wildcard" in cors_data or "reflects_origin" in cors_data):
            s = 100
            if cors_data.get("reflects_origin"):
                s -= 55
            if cors_data.get("wildcard"):
                s -= 30
            if cors_data.get("allows_null"):
                s -= 25
            add("CORS Policy", s)
    except Exception:
        pass
    try:
        exp = len((secrets_data or {}).get("secrets") or []) \
            + len((config_data or {}).get("config_hits") or []) \
            + sum(1 for h in ((content_data or {}).get("content_hits") or []) if h.get("status") == 200)
        add("Data Exposure Control", 100 - exp * 14)
    except Exception:
        pass

    if not cats:
        return None
    overall = int(round(sum(c["score"] for c in cats) / len(cats)))
    return {"overall_score": overall, "overall_grade": _grade(overall), "categories": cats}


def _public(doc):
    doc.pop("_id", None)
    return doc


@router.get("/scans")
async def list_scans():
    docs = await db.recon_scans.find({}, {"_id": 0, "raw": 0}).sort("created_at", -1).to_list(200)
    return docs


@router.get("/diff")
async def diff_scans(a: str, b: str):
    """Compare two scans (a = baseline/older, b = latest) and highlight changes."""
    da = await db.recon_scans.find_one({"id": a}, {"_id": 0})
    db_ = await db.recon_scans.find_one({"id": b}, {"_id": 0})
    if not da or not db_:
        raise HTTPException(status_code=404, detail="One or both scans not found")

    def index(doc):
        return {(f.get("title", ""), f.get("component", "")): f for f in (doc.get("findings") or [])}

    ia, ib = index(da), index(db_)
    added = [ib[k] for k in ib.keys() - ia.keys()]      # new exposures in b
    removed = [ia[k] for k in ia.keys() - ib.keys()]    # resolved since a
    common = [ib[k] for k in ia.keys() & ib.keys()]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    added.sort(key=lambda f: order.get(f.get("severity"), 5))
    removed.sort(key=lambda f: order.get(f.get("severity"), 5))

    def meta(doc):
        return {"id": doc.get("id"), "ref": doc.get("ref"), "host": doc.get("host"),
                "target": doc.get("target"), "risk_score": doc.get("risk_score", 0),
                "posture": doc.get("posture"), "finding_count": doc.get("finding_count", 0),
                "created_at": doc.get("created_at"), "severity_counts": doc.get("severity_counts", {})}

    return {
        "a": meta(da), "b": meta(db_),
        "added": added, "removed": removed, "common_count": len(common),
        "risk_delta": (db_.get("risk_score", 0) - da.get("risk_score", 0)),
        "finding_delta": (db_.get("finding_count", 0) - da.get("finding_count", 0)),
    }


@router.get("/scans/{scan_id}")
async def get_scan(scan_id: str):
    doc = await db.recon_scans.find_one({"id": scan_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Scan not found")
    return doc


@router.delete("/scans/{scan_id}")
async def delete_scan(scan_id: str):
    res = await db.recon_scans.delete_one({"id": scan_id})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"message": "deleted"}


async def perform_scan(data: ScanInput, scan_id: str = None) -> dict:
    host, base, scheme = normalize_target(data.target)
    if not host:
        raise HTTPException(status_code=400, detail="Invalid target")

    loop = asyncio.get_event_loop()
    ports_task = scan_ports(host) if data.scan_ports else asyncio.sleep(0, result=[])
    ssl_future = loop.run_in_executor(None, _ssl_info, host) if data.scan_ssl else None
    headers_future = loop.run_in_executor(None, _headers, base) if data.scan_headers else None
    endpoints_future = loop.run_in_executor(None, _enum, base) if data.scan_endpoints else None

    ports = await ports_task
    ssl_res = await ssl_future if ssl_future else None
    headers_res = await headers_future if headers_future else None
    endpoints = await endpoints_future if endpoints_future else []

    findings = build_findings(host, base, ports, ssl_res, headers_res, endpoints)

    # ---- Deep recon (best-effort, concurrent) ----
    tech_data = subs_data = secrets_data = webvuln_data = api_data = net_data = cms_data = {}
    config_data = cors_data = cookie_data = methods_data = csp_data = waf_data = {}
    dnsext_data = deepvuln_data = graphql_data = takeover_data = wellknown_data = wp_data = {}
    template_data = content_data = {}
    screenshot = None
    html = cookies = raw_headers = None
    try:
        if data.scan_secrets or data.scan_tech or data.scan_csp:
            bp = await loop.run_in_executor(None, recon_lib.fetch_base, recon_lib.new_session(), base)
            html = bp.get("html", ""); cookies = bp.get("cookies", {}); raw_headers = bp.get("headers", {})
    except Exception:
        html = ""

    async def _run(fn, *a):
        try:
            return await loop.run_in_executor(None, fn, *a)
        except Exception:
            return ({}, [])

    tasks = {}
    if data.scan_subdomains: tasks["subs"] = _run(recon_lib.enum_subdomains, host)
    if data.scan_network: tasks["net"] = _run(recon_lib.network_recon, host)
    if data.scan_webvulns: tasks["web"] = _run(recon_lib.web_vuln_probes, recon_lib.new_session(), base)
    if data.scan_api: tasks["api"] = _run(recon_lib.api_tests, recon_lib.new_session(), base)
    if data.scan_secrets: tasks["sec"] = _run(recon_lib.secret_and_js_analysis, recon_lib.new_session(), base, html or "")
    if data.scan_config: tasks["cfg"] = _run(recon_lib.config_exposure_scan, recon_lib.new_session(), base)
    if data.scan_cors: tasks["cors"] = _run(recon_advanced.cors_audit, recon_lib.new_session(), base)
    if data.scan_cookies: tasks["cookie"] = _run(recon_advanced.cookie_audit, recon_lib.new_session(), base)
    if data.scan_methods: tasks["methods"] = _run(recon_advanced.http_methods_audit, recon_lib.new_session(), base)
    if data.scan_csp: tasks["csp"] = _run(recon_advanced.csp_analysis, raw_headers or {})
    if data.scan_waf: tasks["waf"] = _run(recon_advanced.waf_detection, recon_lib.new_session(), base)
    if data.scan_dns_ext: tasks["dnsext"] = _run(recon_advanced.extended_dns, host)
    if data.scan_deepvulns: tasks["deep"] = _run(recon_advanced.advanced_web_vulns, recon_lib.new_session(), base)
    if data.scan_graphql: tasks["gql"] = _run(recon_advanced.graphql_introspection, recon_lib.new_session(), base)
    if data.scan_wellknown: tasks["wk"] = _run(recon_advanced.wellknown_files, recon_lib.new_session(), base)
    if data.scan_templates: tasks["tpl"] = _run(recon_templates.template_scan, recon_lib.new_session(), base)
    if data.scan_content: tasks["content"] = _run(recon_advanced.content_discovery, recon_lib.new_session(), base)
    if tasks:
        done = await asyncio.gather(*tasks.values())
        res = dict(zip(tasks.keys(), done))
        if "subs" in res: subs_data, _f = res["subs"]; findings += _f
        if "net" in res: net_data, _f = res["net"]; findings += _f
        if "web" in res: webvuln_data, _f = res["web"]; findings += _f
        if "api" in res: api_data, _f = res["api"]; findings += _f
        if "sec" in res: secrets_data, _f = res["sec"]; findings += _f
        if "cfg" in res: config_data, _f = res["cfg"]; findings += _f
        if "cors" in res: cors_data, _f = res["cors"]; findings += _f
        if "cookie" in res: cookie_data, _f = res["cookie"]; findings += _f
        if "methods" in res: methods_data, _f = res["methods"]; findings += _f
        if "csp" in res: csp_data, _f = res["csp"]; findings += _f
        if "waf" in res: waf_data, _f = res["waf"]; findings += _f
        if "dnsext" in res: dnsext_data, _f = res["dnsext"]; findings += _f
        if "deep" in res: deepvuln_data, _f = res["deep"]; findings += _f
        if "gql" in res: graphql_data, _f = res["gql"]; findings += _f
        if "wk" in res: wellknown_data, _f = res["wk"]; findings += _f
        if "tpl" in res: template_data, _f = res["tpl"]; findings += _f
        if "content" in res: content_data, _f = res["content"]; findings += _f
    # Subdomain takeover needs the enumerated subdomains
    if data.scan_takeover and subs_data.get("subdomains"):
        takeover_data, _f = await _run(recon_advanced.subdomain_takeover, subs_data.get("subdomains", []))
        findings += _f
    if data.scan_tech:
        try:
            tech_data, _f = recon_lib.fingerprint_tech(raw_headers or {}, html or "", cookies or {}); findings += _f
            cms_data, _f = recon_lib.cms_scan(recon_lib.new_session(), base, tech_data.get("stack", [])); findings += _f
            if any("WordPress" in t for t in tech_data.get("stack", [])):
                wp_data, _f = await _run(recon_advanced.wordpress_deep, recon_lib.new_session(), base); findings += _f
        except Exception:
            pass
    screenshots = []
    if data.capture_screenshot:
        screenshot = recon_lib.screenshot_url(base)
        screenshots.append({"label": host, "url": screenshot})
        for e in (endpoints or [])[:6]:
            screenshots.append({"label": e["path"], "url": recon_lib.screenshot_url(base.rstrip("/") + e["path"])})
    geo = await loop.run_in_executor(None, recon_lib.geolocate, host)
    exec_summary, cve_findings = await ai_enrich(host, ports, ssl_res, headers_res, endpoints)
    for c in cve_findings:
        try:
            cvss = float(c.get("cvss", 0) or 0)
        except Exception:
            cvss = 0.0
        findings.append({
            "title": c.get("title", "Potential known vulnerability"),
            "cvss": round(cvss, 1), "severity": severity_from_cvss(cvss),
            "category": c.get("category", "Vulnerable Component"),
            "component": c.get("component", ""), "evidence": c.get("evidence", ""),
            "recommendation": c.get("recommendation", ""),
        })

    # Per-finding visual proof: endpoint findings -> endpoint snapshot; site-wide web findings -> homepage snapshot
    if screenshots:
        home_shot = screenshots[0]["url"]
        path_shot = {s["label"]: s["url"] for s in screenshots[1:]}
        WEB_COMP = {"HTTP", "TLS", "app", "api", "WordPress"}
        for f in findings:
            proof = None
            for path, url in path_shot.items():
                if path and (path in (f.get("evidence") or "") or path in (f.get("title") or "")):
                    proof = url
                    break
            if not proof and f.get("component") in WEB_COMP:
                proof = home_shot
            if proof:
                f["proof"] = proof

    findings.sort(key=lambda f: f["cvss"], reverse=True)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f["severity"]] += 1
    max_cvss = max([f["cvss"] for f in findings], default=0.0)
    posture = severity_from_cvss(max_cvss) if max_cvss > 0 else "low"
    risk_score = min(100, int(round(max_cvss * 10)) + min(20, 2 * len(findings)))
    if not exec_summary:
        exec_summary = (
            f"Automated attack-surface scan of {host} identified {len(findings)} issue(s) across "
            f"{len(ports or [])} open port(s), TLS configuration, HTTP security headers and endpoint exposure. "
            f"Highest observed severity is {posture.upper()}."
        )

    scorecard = build_scorecard(ssl_res, headers_res, net_data, cookie_data, cors_data, secrets_data, config_data, content_data)

    doc = {
        "id": scan_id or str(uuid.uuid4()),
        "ref": f"InsafeLabs-{str(uuid.uuid4())[:8].upper()}",
        "target": data.target, "host": host, "base": base,
        "ports": ports, "ssl": ssl_res, "headers": headers_res, "endpoints": endpoints,
        "tech": tech_data, "cms": cms_data, "secrets": secrets_data, "subdomains": subs_data,
        "webvulns": webvuln_data, "api": api_data, "network": net_data, "screenshot": screenshot,
        "config": config_data, "cors": cors_data, "cookies_audit": cookie_data, "methods": methods_data,
        "csp": csp_data, "waf": waf_data, "dns_ext": dnsext_data, "deepvulns": deepvuln_data,
        "graphql": graphql_data, "takeover": takeover_data, "wellknown": wellknown_data, "wordpress": wp_data,
        "templates": template_data,
        "content": content_data, "scorecard": scorecard,
        "screenshots": screenshots, "geo": geo,
        "findings": findings, "severity_counts": counts, "finding_count": len(findings),
        "risk_score": risk_score, "posture": posture, "executive_summary": exec_summary,
        "status": "completed",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    if scan_id:
        existing = await db.recon_scans.find_one({"id": scan_id}, {"created_at": 1})
        if existing and existing.get("created_at"):
            doc["created_at"] = existing["created_at"]
        await db.recon_scans.replace_one({"id": scan_id}, dict(doc))
    else:
        await db.recon_scans.insert_one(dict(doc))
    return _public(doc)


async def _bg_scan(data: ScanInput, scan_id: str):
    try:
        await perform_scan(data, scan_id=scan_id)
    except Exception as e:
        await db.recon_scans.update_one({"id": scan_id}, {"$set": {
            "status": "failed", "error": str(e)[:300],
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }})


@router.post("/scan")
async def run_scan(data: ScanInput):
    host, _base, _scheme = normalize_target(data.target)
    if not host:
        raise HTTPException(status_code=400, detail="Invalid target")
    scan_id = str(uuid.uuid4())
    placeholder = {
        "id": scan_id, "ref": f"InsafeLabs-{str(uuid.uuid4())[:8].upper()}",
        "target": data.target, "host": host, "status": "running",
        "findings": [], "finding_count": 0, "posture": "info", "risk_score": 0,
        "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.recon_scans.insert_one(dict(placeholder))
    asyncio.create_task(_bg_scan(data, scan_id))
    return {"id": scan_id, "status": "running"}


@router.get("/scans/{scan_id}/report")
async def report(scan_id: str):
    doc = await db.recon_scans.find_one({"id": scan_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Scan not found")
    pdf = build_pdf(doc)
    return Response(
        content=pdf, media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{doc["ref"]}-report.pdf"'},
    )


def build_pdf(doc) -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.units import mm
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                    TableStyle, HRFlowable)

    SEV_COLOR = {"critical": colors.HexColor("#EF4444"), "high": colors.HexColor("#F97316"),
                 "medium": colors.HexColor("#F59E0B"), "low": colors.HexColor("#3B82F6"),
                 "info": colors.HexColor("#71717A")}
    buf = io.BytesIO()
    d = SimpleDocTemplate(buf, pagesize=A4, topMargin=18 * mm, bottomMargin=16 * mm,
                          leftMargin=16 * mm, rightMargin=16 * mm, title=f"InsafeLabs Report {doc['ref']}")
    styles = getSampleStyleSheet()
    H = ParagraphStyle("H", parent=styles["Title"], textColor=colors.HexColor("#111111"), fontSize=22)
    sub = ParagraphStyle("sub", parent=styles["Normal"], textColor=colors.HexColor("#666666"), fontSize=9)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], textColor=colors.HexColor("#111111"), spaceBefore=10)
    body = ParagraphStyle("body", parent=styles["Normal"], fontSize=9.5, leading=14)
    small = ParagraphStyle("small", parent=styles["Normal"], fontSize=8, textColor=colors.HexColor("#444444"))
    def _esc(v):
        return (str(v) if v is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    el = []

    el.append(Paragraph("InsafeLabs — Security Assessment Report", H))
    el.append(Paragraph(f"Attack-surface scan · Ref {doc['ref']}", sub))
    el.append(Spacer(1, 6))
    el.append(HRFlowable(width="100%", color=colors.HexColor("#FACC15"), thickness=2))
    el.append(Spacer(1, 10))

    meta = [["Target", _esc(doc.get("target", ""))], ["Host", _esc(doc.get("host", ""))],
            ["Scan date (UTC)", doc.get("created_at", "")[:19].replace("T", " ")],
            ["Risk score", f"{doc.get('risk_score', 0)}/100"],
            ["Overall posture", doc.get("posture", "").upper()]]
    t = Table(meta, colWidths=[38 * mm, None])
    t.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#666666")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4), ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, colors.HexColor("#DDDDDD")),
    ]))
    el.append(t)
    el.append(Spacer(1, 12))

    el.append(Paragraph("Executive Summary", h2))
    el.append(Paragraph(_esc(doc.get("executive_summary", "")), body))
    el.append(Spacer(1, 8))

    shot = doc.get("screenshot")
    if shot:
        try:
            import requests as _rq
            from reportlab.platypus import Image as RLImage
            rr = _rq.get(shot, timeout=25)
            ctype = rr.headers.get("Content-Type", "")
            if rr.status_code == 200 and "image" in ctype and "gif" not in ctype:
                el.append(Paragraph("Visual Proof — Target Snapshot", h2))
                el.append(RLImage(io.BytesIO(rr.content), width=165 * mm, height=98 * mm))
                el.append(Spacer(1, 10))
        except Exception:
            pass

    c = doc.get("severity_counts", {})
    sev_row = [["Critical", "High", "Medium", "Low", "Info"],
               [str(c.get("critical", 0)), str(c.get("high", 0)), str(c.get("medium", 0)),
                str(c.get("low", 0)), str(c.get("info", 0))]]
    st = Table(sev_row, colWidths=[35 * mm] * 5)
    st.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#DDDDDD")),
        ("BACKGROUND", (0, 0), (0, 0), SEV_COLOR["critical"]),
        ("BACKGROUND", (1, 0), (1, 0), SEV_COLOR["high"]),
        ("BACKGROUND", (2, 0), (2, 0), SEV_COLOR["medium"]),
        ("BACKGROUND", (3, 0), (3, 0), SEV_COLOR["low"]),
        ("BACKGROUND", (4, 0), (4, 0), SEV_COLOR["info"]),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 10), ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTSIZE", (0, 1), (-1, 1), 14), ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    el.append(st)
    el.append(Spacer(1, 12))

    # Technical sections
    el.append(Paragraph("Open Ports", h2))
    if doc.get("ports"):
        rows = [["Port", "Service"]] + [[str(p["port"]), p["service"]] for p in doc["ports"]]
        pt = Table(rows, colWidths=[30 * mm, None])
        pt.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#DDDDDD")),
                                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111111")),
                                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("FONTSIZE", (0, 0), (-1, -1), 8.5)]))
        el.append(pt)
    else:
        el.append(Paragraph("No common ports detected as open.", small))
    el.append(Spacer(1, 8))

    s = doc.get("ssl") or {}
    el.append(Paragraph("SSL / TLS", h2))
    ssl_txt = (f"TLS version: {s.get('tls_version','-')} · Cipher: {s.get('cipher','-')} · "
               f"Valid: {s.get('valid','-')} · Expires in: {s.get('days_to_expiry','-')} day(s) · "
               f"Issuer: {(s.get('issuer') or {}).get('organizationName','-')}")
    el.append(Paragraph(ssl_txt, small))
    el.append(Spacer(1, 8))

    hh = (doc.get("headers") or {}).get("security_headers", {})
    el.append(Paragraph("HTTP Security Headers", h2))
    hrows = [["Header", "Status"]] + [[k, ("present" if v else "MISSING")] for k, v in hh.items()]
    if len(hrows) > 1:
        ht = Table(hrows, colWidths=[70 * mm, None])
        ht.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#DDDDDD")),
                                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111111")),
                                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("FONTSIZE", (0, 0), (-1, -1), 8.5)]))
        el.append(ht)
    el.append(Spacer(1, 12))

    eps = doc.get("endpoints") or []
    if eps:
        el.append(Paragraph(f"Discovered Endpoints ({len(eps)})", h2))
        erows = [["Path", "HTTP", "Bytes"]] + [[e.get("path", ""), str(e.get("status", "")), str(e.get("length", ""))] for e in eps[:40]]
        et = Table(erows, colWidths=[95 * mm, 25 * mm, None])
        et.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#DDDDDD")),
                                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111111")),
                                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("FONTSIZE", (0, 0), (-1, -1), 8.5)]))
        el.append(et)
        el.append(Spacer(1, 12))

    subs = doc.get("subdomains") or {}
    if subs.get("subdomains"):
        el.append(Paragraph(f"Subdomains ({subs.get('total', 0)})", h2))
        el.append(Paragraph(_esc(", ".join(subs.get("subdomains", [])[:50])), small))
        el.append(Spacer(1, 8))
    secrets = (doc.get("secrets") or {}).get("secrets") or []
    if secrets:
        el.append(Paragraph("Exposed Secrets", h2))
        for s in secrets[:15]:
            el.append(Paragraph(f"\u2022 {_esc(s['type'])} in {_esc(s['source'])}: {_esc(s['match'])}", small))
        el.append(Spacer(1, 8))
    net = doc.get("network") or {}
    if net.get("records"):
        el.append(Paragraph("Network Reconnaissance", h2))
        for rt, vals in (net.get("records") or {}).items():
            el.append(Paragraph(f"<b>{rt}</b>: {', '.join(vals)}", small))
        el.append(Paragraph(f"SPF: {net.get('spf') or 'MISSING'}", small))
        el.append(Paragraph(f"DMARC: {'present' if net.get('dmarc') else 'MISSING'}", small))
        w = net.get("whois") or {}
        if w.get("registrar"):
            el.append(Paragraph(f"Registrar: {w.get('registrar')} \u00b7 Expires: {w.get('expires')}", small))
        el.append(Spacer(1, 8))
    tech = doc.get("tech") or {}
    if tech.get("stack"):
        el.append(Paragraph("Technology Fingerprint", h2))
        el.append(Paragraph(_esc(", ".join(tech.get("stack", []))), small))
        el.append(Spacer(1, 8))

    # ---- Advanced module sections ----
    cfg = doc.get("config") or {}
    if cfg.get("config_hits"):
        el.append(Paragraph(f"Exposed Config / Secret Files ({len(cfg['config_hits'])})", h2))
        for c in cfg["config_hits"][:25]:
            el.append(Paragraph(f"\u2022 {_esc(c.get('path'))} — {_esc(c.get('content_type',''))} · {c.get('size',0)} bytes", small))
        for s in (cfg.get("config_secrets") or [])[:15]:
            el.append(Paragraph(f"\u2022 secret in {_esc(s.get('source'))}: {_esc(s.get('type'))} = {_esc(s.get('match'))}", small))
        el.append(Spacer(1, 8))

    tk = doc.get("takeover") or {}
    if tk.get("vulnerable"):
        el.append(Paragraph(f"Subdomain Takeover ({len(tk['vulnerable'])})", h2))
        for v in tk["vulnerable"][:20]:
            el.append(Paragraph(f"\u2022 {_esc(v.get('subdomain'))} → {_esc(v.get('cname'))} [{_esc(v.get('service'))}]", small))
        el.append(Spacer(1, 8))

    tpl = doc.get("templates") or {}
    if tpl.get("matched"):
        el.append(Paragraph(f"Template Engine Matches ({len(tpl['matched'])} / {tpl.get('total_templates',0)} templates)", h2))
        trows = [["Template", "Severity", "CVE", "URL"]] + [
            [m.get("name", "")[:40], m.get("severity", "").upper(), m.get("cve") or "-", m.get("url", "")[:48]]
            for m in tpl["matched"][:30]]
        tt = Table(trows, colWidths=[52 * mm, 20 * mm, 28 * mm, None])
        tt.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#DDDDDD")),
                                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111111")),
                                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("FONTSIZE", (0, 0), (-1, -1), 7.5)]))
        el.append(tt)
        el.append(Spacer(1, 8))

    cors = doc.get("cors") or {}
    cks = (doc.get("cookies_audit") or {}).get("cookies") or []
    methods = doc.get("methods") or {}
    csp = doc.get("csp") or {}
    waf = doc.get("waf") or {}
    if cors or cks or methods.get("allowed") or csp or waf.get("detected") is not None:
        el.append(Paragraph("Web Configuration Audit", h2))
        if cors:
            el.append(Paragraph(f"<b>CORS:</b> Allow-Origin={cors.get('acao') or 'none'} · Credentials={cors.get('acac')} · reflects-origin={cors.get('reflects_origin')} · null={cors.get('allows_null')}", small))
        if csp:
            issues = ", ".join(csp.get("issues") or []) or "none"
            el.append(Paragraph(f"<b>CSP:</b> {'present' if csp.get('present') else 'MISSING'} · issues: {issues}", small))
        if methods.get("allowed") or methods.get("trace"):
            el.append(Paragraph(f"<b>HTTP methods:</b> {', '.join(methods.get('allowed', [])) or '-'}{' · TRACE ENABLED' if methods.get('trace') else ''}", small))
        if waf:
            el.append(Paragraph(f"<b>WAF/CDN:</b> {waf.get('vendor') if waf.get('detected') else 'not detected'}", small))
        if cks:
            insecure = [c.get("name") for c in cks if not c.get("httponly") or not c.get("samesite")]
            el.append(Paragraph(f"<b>Cookies:</b> {len(cks)} set · flagged: {', '.join(insecure[:8]) or 'none'}", small))
        el.append(Spacer(1, 8))

    dv = doc.get("deepvulns") or {}
    hits = {k: v for k, v in dv.items() if v and v not in ("not detected", "probe failed")}
    if hits:
        el.append(Paragraph("Deep Vulnerability Probes", h2))
        for k, v in hits.items():
            el.append(Paragraph(f"\u2022 {k.replace('_', ' ').title()}: {v}", small))
        el.append(Spacer(1, 8))

    dnx = doc.get("dns_ext") or {}
    if dnx:
        el.append(Paragraph("Extended DNS / Email Security", h2))
        el.append(Paragraph(f"CAA: {'present' if dnx.get('caa') else 'MISSING'} · DNSSEC: {'on' if dnx.get('dnssec') else 'off'} · "
                            f"DKIM: {', '.join(dnx.get('dkim') or []) or 'none'} · AXFR: {'OPEN' if dnx.get('zone_transfer') else 'refused'}", small))
        el.append(Spacer(1, 8))

    wk = doc.get("wellknown") or {}
    if wk:
        el.append(Paragraph("Well-Known Files", h2))
        el.append(Paragraph(f"robots.txt: {'yes' if wk.get('robots') else 'no'} · sitemap: {'yes' if wk.get('sitemap') else 'no'} · "
                            f"security.txt: {'yes' if wk.get('security_txt') else 'no'} · humans.txt: {'yes' if wk.get('humans') else 'no'}", small))
        if wk.get("disallowed"):
            el.append(Paragraph("robots Disallow: " + ", ".join(wk.get("disallowed", [])[:25]), small))
        el.append(Spacer(1, 8))

    el.append(Paragraph("Findings", h2))
    _proof_budget = [5]
    for i, f in enumerate(doc.get("findings", []), 1):
        sevc = SEV_COLOR.get(f["severity"], colors.grey)
        head = Table([[Paragraph(f"<b>{i}. {_esc(f['title'])}</b>", body),
                       Paragraph(f"<b>{_esc(f['severity']).upper()}</b>  CVSS {_esc(f['cvss'])}", small)]],
                     colWidths=[None, 45 * mm])
        head.setStyle(TableStyle([("BACKGROUND", (1, 0), (1, 0), sevc),
                                  ("TEXTCOLOR", (1, 0), (1, 0), colors.white),
                                  ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                                  ("LEFTPADDING", (1, 0), (1, 0), 6), ("RIGHTPADDING", (1, 0), (1, 0), 6),
                                  ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
        el.append(head)
        if f.get("category"):
            el.append(Paragraph(f"<b>Category:</b> {_esc(f['category'])}", small))
        if f.get("evidence"):
            el.append(Paragraph(f"<b>Evidence:</b> {_esc(f['evidence'])}", small))
        if f.get("recommendation"):
            el.append(Paragraph(f"<b>Remediation:</b> {_esc(f['recommendation'])}", small))
        proof = f.get("proof")
        if proof and proof != doc.get("screenshot") and _proof_budget[0] > 0:
            try:
                import requests as _rq
                from reportlab.platypus import Image as RLImage
                rr = _rq.get(proof, timeout=12)
                ct = rr.headers.get("Content-Type", "")
                if rr.status_code == 200 and "image" in ct and "gif" not in ct:
                    el.append(Spacer(1, 3))
                    el.append(Paragraph("<b>Visual proof:</b>", small))
                    el.append(RLImage(io.BytesIO(rr.content), width=95 * mm, height=57 * mm))
                    _proof_budget[0] -= 1
            except Exception:
                pass
        el.append(Spacer(1, 7))
    if not doc.get("findings"):
        el.append(Paragraph("No issues identified.", small))

    el.append(Spacer(1, 14))
    el.append(HRFlowable(width="100%", color=colors.HexColor("#DDDDDD"), thickness=0.5))
    el.append(Paragraph("Generated by InsafeLabs Offensive Security Platform · For authorized testing only", small))

    d.build(el)
    return buf.getvalue()


# ============================================================================
# Scheduled monitors + new-exposure alerts
# ============================================================================
import logging as _logging
_sched_logger = _logging.getLogger("daxx.scheduler")

INTERVALS = {"5min": 300, "hourly": 3600, "daily": 86400, "weekly": 604800}


class ScheduleInput(BaseModel):
    target: str = Field(min_length=3)
    interval: str = "daily"
    options: dict = {}


def _now():
    return datetime.now(timezone.utc)


def _next_run(interval: str):
    from datetime import timedelta
    return (_now() + timedelta(seconds=INTERVALS.get(interval, 86400))).isoformat()


def _titles(findings):
    return sorted({f.get("title", "") for f in (findings or [])})


async def _run_schedule(sch: dict):
    opts = sch.get("options") or {}
    valid = {k: v for k, v in opts.items() if k in ScanInput.model_fields and k != "target"}
    data = ScanInput(target=sch["target"], **valid)
    doc = await perform_scan(data)
    prev = set(sch.get("last_titles") or [])
    current = set(_titles(doc["findings"]))
    new = sorted(current - prev)
    await db.scheduled_scans.update_one({"id": sch["id"]}, {"$set": {
        "last_run": _now().isoformat(), "next_run": _next_run(sch["interval"]),
        "last_scan_id": doc["id"], "last_titles": sorted(current),
        "last_finding_count": doc["finding_count"], "last_posture": doc["posture"],
    }})
    if sch.get("last_run") and new:
        await db.scan_alerts.insert_one({
            "id": str(uuid.uuid4()), "schedule_id": sch["id"], "target": sch["target"],
            "scan_id": doc["id"], "new_findings": new[:20], "count": len(new),
            "created_at": _now().isoformat(), "read": False,
        })
    return doc, new


@router.post("/schedules")
async def create_schedule(data: ScheduleInput):
    if data.interval not in INTERVALS:
        raise HTTPException(status_code=400, detail="Invalid interval")
    doc = {
        "id": str(uuid.uuid4()), "target": data.target, "interval": data.interval,
        "options": data.options or {}, "active": True,
        "created_at": _now().isoformat(), "next_run": _now().isoformat(),
        "last_run": None, "last_scan_id": None, "last_titles": [],
        "last_finding_count": None, "last_posture": None,
    }
    await db.scheduled_scans.insert_one(dict(doc))
    doc.pop("_id", None)
    return doc


@router.get("/schedules")
async def list_schedules():
    return await db.scheduled_scans.find({}, {"_id": 0}).sort("created_at", -1).to_list(100)


@router.delete("/schedules/{schedule_id}")
async def delete_schedule(schedule_id: str):
    res = await db.scheduled_scans.delete_one({"id": schedule_id})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Schedule not found")
    await db.scan_alerts.delete_many({"schedule_id": schedule_id})
    return {"message": "deleted"}


@router.post("/schedules/{schedule_id}/run")
async def run_schedule_now(schedule_id: str):
    sch = await db.scheduled_scans.find_one({"id": schedule_id})
    if not sch:
        raise HTTPException(status_code=404, detail="Schedule not found")
    doc, new = await _run_schedule(sch)
    return {"scan_id": doc["id"], "finding_count": doc["finding_count"], "new_findings": new}


@router.get("/alerts")
async def list_alerts():
    return await db.scan_alerts.find({}, {"_id": 0}).sort("created_at", -1).to_list(100)


@router.post("/alerts/{alert_id}/read")
async def mark_alert_read(alert_id: str):
    await db.scan_alerts.update_one({"id": alert_id}, {"$set": {"read": True}})
    return {"message": "ok"}


@router.delete("/alerts/{alert_id}")
async def delete_alert(alert_id: str):
    await db.scan_alerts.delete_one({"id": alert_id})
    return {"message": "deleted"}


async def scheduler_loop():
    await asyncio.sleep(15)
    while True:
        try:
            now = _now()
            schedules = await db.scheduled_scans.find({"active": True}).to_list(50)
            for sch in schedules:
                nr = sch.get("next_run")
                due = (not nr) or (datetime.fromisoformat(nr) <= now)
                if not due:
                    continue
                await db.scheduled_scans.update_one({"id": sch["id"]},
                                                    {"$set": {"next_run": _next_run(sch["interval"])}})
                try:
                    await _run_schedule(sch)
                    _sched_logger.info(f"[SCHED] ran scan for {sch['target']}")
                except Exception as e:
                    _sched_logger.warning(f"[SCHED] failed for {sch.get('target')}: {e}")
        except Exception as e:
            _sched_logger.warning(f"[SCHED] loop error: {e}")
        await asyncio.sleep(60)
