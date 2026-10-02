"""InsafeLabs Vuln Suite — NATIVE in-app security testing (no external binaries).

Everything here runs in-process in Python and is NON-DESTRUCTIVE: it only sends
benign requests and analyses the responses (no exploitation, no data modification).
Targets are passed through the SSRF guard (netguard.guard_url).
"""
import asyncio
import base64
import concurrent.futures
import ipaddress
import json
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

import requests
import urllib3
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from netguard import guard_url

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

router = APIRouter(prefix="/vulnsuite", tags=["vulnsuite"])

UA = {"User-Agent": "InsafeLabs-VulnSuite/1.0 (authorized assessment)"}

SEC_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "Content-Security-Policy",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}

SENSITIVE_PATHS = [
    (".git/config", "Git config exposed"),
    (".env", ".env exposed"),
    (".env.local", ".env.local exposed"),
    ("backup.zip", "Backup archive exposed"),
    ("backup.sql", "SQL dump exposed"),
    ("db.sql", "SQL dump exposed"),
    ("wp-config.php.bak", "WordPress config backup"),
    ("config.php.bak", "Config backup"),
    (".DS_Store", "macOS .DS_Store exposed"),
    ("server-status", "Apache server-status"),
    ("server-info", "Apache server-info"),
    ("actuator/env", "Spring Boot actuator env"),
    ("actuator/health", "Spring Boot actuator health"),
    ("swagger.json", "Swagger spec exposed"),
    ("openapi.json", "OpenAPI spec exposed"),
    ("phpinfo.php", "phpinfo() exposed"),
    (".svn/entries", "SVN metadata exposed"),
    (".htaccess", "Apache .htaccess exposed"),
    ("composer.lock", "composer.lock exposed"),
    ("package.json", "package.json exposed"),
    (".well-known/security.txt", "security.txt (informational)"),
    ("robots.txt", "robots.txt (informational)"),
    ("sitemap.xml", "sitemap.xml (informational)"),
]

SQL_ERRORS = [
    "you have an error in your sql syntax", "warning: mysql", "mysql_fetch", "mysqli",
    "unclosed quotation mark", "quoted string not properly terminated", "sqlstate",
    "pg_query", "postgresql", "psql:", "sqlite", "sqlite3", "odbc sql server driver",
    "ora-0", "oracle error", "microsoft ole db provider for sql server", "syntax error at or near",
    "unknown column", "sql command not properly ended",
]


def _norm(url: str) -> str:
    u = (url or "").strip()
    if not re.match(r"^https?://", u):
        u = "https://" + u
    return u


def _req(url, method="GET", headers=None, allow_redirects=True, timeout=15, data=None):
    h = {**UA, **(headers or {})}
    return requests.request(method, url, headers=h, timeout=timeout, verify=False,
                            allow_redirects=allow_redirects, data=data)


def _finding(title, severity, detail, evidence=None, recommendation=None):
    return {"title": title, "severity": severity, "detail": detail,
            "evidence": (evidence or "")[:400], "recommendation": recommendation or ""}


# --------------------------------------------------------------------------- Web scan
def _web_scan(url: str) -> dict:
    url = _norm(url)
    guard_url(url)
    try:
        r = _req(url, allow_redirects=True, timeout=20)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Request failed: {str(e)[:140]}")

    headers = {k: v for k, v in r.headers.items()}
    lower = {k.lower(): v for k, v in headers.items()}
    body = (r.text or "")[:150000]
    findings = []
    checks = {}

    # 1. security headers
    present = [label for k, label in SEC_HEADERS.items() if k in lower]
    missing = [label for k, label in SEC_HEADERS.items() if k not in lower]
    grade = ["F", "F", "D", "C", "B", "A", "A+"][min(len(present), 6)]
    checks["security_headers"] = {"present": present, "missing": missing, "grade": grade}
    if "HSTS" in missing and url.startswith("https://"):
        findings.append(_finding("Missing HSTS", "medium",
                                 "No Strict-Transport-Security header — SSL-strip attacks possible.",
                                 recommendation="Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"))
    if "Content-Security-Policy" in missing:
        findings.append(_finding("Missing CSP", "medium",
                                 "No Content-Security-Policy — XSS impact is not mitigated.",
                                 recommendation="Define a restrictive Content-Security-Policy."))
    if "X-Frame-Options" in missing and "frame-ancestors" not in (lower.get("content-security-policy") or ""):
        findings.append(_finding("Clickjacking protection", "medium",
                                 "No X-Frame-Options / CSP frame-ancestors — page can be framed.",
                                 recommendation="Send X-Frame-Options: DENY or CSP frame-ancestors 'none'."))
    if "X-Content-Type-Options" in missing:
        findings.append(_finding("MIME sniffing", "low", "Missing X-Content-Type-Options: nosniff.",
                                 recommendation="Add X-Content-Type-Options: nosniff."))

    # 2. cookies
    cookies = []
    for c in r.cookies:
        flags = {"secure": bool(c.secure), "httponly": bool(c.has_nonstandard_attr("HttpOnly") or c._rest.get("HttpOnly")),
                 "samesite": c._rest.get("SameSite")}
        cookies.append({"name": c.name, **flags})
    insecure = [c["name"] for c in cookies if not c["secure"] or not c["httponly"]]
    checks["cookies"] = cookies
    if insecure:
        findings.append(_finding("Insecure cookie flags", "medium",
                                 f"Cookies missing Secure/HttpOnly: {', '.join(insecure[:8])}",
                                 recommendation="Set Secure; HttpOnly; SameSite=Lax/Strict on session cookies."))

    # 3. CSP quality
    csp = lower.get("content-security-policy", "")
    checks["csp"] = {"present": bool(csp), "unsafe_inline": "unsafe-inline" in csp, "unsafe_eval": "unsafe-eval" in csp}
    if csp and ("unsafe-inline" in csp or "unsafe-eval" in csp):
        findings.append(_finding("Weak CSP", "low", "CSP allows unsafe-inline/unsafe-eval, weakening XSS protection."))

    # 4. HTTP methods / TRACE
    try:
        o = _req(url, method="OPTIONS", allow_redirects=False, timeout=10)
        allow = o.headers.get("Allow", "")
        checks["methods"] = {"allow": allow, "trace": "TRACE" in allow.upper()}
        if "TRACE" in allow.upper():
            findings.append(_finding("HTTP TRACE enabled", "low", "TRACE may enable Cross-Site Tracing (XST).",
                                     recommendation="Disable the TRACE method."))
    except Exception:
        checks["methods"] = {"allow": "", "trace": False}

    # 5. CORS
    try:
        evil = "https://evil-insafelabs.test"
        c = _req(url, headers={"Origin": evil}, allow_redirects=False, timeout=10)
        acao = c.headers.get("Access-Control-Allow-Origin")
        acac = c.headers.get("Access-Control-Allow-Credentials")
        checks["cors"] = {"acao": acao, "acac": acac}
        if acao == evil and (acac or "").lower() == "true":
            findings.append(_finding("CORS: arbitrary origin + credentials", "critical",
                                     "Reflects any Origin AND allows credentials — full cross-origin data theft.",
                                     evidence=f"ACAO: {acao} / ACAC: {acac}", recommendation="Whitelist explicit origins; never combine * / reflection with credentials."))
        elif acao == evil:
            findings.append(_finding("CORS: arbitrary origin reflected", "high",
                                     "Access-Control-Allow-Origin reflects the request Origin.",
                                     evidence=f"ACAO: {acao}", recommendation="Use a strict origin allowlist."))
    except Exception:
        checks["cors"] = {}

    # 6. banner / info disclosure
    checks["server"] = {"server": lower.get("server"), "powered_by": lower.get("x-powered-by")}
    if re.search(r"\d+\.\d+", f"{lower.get('server','')} {lower.get('x-powered-by','')}"):
        findings.append(_finding("Version disclosure", "low",
                                 "Server/X-Powered-By reveals version numbers.",
                                 recommendation="Suppress version banners."))

    # 7. HTTP -> HTTPS redirect
    if url.startswith("https://"):
        try:
            http_url = "http://" + url[len("https://"):]
            h = _req(http_url, allow_redirects=False, timeout=10)
            loc = h.headers.get("Location", "")
            checks["https_redirect"] = {"status": h.status_code, "location": loc}
            if h.status_code < 300 or not loc.startswith("https://"):
                findings.append(_finding("No HTTPS redirect", "medium",
                                         "Plain HTTP does not redirect to HTTPS.",
                                         recommendation="301-redirect all HTTP to HTTPS."))
        except Exception:
            checks["https_redirect"] = {}

    # 8. sensitive files (with a soft-404 baseline: SPAs return 200 + index.html for any path)
    exposed = []
    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    baseline_len = None
    try:
        import uuid as _uuid
        rnd = _req(f"{base}/insafelabs-nope-{_uuid.uuid4().hex[:10]}", allow_redirects=False, timeout=8)
        if rnd.status_code == 200:
            baseline_len = len(rnd.content)
    except Exception:
        baseline_len = None
    for path, label in SENSITIVE_PATHS:
        try:
            p = _req(f"{base}/{path}", allow_redirects=False, timeout=8)
            ok = p.status_code == 200 and len(p.content) > 0
            if not ok:
                continue
            # soft-404 filter: same size as a random nonexistent path → not really the file
            if baseline_len is not None and abs(len(p.content) - baseline_len) < 64:
                continue
            sev = "low" if "informational" in label else "high"
            exposed.append({"path": "/" + path, "label": label, "severity": sev, "size": len(p.content)})
            if sev == "high":
                findings.append(_finding(f"Sensitive file exposed: /{path}", "high",
                                         f"{label} is publicly reachable.", evidence=f"HTTP 200, {len(p.content)} bytes",
                                         recommendation="Remove/deny access to this path."))
        except Exception:
            continue
    checks["exposed_paths"] = exposed

    # 9. directory listing
    if re.search(r"<title>\s*Index of /", body, re.I) or "Index of /</h1>" in body:
        findings.append(_finding("Directory listing enabled", "medium",
                                 "Server returns a browsable directory index.",
                                 recommendation="Disable autoindex."))

    # 10. TLS cert
    tls = None
    if url.startswith("https://"):
        tls = _tls_info(urlparse(url).hostname)
    checks["tls"] = tls
    if tls and tls.get("days_left") is not None and tls["days_left"] < 15:
        findings.append(_finding("TLS certificate expiring soon", "medium",
                                 f"Certificate expires in {tls['days_left']} days.",
                                 recommendation="Renew the certificate."))

    # 11. basic info
    title = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    checks["info"] = {"final_url": r.url, "status": r.status_code, "title": (title.group(1).strip()[:120] if title else None),
                      "elapsed_ms": int(r.elapsed.total_seconds() * 1000), "size": len(r.content)}

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: order.get(f["severity"], 9))
    return {"url": url, "final_url": r.url, "status": r.status_code, "grade": grade,
            "findings_count": len(findings), "findings": findings, "checks": checks}


def _tls_info(host, port=443):
    if not host:
        return None
    try:
        from cryptography import x509
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert(binary_form=True)
                proto = ss.version()
                cipher = ss.cipher()
        c = x509.load_der_x509_certificate(cert)
        na = c.not_valid_after_utc if hasattr(c, "not_valid_after_utc") else c.not_valid_after.replace(tzinfo=timezone.utc)
        days = (na - datetime.now(timezone.utc)).days
        def nm(n):
            return ", ".join(f"{a}={v}" for a, v in n) if isinstance(n, tuple) else str(n)
        try:
            sans = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
        except Exception:
            sans = []
        return {"protocol": proto, "cipher": cipher[0] if cipher else None,
                "subject": nm(c.subject.rfc4514_string()), "issuer": nm(c.issuer.rfc4514_string()),
                "valid_to": na.date().isoformat(), "days_left": days, "sans": sans[:30],
                "self_signed": c.issuer == c.subject}
    except Exception as e:
        return {"error": str(e)[:140]}


# --------------------------------------------------------------------------- Injection
def _replace_param(url, name, value):
    p = urlparse(url)
    q = dict(parse_qsl(p.query, keep_blank_values=True))
    q[name] = value
    return urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(q), p.fragment))


def _injection(url: str) -> dict:
    url = _norm(url)
    guard_url(url)
    p = urlparse(url)
    params = dict(parse_qsl(p.query, keep_blank_values=True))
    if not params:
        raise HTTPException(status_code=400, detail="URL needs at least one query parameter, e.g. ?id=1")
    try:
        baseline = _req(url, timeout=15)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Request failed: {str(e)[:140]}")

    findings = []
    results = []

    for name, orig in params.items():
        entry = {"param": name, "tests": {}}

        # --- error-based SQLi
        for payload in [f"{orig}'", f'{orig}"', f"{orig})", f"{orig}'-- -"]:
            try:
                r = _req(_replace_param(url, name, payload), timeout=12)
                txt = (r.text or "").lower()
                hit = next((sig for sig in SQL_ERRORS if sig in txt), None)
                if hit:
                    finding = f"SQL error signature: '{hit}'"
                    entry["tests"]["sqli_error"] = finding
                    findings.append(_finding("SQL injection (error-based, possible)", "critical",
                                             f"DB error triggered via parameter '{name}'.",
                                             evidence=finding, recommendation="Use parameterised queries / prepared statements."))
                    break
            except Exception:
                continue

        # --- boolean-based SQLi (heuristic)
        try:
            t = _req(_replace_param(url, name, f"{orig}' AND '1'='1"), timeout=12)
            f = _req(_replace_param(url, name, f"{orig}' AND '1'='2"), timeout=12)
            if t.status_code == f.status_code and abs(len(t.content) - len(f.content)) > 32:
                entry["tests"]["sqli_boolean"] = f"len_diff={abs(len(t.content)-len(f.content))}"
                findings.append(_finding("SQL injection (boolean-based, possible)", "high",
                                         f"Different responses for true/false conditions on '{name}'.",
                                         evidence=entry["tests"]["sqli_boolean"],
                                         recommendation="Parameterise queries; validate types."))
        except Exception:
            pass

        # --- reflected XSS (marker)
        marker = "insafelabs7x9z"
        try:
            r = _req(_replace_param(url, name, f'{orig}"\'><{marker}>'), timeout=12)
            txt = r.text or ""
            if f"<{marker}>" in txt:
                entry["tests"]["xss"] = "raw reflection"
                findings.append(_finding("Reflected XSS (possible)", "high",
                                         f"Input is reflected unencoded via '{name}'.",
                                         evidence=f"<{marker}> returned verbatim",
                                         recommendation="Context-aware output encoding + CSP."))
            elif marker in txt:
                entry["tests"]["xss"] = "reflected (encoded)"
        except Exception:
            pass

        # --- CRLF injection
        try:
            r = _req(_replace_param(url, name, f"{orig}%0d%0aInsafeLabs-Injected:1"), allow_redirects=False, timeout=12)
            if r.headers.get("InsafeLabs-Injected"):
                entry["tests"]["crlf"] = "injected header reflected"
                findings.append(_finding("CRLF header injection", "high",
                                         f"Newline injection via '{name}' added a response header.",
                                         recommendation="Strip CR/LF from user input used in headers."))
        except Exception:
            pass

        # --- open redirect
        if re.search(r"url|redirect|next|dest|return|continue|target", name, re.I):
            try:
                r = _req(_replace_param(url, name, "https://evil-insafelabs.test/"), allow_redirects=False, timeout=10)
                loc = r.headers.get("Location", "")
                if "evil-insafelabs.test" in loc:
                    entry["tests"]["open_redirect"] = loc
                    findings.append(_finding("Open redirect", "medium",
                                             f"'{name}' redirects to an arbitrary external host.",
                                             evidence=loc, recommendation="Allowlist redirect destinations."))
            except Exception:
                pass

        results.append(entry)

    # host header injection
    try:
        r = _req(url, headers={"Host": "evil-insafelabs.test"}, timeout=12)
        if "evil-insafelabs.test" in (r.text or ""):
            findings.append(_finding("Host header injection (reflected)", "medium",
                                     "Host header is reflected in the response.",
                                     recommendation="Validate Host against an allowlist."))
    except Exception:
        pass

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: order.get(f["severity"], 9))
    return {"url": url, "params": list(params.keys()), "findings": findings,
            "findings_count": len(findings), "results": results}


# --------------------------------------------------------------------------- Param discovery
COMMON_PARAMS = ["id", "page", "file", "path", "url", "redirect", "next", "q", "s", "search",
                 "query", "lang", "debug", "test", "admin", "token", "key", "user", "name",
                 "view", "action", "cmd", "callback", "format", "type", "sort", "order"]
REFLECT_MARK = "insafelabsref7"


def _params(url: str) -> dict:
    url = _norm(url)
    guard_url(url)
    try:
        base = _req(url, timeout=15)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Request failed: {str(e)[:140]}")
    body = base.text or ""
    found = []

    # existing query params
    existing = list(dict(parse_qsl(urlparse(url).query)).keys())

    # form inputs
    form_params = []
    for m in re.finditer(r"<input[^>]+name=[\"']([^\"']+)[\"']", body, re.I):
        form_params.append(m.group(1))

    # hidden params reflected?
    for name in COMMON_PARAMS:
        if name in existing:
            continue
        try:
            r = _req(_replace_param(url, name, REFLECT_MARK), timeout=10)
            reflected = REFLECT_MARK in (r.text or "")
            size_diff = abs(len(r.content) - len(base.content))
            if reflected or size_diff > 64:
                found.append({"param": name, "reflected": reflected, "size_diff": size_diff,
                              "note": "reflected" if reflected else "response changed"})
        except Exception:
            continue

    return {"url": url, "existing": existing, "form_inputs": sorted(set(form_params)),
            "discovered": found, "tested": len(COMMON_PARAMS)}


# --------------------------------------------------------------------------- TLS
class HostInput(BaseModel):
    host: str = Field(min_length=1, max_length=253)


def _tls_scan(host: str) -> dict:
    host = re.sub(r"^https?://", "", (host or "").strip()).split("/")[0].split(":")[0]
    guard_url(f"https://{host}/")
    info = _tls_info(host) or {}
    protocols = {}
    for name, ver in [("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
                      ("TLSv1.2", ssl.TLSVersion.TLSv1_2), ("TLSv1.3", ssl.TLSVersion.TLSv1_3)]:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ver
            ctx.maximum_version = ver
            with socket.create_connection((host, 443), timeout=6) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    protocols[name] = True
        except Exception:
            protocols[name] = False
    weak = [p for p, ok in protocols.items() if ok and p in ("TLSv1.0", "TLSv1.1")]
    findings = []
    if weak:
        findings.append(_finding("Weak TLS protocol enabled", "high", f"Enabled: {', '.join(weak)}",
                                 recommendation="Disable TLS 1.0/1.1; require TLS 1.2+."))
    if info.get("self_signed"):
        findings.append(_finding("Self-signed certificate", "medium", "Certificate is self-signed.",
                                 recommendation="Use a trusted CA certificate."))
    return {"host": host, "cert": info, "protocols": protocols, "findings": findings}


# --------------------------------------------------------------------------- DNS / AXFR
def _dns_scan(domain: str) -> dict:
    domain = re.sub(r"^https?://", "", (domain or "").strip()).split("/")[0]
    if "." not in domain:
        raise HTTPException(status_code=400, detail="Enter a valid domain")
    try:
        import dns.resolver
        import dns.query
        import dns.zone
    except Exception:
        raise HTTPException(status_code=500, detail="dnspython not available")

    records = {}
    for rtype in ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "CAA"]:
        try:
            ans = dns.resolver.resolve(domain, rtype, lifetime=6)
            records[rtype] = [r.to_text()[:200] for r in ans][:25]
        except Exception:
            records[rtype] = []

    findings = []
    axfr = []
    for ns in records.get("NS", [])[:4]:
        ns = ns.rstrip(".")
        try:
            z = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=6))
            names = [str(n) for n in z.nodes.keys()][:60]
            axfr.append({"ns": ns, "records": len(z.nodes), "sample": names})
            findings.append(_finding("DNS zone transfer (AXFR) allowed", "high",
                                     f"Nameserver {ns} allowed a full zone transfer.",
                                     evidence=f"{len(z.nodes)} records", recommendation="Restrict AXFR to authorised secondaries."))
        except Exception:
            continue
    if not records.get("SPF") and not any("v=spf1" in t for t in records.get("TXT", [])):
        findings.append(_finding("No SPF record", "medium", "Domain has no SPF — email spoofing possible.",
                                 recommendation="Publish an SPF record."))
    return {"domain": domain, "records": records, "axfr": axfr, "findings": findings}


# --------------------------------------------------------------------------- Auth form analyzer
def _auth_form(url: str) -> dict:
    url = _norm(url)
    guard_url(url)
    try:
        r = _req(url, timeout=15)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Request failed: {str(e)[:140]}")
    body = r.text or ""
    findings = []
    forms = []
    for fm in re.finditer(r"<form\b([^>]*)>(.*?)</form>", body, re.I | re.S):
        attrs, inner = fm.group(1), fm.group(2)
        action = (re.search(r'action=["\']([^"\']*)', attrs, re.I) or [None, ""])[1]
        method = ((re.search(r'method=["\']([^"\']*)', attrs, re.I) or [None, "get"])[1] or "get").lower()
        inputs = []
        for im in re.finditer(r"<input\b([^>]*)>", inner, re.I):
            a = im.group(1)
            name = (re.search(r'name=["\']([^"\']*)', a, re.I) or [None, ""])[1]
            itype = ((re.search(r'type=["\']([^"\']*)', a, re.I) or [None, "text"])[1] or "text").lower()
            auto = (re.search(r'autocomplete=["\']([^"\']*)', a, re.I) or [None, ""])[1]
            inputs.append({"name": name, "type": itype, "autocomplete": auto})
        has_password = any(i["type"] == "password" for i in inputs)
        csrf = any(re.search(r"csrf|token|authenticity", i["name"], re.I) for i in inputs)
        if not has_password and "login" not in (action or "").lower():
            continue
        forms.append({"action": action, "method": method, "inputs": inputs,
                      "has_password": has_password, "csrf_token": csrf})
        if has_password and method == "get":
            findings.append(_finding("Login form uses GET", "high",
                                     "Credentials would be placed in the URL/query string (logged, cached).",
                                     recommendation="Use POST for authentication forms."))
        if has_password and not csrf:
            findings.append(_finding("No CSRF token in login form", "medium",
                                     "Form has no apparent anti-CSRF token field.",
                                     recommendation="Add a per-session CSRF token."))
        if has_password:
            pw = next(i for i in inputs if i["type"] == "password")
            if pw.get("autocomplete", "").lower() != "off":
                findings.append(_finding("Password field autocomplete enabled", "low",
                                         "Password input does not set autocomplete=off."))
        if url.startswith("http://"):
            findings.append(_finding("Login page served over HTTP", "high",
                                     "Credentials can be intercepted in transit.",
                                     recommendation="Serve authentication over HTTPS only."))
    rate = {k: v for k, v in r.headers.items() if re.search(r"ratelimit|retry-after", k, re.I)}
    if not rate:
        findings.append(_finding("No rate-limit headers observed", "info",
                                 "No RateLimit/Retry-After headers on the page — verify brute-force protection separately."))
    return {"url": url, "forms": forms, "findings": findings, "rate_limit_headers": rate}


# --------------------------------------------------------------------------- VHost discovery
VHOST_WORDS = ["dev", "staging", "stage", "test", "qa", "uat", "admin", "portal", "api", "internal",
               "intranet", "corp", "jenkins", "gitlab", "git", "jira", "confluence", "grafana",
               "kibana", "prometheus", "mail", "webmail", "vpn", "remote", "cpanel", "whm", "db",
               "mysql", "redis", "mongo", "postgres", "backup", "old", "new", "beta", "demo", "sso",
               "auth", "login", "app", "m", "mobile", "blog", "shop", "store", "crm", "erp",
               "support", "help", "status", "monitor", "dashboard", "panel", "files", "cdn", "static"]


class VhostInput(BaseModel):
    url: str = Field(min_length=4, max_length=2048)
    extra: str = ""


def _vhost(data: VhostInput) -> dict:
    url = _norm(data.url)
    guard_url(url)
    p = urlparse(url)
    host = p.hostname
    try:
        ip = socket.gethostbyname(host)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Could not resolve {host}: {str(e)[:80]}")
    try:
        ptr = socket.gethostbyaddr(ip)[0]
    except Exception:
        ptr = None
    scheme = p.scheme or "https"
    path = p.path or "/"
    base = f"{scheme}://{ip}{path}"

    def fetch(h):
        try:
            r = _req(base, headers={"Host": h}, allow_redirects=False, timeout=10)
            return r.status_code, len(r.content), (r.headers.get("Location", "") or "")
        except Exception:
            return None, None, ""

    host_code, host_len, _ = fetch(host)
    extra = [w.strip() for w in re.split(r"[,\s]+", data.extra or "") if w.strip()]
    found = []
    for w in [*VHOST_WORDS, *extra]:
        c, l, loc = fetch(w)
        if c is None:
            continue
        same = c == host_code and (l is not None and host_len is not None and abs(l - host_len) < 64)
        if not same:
            found.append({"vhost": w, "status": c, "size": l, "location": loc[:160]})
    return {"url": url, "host": host, "ip": ip, "ptr": ptr, "scheme": scheme,
            "baseline": {"status": host_code, "size": host_len},
            "tested": len(VHOST_WORDS) + len(extra), "found": found}


# --------------------------------------------------------------------------- Wordlist
class WordlistInput(BaseModel):
    keywords: str = Field(min_length=1, max_length=400)
    years: str = "2020-2026"
    extra: str = ""


def _wordlist(data: WordlistInput) -> dict:
    kws = [k.strip() for k in re.split(r"[,\s]+", data.keywords) if k.strip()]
    years = []
    m = re.match(r"^(\d{4})-(\d{4})$", (data.years or "").strip())
    if m:
        a, b = int(m.group(1)), int(m.group(2))
        if 0 < b - a <= 30:
            years = [str(y) for y in range(a, b + 1)]
    elif (data.years or "").strip().isdigit():
        years = [data.years.strip()]
    extras = [e.strip() for e in re.split(r"[,\s]+", data.extra or "") if e.strip()]

    suffixes = ["", "1", "12", "123", "1234", "2024", "!", "@", "#", "_", "-", "01", "99"]
    seps = ["", "_", "-", ".", "@"]
    out = set()
    for k in kws:
        variants = {k, k.lower(), k.upper(), k.capitalize()}
        for v in variants:
            out.add(v)
            for s in ["123", "1234", "1", "!", "@", "2024", "2025", "2026"]:
                out.add(v + s)
                out.add(s + v)
            for y in years:
                out.add(v + y)
                out.add(v + "@" + y)
            for e in extras:
                out.add(v + e)
                out.add(v + "_" + e)
        for k2 in kws:
            if k2 != k:
                for sep in seps:
                    out.add(k + sep + k2)
    for e in extras:
        out.add(e)
    words = sorted(w for w in out if 3 <= len(w) <= 40)
    return {"count": len(words), "keywords": kws, "years": years, "words": words[:5000]}


# --------------------------------------------------------------------------- Rate limiting
class RateInput(BaseModel):
    url: str = Field(min_length=4, max_length=2048)
    method: str = "GET"
    count: int = 12


def _rate_limit(data: RateInput) -> dict:
    url = _norm(data.url)
    guard_url(url)
    method = (data.method or "GET").upper()
    if method not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
        raise HTTPException(status_code=400, detail="Unsupported method")
    count = max(5, min(int(data.count or 12), 30))
    codes = {}
    rl_headers = {}
    limited_at = None
    retry_after = None
    t0 = time.time()
    for i in range(count):
        try:
            r = _req(url, method=method, allow_redirects=False, timeout=8)
        except Exception:
            codes["error"] = codes.get("error", 0) + 1
            continue
        codes[r.status_code] = codes.get(r.status_code, 0) + 1
        for h in ("Retry-After", "X-RateLimit-Limit", "X-RateLimit-Remaining",
                  "RateLimit-Limit", "RateLimit-Remaining", "RateLimit-Reset"):
            if h in r.headers:
                rl_headers[h] = r.headers[h]
        if r.status_code in (429, 503) and limited_at is None:
            limited_at = i + 1
            retry_after = r.headers.get("Retry-After")
    elapsed = round(time.time() - t0, 2)
    enforced = limited_at is not None or any(k in rl_headers for k in ("X-RateLimit-Limit", "RateLimit-Limit"))
    findings = []
    if not enforced and codes.get("error", 0) < count:
        findings.append(_finding("No rate limiting observed", "medium",
                                 f"{count} rapid {method} requests were all accepted with no 429/Retry-After.",
                                 evidence=f"status distribution: {json.dumps(codes)}",
                                 recommendation="Add per-IP / per-account rate limiting returning 429 + Retry-After."))
    return {"url": url, "method": method, "requests": count, "elapsed_s": elapsed,
            "status_distribution": codes, "rate_limit_headers": rl_headers,
            "limited_at_request": limited_at, "retry_after": retry_after,
            "enforced": enforced, "findings": findings}


# --------------------------------------------------------------------------- IDOR
class IdorInput(BaseModel):
    url: str = Field(min_length=4, max_length=2048)


def _idor(data: IdorInput) -> dict:
    url = _norm(data.url)
    guard_url(url)
    p = urlparse(url)
    params = dict(parse_qsl(p.query, keep_blank_values=True))
    numeric_param = next((k for k, v in params.items() if str(v).isdigit()), None)

    if numeric_param:
        base_id = int(params[numeric_param])

        def make(n):
            return _replace_param(url, numeric_param, str(n))
        idlabel = f"{numeric_param}={base_id}"
    else:
        hits_re = list(re.finditer(r"/(\d+)(?=/|$|\?)", p.path))
        if not hits_re:
            raise HTTPException(status_code=400, detail="URL needs a numeric id — e.g. /users/1 or ?id=1")
        m = hits_re[-1]
        base_id = int(m.group(1))
        prefix, suffix = p.path[:m.start(1)], p.path[m.end(1):]

        def make(n):
            return urlunparse((p.scheme, p.netloc, prefix + str(n) + suffix, p.params, p.query, p.fragment))
        idlabel = f"path id {base_id}"

    try:
        base = _req(url, timeout=12)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Request failed: {str(e)[:140]}")
    baseline = {"status": base.status_code, "size": len(base.content)}

    tests = [base_id - 1, base_id + 1, 1, 2, 0, base_id + 100, 1000]
    hits = []
    for n in tests:
        if n < 0 or n == base_id:
            continue
        try:
            r = _req(make(n), timeout=12)
        except Exception:
            continue
        status, size = r.status_code, len(r.content)
        if status == 200 and (abs(size - baseline["size"]) > 32 or baseline["status"] != 200):
            hits.append({"id": n, "status": status, "size": size, "diff": abs(size - baseline["size"])})

    findings = []
    if hits:
        findings.append(_finding("Possible IDOR (Insecure Direct Object Reference)", "high",
                                 f"Changing the object id returned HTTP 200 with different content for {len(hits)} value(s). "
                                 "Confirm these objects are not authorized for this session.",
                                 evidence=json.dumps(hits[:6]),
                                 recommendation="Enforce per-object authorization (ownership checks) on every request server-side."))
    return {"url": url, "id": idlabel, "baseline": baseline, "tested": len(tests),
            "hits": hits, "findings": findings}


# --------------------------------------------------------------------------- SSTI
SSTI_PAYLOADS = [
    ("{{7*7}}", "49"), ("${7*7}", "49"), ("#{7*7}", "49"), ("*{7*7}", "49"),
    ("<%= 7*7 %>", "49"), ("{{7*'7'}}", "7777777"), ("${7*'7'}", "7777777"),
]


class ParamInput(BaseModel):
    url: str = Field(min_length=4, max_length=2048)


def _ssti(data: ParamInput) -> dict:
    url = _norm(data.url)
    guard_url(url)
    params = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
    if not params:
        raise HTTPException(status_code=400, detail="URL needs a query parameter, e.g. ?name=test")
    findings, results = [], []
    for name, orig in params.items():
        hit = None
        for payload, marker in SSTI_PAYLOADS:
            try:
                r = _req(_replace_param(url, name, payload), timeout=12)
                if marker in (r.text or "") and marker not in (orig or ""):
                    hit = {"payload": payload, "marker": marker}
                    break
            except Exception:
                continue
        results.append({"param": name, "ssti": bool(hit), "evidence": hit})
        if hit:
            findings.append(_finding("Server-Side Template Injection (SSTI)", "critical",
                                     f"Template expression evaluated via '{name}' ({hit['payload']} → {hit['marker']}).",
                                     evidence=f"{hit['payload']} → {hit['marker']}",
                                     recommendation="Never render user input as template code; use sandboxed/static rendering."))
    return {"url": url, "params": list(params.keys()), "results": results, "findings": findings}


# --------------------------------------------------------------------------- LFI / path traversal
LFI_PAYLOADS = [
    ("../../../../../../etc/passwd", ["root:x:0:0", "root:*:0:0"]),
    ("....//....//....//etc/passwd", ["root:x:0:0"]),
    ("..%2f..%2f..%2f..%2fetc%2fpasswd", ["root:x:0:0"]),
    ("..\\..\\..\\..\\windows\\win.ini", ["[fonts]", "[extensions]"]),
    ("/etc/passwd", ["root:x:0:0"]),
    ("..%5c..%5c..%5cwindows%5cwin.ini", ["[fonts]"]),
]


def _lfi(data: ParamInput) -> dict:
    url = _norm(data.url)
    guard_url(url)
    params = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
    if not params:
        raise HTTPException(status_code=400, detail="URL needs a query parameter, e.g. ?file=a.txt")
    findings, results = [], []
    for name in params:
        hit = None
        for payload, marks in LFI_PAYLOADS:
            try:
                r = _req(_replace_param(url, name, payload), timeout=12)
                txt = r.text or ""
                m = next((mk for mk in marks if mk in txt), None)
                if m:
                    hit = {"payload": payload, "marker": m}
                    break
            except Exception:
                continue
        results.append({"param": name, "lfi": bool(hit), "evidence": hit})
        if hit:
            findings.append(_finding("Local File Inclusion / Path Traversal", "high",
                                     f"File content disclosed via '{name}' ({hit['payload']}).",
                                     evidence=f"marker '{hit['marker']}' found",
                                     recommendation="Canonicalise paths and never pass user input to the filesystem."))
    return {"url": url, "params": list(params.keys()), "results": results, "findings": findings}


# --------------------------------------------------------------------------- Command injection
CMDI_PAYLOADS = [
    (";sleep 5", "time"), ("| sleep 5", "time"), ("$(sleep 5)", "time"), ("`sleep 5`", "time"),
    (";echo INSAFELABS_CMD_7x9", "echo"), ("| echo INSAFELABS_CMD_7x9", "echo"),
]


def _cmdi(data: ParamInput) -> dict:
    url = _norm(data.url)
    guard_url(url)
    params = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
    if not params:
        raise HTTPException(status_code=400, detail="URL needs a query parameter, e.g. ?host=1.2.3.4")
    base_r = _req(url, timeout=20)
    base_t = base_r.elapsed.total_seconds()
    findings, results = [], []
    for name in params:
        hit = None
        for payload, kind in CMDI_PAYLOADS:
            try:
                r = _req(_replace_param(url, name, payload), timeout=25)
            except Exception:
                continue
            if kind == "echo" and "INSAFELABS_CMD_7x9" in (r.text or ""):
                hit = {"payload": payload, "type": "echo"}
                break
            if kind == "time" and r.elapsed.total_seconds() > base_t + 4.0:
                hit = {"payload": payload, "type": "time", "delta_s": round(r.elapsed.total_seconds() - base_t, 2)}
                break
        results.append({"param": name, "cmdi": bool(hit), "evidence": hit, "baseline_s": round(base_t, 2)})
        if hit:
            findings.append(_finding("OS Command Injection", "critical",
                                     f"Command execution indicated via '{name}' ({hit['payload']}).",
                                     evidence=json.dumps(hit),
                                     recommendation="Never build shell commands from user input; use argument arrays/allowlists."))
    return {"url": url, "params": list(params.keys()), "results": results, "findings": findings}


# --------------------------------------------------------------------------- IOC extractor
IOC_RX = {
    "ipv4": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "url": r"https?://[^\s\"'<>\)]+",
    "email": r"\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b",
    "md5": r"\b[a-fA-F0-9]{32}\b",
    "sha1": r"\b[a-fA-F0-9]{40}\b",
    "sha256": r"\b[a-fA-F0-9]{64}\b",
    "cve": r"CVE-\d{4}-\d{4,7}",
    "jwt": r"\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,}\b",
    "btc": r"\b(bc1[a-z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b",
    "domain": r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|co|in|dev|app|cloud|info|biz|ru|cn|uk|de|xyz|top|site|online)\b",
}


class IocInput(BaseModel):
    text: str = Field(min_length=1, max_length=500000)


def _ioc(data: IocInput) -> dict:
    text = data.text
    out = {}
    for k, rx in IOC_RX.items():
        vals = sorted(set(m if isinstance(m, str) else m[0] for m in re.findall(rx, text, re.I)))
        out[k] = vals[:300]
    # dedupe domains that already appear inside URLs
    urls = set(out.get("url", []))
    out["domain"] = [d for d in out.get("domain", []) if not any(d in u for u in urls)][:300]
    total = sum(len(v) for v in out.values())
    return {"counts": {k: len(v) for k, v in out.items()}, "total": total, "iocs": out}


# --------------------------------------------------------------------------- input models
class UrlInput(BaseModel):
    url: str = Field(min_length=4, max_length=2048)


class DomainInput(BaseModel):
    domain: str = Field(min_length=3, max_length=253)


# --------------------------------------------------------------------------- Favicon fingerprint
def _mmh3_32(data: bytes, seed: int = 0) -> int:
    length = len(data)
    nblocks = length // 4
    h1 = seed & 0xFFFFFFFF
    c1, c2 = 0xCC9E2D51, 0x1B873593
    for i in range(nblocks):
        k1 = int.from_bytes(data[i * 4:i * 4 + 4], "little")
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF
    tail = data[nblocks * 4:]
    k1 = 0
    if len(tail) >= 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    return h1


def _favicon(data: UrlInput) -> dict:
    url = _norm(data.url)
    guard_url(url)
    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    candidates = []
    try:
        page = _req(url, timeout=12)
        m = re.search(r'<link[^>]+rel=["\'][^"\']*icon[^"\']*["\'][^>]*href=["\']([^"\']+)', page.text or "", re.I)
        if m:
            href = m.group(1)
            candidates.append(href if href.startswith("http") else base + ("/" + href.lstrip("/")))
    except Exception:
        pass
    candidates += [f"{base}/favicon.ico", f"{base}/favicon.png"]
    for u in candidates:
        try:
            r = _req(u, timeout=10)
            if r.status_code == 200 and r.content:
                content = r.content[:100000]
                b64 = base64.encodebytes(content)
                mm = _mmh3_32(b64)
                signed = mm - 0x100000000 if mm >= 0x80000000 else mm
                import hashlib
                return {"url": url, "favicon_url": u, "size": len(r.content), "content_type": r.headers.get("Content-Type"),
                        "md5": hashlib.md5(content).hexdigest(), "sha256": hashlib.sha256(content).hexdigest(),
                        "mmh3": mm, "shodan_hash": signed}
        except Exception:
            continue
    raise HTTPException(status_code=404, detail="No favicon found")


# --------------------------------------------------------------------------- CIDR / reverse-DNS sweep
class CidrInput(BaseModel):
    target: str = Field(min_length=3, max_length=64)
    limit: int = 256


def _ptr(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def _cidr_sweep(data: CidrInput) -> dict:
    t = (data.target or "").strip()
    guard_url("http://" + t.split("/")[0])
    try:
        net = ipaddress.ip_network(t, strict=False)
    except Exception:
        raise HTTPException(status_code=400, detail="Enter a CIDR, e.g. 192.168.1.0/24")
    limit = max(1, min(int(data.limit or 256), 1024))
    hosts = list(net.hosts())[:limit]
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        for ip, ptr in zip(hosts, ex.map(_ptr, [str(h) for h in hosts])):
            if ptr:
                results.append({"ip": str(ip), "ptr": ptr})
    return {"network": str(net), "scanned": len(hosts),
            "with_ptr": len(results), "results": results}


# --------------------------------------------------------------------------- OpenAPI / Swagger analyzer
def _openapi(data: UrlInput) -> dict:
    url = _norm(data.url)
    guard_url(url)
    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    cands = [url]
    base_paths = ["/openapi.json", "/swagger.json", "/api-docs", "/v3/api-docs", "/swagger/v1/swagger.json"]
    if not re.search(r"\.(json|yaml|yml)", url):
        cands += [base + p for p in base_paths]
    doc, found_at = None, None
    for u in cands:
        try:
            r = _req(u, timeout=12)
            if r.status_code != 200 or not r.content:
                continue
            txt = r.text or ""
            if txt.lstrip().startswith("{"):
                doc = r.json()
            else:
                try:
                    import yaml
                    doc = yaml.safe_load(txt)
                except Exception:
                    doc = None
            if isinstance(doc, dict) and ("paths" in doc or "swagger" in doc or "openapi" in doc):
                found_at = u
                break
            doc = None
        except Exception:
            continue
    if not doc:
        raise HTTPException(status_code=404, detail="No OpenAPI/Swagger spec found")
    paths = doc.get("paths") or {}
    endpoints = []
    no_auth = []
    for path, ops in paths.items():
        if not isinstance(ops, dict):
            continue
        for method, meta in ops.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete", "head", "options"):
                continue
            sec = meta.get("security") if isinstance(meta, dict) else None
            global_sec = doc.get("security")
            protected = bool(sec) or bool(global_sec)
            endpoints.append({"method": method.upper(), "path": path, "protected": protected,
                              "summary": (meta.get("summary") if isinstance(meta, dict) else "") or ""})
            if not protected:
                no_auth.append({"method": method.upper(), "path": path})
    findings = []
    if endpoints:
        findings.append(_finding("API schema exposed", "high",
                                 f"{len(endpoints)} endpoint(s) documented at {found_at}.",
                                 evidence=found_at, recommendation="Restrict API docs to authenticated/internal users."))
    if no_auth:
        findings.append(_finding("Endpoints without declared auth", "medium",
                                 f"{len(no_auth)} endpoint(s) have no security requirement in the spec.",
                                 evidence=json.dumps(no_auth[:10]),
                                 recommendation="Declare authentication requirements and enforce them server-side."))
    return {"spec_url": found_at, "title": doc.get("info", {}).get("title"),
            "version": doc.get("info", {}).get("version"),
            "endpoint_count": len(endpoints), "endpoints": endpoints[:300],
            "without_auth": no_auth[:100], "findings": findings}


# --------------------------------------------------------------------------- XXE
class XxeInput(BaseModel):
    url: str = Field(min_length=4, max_length=2048)


XXE_TEMPLATES = [
    ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>', ["root:x:0:0"]),
    ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><r>&xxe;</r>', ["[fonts]", "[extensions]"]),
]


def _xxe(data: XxeInput) -> dict:
    url = _norm(data.url)
    guard_url(url)
    results = []
    findings = []
    accepted = False
    for payload, marks in XXE_TEMPLATES:
        try:
            r = requests.post(url, data=payload, headers={**UA, "Content-Type": "application/xml"}, timeout=12, verify=False)
            accepted = accepted or r.status_code < 500
            txt = r.text or ""
            hit = next((m for m in marks if m in txt), None)
            results.append({"status": r.status_code, "hit": bool(hit), "marker": hit})
            if hit:
                findings.append(_finding("XML External Entity (XXE)", "critical",
                                         "External entity resolved — local file content disclosed.",
                                         evidence=f"marker '{hit}'", recommendation="Disable external entities / DTDs in the XML parser."))
                break
        except Exception as e:
            results.append({"error": str(e)[:120]})
    return {"url": url, "accepted_xml": accepted, "results": results, "findings": findings}


# --------------------------------------------------------------------------- routes
async def _run(fn, *args):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, fn, *args)


@router.post("/web-scan")
async def web_scan(data: UrlInput):
    return await _run(_web_scan, data.url)


@router.post("/injection")
async def injection(data: UrlInput):
    return await _run(_injection, data.url)


@router.post("/params")
async def params(data: UrlInput):
    return await _run(_params, data.url)


@router.post("/tls")
async def tls(data: HostInput):
    return await _run(_tls_scan, data.host)


@router.post("/dns")
async def dns(data: DomainInput):
    return await _run(_dns_scan, data.domain)


@router.post("/wordlist")
async def wordlist(data: WordlistInput):
    return await _run(_wordlist, data)


@router.post("/auth-form")
async def auth_form(data: UrlInput):
    return await _run(_auth_form, data.url)


@router.post("/rate-limit")
async def rate_limit(data: RateInput):
    return await _run(_rate_limit, data)


@router.post("/idor")
async def idor(data: IdorInput):
    return await _run(_idor, data)


@router.post("/ssti")
async def ssti(data: ParamInput):
    return await _run(_ssti, data)


@router.post("/lfi")
async def lfi(data: ParamInput):
    return await _run(_lfi, data)


@router.post("/cmdi")
async def cmdi(data: ParamInput):
    return await _run(_cmdi, data)


@router.post("/ioc")
async def ioc(data: IocInput):
    return await _run(_ioc, data)


@router.post("/favicon")
async def favicon(data: UrlInput):
    return await _run(_favicon, data)


@router.post("/cidr")
async def cidr(data: CidrInput):
    return await _run(_cidr_sweep, data)


@router.post("/openapi")
async def openapi(data: UrlInput):
    return await _run(_openapi, data)


@router.post("/xxe")
async def xxe(data: XxeInput):
    return await _run(_xxe, data)


@router.post("/vhost")
async def vhost(data: VhostInput):
    return await _run(_vhost, data)
