"""InsafeLabs Bug Bounty Engine — automated recon → vuln → report pipeline.

One target domain in → passive subdomain enum (crt.sh + DNS brute) → live host probing
(status/title/tech/WAF) → per-host automated vuln checks (security headers, cookie flags,
CORS misconfig, subdomain takeover, exposed files, directory listing, open redirect,
reflected-XSS probe) → JS recon (hidden endpoints + leaked secrets) → severity-scored
findings board → AI-written HackerOne/Bugcrowd-style report (Markdown + PDF).

FOR AUTHORIZED / IN-SCOPE TARGETS ONLY. The hosted backend reaches only the public internet.
"""
import io
import re
import json
import uuid
import asyncio
import zipfile
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import httpx
import dns.asyncresolver
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from db import db
import ai
import recon_lib

router = APIRouter(prefix="/bugbounty", tags=["bugbounty"])

UA = "Mozilla/5.0 (compatible; InsafeLabs-BugBounty/1.0; authorized-testing)"
MAX_SUBS = 100
DEEP_HOSTS = 25
EVIL = "https://evil-insafe.example"
XSS_PAYLOAD = "insafe7xss\"'><svg/onload=alert(1)>"

COMMON_SUBS = [
    "www", "mail", "dev", "staging", "test", "api", "admin", "portal", "app", "beta", "vpn", "m",
    "blog", "shop", "cdn", "assets", "static", "img", "dashboard", "secure", "gateway", "auth", "sso",
    "git", "gitlab", "jenkins", "jira", "confluence", "status", "docs", "support", "help", "store",
    "payments", "pay", "internal", "corp", "cpanel", "webmail", "autodiscover", "ns1", "ns2", "smtp",
    "ftp", "backup", "db", "demo", "uat", "qa", "stage", "preprod", "prod", "new", "old", "legacy",
    "mobile", "graphql", "ws", "socket", "cloud", "console", "monitor", "grafana", "kibana",
]

TAKEOVER_FP = {
    "github.io": "There isn't a GitHub Pages site here",
    "herokuapp": "No such app",
    "s3.amazonaws": "NoSuchBucket",
    "azurewebsites": "404 Web Site not found",
    "cloudapp.net": "404 Web Site not found",
    "wordpress.com": "Do you want to register",
    "pantheonsite.io": "The gods are wise",
    "ghost.io": "The thing you were looking for is no longer here",
    "shopify": "Sorry, this shop is currently unavailable",
    "surge.sh": "project not found",
    "bitbucket.io": "Repository not found",
    "readthedocs.io": "unknown to Read the Docs",
    "helpscoutdocs": "No settings were found for this company",
    "fastly.net": "Fastly error: unknown domain",
    "wpengine": "The site you were looking for couldn't be found",
    "tumblr.com": "There's nothing here.",
}

SEC_HEADERS = {
    "content-security-policy": "Content-Security-Policy",
    "strict-transport-security": "Strict-Transport-Security (HSTS)",
    "x-frame-options": "X-Frame-Options (clickjacking)",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}

EXPOSED_FILES = [
    ("/.git/config", "[core]", 8.2, ".git repository exposed (source disclosure)"),
    ("/.git/HEAD", "ref:", 8.2, ".git repository exposed (source disclosure)"),
    ("/.env", None, 9.1, ".env environment file exposed"),
    ("/.DS_Store", "Bud1", 3.5, ".DS_Store directory metadata exposed"),
    ("/.svn/entries", None, 6.0, ".svn metadata exposed"),
    ("/phpinfo.php", "phpinfo()", 5.5, "phpinfo() page exposed"),
    ("/server-status", "Apache Server Status", 5.0, "Apache server-status exposed"),
    ("/wp-config.php.bak", "DB_PASSWORD", 9.1, "WordPress config backup exposed"),
    ("/backup.zip", "PK", 7.0, "backup.zip exposed"),
    ("/.aws/credentials", "aws_access_key", 9.4, "AWS credentials file exposed"),
]
REDIRECT_PARAMS = ["next", "url", "redirect", "return", "returnurl", "dest", "continue", "u"]

# ---- API recon config ----
API_SPEC_PATHS = [
    "/swagger.json", "/openapi.json", "/v2/api-docs", "/v3/api-docs", "/api-docs",
    "/swagger/v1/swagger.json", "/api/swagger.json", "/api/openapi.json", "/swagger/doc.json",
    "/api-docs/swagger.json", "/.well-known/openapi.json", "/api/v1/swagger.json", "/openapi.yaml",
    "/swagger/v2/swagger.json", "/docs/swagger.json",
    "/v2/swagger.json", "/v3/swagger.json", "/spec.json", "/apispec.json", "/apispec_1.json",
    "/api/v3/openapi.json", "/v3/openapi.json", "/api/v2/openapi.json", "/api/docs.json",
    "/swagger/swagger.json", "/api/swagger/swagger.json",
]
GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/query", "/gql"]
API_HINTS = ("/api/", "/api.", "/v1/", "/v2/", "/v3/", "/rest/", "/graphql", "/query", "/oauth",
             "/token", "/auth/", "/users", "/user/", "/account", "/admin", "/internal", "/gateway",
             "/service", "/webhook", "/callback", "/session")


def _now():
    return datetime.now(timezone.utc).isoformat()


def _esc(s):
    return str(s if s is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _finding(host, ftype, title, cvss, detail, evidence="", remediation=""):
    return {
        "id": str(uuid.uuid4()), "host": host, "type": ftype, "title": title,
        "cvss": round(float(cvss), 1), "severity": recon_lib.severity_from_cvss(float(cvss)),
        "detail": detail, "evidence": (evidence or "")[:500], "remediation": remediation,
    }


def _count(findings):
    c = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        s = f.get("severity", "info")
        if s in c:
            c[s] += 1
    return c


# ---------------------------------------------------------------- recon helpers
async def _crtsh(domain):
    subs = set()
    try:
        async with httpx.AsyncClient(timeout=25, headers={"User-Agent": UA, "Accept": "application/json"}) as c:
            r = await c.get(f"https://crt.sh/?q=%25.{domain}&output=json")
            if r.status_code == 200 and r.text.strip().startswith("["):
                for row in r.json():
                    for nm in (row.get("name_value") or "").split("\n"):
                        nm = nm.strip().lower().lstrip("*.")
                        if nm.endswith("." + domain) or nm == domain:
                            if " " not in nm and "@" not in nm:
                                subs.add(nm)
    except Exception:
        pass
    return subs


async def _dns_brute(domain):
    found = set()
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3
    sem = asyncio.Semaphore(30)

    async def check(sub):
        host = f"{sub}.{domain}"
        async with sem:
            try:
                await resolver.resolve(host, "A")
                found.add(host)
            except Exception:
                pass
    await asyncio.gather(*[check(s) for s in COMMON_SUBS])
    return found


async def _cname(host):
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 4
        ans = await resolver.resolve(host, "CNAME")
        return str(ans[0].target).rstrip(".").lower()
    except Exception:
        return ""


def _fingerprint(r):
    h = {k.lower(): (v or "").lower() for k, v in r.headers.items()}
    body = r.text[:40000].lower()
    server = h.get("server", "")
    powered = h.get("x-powered-by", "")
    cookie = h.get("set-cookie", "")
    sig = {
        "WordPress": "wp-content" in body or "wp-includes" in body,
        "Next.js": "/_next/" in body or "__next" in body,
        "React": 'id="root"' in body or "react" in body,
        "Vue": "__vue__" in body or "data-v-" in body,
        "Nginx": "nginx" in server,
        "Apache": "apache" in server,
        "PHP": "php" in powered or ".php" in body,
        "Laravel": "laravel_session" in cookie,
        "Django": "csrftoken" in cookie or "django" in powered,
        "IIS/ASP.NET": "iis" in server or "asp.net" in powered,
        "Express": "express" in powered,
    }
    return [k for k, v in sig.items() if v][:6]


def _waf(r):
    h = {k.lower(): (v or "").lower() for k, v in r.headers.items()}
    keys = " ".join(h.keys())
    vals = " ".join(h.values())
    if "cf-ray" in keys or "cloudflare" in vals:
        return "Cloudflare"
    if "x-amz-cf-id" in keys or "cloudfront" in vals:
        return "AWS CloudFront"
    if "x-sucuri" in keys:
        return "Sucuri"
    if "incap_ses" in keys or "x-iinfo" in keys:
        return "Imperva Incapsula"
    if "akamai" in vals or "x-akamai-transformed" in keys:
        return "Akamai"
    if "x-fastly" in keys or "fastly" in vals:
        return "Fastly"
    return ""


async def _probe(host, client):
    for scheme in ("https", "http"):
        try:
            r = await client.get(f"{scheme}://{host}", follow_redirects=True)
            title = ""
            m = re.search(r"<title[^>]*>(.*?)</title>", r.text[:60000], re.I | re.S)
            if m:
                title = re.sub(r"\s+", " ", m.group(1)).strip()[:120]
            return {
                "host": host, "url": str(r.url), "scheme": scheme, "status": r.status_code,
                "title": title, "server": r.headers.get("server", "")[:80],
                "tech": _fingerprint(r), "waf": _waf(r), "clen": len(r.content),
            }
        except Exception:
            continue
    return None


# ---------------------------------------------------------------- vuln checks
async def _deep_checks(hi, client):
    host = hi["host"]
    base = hi["url"].rstrip("/")
    findings = []
    try:
        root = await client.get(base + "/", follow_redirects=False, headers={"Origin": EVIL})
    except Exception:
        return findings
    h = {k.lower(): v for k, v in root.headers.items()}

    missing = [SEC_HEADERS[k] for k in SEC_HEADERS if k not in h]
    if missing and root.status_code < 500:
        findings.append(_finding(host, "headers", "Missing security headers", 3.7,
                                 "Missing: " + ", ".join(missing),
                                 evidence=", ".join(sorted(h.keys()))[:400],
                                 remediation="Add the missing HTTP response security headers."))

    setc = root.headers.get("set-cookie", "")
    if setc:
        low = setc.lower()
        probs = [x for x, k in (("HttpOnly", "httponly"), ("Secure", "secure"), ("SameSite", "samesite")) if k not in low]
        if probs:
            findings.append(_finding(host, "cookie", "Weak session cookie flags", 4.0,
                                     "Missing: " + ", ".join(probs), evidence=setc[:300],
                                     remediation="Set HttpOnly, Secure and SameSite on session cookies."))

    acao = h.get("access-control-allow-origin", "")
    acac = (h.get("access-control-allow-credentials", "") or "").lower()
    if acao == EVIL or (acao == "*" and acac == "true"):
        cvss = 8.1 if acac == "true" else 5.3
        findings.append(_finding(host, "cors", "CORS misconfiguration", cvss,
                                 f"ACAO reflects arbitrary origin (credentials={acac or 'false'}).",
                                 evidence=f"ACAO: {acao} · ACAC: {acac}",
                                 remediation="Whitelist trusted origins; never reflect arbitrary Origin with credentials."))

    try:
        xr = await client.get(base + "/", params={"q": XSS_PAYLOAD}, follow_redirects=True)
        if XSS_PAYLOAD in xr.text or "<svg/onload=alert(1)>" in xr.text:
            findings.append(_finding(host, "xss", "Reflected input without encoding (potential XSS)", 6.1,
                                     "Injected marker reflected unencoded in the response body.",
                                     evidence=XSS_PAYLOAD,
                                     remediation="Context-encode all reflected user input; add a strict CSP."))
    except Exception:
        pass

    for p in REDIRECT_PARAMS:
        try:
            rr = await client.get(base + "/", params={p: EVIL + "/"}, follow_redirects=False)
            loc = rr.headers.get("location", "")
            if rr.status_code in (301, 302, 303, 307, 308) and "evil-insafe.example" in loc[:80]:
                findings.append(_finding(host, "redirect", "Open redirect", 5.4,
                                         f"Parameter '{p}' redirects to an external, attacker-controlled URL.",
                                         evidence=f"Location: {loc[:200]}",
                                         remediation="Validate redirect targets against an allowlist."))
                break
        except Exception:
            pass

    soft404, baseline = False, ""
    try:
        b = await client.get(base + "/insafe_nope_" + uuid.uuid4().hex[:8], follow_redirects=False)
        soft404 = (b.status_code == 200)
        baseline = b.text[:200]
    except Exception:
        pass

    for path, sig, cvss, label in EXPOSED_FILES:
        try:
            fr = await client.get(base + path, follow_redirects=False)
            if fr.status_code != 200:
                continue
            body = fr.text
            if sig and sig.lower() not in body.lower():
                continue
            if not sig and ("<html" in body[:200].lower() or "<!doctype" in body[:200].lower()):
                continue
            if soft404 and body[:200] == baseline:
                continue
            findings.append(_finding(host, "exposure", label, cvss,
                                     f"{path} returned HTTP 200 with the expected signature.",
                                     evidence=body[:200],
                                     remediation=f"Block public access to {path}."))
        except Exception:
            pass

    try:
        dl = await client.get(base + "/", follow_redirects=True)
        if "<title>index of /" in dl.text[:2000].lower() or ">index of /<" in dl.text[:2000].lower():
            findings.append(_finding(host, "listing", "Directory listing enabled", 4.3,
                                     "Server returns an auto-generated directory index.",
                                     evidence="Index of /", remediation="Disable automatic directory indexing."))
    except Exception:
        pass

    try:
        cn = await _cname(host)
        if cn:
            for prov, fp in TAKEOVER_FP.items():
                if prov in cn and fp.lower() in (root.text or "").lower():
                    findings.append(_finding(host, "takeover", "Possible subdomain takeover", 8.0,
                                             f"CNAME → {cn} ({prov}); page shows an unclaimed-service fingerprint.",
                                             evidence=fp,
                                             remediation="Remove the dangling DNS record or reclaim the service."))
                    break
    except Exception:
        pass
    return findings


# ---------------------------------------------------------------- JS recon
API_HINT_TOKENS = ("/api/", "/api.", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/", "/query",
                   "/admin", "/user", "/users", "/auth", "/oauth", "/token", "/upload",
                   "/internal", "/private", "/secret", "/config", "/account", "/session",
                   "/webhook", "/callback", "/gateway", "/service")

ADMIN_PATH_RX = re.compile(
    r'/(?:admin|administrator|admin-?panel|adminpanel|wp-admin|wp-login|dashboard|console|'
    r'manage(?:ment)?|backoffice|back-office|backend|cpanel|control-?panel|superadmin|'
    r'sysadmin|staff|moderator|operator|_admin|admin-?api|api/admin|portal/admin)'
    r'(?:/[a-z0-9_\-]+){0,4}', re.I)

FLAG_LIB_RX = re.compile(
    r'(launchdarkly|ld-?client|split\.io|splitio|optimizely|unleash|flagsmith|posthog|'
    r'configcat|growthbook|statsig|featureflag|feature-flag)', re.I)
FLAG_KEY_RX = re.compile(
    r'["\']([a-zA-Z0-9_.\-]{0,30}(?:feature[_.-]?flag|feature[_.-]?toggle|is[_.-]?enabled|'
    r'enable[_.-][a-z0-9]|ff[_.-][a-z0-9]|flag[_.-][a-z0-9])[a-zA-Z0-9_.\-]{0,30})["\']', re.I)

DOMAIN_RX = re.compile(r'https?://([a-z0-9][a-z0-9.\-]{2,100}\.[a-z]{2,})', re.I)
PRIVATE_HOST_RX = re.compile(
    r'\b(?:localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|'
    r'172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|[a-z0-9\-]+(?:\.[a-z0-9\-]+)*\.(?:local|internal|intranet))\b', re.I)
INTERNAL_LABELS = {"staging", "stage", "dev", "devel", "development", "qa", "uat", "preprod",
                   "preprd", "preview", "internal", "intranet", "corp", "sandbox", "test",
                   "testing", "nonprod", "local", "svc", "demo"}

SRCMAP_RX = re.compile(r'//[#@]\s*sourceMappingURL=([^\s\'"<>]+\.map)', re.I)

LIB_VULNS = [
    ("jQuery UI", r'jquery[.\-]ui[@/_\-](\d+\.\d+(?:\.\d+)?)', "1.13.2", 6.1, "jQuery UI XSS in widgets (CVE-2022-31160)"),
    ("jQuery", r'jquery[@/_\-](\d+\.\d+(?:\.\d+)?)', "3.5.0", 6.1, "jQuery <3.5.0 XSS via htmlPrefilter (CVE-2020-11022/11023)"),
    ("Lodash", r'lodash[@/_\-](\d+\.\d+(?:\.\d+)?)', "4.17.21", 7.4, "Lodash <4.17.21 prototype pollution / command injection (CVE-2021-23337)"),
    ("AngularJS", r'angular(?:js)?[@/_\-](1\.\d+(?:\.\d+)?)', "1.8.3", 6.1, "AngularJS <1.8.3 multiple XSS / ReDoS"),
    ("Bootstrap", r'bootstrap[@/_\-](\d+\.\d+(?:\.\d+)?)', "4.3.1", 6.1, "Bootstrap <4.3.1 XSS in data-* attributes (CVE-2019-8331)"),
    ("Moment.js", r'moment[@/_\-](\d+\.\d+(?:\.\d+)?)', "2.29.4", 7.5, "Moment.js <2.29.4 path traversal / ReDoS (CVE-2022-24785)"),
    ("Axios", r'axios[@/_\-](\d+\.\d+(?:\.\d+)?)', "1.6.0", 7.5, "Axios <1.6.0 SSRF / token leak / ReDoS (CVE-2023-45857)"),
    ("DOMPurify", r'dompurify[@/_\-](\d+\.\d+(?:\.\d+)?)', "3.0.9", 6.1, "DOMPurify mXSS sanitizer bypass"),
    ("Handlebars", r'handlebars[@/_\-](\d+\.\d+(?:\.\d+)?)', "4.7.7", 8.1, "Handlebars <4.7.7 prototype pollution / RCE"),
    ("Vue.js", r'vue[@/_\-](2\.\d+(?:\.\d+)?)', "2.7.16", 5.3, "Vue 2 <2.7.16 ReDoS in template parser"),
    ("Select2", r'select2[@/_\-](\d+\.\d+(?:\.\d+)?)', "4.0.6", 6.1, "Select2 <4.0.6 XSS"),
]


def _vtuple(v):
    parts = re.findall(r'\d+', v)[:3]
    return tuple(int(x) for x in parts) + (0,) * (3 - len(parts))


def _older(found, fixed):
    try:
        return _vtuple(found) < _vtuple(fixed)
    except Exception:
        return False


def _is_internal_host(host):
    host = host.lower().strip(".")
    if PRIVATE_HOST_RX.search(host):
        return True
    labels = re.split(r'[.\-]', host)
    return any(l in INTERNAL_LABELS for l in labels)


def _detect_libs(text, source, libs):
    for name, rx, fixed, cvss, note in LIB_VULNS:
        m = re.search(rx, text, re.I)
        if not m:
            continue
        ver = m.group(1)
        vulnerable = _older(ver, fixed)
        key = f"{name}:{ver}"
        if key not in libs or (vulnerable and not libs[key].get("vulnerable")):
            libs[key] = {"name": name, "version": ver, "fixed": fixed, "cvss": cvss,
                         "note": note, "vulnerable": vulnerable, "source": source[:140]}


async def _js_recon(live, client, target):
    endpoints, secrets = set(), []
    admin_urls, flags, internal = set(), set(), set()
    libs, srcmaps, seen_maps = {}, [], set()

    def scan_text(text, base, source):
        for m in re.findall(r'["\'](/[a-zA-Z0-9_\-/.]{2,90})["\']', text):
            if any(x in m for x in API_HINT_TOKENS):
                endpoints.add(m)
        for name, cvss, rx in recon_lib.SECRET_PATTERNS:
            for mt in rx.findall(text):
                val = mt if isinstance(mt, str) else (mt[0] if mt else "")
                if val:
                    secrets.append({"type": name, "match": str(val)[:80], "cvss": cvss, "source": source[:140]})
        for m in ADMIN_PATH_RX.findall(text):
            p = m if m.startswith("/") else "/" + m
            admin_urls.add(base + p[:120])
        for m in FLAG_KEY_RX.findall(text):
            flags.add(m[:60])
        for m in FLAG_LIB_RX.findall(text):
            flags.add("[sdk] " + m.lower())
        for host in DOMAIN_RX.findall(text):
            if _is_internal_host(host):
                internal.add(host.lower())
        for m in PRIVATE_HOST_RX.findall(text):
            internal.add(m.lower())
        _detect_libs(text, source, libs)

    for hi in live[:4]:
        base = hi["url"].rstrip("/")
        try:
            r = await client.get(base + "/", follow_redirects=True)
        except Exception:
            continue
        scan_text(r.text, base, base)
        js_urls = []
        for s in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', r.text, re.I)[:30]:
            u = urljoin(base + "/", s)
            if u.startswith("http"):
                js_urls.append(u)
        for ju in js_urls[:14]:
            _detect_libs(ju, ju, libs)  # versioned filename (e.g. jquery-3.4.1.min.js)
            try:
                jr = await client.get(ju, follow_redirects=True)
            except Exception:
                continue
            if jr.status_code != 200 or len(jr.content) >= 3_000_000:
                continue
            scan_text(jr.text, base, ju)
            if len(srcmaps) < 25:
                cands = []
                sm = SRCMAP_RX.search(jr.text[-3000:])
                if sm:
                    cands.append(urljoin(ju, sm.group(1)))
                cands.append(ju + ".map")
                for cu in cands:
                    if cu in seen_maps or cu.startswith("data:"):
                        continue
                    seen_maps.add(cu)
                    try:
                        mr = await client.get(cu, follow_redirects=True)
                        if mr.status_code == 200 and '"sources"' in mr.text[:8000] and '"version"' in mr.text[:400]:
                            try:
                                srcs = (mr.json().get("sources") or [])
                            except Exception:
                                srcs = []
                            srcmaps.append({"url": cu, "sources_count": len(srcs),
                                            "sample": [str(x)[:80] for x in srcs[:8]]})
                            break
                    except Exception:
                        pass

    # probe admin panels for accessibility (GET, no redirect-follow → 200 = potentially open)
    admin_list = []
    sem = asyncio.Semaphore(10)

    async def probe_admin(au):
        async with sem:
            try:
                ar = await client.get(au, follow_redirects=False)
                return {"url": au, "status": ar.status_code, "exposed": ar.status_code == 200}
            except Exception:
                return {"url": au, "status": None, "exposed": False}
    admin_targets = sorted(admin_urls)[:30]
    if admin_targets:
        admin_list = list(await asyncio.gather(*[probe_admin(a) for a in admin_targets]))
        admin_list.sort(key=lambda x: (not x["exposed"], x["url"]))

    seen, uniq = set(), []
    for s in secrets:
        k = (s["type"], s["match"])
        if k not in seen:
            seen.add(k)
            uniq.append(s)

    lib_list = sorted(libs.values(), key=lambda l: (not l["vulnerable"], l["name"]))
    return {
        "endpoints": sorted(endpoints)[:150],
        "secrets": uniq[:60],
        "admin_panels": admin_list[:40],
        "feature_flags": sorted(flags)[:60],
        "internal_domains": sorted(internal)[:60],
        "libraries": lib_list[:40],
        "source_maps": srcmaps[:25],
    }


# ---------------------------------------------------------------- API recon
def _looks_api(u):
    return u.endswith(".json") or any(x in u for x in API_HINTS)


def _parse_openapi(spec, origin):
    out = []
    base = origin
    servers = spec.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        s0 = servers[0].get("url", "")
        if s0.startswith("http"):
            base = s0.rstrip("/")
        elif s0.startswith("/"):
            base = origin + s0.rstrip("/")
    bp = (spec.get("basePath") or "")
    prefix = (base + bp).rstrip("/")
    for p, methods in (spec.get("paths") or {}).items():
        if not isinstance(methods, dict):
            continue
        path = p if str(p).startswith("/") else "/" + str(p)
        for method, info in methods.items():
            if method.lower() not in ("get", "post", "put", "delete", "patch"):
                continue
            params = []
            summary = ""
            if isinstance(info, dict):
                summary = (info.get("summary") or info.get("operationId") or "")[:120]
                for pr in (info.get("parameters") or []):
                    if isinstance(pr, dict) and pr.get("name"):
                        params.append(pr["name"])
            out.append({"method": method.upper(), "url": prefix + path, "params": params[:12], "summary": summary})
    return out[:250]


def _addurl(u, method, base, origin, target, source, add):
    if not u or u.startswith(("data:", "mailto:", "javascript:", "tel:", "#")):
        return
    if u.startswith("//"):
        u = "https:" + u
    if u.startswith("http"):
        full = u
        net = urlparse(full).netloc.lower()
        if net and not (net == target or net.endswith("." + target)):
            return  # skip third-party (out of scope)
    else:
        full = urljoin(base + "/", u)
    if full.startswith("http"):
        add(method, full.split("#")[0][:300], source)


def _harvest(text, base, origin, target, add):
    for m in re.finditer(r'fetch\(\s*[`"\']([^`"\']+)[`"\'](?:\s*,\s*\{[^}]*?method\s*:\s*[`"\']([A-Za-z]+))?', text):
        _addurl(m.group(1), (m.group(2) or "GET").upper(), base, origin, target, "js-fetch", add)
    for m in re.finditer(r'axios\.(get|post|put|delete|patch)\(\s*[`"\']([^`"\']+)', text, re.I):
        _addurl(m.group(2), m.group(1).upper(), base, origin, target, "js-axios", add)
    for m in re.finditer(r'\.open\(\s*[`"\']([A-Z]+)[`"\']\s*,\s*[`"\']([^`"\']+)', text):
        _addurl(m.group(2), m.group(1).upper(), base, origin, target, "js-xhr", add)
    for m in re.findall(r'[`"\'](https?://[^`"\'\s<>]+|/[a-zA-Z0-9_\-/.{}$]{2,90})[`"\']', text):
        if _looks_api(m):
            _addurl(m, "GET", base, origin, target, "js-url", add)


async def _api_recon(live, client, target):
    inventory = {}
    findings = []
    specs = []

    def add(method, url, source, params=None, summary=""):
        key = f"{method} {url}"
        if key not in inventory:
            inventory[key] = {"method": method, "url": url, "source": source, "status": None,
                              "content_type": "", "is_json": False, "auth": None,
                              "params": params or [], "summary": summary}

    for hi in live[:5]:
        base = hi["url"].rstrip("/")
        host = hi["host"]
        # 1) OpenAPI/Swagger spec discovery
        for sp in API_SPEC_PATHS:
            try:
                r = await client.get(base + sp, follow_redirects=True)
                if r.status_code == 200 and (("json" in r.headers.get("content-type", "")) or r.text.strip()[:1] == "{"):
                    try:
                        spec = r.json()
                    except Exception:
                        continue
                    if isinstance(spec, dict) and (spec.get("swagger") or spec.get("openapi") or spec.get("paths")):
                        specs.append(base + sp)
                        findings.append(_finding(host, "api-spec", "Exposed API specification (Swagger/OpenAPI)", 5.0,
                                                 f"Machine-readable API spec publicly accessible at {sp}.",
                                                 evidence=base + sp,
                                                 remediation="Restrict API documentation/specs in production."))
                        for ep in _parse_openapi(spec, base):
                            add(ep["method"], ep["url"], "openapi", ep["params"], ep["summary"])
            except Exception:
                pass
        # 2) GraphQL introspection
        for gp in GRAPHQL_PATHS:
            try:
                r = await client.post(base + gp, json={"query": "{__schema{queryType{name}}}"}, follow_redirects=True)
                if r.status_code == 200 and "__schema" in r.text:
                    findings.append(_finding(host, "graphql", "GraphQL introspection enabled", 5.4,
                                             f"Introspection query succeeded at {gp} — full schema is disclosed.",
                                             evidence=base + gp,
                                             remediation="Disable GraphQL introspection in production."))
                    add("POST", base + gp, "graphql")
            except Exception:
                pass
        # 3) JS + HTML harvest
        try:
            r = await client.get(base + "/", follow_redirects=True)
            _harvest(r.text, base, base, target, add)
            js_urls = [urljoin(base + "/", s) for s in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', r.text, re.I)[:30]]
            for ju in [u for u in js_urls if u.startswith("http")][:15]:
                try:
                    jr = await client.get(ju, follow_redirects=True)
                    if jr.status_code == 200 and len(jr.content) < 2_500_000:
                        _harvest(jr.text, base, base, target, add)
                except Exception:
                    pass
            for fm in re.findall(r'<form[^>]*>', r.text, re.I)[:30]:
                act = re.search(r'action=["\']([^"\']+)["\']', fm, re.I)
                mth = re.search(r'method=["\']([^"\']+)["\']', fm, re.I)
                if act:
                    _addurl(act.group(1), (mth.group(1).upper() if mth else "GET"), base, base, target, "html-form", add)
            for rp in ("/robots.txt", "/sitemap.xml"):
                try:
                    rr = await client.get(base + rp, follow_redirects=True)
                    if rr.status_code == 200:
                        for m in re.findall(r'(/[a-zA-Z0-9_\-/.]{2,80})', rr.text)[:250]:
                            if _looks_api(m):
                                _addurl(m, "GET", base, base, target, "robots/sitemap", add)
                except Exception:
                    pass
        except Exception:
            pass

    # probe GET endpoints (safe — never fires POST/PUT/DELETE)
    records = list(inventory.values())
    get_eps = [r for r in records if r["method"] == "GET"][:70]
    sem = asyncio.Semaphore(12)

    async def probe(rec):
        async with sem:
            try:
                pr = await client.get(rec["url"], follow_redirects=True)
                rec["status"] = pr.status_code
                ct = pr.headers.get("content-type", "")
                rec["content_type"] = ct[:60]
                rec["is_json"] = ("json" in ct) or pr.text.strip()[:1] in ("{", "[")
                rec["auth"] = pr.status_code in (401, 403)
            except Exception:
                pass
    await asyncio.gather(*[probe(r) for r in get_eps])

    for rec in get_eps:
        if rec["status"] == 200 and rec["is_json"] and not rec["auth"]:
            host = urlparse(rec["url"]).netloc or rec["url"]
            findings.append(_finding(host, "api-exposure", "Unauthenticated API endpoint returns data", 4.5,
                                     f"GET {rec['url']} returned JSON (HTTP 200) without authentication.",
                                     evidence=rec["url"],
                                     remediation="Enforce authentication/authorization on data-returning APIs."))

    inv = sorted(records, key=lambda r: (r["method"], r["url"]))[:300]
    return {"inventory": inv, "specs": specs, "api_count": len(inv), "findings": findings}


# ---------------------------------------------------------------- orchestrator
async def _set(scan_id, **fields):
    await db.bugbounty_scans.update_one({"id": scan_id}, {"$set": fields})


async def _compute_diff(target, current_id, subs, live, api_inv, libs):
    """Diff this scan against the most recent previous completed scan of the same domain."""
    prev = await db.bugbounty_scans.find_one(
        {"target": target, "status": "done", "id": {"$ne": current_id}},
        {"_id": 0, "id": 1, "subdomains": 1, "live_hosts": 1, "api_inventory": 1,
         "js_recon": 1, "created_at": 1, "done_at": 1},
        sort=[("created_at", -1)])
    if not prev:
        return None
    p_subs = set(prev.get("subdomains") or [])
    p_hosts = {h.get("url") for h in (prev.get("live_hosts") or []) if h.get("url")}
    p_apis = {f'{a.get("method")} {a.get("url")}' for a in (prev.get("api_inventory") or [])}
    p_libs = {f'{l.get("name")} {l.get("version")}' for l in ((prev.get("js_recon") or {}).get("libraries") or [])}

    c_subs = set(subs)
    c_hosts = {h.get("url") for h in live if h.get("url")}
    c_apis = {f'{a.get("method")} {a.get("url")}' for a in api_inv}
    c_libs = {f'{l.get("name")} {l.get("version")}' for l in libs}

    new_subs = sorted(c_subs - p_subs)
    new_hosts = sorted(c_hosts - p_hosts)
    new_apis = sorted(c_apis - p_apis)
    new_libs = sorted(c_libs - p_libs)
    return {
        "baseline_id": prev.get("id"),
        "baseline_date": prev.get("done_at") or prev.get("created_at"),
        "new_subdomains": new_subs,
        "removed_subdomains": sorted(p_subs - c_subs),
        "new_hosts": new_hosts,
        "new_apis": new_apis[:200],
        "new_libraries": new_libs,
        "counts": {"new_subdomains": len(new_subs), "removed_subdomains": len(p_subs - c_subs),
                   "new_hosts": len(new_hosts), "new_apis": len(new_apis), "new_libraries": len(new_libs)},
    }


async def run_scan(scan_id, target):
    try:
        await _set(scan_id, status="running", stage="subdomains", progress=5)
        subs = {target}
        subs |= await _crtsh(target)
        subs |= await _dns_brute(target)
        subs = sorted(subs)[:MAX_SUBS]
        await _set(scan_id, subdomains=subs, sub_count=len(subs), stage="probing", progress=25)

        limits = httpx.Limits(max_connections=25, max_keepalive_connections=10)
        async with httpx.AsyncClient(verify=False, timeout=httpx.Timeout(7.0, connect=5.0),
                                     headers={"User-Agent": UA}, limits=limits,
                                     follow_redirects=False) as client:
            sem = asyncio.Semaphore(20)

            async def pr(hh):
                async with sem:
                    return await _probe(hh, client)
            probed = await asyncio.gather(*[pr(s) for s in subs])
            live = [p for p in probed if p]
            live.sort(key=lambda x: (x["status"] >= 400, x["host"]))
            await _set(scan_id, live_hosts=live, live_count=len(live), stage="vuln_checks", progress=55)

            findings = []
            sem2 = asyncio.Semaphore(10)

            async def dc(hi):
                async with sem2:
                    return await _deep_checks(hi, client)
            for rf in await asyncio.gather(*[dc(hi) for hi in live[:DEEP_HOSTS]]):
                findings.extend(rf)
            findings.sort(key=lambda x: x["cvss"], reverse=True)
            await _set(scan_id, findings=findings, finding_count=len(findings),
                       counts=_count(findings), stage="js_recon", progress=80)

            js = await _js_recon(live, client, target)
            for s in js["secrets"]:
                findings.append(_finding(s["source"], "js-secret", f"Secret leaked in JavaScript: {s['type']}",
                                         s.get("cvss", 7.0), f"{s['type']} found in client-side JS.",
                                         evidence=s["match"],
                                         remediation="Rotate the key immediately and remove it from client-side code."))
            for sm in js["source_maps"]:
                findings.append(_finding(urlparse(sm["url"]).netloc, "sourcemap",
                                         "Exposed JavaScript source map (source code disclosure)", 5.3,
                                         f"{sm['url']} exposes {sm['sources_count']} original source files, revealing app internals.",
                                         evidence=", ".join(sm.get("sample", []))[:400],
                                         remediation="Do not ship .map files to production, or block public access to them."))
            for lib in js["libraries"]:
                if lib.get("vulnerable"):
                    findings.append(_finding(lib.get("source") or target, "vuln-lib",
                                             f"Outdated/vulnerable library: {lib['name']} {lib['version']}", lib.get("cvss", 6.1),
                                             lib.get("note", ""),
                                             evidence=f"{lib['name']} {lib['version']} — fixed in {lib['fixed']}",
                                             remediation=f"Upgrade {lib['name']} to {lib['fixed']} or later."))
            for ap in js["admin_panels"]:
                if ap.get("exposed"):
                    findings.append(_finding(urlparse(ap["url"]).netloc, "admin-panel",
                                             "Exposed admin/management interface", 5.3,
                                             f"{ap['url']} returned HTTP {ap['status']} — verify it is not an unauthenticated admin panel.",
                                             evidence=ap["url"],
                                             remediation="Restrict admin interfaces to trusted networks and enforce authentication."))
            if js["internal_domains"]:
                findings.append(_finding(target, "internal-leak",
                                         "Internal/staging hostnames leaked in client-side code", 3.7,
                                         "Non-production/internal hostnames were referenced in JavaScript/HTML.",
                                         evidence=", ".join(js["internal_domains"][:20])[:400],
                                         remediation="Remove references to internal/staging infrastructure from public assets."))
            findings.sort(key=lambda x: x["cvss"], reverse=True)
            await _set(scan_id, js_recon=js, findings=findings, finding_count=len(findings),
                       counts=_count(findings), stage="api_recon", progress=88)

            api = await _api_recon(live, client, target)
            findings.extend(api["findings"])
            findings.sort(key=lambda x: x["cvss"], reverse=True)

        diff = await _compute_diff(target, scan_id, subs, live, api["inventory"], js["libraries"])
        await _set(scan_id, api_inventory=api["inventory"], api_count=api["api_count"], api_specs=api["specs"],
                   js_recon=js, findings=findings, finding_count=len(findings), diff=diff,
                   counts=_count(findings), stage="done", status="done", progress=100, done_at=_now())
    except Exception as e:
        await _set(scan_id, status="error", stage="error", error=str(e)[:300], progress=100)


# ---------------------------------------------------------------- API
class BBInput(BaseModel):
    target: str = Field(min_length=3)


@router.post("/scan")
async def start_scan(data: BBInput):
    target = data.target.strip().lower().replace("https://", "").replace("http://", "").strip("/").split("/")[0]
    if "." not in target or " " in target or len(target) < 3:
        raise HTTPException(status_code=400, detail="Enter a valid domain, e.g. example.com")
    scan_id = str(uuid.uuid4())
    doc = {
        "id": scan_id, "target": target, "status": "queued", "stage": "queued", "progress": 0,
        "subdomains": [], "live_hosts": [], "findings": [],
        "js_recon": {"endpoints": [], "secrets": [], "admin_panels": [], "feature_flags": [],
                     "internal_domains": [], "libraries": [], "source_maps": []},
        "api_inventory": [], "api_specs": [], "api_count": 0, "diff": None,
        "counts": _count([]), "sub_count": 0, "live_count": 0, "finding_count": 0,
        "ai_report": None, "created_at": _now(),
    }
    await db.bugbounty_scans.insert_one(dict(doc))
    asyncio.create_task(run_scan(scan_id, target))
    return {"id": scan_id, "target": target, "status": "queued"}


@router.get("/scan/{scan_id}")
async def get_scan(scan_id: str):
    d = await db.bugbounty_scans.find_one({"id": scan_id}, {"_id": 0})
    if not d:
        raise HTTPException(status_code=404, detail="Scan not found")
    return d


@router.get("/scans")
async def list_scans():
    ds = await db.bugbounty_scans.find(
        {}, {"_id": 0, "subdomains": 0, "live_hosts": 0, "findings": 0, "js_recon": 0, "ai_report": 0, "api_inventory": 0, "diff": 0}
    ).sort("created_at", -1).to_list(30)
    return {"scans": ds}


@router.get("/export/{scan_id}/apis")
async def export_apis(scan_id: str):
    d = await db.bugbounty_scans.find_one({"id": scan_id}, {"_id": 0})
    if not d:
        raise HTTPException(status_code=404, detail="Scan not found")
    inv = d.get("api_inventory") or []
    payload = json.dumps({"target": d["target"], "generated": _now(), "count": len(inv),
                          "specs": d.get("api_specs") or [], "endpoints": inv}, indent=2)
    fname = f"insafelabs-apis-{d['target']}.json"
    return StreamingResponse(io.BytesIO(payload.encode()), media_type="application/json",
                             headers={"Content-Disposition": f'attachment; filename="{fname}"'})


@router.get("/export/{scan_id}/postman")
async def export_postman(scan_id: str):
    d = await db.bugbounty_scans.find_one({"id": scan_id}, {"_id": 0})
    if not d:
        raise HTTPException(status_code=404, detail="Scan not found")
    items = []
    for r in (d.get("api_inventory") or []):
        u = urlparse(r["url"])
        items.append({
            "name": f'{r["method"]} {u.path or "/"}',
            "request": {
                "method": r["method"], "header": [],
                "url": {"raw": r["url"], "protocol": u.scheme or "https",
                        "host": (u.netloc or "").split("."), "path": [p for p in (u.path or "").split("/") if p]},
            },
        })
    coll = {"info": {"name": f"InsafeLabs — {d['target']} API Inventory",
                     "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
            "item": items}
    fname = f"insafelabs-postman-{d['target']}.json"
    return StreamingResponse(io.BytesIO(json.dumps(coll, indent=2).encode()), media_type="application/json",
                             headers={"Content-Disposition": f'attachment; filename="{fname}"'})


# ---------------------------------------------------------------- source-map recon export
def _safe_src_path(src, idx):
    s = str(src or "").strip()
    for pre in ("webpack-internal:///", "webpack:///", "webpack://", "webpack:/",
                "https://", "http://", "file://", "ng://"):
        if s.startswith(pre):
            s = s[len(pre):]
            break
    s = s.replace("\\", "/").split("?")[0].split("#")[0]
    parts = [p for p in s.split("/") if p not in ("", ".", "..", "~")]
    clean = "/".join(parts) or f"source_{idx}"
    if not re.search(r"\.[a-z0-9]{1,6}$", clean, re.I):
        clean += ".js"
    return clean[:200]


def _map_dir(url):
    u = urlparse(url)
    base = (u.netloc + u.path).strip("/") or "map"
    return re.sub(r"[^A-Za-z0-9._\-]", "_", base)[:120]


async def _build_sources_zip(maps):
    buf = io.BytesIO()
    manifest = []
    limits = httpx.Limits(max_connections=10)
    async with httpx.AsyncClient(verify=False, timeout=httpx.Timeout(15.0, connect=6.0),
                                 headers={"User-Agent": UA}, limits=limits, follow_redirects=True) as client:
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            used = set()
            for i, sm in enumerate(maps[:30]):
                url = sm.get("url")
                entry = {"map": url}
                try:
                    r = await client.get(url)
                    data = r.json()
                except Exception:
                    entry["error"] = "fetch/parse failed"
                    manifest.append(entry)
                    continue
                sources = data.get("sources") or []
                contents = data.get("sourcesContent") or []
                root = _map_dir(url)
                written = 0
                for si, src in enumerate(sources):
                    content = contents[si] if si < len(contents) else None
                    if content is None:
                        continue
                    path = f"{root}/{_safe_src_path(src, si)}"
                    orig, n = path, 1
                    while path in used:
                        path = f"{orig}.{n}"
                        n += 1
                    used.add(path)
                    try:
                        zf.writestr(path, content)
                        written += 1
                    except Exception:
                        pass
                entry.update({"sources": len(sources), "files_reconstructed": written,
                              "embedded_content": bool(contents)})
                manifest.append(entry)
            zf.writestr("MANIFEST.json", json.dumps({"generated": _now(), "maps": manifest}, indent=2))
            zf.writestr("README.txt",
                        "InsafeLabs - Source Map Recon Export\n\n"
                        "Original source files reconstructed from exposed .js.map files (sourcesContent).\n"
                        "Maps lacking embedded sourcesContent only list file paths in MANIFEST.json.\n\n"
                        "FOR AUTHORIZED SECURITY REVIEW ONLY.\n")
    buf.seek(0)
    return buf


@router.get("/export/{scan_id}/sources")
async def export_sources(scan_id: str):
    d = await db.bugbounty_scans.find_one({"id": scan_id}, {"_id": 0})
    if not d:
        raise HTTPException(status_code=404, detail="Scan not found")
    maps = (d.get("js_recon") or {}).get("source_maps") or []
    if not maps:
        raise HTTPException(status_code=404, detail="No source maps were discovered in this scan")
    buf = await _build_sources_zip(maps)
    fname = f"insafelabs-sources-{d['target']}.zip"
    return StreamingResponse(buf, media_type="application/zip",
                             headers={"Content-Disposition": f'attachment; filename="{fname}"'})


@router.post("/report/{scan_id}")
async def gen_report(scan_id: str):
    d = await db.bugbounty_scans.find_one({"id": scan_id}, {"_id": 0})
    if not d:
        raise HTTPException(status_code=404, detail="Scan not found")
    findings = d.get("findings", [])
    top = findings[:25]
    lines = [f"- [{f['severity'].upper()} CVSS {f['cvss']}] {f['title']} @ {f['host']} — {f['detail']}" for f in top]
    js = d.get("js_recon") or {}
    system = ("You are a senior bug bounty hunter writing a professional vulnerability report for a "
              "HackerOne/Bugcrowd submission. Be precise, technical and concise. Output GitHub-flavoured Markdown only.")
    user = (
        f"Target: {d['target']}\nLive hosts: {d.get('live_count', 0)}  Subdomains discovered: {d.get('sub_count', 0)}\n"
        f"Leaked JS secrets: {len(js.get('secrets', []))}  Interesting endpoints: {len(js.get('endpoints', []))}\n\n"
        f"Findings ({len(findings)}):\n" + ("\n".join(lines) if lines else "(no automated findings — recommend manual testing)") +
        "\n\nWrite the report with these sections: 1) Executive Summary, 2) Scope & Methodology, "
        "3) Findings — for each notable one: Title, Severity/CVSS, Affected Asset, Description, "
        "Steps to Reproduce, Impact, Remediation. 4) Overall Recommendations. Keep it submittable and realistic."
    )
    try:
        md = await ai.complete(f"bb-{scan_id}", system, user)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI report failed: {e}")
    await db.bugbounty_scans.update_one({"id": scan_id}, {"$set": {"ai_report": md}})
    return {"markdown": md}


@router.post("/triage/{scan_id}")
async def ai_triage(scan_id: str):
    """AI auto-triage: dedup + false-positive filtering + confidence for each finding."""
    d = await db.bugbounty_scans.find_one({"id": scan_id}, {"_id": 0})
    if not d:
        raise HTTPException(status_code=404, detail="Scan not found")
    findings = d.get("findings", []) or []
    empty = {"triaged": [], "summary": {"total": 0, "unique": 0, "duplicates": 0,
                                        "false_positives": 0, "confirmed": 0, "likely": 0}, "generated": _now()}
    if not findings:
        await db.bugbounty_scans.update_one({"id": scan_id}, {"$set": {"triage": empty}})
        return empty

    subset = findings[:60]
    valid_ids = {f["id"] for f in subset}
    compact = [{"id": f["id"], "title": f["title"], "host": f["host"], "type": f["type"],
                "cvss": f["cvss"], "severity": f["severity"],
                "detail": (f.get("detail") or "")[:280], "evidence": (f.get("evidence") or "")[:160]}
               for f in subset]
    system = ("You are a senior application-security triage engine for bug-bounty findings. "
              "For each finding decide a verdict: 'confirmed' (clearly a real, exploitable issue), "
              "'likely' (probably real but needs manual confirmation), or 'false_positive' "
              "(noise / informational / not exploitable). Detect duplicates: when a finding is essentially "
              "the same root cause as another (same/related host), keep the highest-severity one as the "
              "representative and point the others to it via duplicate_of. Return STRICT JSON only, no prose.")
    user = ("Findings JSON:\n" + json.dumps(compact) +
            "\n\nReturn exactly: {\"verdicts\":[{\"id\":\"..\",\"verdict\":\"confirmed|likely|false_positive\","
            "\"confidence\":0-100,\"reason\":\"<=140 chars\",\"duplicate_of\":\"<id or null>\"}]}. "
            "Include every id exactly once.")
    try:
        raw = await ai.complete(f"bb-triage-{scan_id}", system, user)
        parsed = ai.parse_json(raw)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"AI triage failed: {str(e)[:140]}")

    by_id = {}
    for v in (parsed.get("verdicts", []) or []):
        vid = v.get("id")
        if vid not in valid_ids:
            continue
        dv = v.get("duplicate_of")
        if dv in ("", "null", None) or dv not in valid_ids or dv == vid:
            dv = None
        verdict = v.get("verdict")
        if verdict not in ("confirmed", "likely", "false_positive"):
            verdict = "likely"
        try:
            conf = int(float(v.get("confidence", 60)))
        except Exception:
            conf = 60
        by_id[vid] = {"id": vid, "verdict": verdict, "confidence": max(0, min(100, conf)),
                      "reason": (v.get("reason") or "")[:160], "duplicate_of": dv}

    triaged = list(by_id.values())
    total = len(triaged)
    summary = {
        "total": total,
        "confirmed": sum(1 for t in triaged if t["verdict"] == "confirmed"),
        "likely": sum(1 for t in triaged if t["verdict"] == "likely"),
        "false_positives": sum(1 for t in triaged if t["verdict"] == "false_positive"),
        "duplicates": sum(1 for t in triaged if t["duplicate_of"]),
        "unique": sum(1 for t in triaged if t["verdict"] != "false_positive" and not t["duplicate_of"]),
    }
    result = {"triaged": triaged, "summary": summary, "generated": _now()}
    await db.bugbounty_scans.update_one({"id": scan_id}, {"$set": {"triage": result}})
    return result


def _bb_pdf(d):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=16 * mm, bottomMargin=16 * mm,
                            leftMargin=16 * mm, rightMargin=16 * mm, title="InsafeLabs Bug Bounty Report")
    ss = getSampleStyleSheet()
    H = ParagraphStyle("BH", parent=ss["Title"], fontSize=23, textColor=colors.HexColor("#0A0A0A"))
    h2 = ParagraphStyle("Bh2", parent=ss["Heading2"], fontSize=13, textColor=colors.HexColor("#B45309"), spaceBefore=10)
    h3 = ParagraphStyle("Bh3", parent=ss["Heading3"], fontSize=10.5, textColor=colors.HexColor("#1F2937"), spaceBefore=6)
    body = ParagraphStyle("Bb", parent=ss["Normal"], fontSize=9, leading=13)
    small = ParagraphStyle("Bs", parent=ss["Normal"], fontSize=8, textColor=colors.grey)
    mono = ParagraphStyle("Bm", parent=ss["Normal"], fontName="Courier", fontSize=8, leading=11)
    sev_c = {"critical": "#DC2626", "high": "#EA580C", "medium": "#D97706", "low": "#65A30D", "info": "#6B7280"}

    def tbl(rows, widths, header=False):
        t = Table(rows, colWidths=widths)
        st = [("FONTSIZE", (0, 0), (-1, -1), 8), ("VALIGN", (0, 0), (-1, -1), "TOP"),
              ("BOTTOMPADDING", (0, 0), (-1, -1), 3), ("TOPPADDING", (0, 0), (-1, -1), 3),
              ("LINEBELOW", (0, 0), (-1, -1), 0.3, colors.HexColor("#E5E7EB"))]
        if header:
            st += [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111111")),
                   ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold")]
        t.setStyle(TableStyle(st))
        return t

    el = []
    el.append(Spacer(1, 40))
    el.append(Paragraph("Bug Bounty Report", H))
    el.append(Paragraph(f"InsafeLabs — Automated Assessment of {_esc(d['target'])}", h2))
    el.append(Spacer(1, 12))
    c = d.get("counts", {})
    meta = [
        ["Target", _esc(d.get("target"))],
        ["Generated", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")],
        ["Subdomains", str(d.get("sub_count", 0))],
        ["Live hosts", str(d.get("live_count", 0))],
        ["Findings", f"{d.get('finding_count', 0)}  (C:{c.get('critical',0)} H:{c.get('high',0)} M:{c.get('medium',0)} L:{c.get('low',0)})"],
    ]
    el.append(tbl([[k, v] for k, v in meta], [45 * mm, 120 * mm]))
    el.append(Spacer(1, 10))
    el.append(Paragraph("CONFIDENTIAL — authorized in-scope testing only.", small))

    if d.get("ai_report"):
        el.append(PageBreak())
        el.append(Paragraph("AI Analyst Report", h2))
        for line in str(d["ai_report"]).split("\n"):
            ln = line.strip()
            if not ln:
                el.append(Spacer(1, 4))
                continue
            if ln.startswith("### "):
                el.append(Paragraph(_esc(ln[4:]), h3))
            elif ln.startswith("## "):
                el.append(Paragraph(_esc(ln[3:]), h2))
            elif ln.startswith("# "):
                el.append(Paragraph(_esc(ln[2:]), h2))
            else:
                el.append(Paragraph(_esc(ln.lstrip("-*• ").replace("**", "")), body))

    el.append(PageBreak())
    el.append(Paragraph(f"Findings ({d.get('finding_count', 0)})", h2))
    findings = d.get("findings", [])
    if not findings:
        el.append(Paragraph("No automated findings — manual testing recommended.", body))
    for f in findings:
        sev = f.get("severity", "info")
        el.append(Paragraph(f'<font color="{sev_c.get(sev, "#6B7280")}"><b>[{sev.upper()} · CVSS {f.get("cvss")}]</b></font> {_esc(f.get("title"))}', h3))
        el.append(Paragraph(f"<b>Asset:</b> {_esc(f.get('host'))}", body))
        if f.get("detail"):
            el.append(Paragraph(f"<b>Description:</b> {_esc(f.get('detail'))}", body))
        if f.get("evidence"):
            el.append(Paragraph(f"<b>Evidence:</b> {_esc(f.get('evidence'))}", mono))
        if f.get("remediation"):
            el.append(Paragraph(f"<b>Remediation:</b> {_esc(f.get('remediation'))}", body))
        el.append(Spacer(1, 6))

    live = d.get("live_hosts", [])
    if live:
        el.append(PageBreak())
        el.append(Paragraph(f"Live Hosts ({len(live)})", h2))
        rows = [["Host", "Status", "Server / Tech", "WAF"]]
        for hh in live[:80]:
            rows.append([_esc(hh.get("host")), str(hh.get("status")),
                         _esc((hh.get("server", "") + " " + ",".join(hh.get("tech", []))).strip())[:60],
                         _esc(hh.get("waf", ""))])
        el.append(tbl(rows, [70 * mm, 18 * mm, 62 * mm, 24 * mm], header=True))

    doc.build(el)
    return buf.getvalue()


@router.get("/report/{scan_id}/pdf")
async def report_pdf(scan_id: str):
    d = await db.bugbounty_scans.find_one({"id": scan_id}, {"_id": 0})
    if not d:
        raise HTTPException(status_code=404, detail="Scan not found")
    pdf = await asyncio.to_thread(_bb_pdf, d)
    fname = f"insafelabs-bugbounty-{d['target']}.pdf"
    return StreamingResponse(io.BytesIO(pdf), media_type="application/pdf",
                             headers={"Content-Disposition": f'attachment; filename="{fname}"'})
