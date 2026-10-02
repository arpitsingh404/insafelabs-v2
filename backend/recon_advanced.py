"""InsafeLabs advanced web recon: CORS, cookies, HTTP methods, CSP, WAF, extended DNS,
deep web-vuln probes, GraphQL introspection, subdomain takeover, well-known files."""
import re
import socket
from urllib.parse import urlparse, quote

import requests

from recon_lib import mk, new_session, UA

EVIL_ORIGIN = "https://evil-daxx-attacker.example"


# ----------------------------------------------------------------------------
# CORS misconfiguration
# ----------------------------------------------------------------------------
def cors_audit(session, base):
    findings, data = [], {}
    try:
        r = session.get(base, headers={"Origin": EVIL_ORIGIN}, timeout=8)
        acao = r.headers.get("Access-Control-Allow-Origin")
        acac = (r.headers.get("Access-Control-Allow-Credentials") or "").lower() == "true"
        data = {"acao": acao, "acac": acac, "reflects_origin": acao == EVIL_ORIGIN,
                "wildcard": acao == "*", "allows_null": False}
        try:
            r2 = session.get(base, headers={"Origin": "null"}, timeout=6)
            data["allows_null"] = r2.headers.get("Access-Control-Allow-Origin") == "null"
        except Exception:
            pass
        if data["reflects_origin"] and acac:
            findings.append(mk("CORS misconfiguration — reflects arbitrary Origin with credentials", 8.1,
                               "A05:2021 Security Misconfiguration / CWE-942",
                               f"Server echoes attacker Origin ({EVIL_ORIGIN}) and allows credentials — cross-site data theft is possible.",
                               "Use a strict server-side allow-list of trusted origins; never reflect the Origin header with credentials.", "CORS"))
        elif data["reflects_origin"]:
            findings.append(mk("CORS reflects arbitrary Origin", 5.4,
                               "A05:2021 Security Misconfiguration / CWE-942",
                               f"Access-Control-Allow-Origin reflects any Origin ({EVIL_ORIGIN}).",
                               "Restrict ACAO to a fixed allow-list of trusted origins.", "CORS"))
        elif data["wildcard"] and acac:
            findings.append(mk("CORS wildcard origin combined with credentials", 6.5,
                               "A05:2021 Security Misconfiguration / CWE-942",
                               "ACAO '*' together with Allow-Credentials is an invalid but dangerous config.",
                               "Do not combine wildcard origins with credentials; pin explicit origins.", "CORS"))
        if data["allows_null"]:
            findings.append(mk("CORS allows the 'null' origin", 5.4,
                               "A05:2021 Security Misconfiguration / CWE-942",
                               "ACAO 'null' can be triggered from sandboxed iframes / data URIs.",
                               "Never allow the null origin in CORS policy.", "CORS"))
    except Exception:
        pass
    return data, findings


# ----------------------------------------------------------------------------
# Cookie security flags
# ----------------------------------------------------------------------------
def cookie_audit(session, base):
    findings, cookies = [], []
    try:
        r = session.get(base, timeout=8)
        is_https = str(r.url).startswith("https")
        for c in r.cookies:
            httponly = c.has_nonstandard_attr("HttpOnly") or c.has_nonstandard_attr("httponly")
            samesite = c.get_nonstandard_attr("SameSite") or c.get_nonstandard_attr("samesite")
            cookies.append({"name": c.name, "httponly": bool(httponly), "secure": bool(c.secure),
                            "samesite": samesite or None})
        sensitive = re.compile(r"(?i)(sess|sid|auth|token|jwt|login|user|remember)")
        for c in cookies:
            issues = []
            looks_auth = sensitive.search(c["name"])
            if looks_auth and not c["httponly"]:
                issues.append("missing HttpOnly (readable by JS / XSS theft)")
            if is_https and not c["secure"]:
                issues.append("missing Secure (sent over cleartext)")
            if not c["samesite"] or str(c["samesite"]).lower() == "none":
                issues.append("weak/none SameSite (CSRF exposure)")
            if issues and looks_auth:
                findings.append(mk(f"Insecure cookie flags: {c['name']}", 5.4,
                                   "A05:2021 Security Misconfiguration / CWE-1004",
                                   f"Cookie '{c['name']}' — " + "; ".join(issues),
                                   "Set HttpOnly, Secure and SameSite=Lax/Strict on session/auth cookies.", "Cookies"))
    except Exception:
        pass
    return {"cookies": cookies}, findings


# ----------------------------------------------------------------------------
# HTTP methods audit
# ----------------------------------------------------------------------------
DANGEROUS_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}


def http_methods_audit(session, base):
    findings, data = [], {"allowed": [], "dangerous": [], "trace": False}
    try:
        r = session.options(base, timeout=7)
        allow = r.headers.get("Allow") or r.headers.get("Access-Control-Allow-Methods") or ""
        methods = sorted({m.strip().upper() for m in allow.split(",") if m.strip()})
        data["allowed"] = methods
        data["dangerous"] = sorted(set(methods) & DANGEROUS_METHODS)
    except Exception:
        pass
    try:
        tr = session.request("TRACE", base, timeout=6)
        if tr.status_code == 200 and ("TRACE" in tr.text[:200] or "message/http" in (tr.headers.get("Content-Type") or "")):
            data["trace"] = True
    except Exception:
        pass
    if data["trace"]:
        findings.append(mk("HTTP TRACE method enabled", 4.3, "Security Misconfiguration / CWE-16",
                           "The server responds to TRACE — enables Cross-Site Tracing (XST).",
                           "Disable the TRACE method at the web server / proxy.", "HTTP"))
    if data["dangerous"]:
        findings.append(mk(f"Dangerous HTTP methods allowed: {', '.join(data['dangerous'])}", 5.3,
                           "Security Misconfiguration / CWE-650",
                           f"OPTIONS advertises write/verb methods: {', '.join(data['dangerous'])}.",
                           "Disable unused HTTP verbs; allow only GET/POST/HEAD where possible.", "HTTP"))
    return data, findings


# ----------------------------------------------------------------------------
# Content-Security-Policy analysis
# ----------------------------------------------------------------------------
def csp_analysis(headers):
    findings = []
    h = {k.lower(): v for k, v in (headers or {}).items()}
    policy = h.get("content-security-policy") or ""
    data = {"present": bool(policy), "policy": policy[:600], "issues": []}
    if not policy:
        data["issues"].append("No Content-Security-Policy header")
        return data, findings
    low = policy.lower()
    if "unsafe-inline" in low:
        data["issues"].append("uses 'unsafe-inline' (defeats XSS protection)")
    if "unsafe-eval" in low:
        data["issues"].append("uses 'unsafe-eval'")
    if re.search(r"(default-src|script-src)[^;]*\*", low):
        data["issues"].append("wildcard '*' source in script/default-src")
    if "default-src" not in low and "script-src" not in low:
        data["issues"].append("no default-src / script-src directive")
    if "object-src" not in low:
        data["issues"].append("missing object-src 'none'")
    if "frame-ancestors" not in low:
        data["issues"].append("missing frame-ancestors (clickjacking)")
    if data["issues"]:
        findings.append(mk("Weak Content-Security-Policy", 4.3,
                           "Security Misconfiguration / CWE-1021",
                           "CSP present but weak: " + "; ".join(data["issues"]),
                           "Tighten CSP: remove unsafe-inline/eval, avoid wildcards, add object-src 'none' and frame-ancestors.", "CSP"))
    return data, findings


# ----------------------------------------------------------------------------
# WAF / CDN detection
# ----------------------------------------------------------------------------
WAF_SIGNS = [
    ("Cloudflare", ["cf-ray", "cf-cache-status", "__cfduid", "server: cloudflare"]),
    ("Akamai", ["akamaighost", "x-akamai", "aka-"]),
    ("AWS WAF / CloudFront", ["x-amz-cf-id", "x-amzn-requestid", "awselb", "x-amz-cf-pop"]),
    ("Sucuri", ["x-sucuri-id", "x-sucuri-cache"]),
    ("Imperva / Incapsula", ["x-iinfo", "incap_ses", "visid_incap"]),
    ("F5 BIG-IP ASM", ["x-waf-event", "bigipserver", "ts01"]),
    ("Fastly", ["x-served-by", "fastly", "x-fastly"]),
    ("Barracuda", ["barra_counter"]),
    ("Wordfence", ["wordfence"]),
    ("StackPath", ["x-sp-", "stackpath"]),
]


def waf_detection(session, base):
    findings, data = [], {"detected": False, "vendor": None, "evidence": ""}
    try:
        r = session.get(base, timeout=8)
        blob = " ".join([f"{k.lower()}: {v.lower()}" for k, v in r.headers.items()])
        blob += " " + " ".join([c.name.lower() for c in r.cookies])
        for vendor, sigs in WAF_SIGNS:
            hit = next((s for s in sigs if s in blob), None)
            if hit:
                data.update({"detected": True, "vendor": vendor, "evidence": hit})
                break
        if not data["detected"]:
            try:
                probe = session.get(base + ("&" if "?" in base else "?") + "x=<script>alert(1)</script>' OR 1=1--",
                                    timeout=7)
                if probe.status_code in (403, 406, 419, 429, 501):
                    data.update({"detected": True, "vendor": "Generic WAF",
                                 "evidence": f"malicious probe blocked (HTTP {probe.status_code})"})
            except Exception:
                pass
    except Exception:
        pass
    return data, findings


# ----------------------------------------------------------------------------
# Extended DNS: CAA, DNSSEC, DKIM, zone transfer (AXFR)
# ----------------------------------------------------------------------------
DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "k2", "mail", "dkim", "s1", "s2", "smtp"]


def extended_dns(domain):
    import dns.resolver
    import dns.query
    import dns.zone
    findings = []
    data = {"caa": [], "dnssec": False, "dkim": [], "zone_transfer": False, "axfr_ns": None}
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5
    resolver.timeout = 5

    def q(name, rtype):
        try:
            return [r.to_text() for r in resolver.resolve(name, rtype)]
        except Exception:
            return []

    data["caa"] = q(domain, "CAA")[:8]
    if not data["caa"]:
        findings.append(mk("Missing CAA record", 2.0, "Certificate Governance / CWE-295",
                           "No CAA DNS record — any CA can issue certificates for this domain.",
                           "Publish a CAA record restricting issuance to your CA(s).", "DNS"))
    data["dnssec"] = bool(q(domain, "DNSKEY"))
    if not data["dnssec"]:
        findings.append(mk("DNSSEC not enabled", 2.0, "DNS Security / CWE-350",
                           "No DNSKEY record found — DNS responses are not cryptographically signed.",
                           "Enable DNSSEC at the domain registrar / DNS provider.", "DNS"))
    for sel in DKIM_SELECTORS:
        recs = q(f"{sel}._domainkey.{domain}", "TXT")
        if recs and any(("dkim1" in r.lower() and re.search(r"p=[A-Za-z0-9+/]{40,}", r)) for r in recs):
            data["dkim"].append(sel)
    if not data["dkim"]:
        findings.append(mk("No DKIM selector found (common set)", 3.1, "Email Security / Spoofing",
                           "No DKIM key found on common selectors — outbound mail may be unsigned/spoofable.",
                           "Publish a DKIM key and sign outbound mail.", "DNS"))
    # Zone transfer (AXFR)
    try:
        ns_list = q(domain, "NS")[:2]
        for ns in ns_list:
            ns = ns.rstrip(".")
            try:
                ns_ip = socket.gethostbyname(ns)
                z = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=6, lifetime=8))
                if z:
                    data["zone_transfer"] = True
                    data["axfr_ns"] = ns
                    findings.append(mk("DNS zone transfer (AXFR) allowed", 7.5,
                                       "Information Disclosure / CWE-200",
                                       f"Nameserver {ns} permits AXFR — the full zone (all records/hosts) is exposed.",
                                       "Restrict AXFR to authorized secondary nameservers only.", "DNS"))
                    break
            except Exception:
                continue
    except Exception:
        pass
    return data, findings


# ----------------------------------------------------------------------------
# Deep web-vulnerability probes (safe heuristics)
# ----------------------------------------------------------------------------
PASSWD_RE = re.compile(r"root:.*?:0:0:")
WIN_INI_RE = re.compile(r"(?i)\[fonts\]|\[extensions\]|for 16-bit app support")


def _q(base, qs):
    return base + ("&" if "?" in base else "?") + qs


def advanced_web_vulns(session, base):
    findings, data = [], {}
    # Path traversal / LFI
    try:
        hit = None
        for payload in ["file=../../../../../../etc/passwd", "page=../../../../../../etc/passwd",
                        "path=..%2f..%2f..%2f..%2f..%2fetc%2fpasswd", "file=../../../../windows/win.ini"]:
            r = session.get(_q(base, payload), timeout=7)
            if PASSWD_RE.search(r.text) or WIN_INI_RE.search(r.text):
                hit = payload.split("=")[0]
                break
        data["path_traversal"] = f"param '{hit}'" if hit else "not detected"
        if hit:
            findings.append(mk("Possible Path Traversal / LFI", 8.6, "A01:2021 / CWE-22",
                               f"Parameter '{hit}' returned OS file contents (/etc/passwd or win.ini).",
                               "Never build file paths from user input; use allow-lists and canonicalization.", "app"))
    except Exception:
        data["path_traversal"] = "probe failed"
    # SSTI (template injection)
    try:
        r = session.get(_q(base, "q=daxx${7*7}{{7*7}}"), timeout=7)
        ssti = "daxx49" in r.text.replace(" ", "") or ">49<" in r.text or "daxx49" in r.text
        data["ssti"] = "template expression evaluated (49)" if ssti else "not detected"
        if ssti:
            findings.append(mk("Possible Server-Side Template Injection", 9.0, "A03:2021 Injection / CWE-1336",
                               "Payload {{7*7}}/${7*7} evaluated to 49 in the response.",
                               "Do not render user input as templates; sandbox the template engine.", "app"))
    except Exception:
        data["ssti"] = "probe failed"
    # CRLF / header injection
    try:
        r = session.get(_q(base, "x=%0d%0aDaxx-Injected%3a%20true"), timeout=6, allow_redirects=False)
        crlf = "true" in (r.headers.get("Daxx-Injected") or "").lower()
        data["crlf"] = "response header injected" if crlf else "not detected"
        if crlf:
            findings.append(mk("Possible CRLF / HTTP response splitting", 6.1, "A03:2021 / CWE-113",
                               "Injected CRLF payload created a new response header (Daxx-Injected).",
                               "Strip CR/LF from any user input reflected into headers.", "app"))
    except Exception:
        data["crlf"] = "probe failed"
    # Command injection heuristic
    try:
        r = session.get(_q(base, "cmd=daxx;id"), timeout=6)
        cmdi = bool(re.search(r"uid=\d+\(", r.text))
        data["cmd_injection"] = "shell output reflected (uid=)" if cmdi else "not detected"
        if cmdi:
            findings.append(mk("Possible OS Command Injection", 9.8, "A03:2021 Injection / CWE-78",
                               "Injected ';id' returned Unix uid= output in the response.",
                               "Never pass user input to shell; use parameterized system APIs.", "app"))
    except Exception:
        data["cmd_injection"] = "probe failed"
    # Host header injection
    try:
        r = session.get(base, headers={"Host": "daxx-evil.example"}, timeout=6, allow_redirects=False)
        loc = r.headers.get("Location", "")
        hh = "daxx-evil.example" in loc or "daxx-evil.example" in r.text[:5000]
        data["host_header"] = "reflected (poisoning/redirect)" if hh else "not detected"
        if hh:
            findings.append(mk("Possible Host Header Injection", 6.1, "A03:2021 / CWE-644",
                               "A spoofed Host header was reflected in the redirect/body — cache poisoning / password-reset poisoning risk.",
                               "Validate the Host header against an allow-list; use an absolute canonical URL.", "app"))
    except Exception:
        data["host_header"] = "probe failed"
    return data, findings


# ----------------------------------------------------------------------------
# GraphQL introspection
# ----------------------------------------------------------------------------
GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/query", "/graphiql"]
INTROSPECTION = {"query": "{__schema{queryType{name} types{name}}}"}


def graphql_introspection(session, base):
    findings, endpoints = [], []
    for p in GRAPHQL_PATHS:
        url = base.rstrip("/") + p
        try:
            r = session.post(url, json=INTROSPECTION, timeout=6)
            ok = r.status_code == 200 and "__schema" in r.text and "queryType" in r.text
            if ok:
                endpoints.append({"path": p, "introspection": True})
        except Exception:
            continue
    if endpoints:
        paths = ", ".join(e["path"] for e in endpoints)
        findings.append(mk("GraphQL introspection enabled", 5.3, "API Security / CWE-200",
                           f"Introspection query succeeded at: {paths} — full schema is disclosed.",
                           "Disable introspection in production; enforce auth and query cost limits.", "api"))
    return {"endpoints": endpoints}, findings


# ----------------------------------------------------------------------------
# Subdomain takeover detection
# ----------------------------------------------------------------------------
TAKEOVER_SIGNS = [
    ("GitHub Pages", ["github.io"], ["there isn't a github pages site here", "for root urls (like http://example.com/) you must provide"]),
    ("Heroku", ["herokuapp.com", "herokudns.com"], ["no such app", "herokucdn.com/error-pages/no-such-app"]),
    ("AWS S3", ["s3.amazonaws.com", "s3-website"], ["nosuchbucket", "the specified bucket does not exist"]),
    ("Azure", ["azurewebsites.net", "cloudapp.net", "trafficmanager.net"], ["404 web site not found", "this azure app service"]),
    ("Fastly", ["fastly.net"], ["fastly error: unknown domain"]),
    ("Shopify", ["myshopify.com"], ["sorry, this shop is currently unavailable"]),
    ("Zendesk", ["zendesk.com"], ["help center closed"]),
    ("Surge.sh", ["surge.sh"], ["project not found"]),
    ("Bitbucket", ["bitbucket.io"], ["repository not found"]),
    ("Netlify", ["netlify.app", "netlify.com"], ["not found - request id"]),
    ("Unbounce", ["unbouncepages.com"], ["the requested url was not found on this server"]),
    ("Cargo", ["cargocollective.com"], ["404 not found"]),
]


def _cname(host):
    try:
        import dns.resolver
        res = dns.resolver.Resolver()
        res.lifetime = 4
        res.timeout = 4
        ans = res.resolve(host, "CNAME")
        return str(ans[0].target).rstrip(".").lower()
    except Exception:
        return None


def subdomain_takeover(subdomains):
    findings, vulnerable = [], []
    for host in (subdomains or [])[:25]:
        cname = _cname(host)
        if not cname:
            continue
        service = next((name for name, doms, _ in TAKEOVER_SIGNS if any(d in cname for d in doms)), None)
        if not service:
            continue
        signs = next((s for name, _, s in TAKEOVER_SIGNS if name == service), [])
        try:
            r = requests.get(("https://" + host), timeout=7, headers=UA, allow_redirects=True)
            body = r.text.lower()
            if any(sig in body for sig in signs):
                vulnerable.append({"subdomain": host, "service": service, "cname": cname})
                findings.append(mk(f"Possible subdomain takeover: {host}", 8.1,
                                   "A05:2021 / CWE-350",
                                   f"{host} → CNAME {cname} ({service}) returns an unclaimed-resource fingerprint.",
                                   "Remove the dangling DNS record or re-claim the resource on the provider.", "DNS"))
        except Exception:
            continue
    return {"vulnerable": vulnerable, "checked": len(subdomains or [])}, findings


# ----------------------------------------------------------------------------
# Well-known files (robots, sitemap, security.txt, humans)
# ----------------------------------------------------------------------------
def wellknown_files(session, base):
    findings = []
    data = {"robots": False, "disallowed": [], "sitemap": False, "security_txt": False, "humans": False}
    root = base.rstrip("/")
    try:
        r = session.get(root + "/robots.txt", timeout=6)
        if r.status_code == 200 and "text/html" not in (r.headers.get("Content-Type") or ""):
            data["robots"] = True
            dis = re.findall(r"(?im)^\s*Disallow:\s*(\S+)", r.text)
            data["disallowed"] = sorted(set(d for d in dis if d and d != "/"))[:40]
            juicy = [d for d in data["disallowed"] if any(k in d.lower() for k in
                     ["admin", "backup", "config", "secret", "private", "db", "sql", "internal", "api", "test", "dev"])]
            if juicy:
                findings.append(mk("Sensitive paths disclosed in robots.txt", 3.1,
                                   "Information Disclosure / CWE-200",
                                   "robots.txt lists interesting Disallow paths: " + ", ".join(juicy[:15]),
                                   "Do not rely on robots.txt to hide sensitive paths; enforce access control instead.", "HTTP"))
    except Exception:
        pass
    for path, key in [("/sitemap.xml", "sitemap"), ("/.well-known/security.txt", "security_txt"),
                      ("/security.txt", "security_txt"), ("/humans.txt", "humans")]:
        try:
            r = session.get(root + path, timeout=6)
            if r.status_code == 200 and r.content:
                data[key] = True
        except Exception:
            continue
    return data, findings


# ----------------------------------------------------------------------------
# WordPress deep enumeration (only meaningful when WP detected)
# ----------------------------------------------------------------------------
def wordpress_deep(session, base):
    findings = []
    data = {"users": [], "xmlrpc": False, "plugins": [], "upload_listing": False}
    root = base.rstrip("/")
    try:
        r = session.get(root + "/wp-json/wp/v2/users", timeout=7)
        if r.status_code == 200 and "application/json" in (r.headers.get("Content-Type") or ""):
            try:
                users = [u.get("slug") or u.get("name") for u in r.json() if isinstance(u, dict)]
                data["users"] = [u for u in users if u][:20]
            except Exception:
                pass
            if data["users"]:
                findings.append(mk("WordPress usernames enumerable via REST API", 5.3,
                                   "Information Disclosure / CWE-200",
                                   "Enumerated users: " + ", ".join(data["users"][:12]),
                                   "Restrict /wp-json/wp/v2/users; harden logins with 2FA + rate limiting.", "WordPress"))
    except Exception:
        pass
    try:
        r = session.post(root + "/xmlrpc.php", data="<methodCall><methodName>system.listMethods</methodName></methodCall>",
                         timeout=6)
        if r.status_code == 200 and ("methodResponse" in r.text or "system.multicall" in r.text):
            data["xmlrpc"] = True
            findings.append(mk("WordPress XML-RPC enabled", 4.3, "Security Misconfiguration / CWE-16",
                               "/xmlrpc.php responds to system.listMethods — enables brute-force amplification & pingback DDoS.",
                               "Disable xmlrpc.php if unused, or block system.multicall/pingback.", "WordPress"))
    except Exception:
        pass
    try:
        base_html = session.get(root, timeout=7).text
        plugins = sorted(set(re.findall(r"/wp-content/plugins/([a-zA-Z0-9\-_]+)", base_html)))[:20]
        data["plugins"] = plugins
    except Exception:
        pass
    try:
        r = session.get(root + "/wp-content/uploads/", timeout=6)
        if r.status_code == 200 and "index of /" in r.text.lower():
            data["upload_listing"] = True
            findings.append(mk("WordPress uploads directory listing enabled", 4.3,
                               "Security Misconfiguration / CWE-548",
                               "/wp-content/uploads/ returns an open directory index.",
                               "Disable directory listing (Options -Indexes) on the web server.", "WordPress"))
    except Exception:
        pass
    return data, findings


# ----------------------------------------------------------------------------
# Content Discovery / directory bruteforce (ffuf-style, curated high-signal list)
# ----------------------------------------------------------------------------
CONTENT_PATHS = [
    ("/.git/HEAD", "high"), ("/.git/config", "high"), ("/.svn/entries", "medium"), ("/.hg/store", "medium"),
    ("/.env", "critical"), ("/.env.local", "critical"), ("/.env.backup", "critical"), ("/.env.prod", "critical"),
    ("/config.php.bak", "high"), ("/wp-config.php.bak", "critical"), ("/wp-config.php~", "critical"),
    ("/backup.zip", "high"), ("/backup.tar.gz", "high"), ("/backup.sql", "high"), ("/db.sql", "high"),
    ("/database.sql", "high"), ("/dump.sql", "high"), ("/www.zip", "high"), ("/site.zip", "high"), ("/app.zip", "medium"),
    ("/.DS_Store", "low"), ("/robots.txt", None), ("/sitemap.xml", None), ("/crossdomain.xml", "low"),
    ("/clientaccesspolicy.xml", "low"), ("/phpinfo.php", "high"), ("/info.php", "high"), ("/test.php", "low"),
    ("/server-status", "medium"), ("/server-info", "medium"), ("/.htaccess", "medium"), ("/.htpasswd", "high"),
    ("/web.config", "medium"), ("/swagger.json", "low"), ("/swagger-ui.html", "low"), ("/openapi.json", "low"),
    ("/api-docs", "low"), ("/actuator", "medium"), ("/actuator/health", None), ("/actuator/env", "high"),
    ("/admin", None), ("/admin/", None), ("/administrator", None), ("/wp-admin/", None), ("/login", None),
    ("/signin", None), ("/dashboard", None), ("/panel", None), ("/manager/html", "medium"), ("/console", None),
    ("/phpmyadmin/", "medium"), ("/pma/", "medium"), ("/adminer.php", "medium"), ("/.well-known/security.txt", None),
    ("/backup/", "medium"), ("/backups/", "medium"), ("/old/", "low"), ("/tmp/", "low"), ("/temp/", "low"),
    ("/logs/", "medium"), ("/log/", "medium"), ("/uploads/", None), ("/files/", None), ("/private/", "medium"),
    ("/.aws/credentials", "critical"), ("/.ssh/id_rsa", "critical"), ("/id_rsa", "critical"), ("/.npmrc", "medium"),
    ("/.dockercfg", "high"), ("/docker-compose.yml", "medium"), ("/Dockerfile", "low"), ("/composer.json", "low"),
    ("/package.json", "low"), ("/yarn.lock", "low"), ("/.gitlab-ci.yml", "low"), ("/Jenkinsfile", "low"),
    ("/.travis.yml", "low"), ("/CHANGELOG.md", None), ("/config.json", "medium"), ("/config.yml", "medium"),
    ("/settings.py", "high"), ("/local.settings.json", "high"), ("/error_log", "medium"), ("/debug.log", "medium"),
    ("/.vscode/settings.json", "low"), ("/.idea/workspace.xml", "low"), ("/metrics", "medium"), ("/health", None),
    ("/status", None), ("/wp-json/wp/v2/users", "low"), ("/register", None),
]


def content_discovery(session, base):
    from concurrent.futures import ThreadPoolExecutor
    findings, hits = [], []

    def probe(item):
        path, sev = item
        try:
            r = session.get(base.rstrip("/") + path, timeout=6, allow_redirects=False)
        except Exception:
            return None
        code = r.status_code
        if code in (200, 301, 302, 401, 403):
            body = r.content if code == 200 else b""
            return {"path": path, "status": code, "length": len(body),
                    "ctype": (r.headers.get("Content-Type") or "")[:50], "sev": sev}
        return None

    with ThreadPoolExecutor(max_workers=12) as ex:
        for res in ex.map(probe, CONTENT_PATHS):
            if res:
                hits.append(res)

    cvss_map = {"critical": 9.1, "high": 7.5, "medium": 5.3, "low": 3.1}
    for h in hits:
        if h["status"] == 200 and h.get("sev"):
            findings.append(mk(f"Exposed sensitive path: {h['path']}", cvss_map.get(h["sev"], 3.1),
                               "Sensitive File / Path Exposure",
                               f"{h['path']} is publicly reachable (HTTP 200, {h['length']} bytes, {h['ctype']}).",
                               "Restrict access and remove backup/VCS/config artifacts from the web root.", "Exposure"))
    out = [{k: v for k, v in h.items() if k != "sev"} for h in hits]
    return {"content_hits": out, "probed": len(CONTENT_PATHS)}, findings

