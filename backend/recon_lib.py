"""InsafeLabs deep-recon helpers: secrets, subdomains, web-vulns, API, tech/CMS, network, screenshots."""
import re
import socket
import concurrent.futures
from urllib.parse import urlparse, quote, urljoin

import requests

UA = {"User-Agent": "Mozilla/5.0 (compatible; InsafeLabs-Scanner/1.0; authorized-assessment)"}


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


def mk(title, cvss, category, evidence, recommendation, component=""):
    return {
        "title": title, "cvss": round(float(cvss), 1), "severity": severity_from_cvss(float(cvss)),
        "category": category, "component": component, "evidence": evidence[:600],
        "recommendation": recommendation,
    }


def new_session():
    s = requests.Session()
    s.headers.update(UA)
    return s


def fetch_base(session, base):
    try:
        r = session.get(base, timeout=9, allow_redirects=True)
        return {
            "html": r.text[:600000], "status": r.status_code, "final_url": str(r.url),
            "headers": dict(r.headers), "cookies": {c.name: c.value for c in r.cookies},
        }
    except Exception as e:
        return {"html": "", "status": None, "error": str(e)[:200], "headers": {}, "cookies": {}}


# ----------------------------------------------------------------------------
# Secret / Key detection + JavaScript analysis
# ----------------------------------------------------------------------------
SECRET_PATTERNS = [
    ("AWS Access Key ID", 9.1, re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS Secret Access Key", 9.8, re.compile(r"(?i)aws.{0,20}?(?:secret|private).{0,3}[:=]\s*['\"][0-9a-zA-Z/+]{40}['\"]")),
    ("Google API Key", 7.5, re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Stripe Live Secret Key", 9.8, re.compile(r"sk_live_[0-9a-zA-Z]{24,}")),
    ("Stripe Live Publishable Key", 4.0, re.compile(r"pk_live_[0-9a-zA-Z]{24,}")),
    ("Stripe Restricted Key", 8.0, re.compile(r"rk_live_[0-9a-zA-Z]{24,}")),
    ("Slack Token", 8.5, re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("GitHub Personal Token", 8.5, re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}")),
    ("Private Key Block", 9.5, re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("JWT Token", 5.3, re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("Hardcoded Password", 6.5, re.compile(r"(?i)(?:password|passwd|pwd|db_pass|secret)\s*[:=]\s*['\"][^'\"]{5,40}['\"]")),
    ("Firebase URL", 4.0, re.compile(r"[a-z0-9\-]+\.firebaseio\.com")),
    ("Twilio SID", 6.0, re.compile(r"AC[a-z0-9]{32}")),
    ("Mailgun Key", 7.0, re.compile(r"key-[0-9a-zA-Z]{32}")),
    ("Generic API Key", 4.3, re.compile(r"(?i)(?:api[_-]?key|apikey|access[_-]?token)\s*[:=]\s*['\"][0-9a-zA-Z\-_]{16,}['\"]")),
    ("Stripe Test Secret Key", 5.0, re.compile(r"sk_test_[0-9a-zA-Z]{24,}")),
    ("Razorpay Key ID", 4.0, re.compile(r"rzp_(?:live|test)_[0-9a-zA-Z]{10,}")),
    ("Razorpay Key Secret", 8.5, re.compile(r"(?i)(?:razorpay|key_secret|razorpay_secret).{0,20}?[:=]\s*['\"][0-9a-zA-Z]{20,}['\"]")),
    ("PayPal Client Secret", 8.0, re.compile(r"(?i)paypal.{0,20}?(?:client_secret|secret).{0,3}[:=]\s*['\"][0-9A-Za-z_\-]{20,}['\"]")),
    ("PayPal/Braintree Token", 7.5, re.compile(r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}")),
    ("Google OAuth Client Secret", 8.0, re.compile(r"GOCSPX-[0-9A-Za-z\-_]{20,}")),
    ("Google OAuth Client ID", 3.0, re.compile(r"[0-9]+-[0-9a-z]{32}\.apps\.googleusercontent\.com")),
    ("Firebase Web API Key", 4.0, re.compile(r"apiKey['\"]?\s*[:=]\s*['\"]AIza[0-9A-Za-z\-_]{35}")),
    ("Firebase Cloud Messaging Key", 7.5, re.compile(r"AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140,}")),
    ("SendGrid API Key", 9.1, re.compile(r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}")),
    ("Mailchimp API Key", 7.0, re.compile(r"[0-9a-f]{32}-us[0-9]{1,2}\b")),
    ("OpenAI API Key", 8.5, re.compile(r"sk-(?:proj-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,}")),
    ("OpenAI Project Key", 8.5, re.compile(r"sk-proj-[A-Za-z0-9\-_]{40,}")),
    ("Anthropic API Key", 8.5, re.compile(r"sk-ant-[A-Za-z0-9\-_]{24,}")),
    ("Discord Bot Token", 7.5, re.compile(r"[MNO][A-Za-z0-9]{23}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27}")),
    ("Discord Webhook", 5.0, re.compile(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_\-]{60,}")),
    ("Telegram Bot Token", 6.0, re.compile(r"\b[0-9]{8,10}:AA[0-9A-Za-z_\-]{32,}\b")),
    ("GitLab Personal Token", 8.5, re.compile(r"glpat-[0-9A-Za-z\-_]{20}")),
    ("npm Token", 8.0, re.compile(r"npm_[0-9A-Za-z]{36}")),
    ("DigitalOcean Token", 8.0, re.compile(r"dop_v1_[0-9a-f]{64}")),
    ("Square Access Token", 8.0, re.compile(r"sq0atp-[0-9A-Za-z\-_]{22}")),
    ("Shopify Access Token", 8.0, re.compile(r"shp(?:at|ca|pa)_[0-9a-fA-F]{32}")),
    ("Shopify Shared Secret", 8.0, re.compile(r"shpss_[0-9a-fA-F]{32}")),
    ("Cloudinary URL", 7.0, re.compile(r"cloudinary://[0-9]{12,18}:[0-9A-Za-z\-_]{20,}@[a-z0-9\-]+")),
    ("Algolia Admin Key", 6.5, re.compile(r"(?i)algolia.{0,20}?(?:admin|api)[_-]?key.{0,3}[:=]\s*['\"][0-9a-f]{32}['\"]")),
    ("Facebook Access Token", 6.0, re.compile(r"EAACEdEose0cBA[0-9A-Za-z]+")),
    ("Twilio Auth Token", 8.0, re.compile(r"(?i)twilio.{0,20}?(?:auth|token).{0,3}[:=]\s*['\"][0-9a-f]{32}['\"]")),
    ("Basic Auth in URL", 8.0, re.compile(r"https?://[a-zA-Z0-9._%\-]+:[^@\s/'\"]{3,}@[a-zA-Z0-9.\-]+")),
    ("GCP Service Account Key", 9.5, re.compile(r"\"type\"\s*:\s*\"service_account\"")),
    ("Postman API Key", 6.0, re.compile(r"PMAK-[0-9a-f]{24}-[0-9a-f]{34}")),
    ("Heroku API Key", 7.5, re.compile(r"(?i)heroku.{0,20}[:=]\s*['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]")),
]

# Common secret / config files worth probing on a web root
CONFIG_PATHS = [
    ("/.env", 9.1), ("/.env.local", 9.1), ("/.env.production", 9.1), ("/.env.development", 8.0),
    ("/.env.backup", 9.1), ("/.env.bak", 9.1), ("/.env.save", 9.1), ("/.env.old", 9.1),
    ("/.env.dev", 8.0), ("/.env.prod", 9.1), ("/.env.example", 3.0), ("/env.js", 5.0),
    ("/config.json", 6.5), ("/config.js", 5.0), ("/config.php", 6.5), ("/config.php.bak", 9.1),
    ("/config.yml", 6.5), ("/config.yaml", 6.5), ("/config.xml", 6.5), ("/configuration.php", 7.0),
    ("/appsettings.json", 7.5), ("/appsettings.Development.json", 7.5), ("/appsettings.Production.json", 8.0),
    ("/firebase.json", 4.0), ("/firebaseConfig.js", 4.0), ("/firebase-config.js", 4.0), ("/.firebaserc", 4.0),
    ("/credentials.json", 9.1), ("/secrets.json", 9.1), ("/secrets.yml", 9.1), ("/secret.key", 9.5),
    ("/local.settings.json", 8.0), ("/wp-config.php.bak", 9.1), ("/wp-config.php~", 9.1),
    ("/wp-config.php.save", 9.1), ("/wp-config.php.old", 9.1), ("/web.config", 6.5), ("/web.config.bak", 8.0),
    ("/.git/config", 6.5), ("/.git/HEAD", 5.0), ("/.git-credentials", 9.5), ("/.svn/entries", 5.0),
    ("/.hg/hgrc", 5.0), ("/.bzr/branch/branch.conf", 4.0),
    ("/.aws/credentials", 9.5), ("/.aws/config", 6.5), ("/docker-compose.yml", 5.3),
    ("/docker-compose.override.yml", 5.3), ("/Dockerfile", 3.0), ("/.dockerignore", 2.0),
    ("/.npmrc", 6.5), ("/.yarnrc", 4.0), ("/.pypirc", 7.0), ("/.netrc", 8.0),
    ("/.htpasswd", 7.5), ("/.htaccess", 4.0), ("/database.yml", 8.0), ("/config/database.yml", 8.0),
    ("/config/secrets.yml", 9.1), ("/config/master.key", 9.5), ("/backup.sql", 8.0), ("/dump.sql", 8.0),
    ("/db.sql", 8.0), ("/database.sql", 8.0), ("/backup.zip", 7.5), ("/backup.tar.gz", 7.5),
    ("/site.tar.gz", 7.0), ("/www.zip", 7.0), ("/.dockercfg", 7.0), ("/settings.py", 6.5),
    ("/settings.local.py", 7.0), ("/local_settings.py", 7.0), ("/id_rsa", 9.5), ("/id_dsa", 9.5),
    ("/id_ed25519", 9.5), ("/.ssh/id_rsa", 9.5), ("/server.key", 9.0), ("/private.key", 9.0),
    ("/.DS_Store", 3.1), ("/composer.json", 3.0), ("/composer.lock", 3.0), ("/package.json", 2.0),
    ("/yarn.lock", 2.0), ("/phpinfo.php", 6.5), ("/info.php", 6.5), ("/.vscode/sftp.json", 8.0),
    ("/.idea/workspace.xml", 3.0), ("/Gemfile", 2.0), ("/Procfile", 3.0), ("/nginx.conf", 5.0),
    ("/.travis.yml", 4.0), ("/.gitlab-ci.yml", 4.0), ("/.circleci/config.yml", 4.0),
    ("/.github/workflows/deploy.yml", 4.0), ("/terraform.tfstate", 8.0), ("/kubeconfig", 8.5),
    ("/.kube/config", 8.5), ("/vault.env", 9.1), ("/.env.vault", 6.0),
]

SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
ENDPOINT_RE = re.compile(r'["\'](/(?:api|v\d|rest|graphql|internal|admin|auth)[a-zA-Z0-9_\-/\.]{0,60})["\']')
FULLURL_RE = re.compile(r'https?://[a-zA-Z0-9\.\-]+/(?:api|v\d|rest|graphql)[a-zA-Z0-9_\-/\.]{0,60}')


def _redact(s):
    s = s.strip().strip("'\"")
    if len(s) <= 10:
        return s[:3] + "***"
    return s[:6] + "***" + s[-3:]


def secret_and_js_analysis(session, base, html):
    findings, secrets, endpoints, js_files = [], [], set(), []
    origin = urlparse(base).netloc

    def scan_text(text, source):
        for name, cvss, pat in SECRET_PATTERNS:
            for m in pat.findall(text):
                val = m if isinstance(m, str) else (m[0] if m else "")
                raw = pat.search(text)
                sample = raw.group(0) if raw else str(val)
                secrets.append({"type": name, "source": source, "match": _redact(sample), "cvss": cvss})
        for m in ENDPOINT_RE.findall(text):
            endpoints.add(m)
        for m in FULLURL_RE.findall(text):
            endpoints.add(m)

    if html:
        scan_text(html, "HTML")
        srcs = SCRIPT_SRC_RE.findall(html)[:24]
        for src in srcs:
            url = urljoin(base + "/", src)
            if not url.startswith("http"):
                continue
            js_files.append(url)
        for url in js_files[:14]:
            try:
                r = session.get(url, timeout=7)
                if r.status_code == 200 and len(r.content) < 1500000:
                    scan_text(r.text, urlparse(url).path.split("/")[-1] or "script.js")
            except Exception:
                continue

    # de-dup secrets by (type, match)
    seen = set()
    uniq = []
    for s in secrets:
        k = (s["type"], s["match"])
        if k not in seen:
            seen.add(k)
            uniq.append(s)
    for s in uniq[:20]:
        findings.append(mk(
            f"Exposed secret: {s['type']}", s["cvss"], "Sensitive Data Exposure / CWE-798",
            f"Found in {s['source']} (redacted): {s['match']}",
            "Revoke/rotate the credential immediately and move secrets to server-side env/secret manager.",
            s["source"]))

    data = {"secrets": uniq[:20], "js_files": js_files[:12], "endpoints": sorted(endpoints)[:40]}
    return data, findings


def _probe_config(args):
    base, path, cvss = args
    url = base.rstrip("/") + path
    try:
        r = new_session().get(url, timeout=5, allow_redirects=False)
    except Exception:
        return None
    if r.status_code != 200 or not r.content:
        return None
    body = r.text[:200000]
    head = body[:400].lstrip().lower()
    ct = (r.headers.get("Content-Type") or "").lower()
    # skip SPA/HTML soft-200 fallbacks for non-HTML file types
    looks_html = head.startswith("<!doctype html") or head.startswith("<html") or "<html" in head or "text/html" in ct
    if looks_html and not path.endswith((".php", ".config", ".html")):
        return None
    hit = {"path": path, "url": url, "size": len(r.content),
           "content_type": ct.split(";")[0] or "unknown", "cvss": cvss, "body": body}
    return hit


def config_exposure_scan(session, base):
    """Probe common secret/config file paths and scan any exposed file for credentials."""
    findings, hits, secrets = [], [], []
    args = [(base, p, c) for p, c in CONFIG_PATHS]
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
        results = [h for h in ex.map(_probe_config, args) if h]
    for h in results:
        body = h.pop("body", "")
        hits.append(h)
        findings.append(mk(
            f"Exposed config/secret file: {h['path']}", h["cvss"], "Sensitive File Exposure / CWE-538",
            f"{h['url']} is publicly accessible ({h['size']} bytes, {h['content_type']})",
            "Remove the file from the web root; store secrets server-side and block dotfiles/backups at the proxy.",
            h["path"]))
        for name, scvss, pat in SECRET_PATTERNS:
            m = pat.search(body)
            if m:
                red = _redact(m.group(0))
                secrets.append({"type": name, "source": h["path"], "match": red, "cvss": scvss})
                findings.append(mk(
                    f"Secret in exposed file: {name}", scvss, "Sensitive Data Exposure / CWE-798",
                    f"Found in {h['path']} (redacted): {red}",
                    "Rotate the credential immediately and remove the file from the web root.", h["path"]))
    seen, uniq = set(), []
    for s in secrets:
        k = (s["type"], s["match"])
        if k not in seen:
            seen.add(k)
            uniq.append(s)
    data = {"config_hits": hits, "config_secrets": uniq[:20], "probed": len(CONFIG_PATHS)}
    return data, findings


# ----------------------------------------------------------------------------
# Subdomain enumeration (crt.sh certificate transparency + DNS brute)
# ----------------------------------------------------------------------------
BRUTE_SUBS = [
    "www", "dev", "staging", "test", "api", "admin", "portal", "app", "beta",
    "mail", "webmail", "vpn", "m", "mobile", "shop", "store", "blog", "cdn",
    "static", "assets", "img", "media", "docs", "support", "help", "status",
    "dashboard", "panel", "cpanel", "git", "gitlab", "jenkins", "jira",
    "internal", "secure", "auth", "sso", "db", "sql", "backup", "old", "new",
]


def _resolve(host):
    try:
        socket.setdefaulttimeout(3)
        socket.getaddrinfo(host, None)
        return True
    except Exception:
        return False


def enum_subdomains(domain):
    findings = []
    found = set()
    # Certificate transparency
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=15, headers=UA)
        if r.status_code == 200:
            for row in r.json():
                for nv in str(row.get("name_value", "")).split("\n"):
                    nv = nv.strip().lstrip("*.").lower()
                    if nv.endswith(domain) and nv != domain and "*" not in nv:
                        found.add(nv)
    except Exception:
        pass
    # DNS brute
    brute = {f"{s}.{domain}" for s in BRUTE_SUBS}
    candidates = list(found | brute)[:80]
    live = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=25) as ex:
        results = list(ex.map(_resolve, candidates))
    for host, ok in zip(candidates, results):
        if ok:
            live.append(host)
    live = sorted(set(live))

    interesting = [s for s in live if any(k in s for k in ["dev", "staging", "test", "admin", "internal", "beta", "old", "backup", "jenkins", "gitlab", "panel", "cpanel"])]
    if interesting:
        findings.append(mk(
            "Sensitive subdomains discovered", 5.3, "Information Disclosure / Attack Surface",
            "Non-production / admin subdomains resolve: " + ", ".join(interesting[:12]),
            "Restrict pre-production and admin subdomains (VPN/IP allow-list) and remove stale DNS records.",
            "DNS"))
    return {"total": len(live), "subdomains": live[:60], "interesting": interesting[:20]}, findings


# ----------------------------------------------------------------------------
# Web application vulnerability probes (safe, heuristic)
# ----------------------------------------------------------------------------
SQL_ERRORS = ["you have an error in your sql syntax", "warning: mysql", "unclosed quotation mark",
              "quoted string not properly terminated", "sqlstate", "pg_query", "psql:", "ora-01756",
              "sqlite error", "mysql_fetch", "syntax error at or near", "odbc sql"]
REDIRECT_PARAMS = ["url", "next", "redirect", "return", "returnUrl", "dest", "destination", "continue", "r"]


def web_vuln_probes(session, base):
    findings, results = [], {}
    # SQL injection (error-based)
    try:
        r = session.get(base + ("&" if "?" in base else "?") + "id=1%27", timeout=8)
        body = r.text.lower()
        hit = next((e for e in SQL_ERRORS if e in body), None)
        results["sqli"] = "error-signature detected" if hit else "no error signature"
        if hit:
            findings.append(mk("Possible SQL Injection (error-based)", 8.6,
                               "A03:2021 Injection / CWE-89",
                               f"Appending a single quote triggered SQL error signature: '{hit}'",
                               "Use parameterized queries / prepared statements; validate & sanitize input.", "app"))
    except Exception:
        results["sqli"] = "probe failed"
    # Reflected XSS
    try:
        marker = "daxx<svg/onload=alert(1)>"
        r = session.get(base + ("&" if "?" in base else "?") + "q=" + quote(marker), timeout=8)
        reflected = "daxx<svg" in r.text
        results["xss"] = "unescaped reflection" if reflected else "no reflection"
        if reflected:
            findings.append(mk("Possible Reflected XSS", 6.1,
                               "A03:2021 Injection / CWE-79",
                               "Injected payload 'daxx<svg/onload=...>' was reflected unencoded in the response.",
                               "Context-aware output encoding; add a strict Content-Security-Policy.", "app"))
    except Exception:
        results["xss"] = "probe failed"
    # Open redirect
    try:
        found_or = None
        for p in REDIRECT_PARAMS:
            r = session.get(base + ("&" if "?" in base else "?") + f"{p}=https://daxx-redirect.example",
                            timeout=6, allow_redirects=False)
            loc = r.headers.get("Location", "")
            if loc.startswith("http") and "daxx-redirect.example" in urlparse(loc).netloc:
                found_or = p
                break
        results["open_redirect"] = f"param '{found_or}'" if found_or else "not detected"
        if found_or:
            findings.append(mk("Possible Open Redirect", 5.4,
                               "A01:2021 Broken Access Control / CWE-601",
                               f"Parameter '{found_or}' redirects to an attacker-controlled external host.",
                               "Allow-list redirect targets; avoid using user input in Location.", "app"))
    except Exception:
        results["open_redirect"] = "probe failed"
    return results, findings


# ----------------------------------------------------------------------------
# API security testing
# ----------------------------------------------------------------------------
API_PATHS = ["/api", "/api/v1", "/api/v2", "/graphql", "/rest", "/v1", "/api/users",
             "/api/admin", "/api/config", "/api/swagger.json", "/openapi.json"]


def api_tests(session, base):
    findings, results = [], {"open_endpoints": [], "rate_limiting": "unknown"}
    for p in API_PATHS:
        try:
            r = session.get(base.rstrip("/") + p, timeout=6, allow_redirects=False)
            ct = r.headers.get("Content-Type", "")
            if r.status_code == 200 and ("json" in ct or "graphql" in p):
                results["open_endpoints"].append({"path": p, "status": 200, "ctype": ct[:40]})
        except Exception:
            continue
    if results["open_endpoints"]:
        paths = ", ".join(e["path"] for e in results["open_endpoints"])
        findings.append(mk("Unauthenticated API endpoint(s) return data", 6.5,
                           "API Security / CWE-284",
                           f"These API paths returned JSON without authentication: {paths}",
                           "Require authentication/authorization on all data endpoints; verify object-level access.", "api"))
    # Rate limiting probe (10 quick requests)
    try:
        codes = []
        for _ in range(10):
            rr = session.get(base, timeout=5)
            codes.append(rr.status_code)
        limited = any(c == 429 for c in codes)
        results["rate_limiting"] = "429 observed" if limited else "no 429 (no rate limit observed)"
        if not limited:
            findings.append(mk("No rate limiting observed", 3.7,
                               "API Security / CWE-770",
                               "10 rapid requests to the base URL did not trigger HTTP 429.",
                               "Apply rate limiting / throttling on authentication and expensive endpoints.", "api"))
    except Exception:
        results["rate_limiting"] = "probe failed"
    return results, findings


# ----------------------------------------------------------------------------
# Technology fingerprinting + CMS scanning
# ----------------------------------------------------------------------------
GENERATOR_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.I)


def fingerprint_tech(headers, html, cookies):
    tech = []
    h = {k.lower(): v for k, v in (headers or {}).items()}
    server = h.get("server", "")
    powered = h.get("x-powered-by", "")
    if server:
        tech.append(f"Server: {server}")
    if powered:
        tech.append(f"X-Powered-By: {powered}")
    if h.get("x-aspnet-version"):
        tech.append(f"ASP.NET {h['x-aspnet-version']}")
    ck = " ".join((cookies or {}).keys()).lower()
    if "phpsessid" in ck:
        tech.append("PHP")
    if "laravel_session" in ck or "xsrf-token" in ck:
        tech.append("Laravel")
    if "csrftoken" in ck or "sessionid" in ck:
        tech.append("Django")
    if "jsessionid" in ck:
        tech.append("Java/JSP")
    if "wordpress" in ck or "/wp-content/" in html or "/wp-includes/" in html:
        tech.append("WordPress")
    if "/sites/default/" in html or "Drupal" in html:
        tech.append("Drupal")
    if "com_content" in html or "Joomla" in html:
        tech.append("Joomla")
    gen = GENERATOR_RE.search(html or "")
    generator = gen.group(1) if gen else None
    if generator:
        tech.append(f"Generator: {generator}")
    findings = []
    if server and any(c.isdigit() for c in server):
        findings.append(mk("Technology / version disclosure", 3.1,
                           "Security Misconfiguration / CWE-200",
                           f"Banners reveal stack: {server} {powered}".strip(),
                           "Suppress version banners (Server / X-Powered-By / generator meta).", server))
    return {"stack": sorted(set(tech)), "generator": generator}, findings


def cms_scan(session, base, tech_stack):
    findings, info = [], {}
    is_wp = any("WordPress" in t for t in tech_stack)
    if not is_wp:
        return info, findings
    info["cms"] = "WordPress"
    try:
        r = session.get(base.rstrip("/") + "/wp-json", timeout=6)
        info["wp_json"] = r.status_code
        if r.status_code == 200:
            findings.append(mk("WordPress REST API exposed (/wp-json)", 3.7,
                               "Information Disclosure",
                               "The WordPress REST API is publicly reachable and may enumerate users at /wp-json/wp/v2/users.",
                               "Restrict /wp-json/wp/v2/users; disable unused REST routes.", "WordPress"))
    except Exception:
        pass
    try:
        r = session.get(base.rstrip("/") + "/wp-login.php", timeout=6, allow_redirects=False)
        if r.status_code in (200, 302):
            findings.append(mk("WordPress login page accessible", 3.1,
                               "Security Misconfiguration",
                               "/wp-login.php is reachable — brute-force / credential-stuffing surface.",
                               "Add rate limiting, 2FA, and IP restrictions to wp-login.php.", "WordPress"))
    except Exception:
        pass
    try:
        r = session.get(base.rstrip("/") + "/readme.html", timeout=6)
        if r.status_code == 200 and "wordpress" in r.text.lower():
            vm = re.search(r"[Vv]ersion\s+([0-9.]+)", r.text)
            ver = vm.group(1) if vm else "unknown"
            info["wp_version"] = ver
            findings.append(mk(f"WordPress version disclosed via readme.html ({ver})", 4.3,
                               "Security Misconfiguration / CWE-200",
                               f"/readme.html discloses WordPress version {ver}.",
                               "Delete readme.html and keep core/plugins updated.", "WordPress"))
    except Exception:
        pass
    return info, findings


# ----------------------------------------------------------------------------
# Network reconnaissance (DNS, SPF/DMARC, WHOIS)
# ----------------------------------------------------------------------------
def network_recon(domain):
    import dns.resolver
    findings = []
    data = {"records": {}, "spf": None, "dmarc": None, "whois": {}}
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5
    resolver.timeout = 5

    def q(name, rtype):
        try:
            return [r.to_text() for r in resolver.resolve(name, rtype)]
        except Exception:
            return []

    for rt in ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]:
        recs = q(domain, rt)
        if recs:
            data["records"][rt] = recs[:8]

    txt = data["records"].get("TXT", [])
    spf = next((t for t in txt if "v=spf1" in t.lower()), None)
    data["spf"] = spf
    if not spf:
        findings.append(mk("Missing SPF record", 4.3, "Email Security / Spoofing",
                           "No v=spf1 TXT record found — the domain can be spoofed in email.",
                           "Publish an SPF record (e.g. 'v=spf1 include:_spf.provider.com -all').", "DNS"))
    dmarc = q("_dmarc." + domain, "TXT")
    dmarc_rec = next((t for t in dmarc if "v=dmarc1" in t.lower()), None)
    data["dmarc"] = dmarc_rec
    if not dmarc_rec:
        findings.append(mk("Missing DMARC record", 4.3, "Email Security / Spoofing",
                           "No _dmarc TXT record found — phishing/spoofing is easier and undetected.",
                           "Publish a DMARC policy (start with p=none, then enforce p=quarantine/reject).", "DNS"))
    # DMARC policy strength
    dmarc_policy = None
    if dmarc_rec:
        m = re.search(r"p\s*=\s*(\w+)", dmarc_rec)
        dmarc_policy = m.group(1).lower() if m else None
        if dmarc_policy == "none":
            findings.append(mk("Weak DMARC policy (p=none)", 3.7, "Email Security / Spoofing",
                               "DMARC is monitor-only (p=none) — spoofed mail is not actively rejected.",
                               "Move to p=quarantine, then p=reject after monitoring reports.", "DNS"))
    data["dmarc_policy"] = dmarc_policy
    # SPF enforcement
    data["spf_enforced"] = bool(spf and "-all" in spf.replace(" ", ""))
    # DKIM — probe common selectors
    dkim_selectors = []
    for sel in ("default", "google", "selector1", "selector2", "k1", "dkim", "mail", "s1", "smtp"):
        rec = q(f"{sel}._domainkey.{domain}", "TXT")
        if any(("v=dkim1" in r.lower()) or ("p=" in r.lower()) for r in rec):
            dkim_selectors.append(sel)
    data["dkim"] = dkim_selectors
    if not dkim_selectors:
        findings.append(mk("No DKIM selector found (common list)", 3.1, "Email Security / Spoofing",
                           "No DKIM TXT record on common selectors — outbound mail may be unsigned/forgeable.",
                           "Publish a DKIM public key and sign all outbound mail.", "DNS"))
    # Overall spoofability verdict
    data["email_spoofable"] = (not data["spf_enforced"]) or (not dmarc_rec) or (dmarc_policy in (None, "none"))
    try:
        import whois as _whois
        w = _whois.whois(domain)
        def s(v):
            if isinstance(v, list):
                v = v[0] if v else None
            return str(v) if v is not None else None
        data["whois"] = {"registrar": s(w.registrar), "created": s(w.creation_date),
                         "expires": s(w.expiration_date),
                         "name_servers": (w.name_servers[:6] if isinstance(w.name_servers, list) else s(w.name_servers))}
    except Exception:
        data["whois"] = {}
    return data, findings


# ----------------------------------------------------------------------------
# Screenshot (WordPress mShots — no API key needed)
# ----------------------------------------------------------------------------
def geolocate(host):
    try:
        r = requests.get(
            f"http://ip-api.com/json/{host}?fields=status,country,countryCode,city,lat,lon,query,isp",
            timeout=8, headers=UA)
        d = r.json()
        if d.get("status") == "success":
            return {"query": d.get("query"), "country": d.get("country"),
                    "countryCode": d.get("countryCode"), "city": d.get("city"),
                    "lat": d.get("lat"), "lon": d.get("lon"), "isp": d.get("isp")}
    except Exception:
        pass
    return None


def screenshot_url(target):
    u = target if target.startswith("http") else "https://" + target
    return f"https://image.thum.io/get/width/1200/crop/750/{u}"
