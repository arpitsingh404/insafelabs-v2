"""InsafeLabs Template Engine — a nuclei-compatible, extensible signature engine.

Each template is a dict: id, name, severity, cvss, category, path, method,
matchers {status, words, words_condition, regex, headers, negative_words},
cve, remediation. Add more templates here (or load nuclei YAML) to grow coverage.
"""
import re
import concurrent.futures
from urllib.parse import urlparse

from recon_lib import mk, new_session

# ----------------------------------------------------------------------------
# Curated template library (exposed panels, dev tools, actuators, known CVEs)
# ----------------------------------------------------------------------------
TEMPLATES = [
    # --- Exposed admin / management panels ---
    {"id": "phpmyadmin", "name": "phpMyAdmin panel exposed", "severity": "medium", "cvss": 5.3, "category": "Exposed Panel",
     "path": "/phpmyadmin/", "matchers": {"status": [200], "regex": [r"pma_username|pmahomepage|phpMyAdmin\s*</title>|token_mismatch"]}, "cve": ""},
    {"id": "adminer", "name": "Adminer database console exposed", "severity": "high", "cvss": 7.5, "category": "Exposed Panel",
     "path": "/adminer.php", "matchers": {"status": [200], "regex": [r"Adminer\s*</title>|name=\"auth\[server\]\"|adminer\.org"]}, "cve": ""},
    {"id": "jenkins", "name": "Jenkins CI dashboard exposed", "severity": "high", "cvss": 7.5, "category": "Exposed Panel",
     "path": "/", "matchers": {"status": [200, 403], "headers": ["x-jenkins"]}, "cve": ""},
    {"id": "grafana", "name": "Grafana dashboard exposed", "severity": "medium", "cvss": 5.3, "category": "Exposed Panel",
     "path": "/login", "matchers": {"status": [200], "regex": [r"grafanaBootData|grafana-app|\"grafanaVersion\""]}, "cve": ""},
    {"id": "kibana", "name": "Kibana console exposed", "severity": "medium", "cvss": 5.3, "category": "Exposed Panel",
     "path": "/app/kibana", "matchers": {"status": [200], "regex": [r"kbnInjectedMetadata|kbn-injected-metadata|kibanaWelcomeView"]}, "cve": ""},
    {"id": "traefik", "name": "Traefik dashboard exposed", "severity": "medium", "cvss": 5.3, "category": "Exposed Panel",
     "path": "/dashboard/", "matchers": {"status": [200], "regex": [r"io\.traefik|Traefik\s*</title>|traefik-ui"]}, "cve": ""},
    {"id": "portainer", "name": "Portainer console exposed", "severity": "high", "cvss": 7.5, "category": "Exposed Panel",
     "path": "/", "matchers": {"status": [200], "regex": [r"io\.portainer|Portainer\s*</title>|portainer\.app"]}, "cve": ""},
    {"id": "rabbitmq", "name": "RabbitMQ management exposed", "severity": "high", "cvss": 7.5, "category": "Exposed Panel",
     "path": "/", "matchers": {"status": [200], "words": ["rabbitmq management"]}, "cve": ""},
    {"id": "prometheus", "name": "Prometheus metrics exposed", "severity": "low", "cvss": 3.7, "category": "Info Leak",
     "path": "/metrics", "matchers": {"status": [200], "words": ["# help", "# type"], "words_condition": "and"}, "cve": ""},
    {"id": "kubernetes-dash", "name": "Kubernetes Dashboard exposed", "severity": "critical", "cvss": 9.1, "category": "Exposed Panel",
     "path": "/", "matchers": {"status": [200], "regex": [r"Kubernetes Dashboard\s*</title>|kubernetesDashboard"]}, "cve": ""},
    {"id": "docker-registry", "name": "Docker Registry API exposed", "severity": "high", "cvss": 7.5, "category": "Exposed Panel",
     "path": "/v2/_catalog", "matchers": {"status": [200], "headers": ["content-type: application/json"], "words": ["repositories"]}, "cve": ""},
    {"id": "sonarqube", "name": "SonarQube exposed", "severity": "medium", "cvss": 5.0, "category": "Exposed Panel",
     "path": "/", "matchers": {"status": [200], "regex": [r"SonarQube\s*</title>|window\.sonar|sonar\.js"]}, "cve": ""},
    {"id": "harbor", "name": "Harbor registry exposed", "severity": "medium", "cvss": 5.0, "category": "Exposed Panel",
     "path": "/api/v2.0/systeminfo", "matchers": {"status": [200], "words": ["harbor_version", "registry_url", "auth_mode"], "words_condition": "or"}, "cve": ""},
    {"id": "minio-console", "name": "MinIO console exposed", "severity": "medium", "cvss": 5.3, "category": "Exposed Panel",
     "path": "/", "matchers": {"status": [200], "headers": ["server: minio"]}, "cve": ""},
    {"id": "pgadmin", "name": "pgAdmin panel exposed", "severity": "medium", "cvss": 5.3, "category": "Exposed Panel",
     "path": "/", "matchers": {"status": [200], "regex": [r"pgadmin4|pgAdmin 4|pga_login"]}, "cve": ""},

    # --- Spring Boot Actuator ---
    {"id": "actuator-env", "name": "Spring Boot Actuator /env exposed", "severity": "high", "cvss": 8.6, "category": "Sensitive Exposure",
     "path": "/actuator/env", "matchers": {"status": [200], "words": ["propertysources", "activeprofiles"], "words_condition": "or"}, "cve": ""},
    {"id": "actuator-health", "name": "Spring Boot Actuator /health exposed", "severity": "info", "cvss": 0.0, "category": "Info Leak",
     "path": "/actuator/health", "matchers": {"status": [200], "words": ["\"status\""]}, "cve": ""},
    {"id": "actuator-heapdump", "name": "Spring Boot Actuator heapdump exposed", "severity": "critical", "cvss": 9.8, "category": "Sensitive Exposure",
     "path": "/actuator/heapdump", "matchers": {"status": [200], "headers": ["content-type: application/octet-stream"]}, "cve": ""},
    {"id": "actuator-mappings", "name": "Spring Boot Actuator /mappings exposed", "severity": "low", "cvss": 3.7, "category": "Info Leak",
     "path": "/actuator/mappings", "matchers": {"status": [200], "words": ["dispatcherservlet", "handler"], "words_condition": "or"}, "cve": ""},
    {"id": "actuator-loggers", "name": "Spring Boot Actuator /loggers exposed", "severity": "medium", "cvss": 5.3, "category": "Info Leak",
     "path": "/actuator/loggers", "matchers": {"status": [200], "words": ["configuredlevel", "levels"], "words_condition": "or"}, "cve": ""},

    # --- API docs / schemas ---
    {"id": "swagger-ui", "name": "Swagger UI exposed", "severity": "low", "cvss": 3.7, "category": "Info Leak",
     "path": "/swagger-ui/index.html", "matchers": {"status": [200], "words": ["swagger"]}, "cve": ""},
    {"id": "openapi-json", "name": "OpenAPI spec exposed", "severity": "low", "cvss": 3.1, "category": "Info Leak",
     "path": "/openapi.json", "matchers": {"status": [200], "words": ["openapi", "swagger"], "words_condition": "or"}, "cve": ""},
    {"id": "api-docs", "name": "API docs (v2/api-docs) exposed", "severity": "low", "cvss": 3.1, "category": "Info Leak",
     "path": "/v2/api-docs", "matchers": {"status": [200], "words": ["swagger", "paths"], "words_condition": "or"}, "cve": ""},
    {"id": "graphql-playground", "name": "GraphQL Playground exposed", "severity": "low", "cvss": 3.7, "category": "Info Leak",
     "path": "/playground", "matchers": {"status": [200], "words": ["graphql playground"]}, "cve": ""},

    # --- Framework debug / info leaks ---
    {"id": "phpinfo", "name": "phpinfo() page exposed", "severity": "medium", "cvss": 5.3, "category": "Info Leak",
     "path": "/phpinfo.php", "matchers": {"status": [200], "words": ["phpinfo()", "php version"], "words_condition": "or"}, "cve": ""},
    {"id": "laravel-telescope", "name": "Laravel Telescope exposed", "severity": "high", "cvss": 7.5, "category": "Sensitive Exposure",
     "path": "/telescope/requests", "matchers": {"status": [200], "words": ["telescope"]}, "cve": ""},
    {"id": "laravel-debug", "name": "Laravel debug mode / Ignition exposed", "severity": "medium", "cvss": 5.3, "category": "Info Leak",
     "path": "/_ignition/health-check", "matchers": {"status": [200], "words": ["can_execute_commands", "ignition"], "words_condition": "or"}, "cve": "CVE-2021-3129"},
    {"id": "laravel-log", "name": "Laravel log file exposed", "severity": "high", "cvss": 7.5, "category": "Sensitive Exposure",
     "path": "/storage/logs/laravel.log", "matchers": {"status": [200], "words": ["production.error", "stacktrace", "exception"], "words_condition": "or"}, "cve": ""},
    {"id": "django-debug", "name": "Django DEBUG traceback exposed", "severity": "medium", "cvss": 5.3, "category": "Info Leak",
     "path": "/nonexistent-daxx-probe", "matchers": {"status": [500], "words": ["djangotemplates", "traceback (most recent call last)"], "words_condition": "or"}, "cve": ""},
    {"id": "symfony-profiler", "name": "Symfony profiler exposed", "severity": "high", "cvss": 7.5, "category": "Sensitive Exposure",
     "path": "/_profiler", "matchers": {"status": [200], "words": ["symfony profiler"]}, "cve": ""},
    {"id": "rails-routes", "name": "Rails routes / info page exposed", "severity": "medium", "cvss": 5.0, "category": "Info Leak",
     "path": "/rails/info/routes", "matchers": {"status": [200], "words": ["routes", "path helper"], "words_condition": "or"}, "cve": ""},

    # --- Server status / VCS / editor / IDE ---
    {"id": "apache-status", "name": "Apache server-status exposed", "severity": "low", "cvss": 3.7, "category": "Info Leak",
     "path": "/server-status", "matchers": {"status": [200], "words": ["apache server status"]}, "cve": ""},
    {"id": "apache-info", "name": "Apache server-info exposed", "severity": "low", "cvss": 3.7, "category": "Info Leak",
     "path": "/server-info", "matchers": {"status": [200], "words": ["apache server information"]}, "cve": ""},
    {"id": "nginx-status", "name": "Nginx stub_status exposed", "severity": "low", "cvss": 3.1, "category": "Info Leak",
     "path": "/nginx_status", "matchers": {"status": [200], "words": ["active connections"]}, "cve": ""},
    {"id": "ds-store", "name": ".DS_Store file exposed", "severity": "low", "cvss": 4.3, "category": "Info Leak",
     "path": "/.DS_Store", "matchers": {"status": [200], "regex": [r"Bud1"]}, "cve": ""},
    {"id": "svn-entries", "name": "Subversion .svn/entries exposed", "severity": "medium", "cvss": 5.3, "category": "Sensitive Exposure",
     "path": "/.svn/entries", "matchers": {"status": [200], "regex": [r"^\d+"], "negative_words": ["<html"]}, "cve": ""},
    {"id": "vscode-sftp", "name": "VS Code sftp.json exposed", "severity": "high", "cvss": 8.0, "category": "Sensitive Exposure",
     "path": "/.vscode/sftp.json", "matchers": {"status": [200], "words": ["host", "password", "username"], "words_condition": "or"}, "cve": ""},

    # --- CMS specific ---
    {"id": "wp-debug-log", "name": "WordPress debug.log exposed", "severity": "medium", "cvss": 5.3, "category": "Info Leak",
     "path": "/wp-content/debug.log", "matchers": {"status": [200], "words": ["php", "error", "stack trace"], "words_condition": "or"}, "cve": ""},
    {"id": "wp-config-bak", "name": "WordPress wp-config backup exposed", "severity": "critical", "cvss": 9.8, "category": "Sensitive Exposure",
     "path": "/wp-config.php.bak", "matchers": {"status": [200], "words": ["db_password", "db_name"], "words_condition": "or"}, "cve": ""},
    {"id": "drupal-changelog", "name": "Drupal CHANGELOG version disclosure", "severity": "low", "cvss": 3.1, "category": "Info Leak",
     "path": "/CHANGELOG.txt", "matchers": {"status": [200], "words": ["drupal"]}, "cve": ""},
    {"id": "joomla-manifest", "name": "Joomla version manifest disclosure", "severity": "low", "cvss": 3.1, "category": "Info Leak",
     "path": "/administrator/manifests/files/joomla.xml", "matchers": {"status": [200], "words": ["<version>"]}, "cve": ""},
    {"id": "magento-version", "name": "Magento version disclosure", "severity": "low", "cvss": 3.1, "category": "Info Leak",
     "path": "/magento_version", "matchers": {"status": [200], "words": ["magento"]}, "cve": ""},

    # --- Backups / archives ---
    {"id": "sql-dump", "name": "SQL database dump exposed", "severity": "critical", "cvss": 9.1, "category": "Sensitive Exposure",
     "path": "/dump.sql", "matchers": {"status": [200], "words": ["insert into", "create table"], "words_condition": "or"}, "cve": ""},
    {"id": "backup-zip", "name": "Backup archive exposed (backup.zip)", "severity": "high", "cvss": 7.5, "category": "Sensitive Exposure",
     "path": "/backup.zip", "matchers": {"status": [200], "headers": ["content-type: application/zip"]}, "cve": ""},
    {"id": "www-tar", "name": "Site archive exposed (www.tar.gz)", "severity": "high", "cvss": 7.5, "category": "Sensitive Exposure",
     "path": "/www.tar.gz", "matchers": {"status": [200], "headers": ["content-type: application/gzip"]}, "cve": ""},

    # --- Known CVE path indicators ---
    {"id": "cve-2021-41773", "name": "Apache path traversal (CVE-2021-41773)", "severity": "critical", "cvss": 9.8, "category": "A01 / CWE-22",
     "path": "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd", "matchers": {"status": [200], "regex": [r"root:.*?:0:0:"]}, "cve": "CVE-2021-41773"},
    {"id": "cve-2017-5638", "name": "Apache Struts RCE surface (CVE-2017-5638)", "severity": "high", "cvss": 8.1, "category": "A06 / RCE",
     "path": "/index.action", "matchers": {"status": [200], "headers": ["x-powered-by: struts"]}, "cve": "CVE-2017-5638"},
    {"id": "cve-2019-11510", "name": "Pulse Secure VPN arbitrary read (CVE-2019-11510)", "severity": "critical", "cvss": 9.8, "category": "A01 / CWE-22",
     "path": "/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/", "matchers": {"status": [200], "regex": [r"root:.*?:0:0:"]}, "cve": "CVE-2019-11510"},
    {"id": "gitlab-version", "name": "GitLab instance detected", "severity": "info", "cvss": 0.0, "category": "Info Leak",
     "path": "/users/sign_in", "matchers": {"status": [200], "regex": [r"gon\.gitlab|GitLab\s*</title>|gitlab_logo|data-page=\"sessions"]}, "cve": ""},
    {"id": "confluence", "name": "Atlassian Confluence detected", "severity": "info", "cvss": 0.0, "category": "Info Leak",
     "path": "/", "matchers": {"status": [200], "regex": [r"Confluence\s*</title>|confluence-context-path|ajs-.*confluence"]}, "cve": ""},
    {"id": "jira-dashboard", "name": "Atlassian Jira detected", "severity": "info", "cvss": 0.0, "category": "Info Leak",
     "path": "/secure/Dashboard.jspa", "matchers": {"status": [200], "regex": [r"jira\.webresources|JIRA\s*</title>|ajs-.*jira"]}, "cve": ""},

    # --- Cloud metadata / misc ---
    {"id": "well-known-openid", "name": "OpenID configuration exposed", "severity": "info", "cvss": 0.0, "category": "Info Leak",
     "path": "/.well-known/openid-configuration", "matchers": {"status": [200], "words": ["issuer", "authorization_endpoint"], "words_condition": "or"}, "cve": ""},
    {"id": "env-json", "name": "Frontend env.json exposed", "severity": "medium", "cvss": 6.5, "category": "Sensitive Exposure",
     "path": "/env.json", "matchers": {"status": [200], "words": ["apikey", "api_key", "secret", "token"], "words_condition": "or"}, "cve": ""},
    {"id": "elmah-axd", "name": "ASP.NET ELMAH error log exposed", "severity": "high", "cvss": 7.5, "category": "Sensitive Exposure",
     "path": "/elmah.axd", "matchers": {"status": [200], "words": ["error log for"]}, "cve": ""},
    {"id": "trace-axd", "name": "ASP.NET trace.axd exposed", "severity": "medium", "cvss": 5.3, "category": "Info Leak",
     "path": "/trace.axd", "matchers": {"status": [200], "words": ["application trace"]}, "cve": ""},
]

REMEDIATION = {
    "Exposed Panel": "Restrict the panel behind VPN/IP allow-list + strong auth; do not expose management UIs publicly.",
    "Sensitive Exposure": "Remove the file/endpoint from the web root, rotate any exposed secrets, and block it at the proxy.",
    "Info Leak": "Disable or restrict the endpoint; suppress verbose diagnostics in production.",
    "A01 / CWE-22": "Patch the affected software immediately and reject traversal sequences at the server.",
    "A06 / RCE": "Patch to a fixed version urgently; the component is remotely exploitable.",
}


def _match(r, m):
    if "status" in m and r.status_code not in m["status"]:
        return False
    body = r.text[:250000]
    low = body.lower()
    if "words" in m:
        cond = m.get("words_condition", "and")
        checks = [w.lower() in low for w in m["words"]]
        if cond == "and" and not all(checks):
            return False
        if cond == "or" and not any(checks):
            return False
    if "regex" in m:
        if not any(re.search(rx, body, re.M) for rx in m["regex"]):
            return False
    if "headers" in m:
        hb = " ".join(f"{k}: {v}" for k, v in r.headers.items()).lower()
        if not all(h.lower() in hb for h in m["headers"]):
            return False
    if "negative_words" in m:
        if any(w.lower() in low for w in m["negative_words"]):
            return False
    return True


def _run_one(args):
    base, tpl = args
    url = base.rstrip("/") + tpl["path"]
    try:
        r = new_session().get(url, timeout=6, allow_redirects=False)
    except Exception:
        return None
    try:
        if _match(r, tpl["matchers"]):
            return {"id": tpl["id"], "name": tpl["name"], "severity": tpl["severity"],
                    "cvss": tpl["cvss"], "category": tpl["category"], "url": url,
                    "cve": tpl.get("cve", ""), "status": r.status_code}
    except Exception:
        return None
    return None


def template_scan(session, base):
    """Run the template library against the target; return (data, findings)."""
    findings, matched = [], []
    args = [(base, t) for t in TEMPLATES]
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        results = [h for h in ex.map(_run_one, args) if h]
    for h in results:
        title = h["name"] + (f" ({h['cve']})" if h["cve"] and h["cve"] not in h["name"] else "")
        matched.append(h)
        findings.append(mk(
            f"[template] {title}", h["cvss"], f"Template Match / {h['category']}",
            f"Signature '{h['id']}' matched at {h['url']} (HTTP {h['status']})" + (f" · {h['cve']}" if h["cve"] else ""),
            REMEDIATION.get(h["category"], "Investigate and restrict/patch the matched resource."),
            "template-engine"))
    data = {"matched": matched, "total_templates": len(TEMPLATES), "match_count": len(matched)}
    return data, findings
