"""Shared tool registry used by the AI Agent and Playbooks.

Each tool exposes: desc, params, and either fn(args)->dict (sync, run in a
thread) or afn(args)->coroutine (async, e.g. the Arsenal runner).
"""
import asyncio

from fastapi import HTTPException


def registry():
    from routers import toolkit, vulnsuite, arsenal

    def _dns_domain(domain):
        import re
        import recon_lib
        d = re.sub(r"^https?://", "", (domain or "").strip()).split("/")[0].split(":")[0]
        res, findings = recon_lib.network_recon(d)
        res["domain"] = d
        res["findings"] = findings
        return res

    def port(args):
        return asyncio.run(toolkit._port_scan(args["host"]))

    def subs(args):
        return asyncio.run(toolkit._subdomain_enum(args["domain"]))

    def nmap(args):
        return arsenal.run(arsenal.RunBody(id="nmap", profile="service", target=args["host"]))

    def nuclei(args):
        return arsenal.run(arsenal.RunBody(id="nuclei", profile="safe", target=args["url"]))

    return {
        "web_scan": {"desc": "Full non-destructive web security scan (headers/grade, cookies, CORS, sensitive files, TLS, methods)",
                     "params": ["url"], "fn": lambda a: vulnsuite._web_scan(a["url"])},
        "injection": {"desc": "Test a URL's query params for SQLi, XSS, CRLF, open-redirect (url must contain ?params)",
                      "params": ["url"], "fn": lambda a: vulnsuite._injection(a["url"])},
        "param_discovery": {"desc": "Discover hidden parameters of a URL",
                            "params": ["url"], "fn": lambda a: vulnsuite._params(a["url"])},
        "auth_form": {"desc": "Analyse a login form (method, CSRF, transport, rate-limit hints)",
                      "params": ["url"], "fn": lambda a: vulnsuite._auth_form(a["url"])},
        "tls_scan": {"desc": "TLS certificate + protocol support (1.0-1.3)",
                     "params": ["host"], "fn": lambda a: vulnsuite._tls_scan(a["host"])},
        "vhost_discovery": {"desc": "Virtual-host discovery via Host header",
                            "params": ["url"], "fn": lambda a: vulnsuite._vhost(vulnsuite.VhostInput(url=a["url"], extra=a.get("extra", "")))},
        "dns_recon": {"desc": "DNS records / WHOIS style recon for a domain",
                      "params": ["domain"], "fn": lambda a: _dns_domain(a["domain"])},
        "dns_axfr": {"desc": "DNS records + zone transfer (AXFR) + SPF check",
                     "params": ["domain"], "fn": lambda a: vulnsuite._dns_scan(a["domain"])},
        "email_security": {"desc": "SPF / DMARC / DKIM / DNSSEC / CAA for a domain",
                           "params": ["domain"], "fn": lambda a: toolkit._email_dns(a["domain"])},
        "subdomain_enum": {"desc": "Enumerate common subdomains of a domain",
                           "params": ["domain"], "fn": lambda a: subs(a)},
        "port_scan": {"desc": "Quick port/service scan of a host (~35 common ports)",
                      "params": ["host"], "fn": lambda a: port(a)},
        "http_inspect": {"desc": "HTTP header + TLS certificate inspector for a URL",
                         "params": ["url"], "fn": lambda a: toolkit._http_inspect(a["url"])},
        "fingerprint": {"desc": "Web technology + WAF fingerprint of a URL",
                        "params": ["url"], "fn": lambda a: toolkit._web_fingerprint(a["url"])},
        "cors_test": {"desc": "CORS misconfiguration test for a URL",
                      "params": ["url"], "fn": lambda a: toolkit._cors_test(a["url"])},
        "takeover": {"desc": "Subdomain takeover check for a host",
                     "params": ["host"], "fn": lambda a: toolkit._takeover(a["host"])},
        "rate_limit_check": {"desc": "Check whether a URL enforces rate limiting (429/Retry-After)",
                             "params": ["url"], "fn": lambda a: vulnsuite._rate_limit(vulnsuite.RateInput(url=a["url"], count=int(a.get("count", 12) or 12)))},
        "idor_check": {"desc": "Test for IDOR by varying a numeric object id in the URL (e.g. /users/1 or ?id=1)",
                       "params": ["url"], "fn": lambda a: vulnsuite._idor(vulnsuite.IdorInput(url=a["url"]))},
        "ssti_check": {"desc": "Test query params for Server-Side Template Injection",
                       "params": ["url"], "fn": lambda a: vulnsuite._ssti(vulnsuite.ParamInput(url=a["url"]))},
        "lfi_check": {"desc": "Test query params for Local File Inclusion / path traversal",
                      "params": ["url"], "fn": lambda a: vulnsuite._lfi(vulnsuite.ParamInput(url=a["url"]))},
        "cmdi_check": {"desc": "Test query params for OS command injection (time/echo based)",
                       "params": ["url"], "fn": lambda a: vulnsuite._cmdi(vulnsuite.ParamInput(url=a["url"]))},
        "favicon_fingerprint": {"desc": "Fingerprint the site favicon (md5/sha256 + Shodan-style mmh3 hash)",
                                "params": ["url"], "fn": lambda a: vulnsuite._favicon(vulnsuite.UrlInput(url=a["url"]))},
        "cidr_sweep": {"desc": "Reverse-DNS (PTR) sweep of a CIDR / subnet",
                       "params": ["target"], "fn": lambda a: vulnsuite._cidr_sweep(vulnsuite.CidrInput(target=a["target"]))},
        "openapi_analyze": {"desc": "Find and analyse an OpenAPI/Swagger spec (endpoints + missing auth)",
                            "params": ["url"], "fn": lambda a: vulnsuite._openapi(vulnsuite.UrlInput(url=a["url"]))},
        "xxe_check": {"desc": "Test an XML endpoint for XXE (external entity file disclosure)",
                      "params": ["url"], "fn": lambda a: vulnsuite._xxe(vulnsuite.XxeInput(url=a["url"]))},
        "nmap_scan": {"desc": "Nmap service/version scan (via the Arsenal runner; needs nmap installed)",
                      "params": ["host"], "afn": lambda a: nmap(a)},
        "nuclei_scan": {"desc": "Nuclei template scan (via the Arsenal runner; needs nuclei installed)",
                        "params": ["url"], "afn": lambda a: nuclei(a)},
    }


def catalog_text(reg):
    return "\n".join(f"- {name}({', '.join(t['params'])}): {t['desc']}" for name, t in reg.items())


def summarize(name, res):
    if not isinstance(res, dict):
        return "no data"
    if res.get("error"):
        return f"error: {res['error']}"
    bits = []
    for k in ("findings_count", "found_count", "open_count", "count", "vulnerable", "grade", "status", "exit_code"):
        if k in res:
            bits.append(f"{k}={res[k]}")
    for k in ("findings", "found", "open_ports"):
        if isinstance(res.get(k), list):
            bits.append(f"{k}={len(res[k])}")
    return ", ".join(bits) or "ok"


async def exec_tool(name, args, reg=None):
    reg = reg or registry()
    entry = reg.get(name)
    if not entry:
        return {"error": f"unknown tool '{name}'"}
    missing = [p for p in entry["params"] if not str(args.get(p, "")).strip()]
    if missing:
        return {"error": f"missing params: {', '.join(missing)}"}
    try:
        if "afn" in entry:
            res = await entry["afn"](args)
        else:
            loop = asyncio.get_event_loop()
            res = await loop.run_in_executor(None, entry["fn"], args)
    except HTTPException as e:
        return {"error": e.detail}
    except Exception as e:
        return {"error": str(e)[:200]}
    return res if isinstance(res, dict) else {"result": res}
