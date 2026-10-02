"""Blacklist / reputation checks — DNS-based blocklists (RBL/DNSBL/URIBL).

Checks an IP, domain or email against public DNS blocklists. Read-only DNS
lookups (no external API keys needed).
"""
import re
import socket

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(prefix="/blacklist", tags=["blacklist"])

# IP-based realtime blocklists (RBL / DNSBL)
IP_BLOCKLISTS = {
    "zen.spamhaus.org": "Spamhaus ZEN (SBL+XBL+PBL)",
    "b.barracudacentral.org": "Barracuda Central",
    "bl.spamcop.net": "SpamCop",
    "dnsbl.sorbs.net": "SORBS",
    "cbl.abuseat.org": "Abuseat CBL",
    "dnsbl-1.uceprotect.net": "UCEPROTECT L1",
    "psbl.surriel.com": "PSBL",
    "spamsources.fabel.dk": "SpamSources",
    "ubl.unsubscore.com": "UnsubScore",
    "all.s5h.net": "s5h.net",
    "dnsbl.dronebl.org": "DroneBL",
    "spam.dnsbl.anonmails.de": "anonmails",
}

# Domain / URI blocklists
DOMAIN_BLOCKLISTS = {
    "dbl.spamhaus.org": "Spamhaus DBL",
    "multi.surbl.org": "SURBL",
    "uribl.spameatingmonkey.net": "SpamEatingMonkey URIBL",
    "black.uribl.com": "URIBL",
    "dbl.nordspam.com": "NordSpam DBL",
}

EMAIL_RE = re.compile(r"^[^@\s]+@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})$")
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _query(zone: str):
    try:
        import dns.resolver
        ans = dns.resolver.resolve(zone, "A", lifetime=5)
        return sorted({r.to_text() for r in ans})
    except Exception:
        return []


def _rev_ip(ip: str) -> str:
    return ".".join(reversed(ip.split(".")))


def _check_ip(ip: str):
    rev = _rev_ip(ip)
    out = []
    for zone, label in IP_BLOCKLISTS.items():
        codes = _query(f"{rev}.{zone}")
        out.append({"list": zone, "label": label, "listed": bool(codes), "codes": codes})
    return out


def _check_domain(domain: str):
    out = []
    for zone, label in DOMAIN_BLOCKLISTS.items():
        codes = _query(f"{domain}.{zone}")
        out.append({"list": zone, "label": label, "listed": bool(codes), "codes": codes})
    return out


def _resolve(host: str):
    try:
        infos = socket.getaddrinfo(host, None)
        return sorted({i[4][0] for i in infos})
    except Exception:
        return []


class TargetInput(BaseModel):
    target: str = Field(min_length=1, max_length=253)


def _run(target: str) -> dict:
    t = (target or "").strip().lower()
    kind = "unknown"
    domain = None
    ip = None

    m = EMAIL_RE.match(t)
    if m:
        kind = "email"
        domain = m.group(1)
    elif IP_RE.match(t):
        kind = "ip"
        ip = t
    elif "." in t:
        kind = "domain"
        domain = re.sub(r"^https?://", "", t).split("/")[0].split(":")[0]

    result = {"target": t, "kind": kind, "ip_blocklists": [], "domain_blocklists": [],
              "resolved_ips": [], "mx": [], "listed_count": 0}

    if kind in ("domain", "email"):
        result["domain_blocklists"] = _check_domain(domain)
        result["resolved_ips"] = _resolve(domain)
        # MX records for email reputation
        try:
            import dns.resolver
            for mx in dns.resolver.resolve(domain, "MX", lifetime=6):
                host = str(mx.exchange).rstrip(".")
                result["mx"].append({"host": host, "ips": _resolve(host)})
        except Exception:
            pass

    ips_to_check = [ip] if ip else result["resolved_ips"][:2]
    for one in ips_to_check:
        result["ip_blocklists"].append({"ip": one, "lists": _check_ip(one)})

    result["listed_count"] = (
        sum(1 for x in result["domain_blocklists"] if x["listed"])
        + sum(1 for grp in result["ip_blocklists"] for x in grp["lists"] if x["listed"])
    )
    result["clean"] = result["listed_count"] == 0
    return result


@router.post("/check")
async def check(body: TargetInput):
    return _run(body.target)


@router.get("/lists")
async def lists():
    return {
        "ip_blocklists": [{"list": k, "label": v} for k, v in IP_BLOCKLISTS.items()],
        "domain_blocklists": [{"list": k, "label": v} for k, v in DOMAIN_BLOCKLISTS.items()],
    }
