"""Guided playbooks — one-click sequences of the app's native tools."""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from routers import toolreg

router = APIRouter(prefix="/playbooks", tags=["playbooks"])

PLAYBOOKS = [
    {"id": "external_recon", "name": "External Recon", "icon": "radar",
     "desc": "DNS records, subdomain enumeration, email security (SPF/DMARC/DKIM), zone transfer and subdomain takeover.",
     "targetHint": "domain — e.g. example.com",
     "steps": [["dns_recon", "domain"], ["subdomain_enum", "domain"], ["email_security", "domain"],
               ["dns_axfr", "domain"], ["takeover", "host"]]},
    {"id": "web_quick", "name": "Web Quick Check", "icon": "globe",
     "desc": "Fast, non-destructive web check: headers/grade, tech & WAF fingerprint, CORS, login-form analysis.",
     "targetHint": "URL — e.g. https://target.tld",
     "steps": [["web_scan", "url"], ["fingerprint", "url"], ["cors_test", "url"], ["auth_form", "url"]]},
    {"id": "web_deep", "name": "Web Deep Assessment", "icon": "shield",
     "desc": "Comprehensive web testing: full web scan, injection (SQLi/XSS/CRLF/redirect), parameter discovery, vhost, TLS.",
     "targetHint": "URL — e.g. https://target.tld/page?id=1",
     "steps": [["web_scan", "url"], ["injection", "url"], ["ssti_check", "url"], ["lfi_check", "url"],
               ["cmdi_check", "url"], ["param_discovery", "url"],
               ["vhost_discovery", "url"], ["idor_check", "url"], ["rate_limit_check", "url"],
               ["tls_scan", "host"]]},
    {"id": "infra_tls", "name": "Infra / TLS", "icon": "lock",
     "desc": "TLS certificate + protocol support, HTTP headers & TLS inspection, DNS posture.",
     "targetHint": "host or URL — e.g. target.tld",
     "steps": [["tls_scan", "host"], ["http_inspect", "url"], ["dns_recon", "domain"]]},
    {"id": "full", "name": "Full Sweep", "icon": "layers",
     "desc": "Everything: external recon + web deep + Nuclei (if installed). The one-button full assessment.",
     "targetHint": "URL or domain",
     "steps": [["dns_recon", "domain"], ["subdomain_enum", "domain"], ["email_security", "domain"],
               ["web_scan", "url"], ["injection", "url"], ["param_discovery", "url"],
               ["vhost_discovery", "url"], ["tls_scan", "host"], ["nuclei_scan", "url"]]},
]


class PlaybookBody(BaseModel):
    playbook: str
    target: str = Field(min_length=1, max_length=2048)


@router.get("")
async def list_playbooks():
    reg = toolreg.registry()
    return {"playbooks": [{**{k: v for k, v in p.items() if k != "steps"},
                           "steps": [{"tool": t, "param": par, "desc": reg.get(t, {}).get("desc", "")} for t, par in p["steps"]]}
                          for p in PLAYBOOKS]}


@router.post("/run")
async def run_playbook(body: PlaybookBody):
    pb = next((p for p in PLAYBOOKS if p["id"] == body.playbook), None)
    if not pb:
        raise HTTPException(status_code=404, detail="Unknown playbook")
    reg = toolreg.registry()
    steps = []
    findings_total = 0
    for tool, param in pb["steps"]:
        res = await toolreg.exec_tool(tool, {param: body.target}, reg)
        findings_total += len(res.get("findings", [])) if isinstance(res, dict) else 0
        steps.append({"tool": tool, "param": param, "summary": toolreg.summarize(tool, res), "result": res})
    return {"playbook": pb["id"], "name": pb["name"], "target": body.target,
            "steps": steps, "findings_total": findings_total}
