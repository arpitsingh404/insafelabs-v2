"""VAPT (full assessment) and WAPT (OWASP-mapped web app test).

Both reuse the shared native tool registry (toolreg) and produce:
  * per-phase / per-OWASP findings,
  * a normalised finding list with CVSS + severity,
  * a risk score + letter grade,
  * a ready-to-download Markdown report,
  * an on-demand AI executive summary.
"""
import asyncio
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

import ai
from routers import toolreg

router = APIRouter(tags=["assessment"])

CVSS = {"critical": 9.0, "high": 7.5, "medium": 5.0, "low": 3.0, "info": 0.0}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]

# ---- WAPT: OWASP Top 10 (2021) mapped to the native tools -------------------
WAPT_CATEGORIES = [
    {"id": "A01", "name": "Broken Access Control",
     "tools": [["param_discovery", "url"], ["vhost_discovery", "url"], ["idor_check", "url"]]},
    {"id": "A02", "name": "Cryptographic Failures",
     "tools": [["tls_scan", "host"]]},
    {"id": "A03", "name": "Injection",
     "tools": [["injection", "url"], ["ssti_check", "url"], ["lfi_check", "url"], ["cmdi_check", "url"], ["xxe_check", "url"]]},
    {"id": "A05", "name": "Security Misconfiguration",
     "tools": [["web_scan", "url"], ["fingerprint", "url"], ["cors_test", "url"], ["openapi_analyze", "url"], ["favicon_fingerprint", "url"]]},
    {"id": "A06", "name": "Vulnerable & Outdated Components",
     "tools": [["fingerprint", "url"]]},
    {"id": "A07", "name": "Identification & Authentication Failures",
     "tools": [["auth_form", "url"], ["rate_limit_check", "url"]]},
]

# ---- VAPT: phased full assessment -------------------------------------------
VAPT_PHASES = [
    {"id": "recon", "name": "1 · Reconnaissance",
     "tools": [["dns_recon", "domain"], ["subdomain_enum", "domain"], ["email_security", "domain"]]},
    {"id": "infra", "name": "2 · Infrastructure / Network",
     "tools": [["port_scan", "host"], ["tls_scan", "host"], ["takeover", "host"]]},
    {"id": "web", "name": "3 · Web Application",
     "tools": [["web_scan", "url"], ["injection", "url"], ["ssti_check", "url"], ["lfi_check", "url"],
               ["cmdi_check", "url"], ["param_discovery", "url"],
               ["vhost_discovery", "url"], ["idor_check", "url"], ["rate_limit_check", "url"],
               ["fingerprint", "url"], ["cors_test", "url"], ["auth_form", "url"]]},
    {"id": "vuln", "name": "4 · Vulnerability Scan",
     "tools": [["nuclei_scan", "url"]]},
]


def _extract_findings(res):
    """Normalise a tool result into [{severity,title,detail,evidence,recommendation}]."""
    out = []
    if not isinstance(res, dict):
        return out
    for f in res.get("findings", []) or []:
        if isinstance(f, dict):
            out.append({"severity": (f.get("severity") or "info").lower(),
                        "title": f.get("title") or f.get("check") or "Finding",
                        "detail": f.get("detail") or "", "evidence": f.get("evidence") or "",
                        "recommendation": f.get("recommendation") or ""})
    for it in res.get("issues", []) or []:   # email-security style
        if isinstance(it, dict):
            out.append({"severity": (it.get("severity") or "info").lower(),
                        "title": it.get("check") or "Issue", "detail": it.get("detail") or "",
                        "evidence": "", "recommendation": ""})
    return out


def _summary(findings):
    counts = {s: 0 for s in SEV_ORDER}
    for f in findings:
        counts[f.get("severity", "info")] = counts.get(f.get("severity", "info"), 0) + 1
    total = len(findings)
    avg = (sum(CVSS.get(f.get("severity", "info"), 0) for f in findings) / total) if total else 0.0
    score = round(avg * 10)
    if counts["critical"] or score >= 75:
        grade, posture = "F", "CRITICAL"
    elif counts["high"] or score >= 50:
        grade, posture = "D", "HIGH"
    elif counts["medium"] or score >= 25:
        grade, posture = "C", "ELEVATED"
    elif counts["low"] or total:
        grade, posture = "B", "GUARDED"
    else:
        grade, posture = "A", "LOW"
    return {"total": total, **counts, "avg_cvss": round(avg, 1), "risk_score": score,
            "grade": grade, "posture": posture}


def _report_md(title, target, kind, sections, findings, summary, generated):
    lines = [f"# {title}", "", f"**Target:** `{target}`  ", f"**Type:** {kind}  ",
             f"**Generated:** {generated}  ", f"**Overall grade:** {summary['grade']} ({summary['posture']})  ",
             f"**Risk score:** {summary['risk_score']}/100  ", "", "## Executive summary", "",
             f"{summary['total']} finding(s): " +
             ", ".join(f"{k} {summary[k]}" for k in SEV_ORDER if summary[k]) or "no findings", "",
             "## Scope & methodology", "",
             "Assessment performed with the InsafeLabs platform's native tooling. "
             "All checks are non-destructive; findings require manual validation before remediation sign-off.", ""]
    for sec in sections:
        lines.append(f"## {sec['name']}")
        lines.append("")
        if not sec["findings"]:
            lines.append("_No findings in this phase._")
        else:
            for f in sec["findings"]:
                lines.append(f"- **[{f['severity'].upper()}] {f['title']}** — {f['detail']}")
                if f.get("evidence"):
                    lines.append(f"  - evidence: `{f['evidence'][:300]}`")
                if f.get("recommendation"):
                    lines.append(f"  - remediation: {f['recommendation']}")
        lines.append("")
    if findings:
        lines += ["## Consolidated findings", "", "| Severity | Finding | CVSS |", "|---|---|---|"]
        for f in sorted(findings, key=lambda x: CVSS.get(x["severity"], 0), reverse=True):
            lines.append(f"| {f['severity'].upper()} | {f['title']} | {CVSS.get(f['severity'], 0)} |")
        lines.append("")
    lines += ["---", "_Generated by InsafeLabs · for authorized testing only._"]
    return "\n".join(lines)


class AssessBody(BaseModel):
    target: str = Field(min_length=1, max_length=2048)


async def _run_plan(target, plan, reg):
    sections = []
    all_findings = []
    for group in plan:
        gfind = []
        for tool, param in group["tools"]:
            res = await toolreg.exec_tool(tool, {param: target}, reg)
            for f in _extract_findings(res):
                f = {**f, "source": tool}
                gfind.append(f)
        all_findings.extend(gfind)
        sections.append({"id": group["id"], "name": group["name"], "findings": gfind,
                         "tools": [t for t, _ in group["tools"]]})
    summary = _summary(all_findings)
    return sections, all_findings, summary


@router.post("/wapt/run")
async def wapt_run(body: AssessBody):
    reg = toolreg.registry()
    sections, findings, summary = await _run_plan(body.target, WAPT_CATEGORIES, reg)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    report = _report_md("Web Application Penetration Test (WAPT)", body.target, "OWASP Top 10 (2021)",
                        sections, findings, summary, generated)
    return {"kind": "wapt", "target": body.target, "generated": generated,
            "sections": sections, "findings": findings, "summary": summary, "report_md": report}


@router.post("/vapt/run")
async def vapt_run(body: AssessBody):
    reg = toolreg.registry()
    sections, findings, summary = await _run_plan(body.target, VAPT_PHASES, reg)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    report = _report_md("Vulnerability Assessment & Penetration Test (VAPT)", body.target,
                        "Recon → Infra → Web → Vuln scan", sections, findings, summary, generated)
    return {"kind": "vapt", "target": body.target, "generated": generated,
            "sections": sections, "findings": findings, "summary": summary, "report_md": report}


class ReportBody(BaseModel):
    target: str = ""
    findings: list = Field(default_factory=list)
    summary: dict = Field(default_factory=dict)


@router.post("/vapt/ai-summary")
async def ai_summary(body: ReportBody):
    import json as _json
    system = ("You are InsafeLabs-AI, a senior penetration tester. Write a concise executive summary "
              "(Markdown, ~200 words) of the assessment results: overall risk, the most important findings, "
              "business impact, and prioritised remediation. Only use the provided data.")
    user = f"Target: {body.target}\nSummary: {_json.dumps(body.summary)}\nFindings: {_json.dumps(body.findings, default=str)[:40000]}"
    try:
        text = await ai.complete("vapt-ai-summary", system, user)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"AI summary failed: {str(e)[:150]}")
    return {"summary": text}
