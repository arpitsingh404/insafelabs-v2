import uuid
import json
from datetime import datetime, timezone
from typing import Dict, Any

import requests
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from db import db
import ai

router = APIRouter(prefix="/assessments", tags=["assessments"])

SEVERITIES = ["critical", "high", "medium", "low", "info"]

_JSON_SCHEMA = (
    "Respond with STRICT JSON only, no markdown, no prose outside the JSON. Schema:\n"
    "{\n"
    '  "summary": string (2-4 sentence executive summary of the security posture),\n'
    '  "risk_score": integer 0-100 (100 = worst),\n'
    '  "posture": "critical"|"high"|"medium"|"low",\n'
    '  "findings": [ {\n'
    '     "title": string,\n'
    '     "severity": "critical"|"high"|"medium"|"low"|"info",\n'
    '     "category": string (the exact framework mapping),\n'
    '     "cwe": string (e.g. "CWE-89"),\n'
    '     "cvss": number (0-10),\n'
    '     "description": string,\n'
    '     "evidence": string (why/where this applies),\n'
    '     "location": string (file:line or function/endpoint if applicable, else ""),\n'
    '     "recommendation": string (concrete remediation)\n'
    "  } ]\n"
    "}\n"
    "Return 4-10 prioritized, realistic findings ordered by severity."
)

MODULES = {
    "web": {
        "default_title": "Web Application Assessment",
        "system": (
            "You are InsafeLabs, an elite web application penetration tester. Perform an AI-driven "
            "security assessment of the described web application. Map EVERY finding to OWASP "
            "Top 10 (2021) and CWE / SANS Top 25 (e.g. 'A01:2021 Broken Access Control'). Cover "
            "authentication, session management, injection (SQLi/XSS/SSTI), access control, SSRF, "
            "security misconfiguration, vulnerable components, crypto failures and missing security "
            "headers. If live recon headers are provided, use them as concrete evidence. " + _JSON_SCHEMA
        ),
    },
    "mobile": {
        "default_title": "Mobile Application Assessment",
        "system": (
            "You are InsafeLabs, an elite mobile application security tester covering iOS and Android. "
            "Perform static + dynamic analysis reasoning and map EVERY finding to OWASP MASVS, the "
            "OWASP Mobile Top 10, and NIST guidance. Cover insecure data storage, weak cryptography, "
            "insecure communication, improper platform usage, code tampering / reverse engineering, "
            "insecure authentication, and exported components / IPC. " + _JSON_SCHEMA
        ),
    },
    "code-review": {
        "default_title": "Secure Code Review",
        "system": (
            "You are InsafeLabs, an elite secure code reviewer. Review the provided source code and map "
            "EVERY finding to OWASP Top 10 and CWE / SANS Top 25. Identify injection, hardcoded "
            "secrets, insecure deserialization, path traversal, weak crypto, missing authz checks, "
            "unsafe input handling and dangerous functions. In 'location' put the function name or "
            "an approximate line/snippet reference where the issue occurs. " + _JSON_SCHEMA
        ),
    },
}


class RunInput(BaseModel):
    module: str
    title: str = ""
    inputs: Dict[str, Any] = {}


def _public(doc: dict) -> dict:
    doc.pop("_id", None)
    return doc


def fetch_security_headers(url: str):
    if not url.startswith("http"):
        url = "https://" + url
    try:
        r = requests.get(url, timeout=8, allow_redirects=True,
                         headers={"User-Agent": "InsafeLabs-Scanner/1.0"})
        wanted = [
            "Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options",
            "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
            "Server", "X-Powered-By", "Set-Cookie",
        ]
        return {
            "reachable": True,
            "status": r.status_code,
            "final_url": str(r.url),
            "headers": {h: r.headers.get(h) for h in wanted},
        }
    except Exception as e:
        return {"reachable": False, "error": str(e)[:200]}


@router.get("")
async def list_assessments(module: str = None):
    query = {}
    if module:
        query["module"] = module
    docs = await db.assessments.find(query, {"_id": 0, "findings": 0, "inputs": 0}) \
        .sort("created_at", -1).to_list(300)
    return docs


@router.get("/{assessment_id}")
async def get_assessment(assessment_id: str):
    doc = await db.assessments.find_one({"id": assessment_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return doc


@router.delete("/{assessment_id}")
async def delete_assessment(assessment_id: str):
    res = await db.assessments.delete_one({"id": assessment_id})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return {"message": "deleted"}


@router.post("/run")
async def run_assessment(data: RunInput):
    if data.module not in MODULES:
        raise HTTPException(status_code=400, detail="Unknown module")
    cfg = MODULES[data.module]
    inputs = data.inputs or {}

    recon = None
    if data.module == "web" and inputs.get("target"):
        recon = fetch_security_headers(str(inputs["target"]))

    context = []
    for k, v in inputs.items():
        if v:
            val = str(v)
            if len(val) > 80000:
                val = val[:80000] + "\n…[truncated for analysis]"
            label = k.replace("_", " ").title()
            context.append(f"{label}:\n{val}" if len(val) > 80 else f"{label}: {val}")
    if recon:
        context.append("Live security-header recon:\n" + json.dumps(recon)[:2500])
    prompt = "\n\n".join(context) or "No details provided; produce a best-effort baseline assessment."

    try:
        raw = await ai.complete(f"assess-{data.module}", cfg["system"], prompt)
        parsed = ai.parse_json(raw)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"AI assessment failed: {str(e)[:120]}")

    findings = parsed.get("findings", []) or []
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        sev = str(f.get("severity", "info")).lower()
        if sev not in SEVERITIES:
            sev = "info"
        f["severity"] = sev
        counts[sev] += 1

    posture = str(parsed.get("posture", "")).lower()
    if posture not in SEVERITIES[:4]:
        posture = next((s for s in SEVERITIES[:4] if counts[s] > 0), "low")

    title = data.title or inputs.get("target") or inputs.get("package_id") or cfg["default_title"]
    try:
        risk_score = int(parsed.get("risk_score", 0) or 0)
    except (TypeError, ValueError):
        risk_score = 0
    doc = {
        "id": str(uuid.uuid4()),
        "ref": f"InsafeLabs-{str(uuid.uuid4())[:8].upper()}",
        "module": data.module,
        "title": str(title)[:120],
        "inputs": inputs,
        "recon": recon,
        "summary": parsed.get("summary", ""),
        "risk_score": risk_score,
        "posture": posture,
        "findings": findings,
        "severity_counts": counts,
        "finding_count": len(findings),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.assessments.insert_one(dict(doc))
    return _public(doc)
