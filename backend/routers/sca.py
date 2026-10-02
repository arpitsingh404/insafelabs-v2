import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from db import db
import ai

router = APIRouter(prefix="/sca", tags=["sca"])


class ScanInput(BaseModel):
    name: str = Field(min_length=1)
    ecosystem: str = "npm"
    manifest: str = Field(min_length=1)


def _public(doc: dict) -> dict:
    doc.pop("_id", None)
    return doc


@router.get("/scans")
async def list_scans():
    docs = await db.sca_scans.find({}, {"_id": 0}).sort("created_at", -1).to_list(200)
    return docs


@router.get("/scans/{scan_id}")
async def get_scan(scan_id: str):
    doc = await db.sca_scans.find_one({"id": scan_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Scan not found")
    return doc


@router.delete("/scans/{scan_id}")
async def delete_scan(scan_id: str):
    res = await db.sca_scans.delete_one({"id": scan_id})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"message": "deleted"}


@router.post("/scan")
async def run_scan(data: ScanInput):
    system = (
        "You are InsafeLabs SCA engine, an expert in Software Composition Analysis. Parse the provided "
        "dependency manifest and produce a Software Bill of Materials (SBOM) plus known CVE / "
        "vulnerability detection for each open-source component. Use your knowledge of real, "
        "well-known CVEs. Respond with STRICT JSON only (no markdown). Schema:\n"
        "{\n"
        '  "components": [{"name": str, "version": str, "license": str, "purl": str}],\n'
        '  "vulnerabilities": [{"component": str, "version": str, "cve": str, '
        '"severity": "critical|high|medium|low", "cvss": float, "title": str, '
        '"description": str, "fixed_version": str}]\n'
        "}\n"
        "If a component has no known vulnerability, do not add it to vulnerabilities. "
        "Generate a valid purl (e.g. pkg:npm/lodash@4.17.20)."
    )
    prompt = f"Ecosystem: {data.ecosystem}\nManifest:\n{data.manifest[:8000]}"
    try:
        raw = await ai.complete("sca-daxx", system, prompt)
        parsed = ai.parse_json(raw)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"SCA analysis failed: {str(e)}")

    components = parsed.get("components", []) or []
    vulns = parsed.get("vulnerabilities", []) or []
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in vulns:
        sev = str(v.get("severity", "")).lower()
        if sev in summary:
            summary[sev] += 1

    doc = {
        "id": str(uuid.uuid4()),
        "name": data.name,
        "ecosystem": data.ecosystem,
        "manifest": data.manifest[:8000],
        "components": components,
        "vulnerabilities": vulns,
        "summary": summary,
        "component_count": len(components),
        "vuln_count": len(vulns),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.sca_scans.insert_one(dict(doc))
    return _public(doc)
