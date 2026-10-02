from fastapi import APIRouter
from fastapi.responses import Response
import json
from datetime import datetime, timezone

from db import db

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

SEVERITIES = ["critical", "high", "medium", "low", "info"]


@router.get("/stats")
async def stats():
    assessments = await db.assessments.find(
        {}, {"_id": 0, "id": 1, "module": 1, "title": 1, "severity_counts": 1,
             "finding_count": 1, "posture": 1, "created_at": 1, "risk_score": 1}
    ).sort("created_at", -1).to_list(2000)

    by_severity = {s: 0 for s in SEVERITIES}
    by_module = {"web": 0, "mobile": 0, "code-review": 0}
    total_findings = 0
    for a in assessments:
        counts = a.get("severity_counts", {}) or {}
        for s in SEVERITIES:
            by_severity[s] += counts.get(s, 0)
        total_findings += a.get("finding_count", 0)
        m = a.get("module")
        if m in by_module:
            by_module[m] += 1

    recent = [
        {
            "id": a["id"], "module": a["module"], "title": a.get("title", ""),
            "posture": a.get("posture", "low"), "finding_count": a.get("finding_count", 0),
            "risk_score": a.get("risk_score", 0), "created_at": a.get("created_at"),
        }
        for a in assessments[:6]
    ]

    scans = await db.sca_scans.find({}, {"_id": 0, "vuln_count": 1}).to_list(2000)
    sca_vulns = sum(s.get("vuln_count", 0) for s in scans)

    recon = await db.recon_scans.find(
        {}, {"_id": 0, "severity_counts": 1, "finding_count": 1, "host": 1,
             "risk_score": 1, "posture": 1, "created_at": 1, "ports": 1, "secrets": 1}
    ).sort("created_at", -1).to_list(2000)
    recon_findings = 0
    for r in recon:
        counts = r.get("severity_counts", {}) or {}
        for s in SEVERITIES:
            by_severity[s] += counts.get(s, 0)
        recon_findings += r.get("finding_count", 0)
    total_findings += recon_findings

    tps = await db.recon_scans.find({"geo": {"$ne": None}},
                                    {"_id": 0, "host": 1, "geo": 1, "posture": 1, "risk_score": 1}) \
        .sort("created_at", -1).to_list(300)
    threat_points, seen = [], set()
    for r in tps:
        g = r.get("geo") or {}
        if g.get("lat") is None or r.get("host") in seen:
            continue
        seen.add(r.get("host"))
        threat_points.append({
            "host": r.get("host"), "lat": g.get("lat"), "lon": g.get("lon"),
            "country": g.get("country"), "countryCode": g.get("countryCode"),
            "posture": r.get("posture"), "risk_score": r.get("risk_score"),
        })
    alerts = await db.scan_alerts.find({}, {"_id": 0}).sort("created_at", -1).to_list(20)

    vdp_all = await db.vdp_reports.find({}, {"_id": 0, "status": 1}).to_list(5000)
    vdp_status = {}
    for r in vdp_all:
        vdp_status[r.get("status", "new")] = vdp_status.get(r.get("status", "new"), 0) + 1

    sessions = await db.pentest_sessions.count_documents({})

    # ---- Advanced telemetry (iteration 8) ----
    from datetime import datetime, timezone, timedelta
    osint_count = await db.osint_lookups.count_documents({})
    apk_count = await db.apk_scans.count_documents({})
    cloud_count = await db.cloud_scans.count_documents({})
    monitors_active = await db.scheduled_scans.count_documents({"active": True})

    risk_vals = [r.get("risk_score", 0) for r in recon if r.get("risk_score") is not None]
    avg_risk = round(sum(risk_vals) / len(risk_vals)) if risk_vals else 0

    # Top exposed targets (dedupe by host, highest risk first)
    top_targets, seen_hosts = [], set()
    for r in sorted(recon, key=lambda x: x.get("risk_score", 0), reverse=True):
        h = r.get("host")
        if not h or h in seen_hosts:
            continue
        seen_hosts.add(h)
        top_targets.append({"host": h, "risk_score": r.get("risk_score", 0),
                            "posture": r.get("posture", "low"), "finding_count": r.get("finding_count", 0)})
        if len(top_targets) >= 6:
            break

    # 14-day risk/scan trend
    today = datetime.now(timezone.utc).date()
    days = [(today - timedelta(days=i)) for i in range(13, -1, -1)]
    tmap = {d.isoformat(): {"findings": 0, "scans": 0} for d in days}
    for r in recon:
        d = (r.get("created_at") or "")[:10]
        if d in tmap:
            tmap[d]["scans"] += 1
            tmap[d]["findings"] += r.get("finding_count", 0)
    for a in assessments:
        d = (a.get("created_at") or "")[:10]
        if d in tmap:
            tmap[d]["scans"] += 1
            tmap[d]["findings"] += a.get("finding_count", 0)
    trend = [{"date": d.strftime("%m/%d"), "findings": tmap[d.isoformat()]["findings"],
              "scans": tmap[d.isoformat()]["scans"]} for d in days]

    # Cross-module activity log
    osint_recent = await db.osint_lookups.find({}, {"_id": 0, "kind": 1, "query": 1, "created_at": 1}).sort("created_at", -1).to_list(8)
    cloud_recent = await db.cloud_scans.find({}, {"_id": 0, "bucket": 1, "finding_count": 1, "created_at": 1}).sort("created_at", -1).to_list(6)
    apk_recent = await db.apk_scans.find({}, {"_id": 0, "app": 1, "finding_count": 1, "created_at": 1}).sort("created_at", -1).to_list(6)
    activity = []
    for r in recon[:10]:
        activity.append({"type": "scanner", "text": f"Recon scan · {r.get('host')} · risk {r.get('risk_score', 0)}", "created_at": r.get("created_at")})
    for o in osint_recent:
        activity.append({"type": "osint", "text": f"OSINT {o.get('kind')} · {o.get('query')}", "created_at": o.get("created_at")})
    for c in cloud_recent:
        activity.append({"type": "cloud", "text": f"Cloud check · {c.get('bucket')} · {c.get('finding_count', 0)} findings", "created_at": c.get("created_at")})
    for k in apk_recent:
        activity.append({"type": "redteam", "text": f"APK analysis · {(k.get('app') or {}).get('package') or 'app'} · {k.get('finding_count', 0)} findings", "created_at": k.get("created_at")})
    for a in assessments[:8]:
        activity.append({"type": a.get("module"), "text": f"{a.get('module')} · {a.get('title', '')[:48]}", "created_at": a.get("created_at")})
    activity = sorted(activity, key=lambda x: x.get("created_at") or "", reverse=True)[:14]

    # ---- advanced dashboard analytics (iteration 19) ----
    sev_keys = ["critical", "high", "medium", "low"]
    sev_days = {d.isoformat(): {s: 0 for s in sev_keys} for d in days}
    for src in (recon, assessments):
        for r in src:
            d = (r.get("created_at") or "")[:10]
            if d in sev_days:
                c = r.get("severity_counts") or {}
                for s in sev_keys:
                    sev_days[d][s] += c.get(s, 0)
    severity_trend = [{"date": d.strftime("%m/%d"), **sev_days[d.isoformat()]} for d in days]

    port_counts, secret_counts = {}, {}
    for r in recon:
        for p in (r.get("ports") or []):
            key = f"{p.get('port')}/{p.get('service', '')}"
            port_counts[key] = port_counts.get(key, 0) + 1
        for s in ((r.get("secrets") or {}).get("secrets") or []):
            t = s.get("type") or s.get("name") or "secret"
            secret_counts[t] = secret_counts.get(t, 0) + 1
    top_ports = sorted([{"label": k, "count": v} for k, v in port_counts.items()], key=lambda x: x["count"], reverse=True)[:8]
    secrets_exposed = sorted([{"type": k, "count": v} for k, v in secret_counts.items()], key=lambda x: x["count"], reverse=True)[:8]
    secrets_total = sum(secret_counts.values())

    network_total = await db.network_scans.count_documents({})
    binary_total = await db.binary_scans.count_documents({})
    module_coverage = [
        {"module": "Scanner", "count": len(recon)},
        {"module": "OSINT", "count": osint_count},
        {"module": "Red Team", "count": apk_count + cloud_count},
        {"module": "Network", "count": network_total},
        {"module": "Reverse", "count": binary_total},
        {"module": "SCA", "count": len(scans)},
        {"module": "AI", "count": sessions},
    ]

    cal_start = today - timedelta(days=90)
    cal = {}
    for src in (recon, assessments):
        for r in src:
            d = (r.get("created_at") or "")[:10]
            if d and d >= cal_start.isoformat():
                cal[d] = cal.get(d, 0) + 1
    scan_calendar = [{"date": (cal_start + timedelta(days=i)).isoformat(),
                      "count": cal.get((cal_start + timedelta(days=i)).isoformat(), 0)} for i in range(91)]

    return {
        "total_findings": total_findings,
        "critical_findings": by_severity["critical"],
        "high_findings": by_severity["high"],
        "by_severity": by_severity,
        "assessments_total": len(assessments),
        "by_module": by_module,
        "recent": recent,
        "sca_scans": len(scans),
        "sca_vulnerabilities": sca_vulns,
        "recon_scans": len(recon),
        "osint_lookups": osint_count,
        "apk_scans": apk_count,
        "cloud_scans": cloud_count,
        "monitors_active": monitors_active,
        "avg_risk": avg_risk,
        "top_targets": top_targets,
        "risk_trend": trend,
        "activity": activity,
        "threat_points": threat_points,
        "alerts": alerts,
        "alerts_count": len([a for a in alerts if not a.get("read")]),
        "vdp_total": len(vdp_all),
        "vdp_by_status": vdp_status,
        "pentest_sessions": sessions,
        "severity_trend": severity_trend,
        "top_ports": top_ports,
        "secrets_exposed": secrets_exposed,
        "secrets_total": secrets_total,
        "module_coverage": module_coverage,
        "scan_calendar": scan_calendar,
        "network_scans": network_total,
        "binary_scans_count": binary_total,
    }


SEV_TAG = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO"}


@router.get("/livefeed")
async def livefeed():
    """Terminal-style stream lines built from real recent recon scans (public hero feed)."""
    scans = await db.recon_scans.find(
        {"status": {"$ne": "running"}},
        {"_id": 0, "host": 1, "findings": 1, "posture": 1, "risk_score": 1,
         "ports": 1, "secrets": 1, "config": 1, "network": 1, "created_at": 1},
    ).sort("created_at", -1).to_list(12)

    lines = []
    for s in scans:
        host = s.get("host") or "target"
        lines.append({"t": "[recon]", "m": f"engaging {host}", "c": "#A1A1AA"})
        for p in (s.get("ports") or [])[:2]:
            lines.append({"t": "[scan]", "m": f"port {p.get('port')}/tcp OPEN · {p.get('service')}", "c": "#22C55E"})
        net = s.get("network") or {}
        if net.get("records", {}).get("A"):
            lines.append({"t": "[dns]", "m": f"A {net['records']['A'][0]}", "c": "#A1A1AA"})
        for sec in ((s.get("secrets") or {}).get("secrets") or [])[:1]:
            lines.append({"t": "[secret]", "m": f"{sec.get('type')} leaked in {sec.get('source')}", "tag": "CRITICAL"})
        for cf in ((s.get("config") or {}).get("config_hits") or [])[:1]:
            lines.append({"t": "[expose]", "m": f"{cf.get('path')} publicly accessible", "tag": "HIGH"})
        top = sorted(s.get("findings") or [], key=lambda f: f.get("cvss", 0), reverse=True)
        for f in top[:2]:
            lines.append({"t": "[vuln]", "m": (f.get("title") or "")[:60], "tag": SEV_TAG.get(f.get("severity"), "INFO")})
        lines.append({"t": "[cvss]", "m": f"{host} risk {s.get('risk_score', 0)}/100 · {(s.get('posture') or 'low').upper()}", "c": "#FACC15"})

    return {"lines": lines[:60], "scan_count": len(scans)}


@router.get("/findings")
async def findings(severity: str | None = None, limit: int = 300):
    """Flattened findings across all recon scans, optionally filtered by severity (drilldown view)."""
    recon = await db.recon_scans.find(
        {"status": {"$ne": "running"}},
        {"_id": 0, "id": 1, "ref": 1, "host": 1, "target": 1, "findings": 1, "created_at": 1},
    ).sort("created_at", -1).to_list(500)
    sev = (severity or "").lower().strip() or None
    all_f, out = [], []
    for r in recon:
        for f in (r.get("findings") or []):
            rec = {
                "title": f.get("title"), "severity": f.get("severity"),
                "cvss": f.get("cvss"), "component": f.get("component"),
                "description": f.get("description"), "proof": f.get("proof"),
                "host": r.get("host") or r.get("target"),
                "scan_id": r.get("id"), "ref": r.get("ref"), "created_at": r.get("created_at"),
            }
            all_f.append(rec)
            if not sev or (f.get("severity") or "").lower() == sev:
                out.append(rec)
    out.sort(key=lambda x: x.get("cvss") or 0, reverse=True)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in all_f:
        s = (f.get("severity") or "info").lower()
        if s in counts:
            counts[s] += 1
    return {"severity": sev, "count": len(out), "total": len(all_f), "counts": counts, "findings": out[:limit]}



# collections that hold search / scan / lookup HISTORY & results
HISTORY_COLLECTIONS = [
    "recon_scans", "network_scans", "bugbounty_scans", "osint_lookups",
    "assessments", "sca_scans", "binary_scans", "apk_scans", "cloud_scans",
    "scan_alerts", "pentest_sessions", "pentest_messages", "vdp_reports",
]


@router.post("/clear-history")
async def clear_history(include_monitors: bool = False):
    """Wipe all stored searches, site checks, scans, lookups and results — fresh start.
    Scheduled monitors (config) are kept unless include_monitors=true."""
    collections = list(HISTORY_COLLECTIONS)
    if include_monitors:
        collections.append("scheduled_scans")
    deleted = {}
    total = 0
    for name in collections:
        res = await db[name].delete_many({})
        deleted[name] = res.deleted_count
        total += res.deleted_count
    return {"ok": True, "total_deleted": total, "deleted": deleted}



# map a module name -> the collections that hold its history
MODULE_COLLECTIONS = {
    "osint": ["osint_lookups"],
    "scanner": ["recon_scans", "scan_alerts"],
    "bugbounty": ["bugbounty_scans"],
    "network": ["network_scans"],
    "code": ["assessments", "sca_scans"],
    "binary": ["binary_scans"],
    "redteam": ["apk_scans", "cloud_scans"],
    "ai": ["pentest_sessions", "pentest_messages"],
}


@router.get("/export-history")
async def export_history():
    """One-click backup — dump every history collection to a downloadable JSON file."""
    dump = {"generated": datetime.now(timezone.utc).isoformat(), "collections": {}}
    total = 0
    for name in HISTORY_COLLECTIONS:
        docs = await db[name].find({}, {"_id": 0}).to_list(100000)
        dump["collections"][name] = docs
        total += len(docs)
    dump["total_records"] = total
    body = json.dumps(dump, default=str, indent=2)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return Response(
        content=body, media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="insafelabs-history-backup-{stamp}.json"'},
    )


@router.post("/clear-history/{module}")
async def clear_history_module(module: str):
    """Wipe history for a single module (osint / scanner / bugbounty / network / …)."""
    collections = MODULE_COLLECTIONS.get(module)
    if not collections:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail=f"Unknown module '{module}'")
    deleted = {}
    total = 0
    for name in collections:
        res = await db[name].delete_many({})
        deleted[name] = res.deleted_count
        total += res.deleted_count
    return {"ok": True, "module": module, "total_deleted": total, "deleted": deleted}
