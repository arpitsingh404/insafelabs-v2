"""SOC — Security Operations Center.

Aggregates health, threat telemetry and alert triage into one console, and keeps
an IOC watchlist (blacklist / rate-limit results that an analyst wants to track).
"""
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

import ai
from db import db

router = APIRouter(prefix="/soc", tags=["soc"])


@router.get("/overview")
async def overview():
    from routers import dashboard

    health = {"mongo": "down", "ai_backend": ai.backend(), "ai_model": ai.current_model(),
              "ai_key": ai.key_present(), "server": "ok"}
    try:
        await db.command("ping")
        health["mongo"] = "ok"
    except Exception as e:
        health["mongo"] = f"down: {str(e)[:60]}"

    try:
        stats = await dashboard.stats()
    except Exception:
        stats = {}

    alerts = await db.scan_alerts.find({}, {"_id": 0}).sort("created_at", -1).to_list(50)
    watch = await db.soc_watchlist.find({}, {"_id": 0}).sort("created_at", -1).to_list(100)

    sev = stats.get("by_severity", {}) or {}
    return {
        "health": health,
        "counts": {
            "findings": stats.get("total_findings", 0),
            "critical": stats.get("critical_findings", 0),
            "high": stats.get("high_findings", 0),
            "avg_risk": stats.get("avg_risk", 0),
            "recon_scans": stats.get("recon_scans", 0),
            "monitors": stats.get("monitors_active", 0),
            "alerts": stats.get("alerts_count", len(alerts)),
            "osint": stats.get("osint_lookups", 0),
            "secrets": stats.get("secrets_total", 0),
        },
        "severity": sev,
        "top_targets": stats.get("top_targets", []),
        "severity_trend": stats.get("severity_trend", []),
        "activity": stats.get("activity", []),
        "alerts": alerts,
        "watchlist": watch,
    }


class WatchBody(BaseModel):
    target: str = Field(min_length=1, max_length=253)
    kind: str = "unknown"
    listed_count: int = 0
    note: str = ""


@router.get("/watchlist")
async def watchlist():
    items = await db.soc_watchlist.find({}, {"_id": 0}).sort("created_at", -1).to_list(200)
    return {"watchlist": items}


@router.post("/watchlist")
async def add_watch(body: WatchBody):
    doc = {"id": f"{body.target}-{int(datetime.now().timestamp())}", "target": body.target,
           "kind": body.kind, "listed_count": body.listed_count, "note": body.note,
           "created_at": datetime.now(timezone.utc).isoformat()}
    await db.soc_watchlist.update_one({"target": body.target}, {"$set": doc}, upsert=True)
    return doc


@router.delete("/watchlist/{item_id}")
async def del_watch(item_id: str):
    r = await db.soc_watchlist.delete_one({"id": item_id})
    if not r.deleted_count:
        raise HTTPException(status_code=404, detail="Not in watchlist")
    return {"ok": True}
