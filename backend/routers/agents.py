import asyncio
import socket
import uuid
import json
import os
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

import ai
from db import db

router = APIRouter(prefix="/agents", tags=["agents"])

STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")

# id -> (label, icon-key used by the frontend)
AGENT_META = {
    "planner":    ("Planner",            "brain"),
    "recon":      ("Recon",              "radar"),
    "subdomains": ("Subdomain OSINT",    "share2"),
    "ports":      ("Port Scanner",       "network"),
    "webvuln":    ("Web Vuln / BugBounty", "bug"),
    "local":      ("Local / PC Test",    "monitor"),
    "redteam":    ("Red Team",           "swords"),
    "report":     ("Report",             "filetext"),
}
GATHER_AGENTS = ["recon", "subdomains", "ports", "webvuln", "local"]
ANALYSIS_AGENTS = ["redteam", "report"]
COMMON_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 3306, 3389, 5432, 6379, 8080, 8443]
SEC_HEADERS = ["content-security-policy", "x-frame-options", "strict-transport-security",
               "x-content-type-options", "referrer-policy"]

# op_id -> running asyncio.Task (so a Stop request can cancel it mid-flight)
_RUNNING: dict = {}


def _now():
    return datetime.now(timezone.utc).isoformat()


def _host(target: str) -> str:
    t = (target or "").strip()
    if not t:
        return ""
    if "://" not in t:
        t = "http://" + t
    return urlparse(t).hostname or ""


def _url(target: str) -> str:
    t = (target or "").strip()
    if not t:
        return ""
    if "://" not in t:
        t = "https://" + t
    return t


# ------------------------------------------------------------------ doc helpers
async def _set(op_id, aid, **fields):
    sets = {f"agents.$[a].{k}": v for k, v in fields.items()}
    sets["updated_at"] = _now()
    await db.agent_ops.update_one({"id": op_id}, {"$set": sets}, array_filters=[{"a.id": aid}])


async def _log(op_id, aid, msg):
    await db.agent_ops.update_one({"id": op_id},
                                  {"$push": {"agents.$[a].log": {"t": _now(), "msg": msg}}},
                                  array_filters=[{"a.id": aid}])


async def _op_set(op_id, **fields):
    fields["updated_at"] = _now()
    await db.agent_ops.update_one({"id": op_id}, {"$set": fields})


async def _add_spend(op_id, cost):
    if cost:
        await db.agent_ops.update_one({"id": op_id}, {"$inc": {"spend": float(cost)}})


async def _mark_stopped(op_id):
    d = await db.agent_ops.find_one({"id": op_id}, {"_id": 0, "agents": 1})
    for a in (d or {}).get("agents", []):
        if a.get("status") in ("queued", "working"):
            await _log(op_id, a["id"], "Operation stopped by operator.")
            await _set(op_id, a["id"], status="stopped", action="stopped", finished_at=_now())
    await _op_set(op_id, status="stopped", finished_at=_now())


# ------------------------------------------------------------------ real agents
async def _agent_recon(op_id, task, target):
    aid = "recon"
    out = {}
    host = _host(target)
    if not host:
        await _log(op_id, aid, "No target host — skipping network recon.")
        return {"note": "no target"}
    await _log(op_id, aid, f"Resolving DNS for {host}…")
    try:
        loop = asyncio.get_event_loop()
        infos = await asyncio.wait_for(loop.getaddrinfo(host, None), 8)
        ips = sorted({i[4][0] for i in infos})
        out["ips"] = ips
        await _log(op_id, aid, f"Resolved: {', '.join(ips[:4])}")
        await _set(op_id, aid, progress=40)
    except Exception as e:
        await _log(op_id, aid, f"DNS failed: {str(e)[:80]}")
    await _log(op_id, aid, f"Fetching {_url(target)} …")
    try:
        async with httpx.AsyncClient(timeout=12, follow_redirects=True, verify=False) as c:
            r = await c.get(_url(target), headers={"User-Agent": "InsafeLabs-Agent/1.0"})
            out["status"] = r.status_code
            out["server"] = r.headers.get("server", "unknown")
            powered = r.headers.get("x-powered-by")
            if powered:
                out["x_powered_by"] = powered
            await _log(op_id, aid, f"HTTP {r.status_code} · server: {out['server']}" + (f" · {powered}" if powered else ""))
    except Exception as e:
        await _log(op_id, aid, f"HTTP fetch failed: {str(e)[:80]}")
    await _set(op_id, aid, progress=100)
    return out


async def _agent_subdomains(op_id, task, target):
    aid = "subdomains"
    host = _host(target)
    if not host:
        await _log(op_id, aid, "No target — skipping.")
        return {"note": "no target"}
    domain = ".".join(host.split(".")[-2:]) if host.count(".") >= 1 else host
    await _log(op_id, aid, f"Querying crt.sh for *.{domain} …")
    subs = set()
    try:
        async with httpx.AsyncClient(timeout=20, verify=False) as c:
            r = await c.get(f"https://crt.sh/?q=%25.{domain}&output=json")
            if r.status_code == 200:
                for row in r.json():
                    for nm in str(row.get("name_value", "")).split("\n"):
                        nm = nm.strip().lstrip("*.")
                        if nm.endswith(domain):
                            subs.add(nm)
    except Exception as e:
        await _log(op_id, aid, f"crt.sh error: {str(e)[:80]}")
    subs = sorted(subs)[:40]
    await _log(op_id, aid, f"Found {len(subs)} unique subdomain(s).")
    await _set(op_id, aid, progress=100)
    return {"subdomains": subs, "count": len(subs)}


async def _probe_port(host, port):
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=1.6)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return port
    except Exception:
        return None


async def _agent_ports(op_id, task, target):
    aid = "ports"
    host = _host(target)
    if not host:
        await _log(op_id, aid, "No target — skipping.")
        return {"note": "no target"}
    await _log(op_id, aid, f"Scanning {len(COMMON_PORTS)} common ports on {host} …")
    results = await asyncio.gather(*[_probe_port(host, p) for p in COMMON_PORTS])
    open_ports = [p for p in results if p]
    await _log(op_id, aid, f"Open: {', '.join(map(str, open_ports)) if open_ports else 'none detected'}")
    await _set(op_id, aid, progress=100)
    return {"open_ports": open_ports}


async def _agent_webvuln(op_id, task, target):
    aid = "webvuln"
    if not _host(target):
        await _log(op_id, aid, "No target — skipping.")
        return {"note": "no target"}
    issues = []
    await _log(op_id, aid, "Inspecting security headers…")
    try:
        async with httpx.AsyncClient(timeout=12, follow_redirects=True, verify=False) as c:
            r = await c.get(_url(target), headers={"User-Agent": "InsafeLabs-Agent/1.0"})
            hdrs = {k.lower(): v for k, v in r.headers.items()}
            for h in SEC_HEADERS:
                if h not in hdrs:
                    issues.append(f"Missing security header: {h}")
            if hdrs.get("server"):
                issues.append(f"Server banner exposed: {hdrs['server']}")
            await _set(op_id, aid, progress=55)
            # CORS reflection test
            r2 = await c.get(_url(target), headers={"Origin": "https://evil.example", "User-Agent": "InsafeLabs-Agent/1.0"})
            acao = r2.headers.get("access-control-allow-origin", "")
            if acao == "*":
                issues.append("CORS: Access-Control-Allow-Origin is a wildcard (*)")
            elif acao == "https://evil.example":
                issues.append("CORS: origin reflected (dangerous)")
    except Exception as e:
        await _log(op_id, aid, f"Probe error: {str(e)[:80]}")
    for i in issues[:8]:
        await _log(op_id, aid, "⚠ " + i)
    if not issues:
        await _log(op_id, aid, "No obvious header/CORS issues.")
    await _set(op_id, aid, progress=100)
    return {"issues": issues}


async def _agent_local(op_id, task, target):
    aid = "local"
    out = {}
    await _log(op_id, aid, "Self-checking InsafeLabs host…")
    try:
        async with httpx.AsyncClient(timeout=8) as c:
            r = await c.get("http://localhost:8001/api/")
            out["app_status"] = r.status_code
            present = [h for h in ["x-frame-options", "x-content-type-options", "referrer-policy"] if h in {k.lower() for k in r.headers}]
            out["security_headers"] = present
            await _log(op_id, aid, f"App API: HTTP {r.status_code} · headers: {', '.join(present) or 'none'}")
    except Exception as e:
        await _log(op_id, aid, f"App self-check failed: {str(e)[:80]}")
    await _set(op_id, aid, progress=50)
    local_ports = await asyncio.gather(*[_probe_port("127.0.0.1", p) for p in [8001, 3000, 27017, 11434]])
    out["local_open_ports"] = [p for p in local_ports if p]
    await _log(op_id, aid, f"Local services up on: {', '.join(map(str, out['local_open_ports'])) or 'none'}")
    bridge = os.path.exists(os.path.join(STATIC_DIR, "local_gesture_control.py"))
    out["pc_control_bridge"] = bridge
    await _log(op_id, aid, "PC-control bridge (gesture script): " + ("available for download ✓" if bridge else "not found"))
    if 11434 in out["local_open_ports"]:
        await _log(op_id, aid, "Local Ollama detected on :11434 — offline AI possible.")
    await _set(op_id, aid, progress=100)
    return out


# ------------------------------------------------------------------ AI agents
async def _agent_redteam(op_id, task, target, findings):
    aid = "redteam"
    await _log(op_id, aid, "Mapping findings to MITRE ATT&CK attack paths…")
    system = ("You are a red-team lead. Given recon/scan findings, produce a concise attack narrative "
              "mapped to MITRE ATT&CK tactics. Use markdown, be specific and practical. Authorized testing only.")
    user = f"Task: {task}\nTarget: {target or 'n/a'}\nFindings JSON:\n{json.dumps(findings)[:6000]}"
    try:
        md, cost = await ai.complete_ex(f"agent-redteam-{op_id}", system, user)
        await _add_spend(op_id, cost)
    except Exception as e:
        await _log(op_id, aid, f"AI error: {str(e)[:100]}")
        return {"error": str(e)[:160]}
    await _log(op_id, aid, "Attack path drafted.")
    await _set(op_id, aid, progress=100, result_md=md)
    return {"attack_plan_md": md}


async def _agent_report(op_id, task, target, findings):
    aid = "report"
    await _log(op_id, aid, "Synthesizing executive report…")
    system = ("You are a security analyst. Write a crisp markdown operation report: an executive summary, "
              "a prioritized findings table (Severity | Finding | Evidence), and clear next-step recommendations. "
              "Base it strictly on the provided findings. Authorized testing only.")
    user = f"Task: {task}\nTarget: {target or 'n/a'}\nAll agent findings JSON:\n{json.dumps(findings)[:7000]}"
    try:
        md, cost = await ai.complete_ex(f"agent-report-{op_id}", system, user)
        await _add_spend(op_id, cost)
    except Exception as e:
        await _log(op_id, aid, f"AI error: {str(e)[:100]}")
        return {"error": str(e)[:160]}
    await _log(op_id, aid, "Report ready.")
    await _set(op_id, aid, progress=100, result_md=md)
    return {"report_md": md}


GATHER_FN = {
    "recon": _agent_recon, "subdomains": _agent_subdomains, "ports": _agent_ports,
    "webvuln": _agent_webvuln, "local": _agent_local,
}


# ------------------------------------------------------------------ planner + orchestrator
async def _plan(task, target):
    system = ("You are the orchestrator of a security operations desk. Choose which agents to deploy for the "
              "given task. Available agents: recon, subdomains, ports, webvuln, local, redteam, report. "
              "Return STRICT JSON: {\"summary\":\"one line plan\",\"agents\":[{\"id\":\"recon\",\"objective\":\"...\"}]}. "
              "Rules: if a target host/URL is given, include the network agents (recon, subdomains, ports, webvuln). "
              "Always include 'local' (host self-check) and always finish with 'redteam' then 'report'.")
    user = f"Task: {task}\nTarget: {target or '(none provided)'}"
    try:
        raw, cost = await ai.complete_ex("agent-planner", system, user)
        parsed = ai.parse_json(raw)
        chosen = []
        objectives = {}
        for a in parsed.get("agents", []):
            aid = a.get("id")
            if aid in AGENT_META and aid != "planner" and aid not in chosen:
                chosen.append(aid)
                objectives[aid] = (a.get("objective") or "")[:140]
        summary = (parsed.get("summary") or "").strip()[:200]
        if not chosen:
            raise ValueError("empty plan")
        return summary, chosen, objectives, cost
    except Exception:
        # deterministic fallback
        base = (GATHER_AGENTS if _host(target) else ["local"]) + ANALYSIS_AGENTS
        return "Automated default plan.", base, {}, 0.0


async def run_operation(op_id, task, target):
    try:
        await _op_set(op_id, status="planning")
        summary, chosen, objectives, plan_cost = await _plan(task, target)
        await _add_spend(op_id, plan_cost)
        # ensure local + analysis agents present and ordered
        for must in ["local"]:
            if must not in chosen:
                chosen.append(must)
        for a in ANALYSIS_AGENTS:
            if a in chosen:
                chosen.remove(a)
        ordered = [a for a in chosen if a in GATHER_FN] + [a for a in ANALYSIS_AGENTS]
        agents = [{
            "id": a, "name": AGENT_META[a][0], "icon": AGENT_META[a][1],
            "objective": objectives.get(a, ""), "status": "queued",
            "progress": 0, "log": [], "result_md": None,
            "started_at": None, "finished_at": None,
        } for a in ordered]
        await _op_set(op_id, status="running", plan=summary, agents=agents, started_at=_now())

        # Phase 1 — data-gathering agents run concurrently
        gatherers = [a for a in ordered if a in GATHER_FN]
        findings = {}

        async def _run_gather(aid):
            await _set(op_id, aid, status="working", action="executing", started_at=_now())
            try:
                res = await asyncio.wait_for(GATHER_FN[aid](op_id, task, target), 60)
                findings[aid] = res
                await _set(op_id, aid, status="done", action="complete", finished_at=_now())
            except asyncio.TimeoutError:
                await _log(op_id, aid, "Timed out.")
                await _set(op_id, aid, status="failed", action="timeout", finished_at=_now())
            except Exception as e:
                await _log(op_id, aid, f"Error: {str(e)[:100]}")
                await _set(op_id, aid, status="failed", action="error", finished_at=_now())

        await asyncio.gather(*[_run_gather(a) for a in gatherers])
        await _op_set(op_id, findings=findings)

        # Phase 2 — analysis agents (sequential, use gathered findings)
        for aid in [a for a in ANALYSIS_AGENTS if a in ordered]:
            await _set(op_id, aid, status="working", action="analyzing", started_at=_now())
            try:
                fn = _agent_redteam if aid == "redteam" else _agent_report
                res = await asyncio.wait_for(fn(op_id, task, target, findings), 90)
                findings[aid] = res
                await _set(op_id, aid, status="done", action="complete", finished_at=_now())
            except asyncio.TimeoutError:
                await _log(op_id, aid, "Timed out.")
                await _set(op_id, aid, status="failed", action="timeout", finished_at=_now())
            except Exception as e:
                await _log(op_id, aid, f"Error: {str(e)[:100]}")
                await _set(op_id, aid, status="failed", action="error", finished_at=_now())

        report_md = (findings.get("report") or {}).get("report_md", "")
        cur = await db.agent_ops.find_one({"id": op_id}, {"_id": 0, "status": 1})
        if (cur or {}).get("status") != "stopped":
            await _op_set(op_id, status="done", report=report_md, findings=findings, finished_at=_now())
    except asyncio.CancelledError:
        await _mark_stopped(op_id)
        raise
    except Exception as e:
        await _op_set(op_id, status="failed", error=str(e)[:200], finished_at=_now())
    finally:
        _RUNNING.pop(op_id, None)


async def resume_operation(op_id, task, target):
    """Re-run only the agents left unfinished when an operation was stopped."""
    try:
        d = await db.agent_ops.find_one({"id": op_id}, {"_id": 0})
        agents = (d or {}).get("agents") or []
        if not agents:
            await run_operation(op_id, task, target)  # nothing was planned yet
            return
        findings = dict((d or {}).get("findings") or {})
        ordered = [a["id"] for a in agents]
        status_by = {a["id"]: a.get("status") for a in agents}
        await _op_set(op_id, status="running", finished_at=None)
        if (d or {}).get("started_at") is None:
            await _op_set(op_id, started_at=_now())

        pending = ("stopped", "queued", "failed")
        gatherers = [a for a in ordered if a in GATHER_FN and status_by.get(a) in pending]

        async def _run_gather(aid):
            await _set(op_id, aid, status="working", action="executing", started_at=_now(), finished_at=None)
            try:
                res = await asyncio.wait_for(GATHER_FN[aid](op_id, task, target), 60)
                findings[aid] = res
                await _set(op_id, aid, status="done", action="complete", finished_at=_now())
            except asyncio.TimeoutError:
                await _log(op_id, aid, "Timed out.")
                await _set(op_id, aid, status="failed", action="timeout", finished_at=_now())
            except Exception as e:
                await _log(op_id, aid, f"Error: {str(e)[:100]}")
                await _set(op_id, aid, status="failed", action="error", finished_at=_now())

        if gatherers:
            await asyncio.gather(*[_run_gather(a) for a in gatherers])
            await _op_set(op_id, findings=findings)

        for aid in [a for a in ANALYSIS_AGENTS if a in ordered and status_by.get(a) in pending]:
            await _set(op_id, aid, status="working", action="analyzing", started_at=_now(), finished_at=None)
            try:
                fn = _agent_redteam if aid == "redteam" else _agent_report
                res = await asyncio.wait_for(fn(op_id, task, target, findings), 90)
                findings[aid] = res
                await _set(op_id, aid, status="done", action="complete", finished_at=_now())
            except asyncio.TimeoutError:
                await _log(op_id, aid, "Timed out.")
                await _set(op_id, aid, status="failed", action="timeout", finished_at=_now())
            except Exception as e:
                await _log(op_id, aid, f"Error: {str(e)[:100]}")
                await _set(op_id, aid, status="failed", action="error", finished_at=_now())

        report_md = (findings.get("report") or {}).get("report_md", "") or (d or {}).get("report", "")
        cur = await db.agent_ops.find_one({"id": op_id}, {"_id": 0, "status": 1})
        if (cur or {}).get("status") != "stopped":
            await _op_set(op_id, status="done", report=report_md, findings=findings, finished_at=_now())
    except asyncio.CancelledError:
        await _mark_stopped(op_id)
        raise
    except Exception as e:
        await _op_set(op_id, status="failed", error=str(e)[:200], finished_at=_now())
    finally:
        _RUNNING.pop(op_id, None)


# ------------------------------------------------------------------ API
class RunBody(BaseModel):
    task: str
    target: str = ""


@router.post("/run")
async def run(body: RunBody):
    if not (body.task or "").strip():
        raise HTTPException(status_code=400, detail="Task is required")
    op_id = str(uuid.uuid4())
    doc = {
        "id": op_id, "task": body.task.strip(), "target": (body.target or "").strip(),
        "status": "queued", "plan": "", "agents": [], "findings": {}, "report": "",
        "spend": 0.0, "started_at": None, "finished_at": None,
        "created_at": _now(), "updated_at": _now(),
    }
    await db.agent_ops.insert_one(doc)
    _RUNNING[op_id] = asyncio.create_task(run_operation(op_id, body.task.strip(), (body.target or "").strip()))
    return {"id": op_id}


@router.post("/stop/{op_id}")
async def stop_op(op_id: str):
    d = await db.agent_ops.find_one({"id": op_id}, {"_id": 0, "status": 1})
    if not d:
        raise HTTPException(status_code=404, detail="Operation not found")
    if d.get("status") in ("done", "failed", "stopped"):
        return {"ok": True, "status": d["status"]}
    t = _RUNNING.pop(op_id, None)
    if t and not t.done():
        t.cancel()
    await _mark_stopped(op_id)
    return {"ok": True, "status": "stopped"}


@router.post("/resume/{op_id}")
async def resume_op(op_id: str):
    d = await db.agent_ops.find_one({"id": op_id}, {"_id": 0, "status": 1, "task": 1, "target": 1})
    if not d:
        raise HTTPException(status_code=404, detail="Operation not found")
    if d.get("status") != "stopped":
        raise HTTPException(status_code=400, detail="Only a stopped operation can be resumed")
    _RUNNING[op_id] = asyncio.create_task(resume_operation(op_id, d.get("task", ""), d.get("target", "")))
    return {"ok": True, "status": "running"}


@router.get("/operations")
async def list_ops():
    cur = db.agent_ops.find({}, {"_id": 0, "agents": 0, "findings": 0, "report": 0}).sort("created_at", -1).limit(20)
    return {"operations": [d async for d in cur]}


@router.get("/operations/{op_id}")
async def get_op(op_id: str):
    d = await db.agent_ops.find_one({"id": op_id}, {"_id": 0})
    if not d:
        raise HTTPException(status_code=404, detail="Operation not found")
    return d


@router.delete("/operations/{op_id}")
async def del_op(op_id: str):
    await db.agent_ops.delete_one({"id": op_id})
    return {"ok": True}
