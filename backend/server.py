from dotenv import load_dotenv
from pathlib import Path

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

import logging
import asyncio
import os
import time
from collections import defaultdict, deque

from fastapi import FastAPI, APIRouter, Depends
from fastapi.responses import JSONResponse
from starlette.middleware.cors import CORSMiddleware

from db import client, db
from routers import dashboard, assessments, sca, pentest, scanner, tools, osint, redteam, toolkit, keyrecon, offensive, bugbounty, auth, agents, ai_config, arsenal, vulnsuite, ai_agent, playbooks, blacklist, assess, soc, proxy, legal, toolbox
from routers.auth import verify_token
import ai

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="InsafeLabs Security Platform", docs_url=None, redoc_url=None, openapi_url=None)
api_router = APIRouter(prefix="/api")


@api_router.get("/")
async def root():
    return {"status": "ok", "service": "InsafeLabs Security Platform"}


_auth = [Depends(verify_token)]
api_router.include_router(auth.router)
api_router.include_router(dashboard.router, dependencies=_auth)
api_router.include_router(assessments.router, dependencies=_auth)
api_router.include_router(sca.router, dependencies=_auth)
api_router.include_router(pentest.router, dependencies=_auth)
api_router.include_router(scanner.router, dependencies=_auth)
api_router.include_router(tools.router, dependencies=_auth)
api_router.include_router(osint.router, dependencies=_auth)
api_router.include_router(redteam.router, dependencies=_auth)
api_router.include_router(toolkit.router, dependencies=_auth)
api_router.include_router(keyrecon.router, dependencies=_auth)
api_router.include_router(offensive.router, dependencies=_auth)
api_router.include_router(bugbounty.router, dependencies=_auth)
api_router.include_router(agents.router, dependencies=_auth)
api_router.include_router(ai_config.router, dependencies=_auth)
api_router.include_router(arsenal.router, dependencies=_auth)
api_router.include_router(vulnsuite.router, dependencies=_auth)
api_router.include_router(ai_agent.router, dependencies=_auth)
api_router.include_router(playbooks.router, dependencies=_auth)
api_router.include_router(blacklist.router, dependencies=_auth)
api_router.include_router(assess.router, dependencies=_auth)
api_router.include_router(soc.router, dependencies=_auth)
api_router.include_router(proxy.router, dependencies=_auth)
api_router.include_router(legal.router, dependencies=_auth)
api_router.include_router(toolbox.router, dependencies=_auth)

app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.environ.get("FRONTEND_URL", "http://localhost:3000"), "http://localhost:3000"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---- lightweight global rate limiter (per client IP, sliding 60s window) ----
_RATE_HITS = defaultdict(deque)
RATE_LIMIT_PER_MIN = int(os.environ.get("RATE_LIMIT_PER_MIN", "600"))


@app.middleware("http")
async def rate_limit_mw(request, call_next):
    ip = request.client.host if request.client else "unknown"
    now = time.monotonic()
    q = _RATE_HITS[ip]
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= RATE_LIMIT_PER_MIN:
        return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded — slow down."},
                            headers={"Retry-After": "60", "X-RateLimit-Limit": str(RATE_LIMIT_PER_MIN)})
    q.append(now)
    resp = await call_next(request)
    resp.headers["X-RateLimit-Limit"] = str(RATE_LIMIT_PER_MIN)
    resp.headers["X-RateLimit-Remaining"] = str(max(0, RATE_LIMIT_PER_MIN - len(q)))
    return resp


@app.middleware("http")
async def security_headers(request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    resp.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.on_event("startup")
async def on_startup():
    if not os.environ.get("JWT_SECRET"):
        raise RuntimeError("JWT_SECRET must be set — refusing to start (see backend/.env)")
    if not os.environ.get("ADMIN_PASSWORD"):
        raise RuntimeError("ADMIN_PASSWORD must be set — refusing to start (see backend/.env)")
    await db.assessments.create_index("module")
    await db.assessments.create_index("created_at")
    await db.sca_scans.create_index("created_at")
    await db.recon_scans.create_index("created_at")
    asyncio.create_task(scanner.scheduler_loop())
    saved = await db.ai_state.find_one({"_id": "model"})
    if saved and saved.get("value"):
        ai.set_model_override(saved["value"])
    logger.info("InsafeLabs Security Platform started (password-gated private mode).")


@app.on_event("shutdown")
async def on_shutdown():
    client.close()
