import os
import time
from datetime import datetime, timezone, timedelta

import bcrypt
import jwt
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from pymongo import ReturnDocument

from db import db

router = APIRouter(prefix="/auth", tags=["auth"])

JWT_ALGORITHM = "HS256"
TOKEN_TTL_DAYS = 30  # "remember me" — stays signed in on this device
MAX_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

# Only trust X-Forwarded-For when explicitly running behind a trusted reverse proxy.
# Otherwise a client could spoof the header to bypass the per-IP brute-force lockout.
TRUST_PROXY = os.environ.get("TRUST_PROXY", "").strip().lower() in ("1", "true", "yes")

# Refuse to boot with an empty access code (bcrypt.hashpw(b"") would make the
# empty password authenticate successfully).
_ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
if not _ADMIN_PASSWORD:
    raise RuntimeError("ADMIN_PASSWORD must be set — refusing to start with an empty access code")

# Hash the configured access code once at import (kept out of the DB / responses).
_ADMIN_HASH = bcrypt.hashpw(_ADMIN_PASSWORD.encode("utf-8"), bcrypt.gensalt())


def _secret() -> str:
    s = os.environ.get("JWT_SECRET", "")
    if not s:
        raise RuntimeError("JWT_SECRET must be set")
    return s


# ---- token revocation via a server-side epoch (logout invalidates all tokens) ----
# Short TTL cache so a logout is honoured promptly even across multiple workers,
# without hitting Mongo on every single request.
_EPOCH_CACHE = {"value": None, "at": 0.0}
_EPOCH_TTL_SECONDS = 3.0


async def _current_epoch() -> int:
    now = time.monotonic()
    if _EPOCH_CACHE["value"] is not None and (now - _EPOCH_CACHE["at"]) < _EPOCH_TTL_SECONDS:
        return _EPOCH_CACHE["value"]
    doc = await db.auth_state.find_one({"_id": "epoch"})
    val = int(doc["value"]) if doc and "value" in doc else 1
    _EPOCH_CACHE.update(value=val, at=now)
    return val


async def _bump_epoch() -> int:
    # Atomic increment so concurrent logouts can't clobber each other.
    doc = await db.auth_state.find_one_and_update(
        {"_id": "epoch"}, {"$inc": {"value": 1}}, upsert=True, return_document=ReturnDocument.AFTER,
    )
    nxt = int(doc["value"]) if doc and "value" in doc else 1
    _EPOCH_CACHE.update(value=nxt, at=time.monotonic())
    return nxt


async def _create_access_token() -> str:
    payload = {
        "sub": "operator",
        "type": "access",
        "epoch": await _current_epoch(),
        "exp": datetime.now(timezone.utc) + timedelta(days=TOKEN_TTL_DAYS),
    }
    return jwt.encode(payload, _secret(), algorithm=JWT_ALGORITHM)


async def verify_token(request: Request) -> bool:
    """Auth dependency — Bearer token only; rejects tokens issued before the last logout."""
    token = ""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token, _secret(), algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Session expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid token")
    if int(payload.get("epoch", 0)) != await _current_epoch():
        raise HTTPException(status_code=401, detail="Session revoked")
    return True


class LoginBody(BaseModel):
    password: str


def _client_ip(request: Request) -> str:
    if TRUST_PROXY:
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _as_utc(dt):
    if isinstance(dt, str):
        dt = datetime.fromisoformat(dt)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


@router.post("/login")
async def login(body: LoginBody, request: Request):
    ip = _client_ip(request)
    now = datetime.now(timezone.utc)
    rec = await db.login_attempts.find_one({"identifier": ip})

    # Active lockout?
    if rec and rec.get("locked_until"):
        lu = _as_utc(rec["locked_until"])
        if lu > now:
            secs = max(1, int((lu - now).total_seconds()))
            mins = secs // 60 + 1
            raise HTTPException(status_code=429, detail=f"Too many attempts · locked for {mins} min",
                                headers={"Retry-After": str(secs)})

    supplied = (body.password or "").encode("utf-8")
    # Explicitly reject empty / oversized passwords before touching bcrypt.
    if not body.password or len(body.password) > 256 or not bcrypt.checkpw(supplied, _ADMIN_HASH):
        prior = rec.get("attempts", 0) if rec else 0
        # reset the counter if a previous lockout has already expired
        if rec and rec.get("locked_until") and _as_utc(rec["locked_until"]) <= now:
            prior = 0
        attempts = prior + 1
        if attempts >= MAX_ATTEMPTS:
            await db.login_attempts.update_one(
                {"identifier": ip},
                {"$set": {"identifier": ip, "attempts": 0, "locked_until": now + timedelta(minutes=LOCKOUT_MINUTES), "updated_at": now}},
                upsert=True,
            )
            raise HTTPException(status_code=429, detail=f"Too many attempts · locked for {LOCKOUT_MINUTES} min",
                                headers={"Retry-After": str(LOCKOUT_MINUTES * 60)})
        await db.login_attempts.update_one(
            {"identifier": ip},
            {"$set": {"identifier": ip, "attempts": attempts, "locked_until": None, "updated_at": now}},
            upsert=True,
        )
        left = MAX_ATTEMPTS - attempts
        raise HTTPException(status_code=401, detail=f"Incorrect access code · {left} attempt{'s' if left != 1 else ''} left")

    # success — clear brute-force record + record login telemetry
    await db.login_attempts.delete_one({"identifier": ip})
    prev = await db.auth_state.find_one({"_id": "session"})
    previous_login = {"at": prev.get("last_login_at"), "ip": prev.get("last_login_ip")} if prev else {"at": None, "ip": None}
    await db.auth_state.update_one({"_id": "session"},
                                   {"$set": {"last_login_at": now.isoformat(), "last_login_ip": ip}}, upsert=True)
    return {"token": await _create_access_token(), "token_type": "bearer", "previous_login": previous_login}


@router.get("/me")
async def me(request: Request):
    await verify_token(request)
    return {"authenticated": True, "operator": "operator"}


@router.post("/logout")
async def logout(request: Request):
    await verify_token(request)
    await _bump_epoch()  # invalidate every previously-issued token
    return {"ok": True}
