"""InsafeLabs OSINT — email / phone / image / username intelligence (no auth)."""
import asyncio
import base64
import hashlib
import io
import os
import re
import uuid
from datetime import datetime, timezone

import requests
from fastapi import APIRouter, HTTPException, UploadFile, File, Form
from fastapi.responses import Response
from pydantic import BaseModel, Field

from db import db
import ai
from netguard import guard_url

router = APIRouter(prefix="/osint", tags=["osint"])

UA = {"User-Agent": "Mozilla/5.0 (compatible; InsafeLabs-OSINT/1.0; authorized-assessment)"}
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


def _now():
    return datetime.now(timezone.utc).isoformat()


async def _save(kind: str, query: str, result: dict) -> dict:
    doc = {
        "id": str(uuid.uuid4()), "kind": kind, "query": query,
        "result": result, "created_at": _now(),
    }
    await db.osint_lookups.insert_one(dict(doc))
    doc.pop("_id", None)
    return doc


# ============================================================================
# EMAIL
# ============================================================================
class EmailInput(BaseModel):
    email: str = Field(min_length=5)


SOCIAL_TEMPLATES = {
    "GitHub": "https://github.com/{u}",
    "Twitter/X": "https://x.com/{u}",
    "Instagram": "https://www.instagram.com/{u}/",
    "LinkedIn": "https://www.linkedin.com/in/{u}",
    "Reddit": "https://www.reddit.com/user/{u}",
    "Facebook": "https://www.facebook.com/{u}",
}


def _email_intel(email: str) -> dict:
    email = email.strip().lower()
    if not EMAIL_RE.match(email):
        raise HTTPException(status_code=400, detail="Invalid email address")
    local, _, domain = email.partition("@")
    h = hashlib.md5(email.encode()).hexdigest()

    gravatar = {"hash": h, "avatar": f"https://www.gravatar.com/avatar/{h}?s=256&d=404",
                "exists": False, "has_avatar": False, "profile": None}
    try:
        r = requests.get(f"https://www.gravatar.com/{h}.json", timeout=8, headers=UA)
        if r.status_code == 200:
            entry = (r.json().get("entry") or [{}])[0]
            gravatar["exists"] = True
            gravatar["profile"] = {
                "username": entry.get("preferredUsername"),
                "display_name": entry.get("displayName"),
                "location": entry.get("currentLocation"),
                "about": entry.get("aboutMe"),
                "profile_url": entry.get("profileUrl"),
                "accounts": [{"name": a.get("shortname") or a.get("name"), "url": a.get("url")}
                             for a in (entry.get("accounts") or [])],
            }
    except Exception:
        pass
    try:
        gravatar["has_avatar"] = requests.get(gravatar["avatar"], timeout=6, headers=UA).status_code == 200
    except Exception:
        pass

    mx, a_rec, spf = [], [], None
    try:
        import dns.resolver
        rs = dns.resolver.Resolver()
        rs.lifetime = 5
        rs.timeout = 5
        try:
            mx = sorted([r.to_text() for r in rs.resolve(domain, "MX")])[:6]
        except Exception:
            pass
        try:
            a_rec = [r.to_text() for r in rs.resolve(domain, "A")][:6]
        except Exception:
            pass
        try:
            txt = [r.to_text() for r in rs.resolve(domain, "TXT")]
            spf = next((t for t in txt if "v=spf1" in t.lower()), None)
        except Exception:
            pass
    except Exception:
        pass

    provider = "Unknown"
    mxl = " ".join(mx).lower()
    if "google" in mxl or "gmail" in domain:
        provider = "Google Workspace / Gmail"
    elif "outlook" in mxl or "protection.outlook" in mxl or domain in ("outlook.com", "hotmail.com", "live.com"):
        provider = "Microsoft / Outlook"
    elif "zoho" in mxl:
        provider = "Zoho"
    elif "protonmail" in mxl or domain == "proton.me":
        provider = "Proton Mail"
    elif "yahoodns" in mxl or domain == "yahoo.com":
        provider = "Yahoo"
    elif mx:
        provider = "Custom / self-hosted"

    guess = gravatar.get("profile", {}).get("username") if gravatar.get("profile") else None
    username = guess or local
    social = [{"platform": p, "url": t.format(u=username)} for p, t in SOCIAL_TEMPLATES.items()]

    return {
        "email": email, "valid_format": True, "local_part": local, "domain": domain,
        "gravatar": gravatar, "mail": {"mx": mx, "a": a_rec, "spf": spf, "provider": provider,
                                       "deliverable_domain": bool(mx)},
        "derived_username": username, "candidate_profiles": social,
    }


@router.post("/email")
async def osint_email(data: EmailInput):
    loop = asyncio.get_event_loop()
    intel = await loop.run_in_executor(None, _email_intel, data.email)
    system = ("You are InsafeLabs, an OSINT analyst. Given structured email-intelligence JSON, write a concise "
              "3-4 sentence investigative summary: what the email/domain reveals, mail provider posture "
              "(SPF present or spoofable), whether a public Gravatar identity exists, and recommended next "
              "OSINT pivots. Be factual, do not invent data.")
    try:
        intel["ai_summary"] = await ai.complete("osint-email", system, str(intel))
    except Exception:
        intel["ai_summary"] = ""
    return await _save("email", data.email, intel)


# ============================================================================
# PHONE
# ============================================================================
class PhoneInput(BaseModel):
    phone: str = Field(min_length=5)
    region: str | None = None


_PH_TYPES = {}


def _phone_intel(phone: str, region: str | None) -> dict:
    import phonenumbers
    from phonenumbers import carrier, geocoder, timezone as ph_tz, PhoneNumberType, PhoneNumberFormat
    global _PH_TYPES
    if not _PH_TYPES:
        _PH_TYPES = {
            PhoneNumberType.MOBILE: "Mobile", PhoneNumberType.FIXED_LINE: "Fixed line",
            PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed line or mobile",
            PhoneNumberType.TOLL_FREE: "Toll free", PhoneNumberType.PREMIUM_RATE: "Premium rate",
            PhoneNumberType.VOIP: "VoIP", PhoneNumberType.PERSONAL_NUMBER: "Personal number",
            PhoneNumberType.PAGER: "Pager", PhoneNumberType.UAN: "UAN",
            PhoneNumberType.VOICEMAIL: "Voicemail", PhoneNumberType.UNKNOWN: "Unknown",
        }
    try:
        num = phonenumbers.parse(phone, (region or None) and region.upper())
    except phonenumbers.NumberParseException as e:
        raise HTTPException(status_code=400,
                            detail=f"Could not parse number ({e}). Use +country code, or provide a region (e.g. US, IN).")
    valid = phonenumbers.is_valid_number(num)
    return {
        "input": phone, "valid": valid, "possible": phonenumbers.is_possible_number(num),
        "country_code": f"+{num.country_code}",
        "national_number": str(num.national_number),
        "region": geocoder.description_for_number(num, "en") or None,
        "carrier": carrier.name_for_number(num, "en") or None,
        "line_type": _PH_TYPES.get(phonenumbers.number_type(num), "Unknown"),
        "timezones": list(ph_tz.time_zones_for_number(num)),
        "formats": {
            "e164": phonenumbers.format_number(num, PhoneNumberFormat.E164),
            "international": phonenumbers.format_number(num, PhoneNumberFormat.INTERNATIONAL),
            "national": phonenumbers.format_number(num, PhoneNumberFormat.NATIONAL),
        },
    }


@router.post("/phone")
async def osint_phone(data: PhoneInput):
    loop = asyncio.get_event_loop()
    intel = await loop.run_in_executor(None, _phone_intel, data.phone, data.region)
    return await _save("phone", data.phone, intel)


# ============================================================================
# IMAGE
# ============================================================================
class ImageInput(BaseModel):
    image_url: str = Field(min_length=5)


def _dms_to_deg(dms, ref):
    try:
        d = float(dms[0]); m = float(dms[1]); s = float(dms[2])
        val = d + m / 60.0 + s / 3600.0
        if ref in ("S", "W"):
            val = -val
        return round(val, 6)
    except Exception:
        return None


def _image_intel(content: bytes) -> tuple:
    from PIL import Image, ExifTags
    img = Image.open(io.BytesIO(content))
    meta = {"format": img.format, "mode": img.mode, "width": img.width, "height": img.height,
            "size_kb": round(len(content) / 1024, 1)}
    exif_out, gps = {}, None
    try:
        raw = img.getexif()
        for tag_id, val in raw.items():
            tag = ExifTags.TAGS.get(tag_id, str(tag_id))
            if tag in ("Make", "Model", "Software", "DateTime", "Orientation", "Artist", "Copyright"):
                exif_out[tag] = str(val)[:120]
        gps_ifd = raw.get_ifd(ExifTags.IFD.GPSInfo) if hasattr(ExifTags, "IFD") else {}
        if gps_ifd:
            g = {ExifTags.GPSTAGS.get(k, k): v for k, v in gps_ifd.items()}
            lat = _dms_to_deg(g.get("GPSLatitude"), g.get("GPSLatitudeRef"))
            lon = _dms_to_deg(g.get("GPSLongitude"), g.get("GPSLongitudeRef"))
            if lat is not None and lon is not None:
                gps = {"lat": lat, "lon": lon,
                       "maps_url": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=15/{lat}/{lon}"}
    except Exception:
        pass

    # prepare base64 for vision (transcode if needed)
    fmt = (img.format or "").upper()
    if fmt in ("JPEG", "PNG", "WEBP"):
        b64 = base64.b64encode(content).decode()
    else:
        buf = io.BytesIO()
        img.convert("RGB").save(buf, format="JPEG", quality=85)
        b64 = base64.b64encode(buf.getvalue()).decode()
    # small preview thumbnail (data URL) — used when the source is an uploaded file
    try:
        tim = img.convert("RGB")
        tim.thumbnail((480, 480))
        tbuf = io.BytesIO()
        tim.save(tbuf, format="JPEG", quality=70)
        thumb = "data:image/jpeg;base64," + base64.b64encode(tbuf.getvalue()).decode()
    except Exception:
        thumb = None
    return meta, exif_out, gps, b64, thumb


@router.post("/image")
async def osint_image(image_url: str | None = Form(default=None), image: UploadFile | None = File(default=None)):
    if bool(image_url) == bool(image):
        raise HTTPException(status_code=400, detail="Provide exactly one: an image URL OR an uploaded file.")
    is_upload = image is not None
    if is_upload:
        content = await image.read()
        if not content:
            raise HTTPException(status_code=400, detail="Uploaded image is empty")
        if len(content) > 20 * 1024 * 1024:
            raise HTTPException(status_code=413, detail="Image too large (max 20MB)")
        src = f"upload:{image.filename or 'image'}"
    else:
        if not image_url.startswith(("http://", "https://")):
            raise HTTPException(status_code=400, detail="Provide a valid http(s) image URL")
        guard_url(image_url)
        try:
            from urllib.parse import urlparse as _up
            _o = _up(image_url)
            img_headers = {**UA, "Accept": "image/*,*/*;q=0.8", "Referer": f"{_o.scheme}://{_o.netloc}/"}
            r = requests.get(image_url, timeout=20, headers=img_headers, stream=True)
            cl = int(r.headers.get("Content-Length") or 0)
            if cl and cl > 20 * 1024 * 1024:
                raise HTTPException(status_code=400, detail="Image too large (max 20MB)")
            content = r.raw.read(20 * 1024 * 1024 + 1, decode_content=True)
            if len(content) > 20 * 1024 * 1024:
                raise HTTPException(status_code=400, detail="Image too large (max 20MB)")
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Could not fetch image: {str(e)[:120]}")
        if r.status_code != 200 or not content:
            raise HTTPException(status_code=400, detail="Image URL did not return an image")
        src = image_url
    loop = asyncio.get_event_loop()
    try:
        meta, exif_out, gps, b64, thumb = await loop.run_in_executor(None, _image_intel, content)
    except Exception:
        raise HTTPException(status_code=400, detail="Could not decode image (unsupported or corrupt)")

    system = ("You are InsafeLabs, an OSINT image analyst. Describe the image factually and extract investigative "
              "signals: people (count, apparent attributes — NO identity guesses), setting/location clues, "
              "visible text/signage/license plates, brand logos, objects, and any indicators of time/place. "
              "Be concise (4-6 sentences). Do not fabricate.")
    analysis = ""
    try:
        analysis = await ai.analyze_image("osint-image", system, "Analyze this image for OSINT signals.", b64)
    except Exception:
        analysis = ""

    preview = thumb if is_upload else src
    result = {"image_url": preview, "source": src, "is_upload": is_upload, "metadata": meta,
              "exif": exif_out, "gps": gps, "ai_analysis": analysis}
    return await _save("image", src, result)


# ============================================================================
# REVERSE IMAGE SEARCH — "where is this photo online" (Google Vision Web Detection)
# ============================================================================
VISION_URL = "https://vision.googleapis.com/v1/images:annotate"


def _prep_b64(content: bytes) -> str:
    from PIL import Image
    try:
        img = Image.open(io.BytesIO(content))
        if (img.format or "").upper() in ("JPEG", "PNG", "WEBP", "BMP", "GIF"):
            return base64.b64encode(content).decode()
        buf = io.BytesIO()
        img.convert("RGB").save(buf, format="JPEG", quality=88)
        return base64.b64encode(buf.getvalue()).decode()
    except Exception:
        return base64.b64encode(content).decode()


def _vision_web_detection(b64: str, max_results: int = 20) -> dict:
    key = os.environ.get("VISION_API_KEY")
    if not key:
        raise HTTPException(status_code=400,
                            detail="Reverse image search not configured — add a Google Cloud Vision API key as VISION_API_KEY in backend/.env, then restart the backend.")
    body = {"requests": [{"image": {"content": b64},
                          "features": [{"type": "WEB_DETECTION", "maxResults": max_results}]}]}
    try:
        r = requests.post(VISION_URL, headers={"x-goog-api-key": key, "Content-Type": "application/json"},
                          json=body, timeout=45)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Could not reach Vision API: {str(e)[:120]}")
    if r.status_code >= 400:
        try:
            msg = r.json().get("error", {}).get("message", "Vision API error")
        except Exception:
            msg = "Vision API error"
        raise HTTPException(status_code=r.status_code if r.status_code < 500 else 502, detail=f"Vision: {msg}")
    first = (r.json().get("responses") or [{}])[0]
    if first.get("error"):
        raise HTTPException(status_code=502, detail=first["error"].get("message", "Vision annotation failed"))
    return first.get("webDetection", {}) or {}


def _normalize_web(wd: dict) -> dict:
    pages = []
    for p in (wd.get("pagesWithMatchingImages") or []):
        pages.append({
            "url": p.get("url"), "title": p.get("pageTitle"),
            "full": [i.get("url") for i in (p.get("fullMatchingImages") or []) if i.get("url")],
            "partial": [i.get("url") for i in (p.get("partialMatchingImages") or []) if i.get("url")],
        })
    take = lambda key: [x.get("url") for x in (wd.get(key) or []) if x.get("url")]
    return {
        "pages": pages,
        "full_matching": take("fullMatchingImages"),
        "partial_matching": take("partialMatchingImages"),
        "visually_similar": take("visuallySimilarImages"),
        "web_entities": [{"description": e.get("description"), "score": round(e.get("score", 0), 2)}
                         for e in (wd.get("webEntities") or []) if e.get("description")][:20],
        "best_guess": [b.get("label") for b in (wd.get("bestGuessLabels") or []) if b.get("label")],
        "counts": {"pages": len(pages),
                   "full": len(wd.get("fullMatchingImages") or []),
                   "partial": len(wd.get("partialMatchingImages") or []),
                   "similar": len(wd.get("visuallySimilarImages") or [])},
    }


@router.post("/reverse-image")
async def reverse_image(image_url: str | None = Form(default=None), image: UploadFile | None = File(default=None)):
    if bool(image_url) == bool(image):
        raise HTTPException(status_code=400, detail="Provide exactly one: an image URL OR an uploaded file.")
    if image is not None:
        content = await image.read()
        if not content:
            raise HTTPException(status_code=400, detail="Uploaded image is empty")
        if len(content) > 15 * 1024 * 1024:
            raise HTTPException(status_code=413, detail="Image too large (max 15MB)")
        src = f"upload:{image.filename}"
    else:
        if not image_url.startswith(("http://", "https://")):
            raise HTTPException(status_code=400, detail="Provide a valid http(s) image URL")
        guard_url(image_url)
        try:
            from urllib.parse import urlparse as _up
            _o = _up(image_url)
            hh = {**UA, "Accept": "image/*,*/*;q=0.8", "Referer": f"{_o.scheme}://{_o.netloc}/"}
            rr = requests.get(image_url, timeout=20, headers=hh, stream=True)
            content = rr.raw.read(15 * 1024 * 1024 + 1, decode_content=True)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Could not fetch image: {str(e)[:120]}")
        if not content or rr.status_code != 200:
            raise HTTPException(status_code=400, detail="Image URL did not return an image")
        if len(content) > 15 * 1024 * 1024:
            raise HTTPException(status_code=413, detail="Image too large (max 15MB)")
        src = image_url

    loop = asyncio.get_event_loop()
    b64 = await loop.run_in_executor(None, _prep_b64, content)
    wd = await loop.run_in_executor(None, _vision_web_detection, b64, 20)
    result = _normalize_web(wd)
    result["source"] = src
    return await _save("reverse-image", src, result)


# ============================================================================
# TAKEDOWN / REMOVAL ADVISOR — how to get an unwanted image removed (AI, no key)
# ============================================================================
class TakedownInput(BaseModel):
    description: str = Field(min_length=3)
    where: str | None = None


TAKEDOWN_SYSTEM = (
    "You are InsafeLabs Image Takedown Advisor, a compassionate expert who helps people get their own "
    "unwanted, leaked or non-consensual images removed from the internet. Given the situation, give a clear, "
    "step-by-step action plan in markdown: "
    "1) Locate every copy (reverse image search, Google 'Results about you'). "
    "2) Google Search removal — 'Remove content from Google' / personal-info & explicit-image removal request forms. "
    "3) Contact the website owner & its hosting provider; if you own the copyright, file a DMCA takedown. "
    "4) Platform reports — Instagram/Facebook (Meta), X/Twitter, Reddit, TikTok, YouTube: name the exact report path. "
    "5) Non-consensual intimate imagery (NCII): StopNCII.org (adults, hash-based proactive blocking across Meta/TikTok/Bumble/Reddit), "
    "and NCMEC 'Take It Down' for anyone who was a minor. "
    "6) Helplines & legal: India — cybercrime.gov.in and helpline 1930; also mention reporting to local police and preserving evidence (screenshots, URLs, timestamps). "
    "Be supportive and practical, include the real URLs, and keep it under ~380 words. Never victim-blame."
)


@router.post("/takedown-advise")
async def takedown_advise(data: TakedownInput):
    prompt = f"SITUATION: {data.description}"
    if data.where:
        prompt += f"\nWHERE IT APPEARS: {data.where}"
    try:
        answer = await ai.complete("takedown", TAKEDOWN_SYSTEM, prompt)
    except Exception:
        raise HTTPException(status_code=502, detail="Advisor temporarily unavailable.")
    return {"answer": answer}


# ============================================================================
# USERNAME
# ============================================================================
class UsernameInput(BaseModel):
    username: str = Field(min_length=2)


USERNAME_SITES = [
    ("GitHub", "https://github.com/{u}"),
    ("GitLab", "https://gitlab.com/{u}"),
    ("Reddit", "https://www.reddit.com/user/{u}"),
    ("Instagram", "https://www.instagram.com/{u}/"),
    ("Twitter/X", "https://x.com/{u}"),
    ("TikTok", "https://www.tiktok.com/@{u}"),
    ("YouTube", "https://www.youtube.com/@{u}"),
    ("Twitch", "https://www.twitch.tv/{u}"),
    ("Telegram", "https://t.me/{u}"),
    ("Medium", "https://medium.com/@{u}"),
    ("Dev.to", "https://dev.to/{u}"),
    ("Pinterest", "https://www.pinterest.com/{u}/"),
    ("Steam", "https://steamcommunity.com/id/{u}"),
    ("Keybase", "https://keybase.io/{u}"),
    ("Replit", "https://replit.com/@{u}"),
    ("Dribbble", "https://dribbble.com/{u}"),
]


def _check_site(args):
    name, tmpl, username = args
    url = tmpl.format(u=username)
    try:
        r = requests.get(url, timeout=8, headers=UA, allow_redirects=True)
        code = r.status_code
        if code == 200:
            status = "found"
        elif code in (404, 410):
            status = "not found"
        else:
            status = "unknown"
        return {"site": name, "url": url, "status": status, "http": code}
    except Exception:
        return {"site": name, "url": url, "status": "error", "http": None}


def _username_intel(username: str) -> dict:
    import concurrent.futures
    args = [(n, t, username) for n, t in USERNAME_SITES]
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
        results = list(ex.map(_check_site, args))
    found = [r for r in results if r["status"] == "found"]
    return {"username": username, "checked": len(results), "found_count": len(found),
            "results": results}


@router.post("/username")
async def osint_username(data: UsernameInput):
    u = data.username.strip().lstrip("@")
    if not re.match(r"^[A-Za-z0-9_.\-]{2,40}$", u):
        raise HTTPException(status_code=400, detail="Invalid username (letters, numbers, _ . - only)")
    loop = asyncio.get_event_loop()
    intel = await loop.run_in_executor(None, _username_intel, u)
    return await _save("username", u, intel)


# ============================================================================
# HISTORY
# ============================================================================
@router.get("/history")
async def history():
    return await db.osint_lookups.find({}, {"_id": 0}).sort("created_at", -1).to_list(100)


@router.delete("/history/{lookup_id}")
async def delete_lookup(lookup_id: str):
    res = await db.osint_lookups.delete_one({"id": lookup_id})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Not found")
    return {"message": "deleted"}


# ============================================================================
# IMEI (device intelligence via imei.info — reuses toolkit checker, persists to case)
# ============================================================================
class ImeiInput(BaseModel):
    imei: str = Field(min_length=6)
    service_id: int = 0


@router.post("/imei")
async def osint_imei(data: ImeiInput):
    from routers.toolkit import _imei_check
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, _imei_check, data.imei, data.service_id)
    return await _save("imei", data.imei.strip(), result)


# ============================================================================
# CASE REPORT — combined PDF dossier
# ============================================================================
class DossierInput(BaseModel):
    lookup_ids: list[str] = []


def _build_dossier(lookups: list) -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.units import mm
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable)

    buf = io.BytesIO()
    d = SimpleDocTemplate(buf, pagesize=A4, topMargin=18 * mm, bottomMargin=16 * mm,
                          leftMargin=16 * mm, rightMargin=16 * mm, title="InsafeLabs OSINT Dossier")
    styles = getSampleStyleSheet()
    H = ParagraphStyle("H", parent=styles["Title"], textColor=colors.HexColor("#111111"), fontSize=22)
    sub = ParagraphStyle("sub", parent=styles["Normal"], textColor=colors.HexColor("#666666"), fontSize=9)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], textColor=colors.HexColor("#111111"), spaceBefore=10)
    body = ParagraphStyle("body", parent=styles["Normal"], fontSize=9.5, leading=14)
    small = ParagraphStyle("small", parent=styles["Normal"], fontSize=8.5, textColor=colors.HexColor("#333333"), leading=12)
    el = []

    def esc(v):
        return str(v).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def kv(rows):
        rows = [[k, Paragraph(esc(v), small)] for k, v in rows if v not in (None, "", [])]
        if not rows:
            return
        t = Table(rows, colWidths=[42 * mm, None])
        t.setStyle(TableStyle([("FONTSIZE", (0, 0), (-1, -1), 8.5),
                               ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#666666")),
                               ("VALIGN", (0, 0), (-1, -1), "TOP"),
                               ("BOTTOMPADDING", (0, 0), (-1, -1), 3), ("TOPPADDING", (0, 0), (-1, -1), 3),
                               ("LINEBELOW", (0, 0), (-1, -2), 0.4, colors.HexColor("#DDDDDD"))]))
        el.append(t)

    el.append(Paragraph("InsafeLabs — OSINT Investigation Dossier", H))
    el.append(Paragraph(f"Compiled {datetime.now(timezone.utc).isoformat()[:19].replace('T', ' ')} UTC · "
                        f"{len(lookups)} lookup(s)", sub))
    el.append(Spacer(1, 6))
    el.append(HRFlowable(width="100%", color=colors.HexColor("#FACC15"), thickness=2))
    el.append(Spacer(1, 8))

    for lk in lookups:
        kind = lk.get("kind"); r = lk.get("result") or {}
        el.append(Paragraph(f"{kind.upper()} — {esc(lk.get('query'))}", h2))
        if kind == "email":
            m = r.get("mail") or {}; g = r.get("gravatar") or {}
            kv([("Domain", r.get("domain")), ("Mail provider", m.get("provider")),
                ("MX records", ", ".join(m.get("mx") or [])), ("SPF", m.get("spf") or "MISSING"),
                ("Gravatar", "found" if g.get("exists") else "none"),
                ("Gravatar name", (g.get("profile") or {}).get("display_name") if g.get("profile") else None)])
            if r.get("ai_summary"):
                el.append(Spacer(1, 4)); el.append(Paragraph("<b>Analyst summary:</b> " + esc(r["ai_summary"]), body))
        elif kind == "phone":
            f = r.get("formats") or {}
            kv([("Valid", r.get("valid")), ("Region", r.get("region")), ("Country code", r.get("country_code")),
                ("Carrier", r.get("carrier")), ("Line type", r.get("line_type")),
                ("Timezones", ", ".join(r.get("timezones") or [])), ("E.164", f.get("e164"))])
        elif kind == "image":
            meta = r.get("metadata") or {}; ex = r.get("exif") or {}; gps = r.get("gps") or {}
            kv([("Image URL", r.get("image_url")),
                ("Dimensions", f"{meta.get('width')}x{meta.get('height')}" if meta else None),
                ("Camera", f"{ex.get('Make', '')} {ex.get('Model', '')}".strip() or None),
                ("Taken", ex.get("DateTime")),
                ("GPS", f"{gps.get('lat')}, {gps.get('lon')}" if gps else None)])
            if r.get("ai_analysis"):
                el.append(Spacer(1, 4)); el.append(Paragraph("<b>Vision analysis:</b> " + esc(r["ai_analysis"]), body))
        elif kind == "reverse-image":
            c = r.get("counts") or {}
            kv([("Source", r.get("source")),
                ("Pages with this image", c.get("pages")),
                ("Exact matches", c.get("full")), ("Partial matches", c.get("partial")),
                ("Visually similar", c.get("similar")),
                ("Best guess", ", ".join(r.get("best_guess") or [])),
                ("Top pages", ", ".join([p.get("url") for p in (r.get("pages") or [])[:5] if p.get("url")]))])
        elif kind == "username":
            found = [x["site"] for x in (r.get("results") or []) if x.get("status") == "found"]
            kv([("Username", r.get("username")), ("Checked", r.get("checked")),
                ("Likely present", f"{r.get('found_count')} sites"), ("Sites", ", ".join(found) or "none")])
        elif kind == "imei":
            rr = r.get("result") or {}
            kv([("IMEI", r.get("imei")), ("Service", r.get("service")), ("Status", r.get("status")),
                ("Brand", rr.get("brand_name") or rr.get("manufacturer")),
                ("Model", rr.get("model") or rr.get("model_name")),
                ("Blacklist status", rr.get("blacklist_status")),
                ("Device clean", rr.get("device_is_clean"))])
        el.append(Spacer(1, 8))

    el.append(HRFlowable(width="100%", color=colors.HexColor("#DDDDDD"), thickness=0.5))
    el.append(Paragraph("Generated by InsafeLabs OSINT Investigator · Authorized use only", small))
    d.build(el)
    return buf.getvalue()


@router.post("/report")
async def dossier(data: DossierInput):
    if data.lookup_ids:
        lookups = await db.osint_lookups.find({"id": {"$in": data.lookup_ids}}, {"_id": 0}).to_list(200)
        order = {i: n for n, i in enumerate(data.lookup_ids)}
        lookups.sort(key=lambda x: order.get(x.get("id"), 999))
    else:
        lookups = await db.osint_lookups.find({}, {"_id": 0}).sort("created_at", -1).to_list(50)
    if not lookups:
        raise HTTPException(status_code=404, detail="No lookups to compile. Run an investigation first.")
    pdf = _build_dossier(lookups)
    return Response(content=pdf, media_type="application/pdf",
                    headers={"Content-Disposition": 'attachment; filename="InsafeLabs-OSINT-Dossier.pdf"'})
