"""InsafeLabs Red Team Ops — AI advisor, phishing-simulation generator, cloud exposure checker,
APK static analysis. Authorized assessments only. No live weaponization."""
import io
import json
import re
import uuid
import zipfile
import tempfile
import os
import asyncio
from datetime import datetime, timezone

import requests
from fastapi import APIRouter, HTTPException, UploadFile, File
from pydantic import BaseModel, Field

from db import db
import ai
import recon_lib
from netguard import guard_url

router = APIRouter(prefix="/redteam", tags=["redteam"])

UA = {"User-Agent": "Mozilla/5.0 (compatible; InsafeLabs-RedTeam/1.0; authorized-assessment)"}


def _now():
    return datetime.now(timezone.utc).isoformat()


def severity_from_cvss(c):
    return recon_lib.severity_from_cvss(c)


# ============================================================================
# AI RED-TEAM ADVISOR (all domains)
# ============================================================================
class AdvisorInput(BaseModel):
    domain: str = Field(min_length=2)
    question: str = Field(min_length=3)


ADVISOR_SYSTEM = (
    "You are InsafeLabs Red-Team Advisor, an expert offensive-security consultant supporting AUTHORIZED, "
    "scoped operations (client authorization is assumed). Given a red-team DOMAIN and a QUESTION, give "
    "concise, practical, professional guidance: recommended assessment techniques mapped to MITRE ATT&CK "
    "IDs where relevant, tooling, a safe step-by-step methodology, common pitfalls, and blue-team "
    "detection/mitigation notes. Formatting: short markdown with headers and bullets. "
    "STRICT SAFETY: never output functional malware, working exploit code, real credential-harvesting "
    "pages, or instructions to attack systems the operator is not authorized to test. Keep the focus on "
    "methodology, findings, and defensive value. Keep the entire answer under ~320 words — be dense and practical."
)


@router.post("/advisor")
async def advisor(data: AdvisorInput):
    prompt = f"DOMAIN: {data.domain}\nQUESTION: {data.question}"
    try:
        answer = await ai.complete(f"redteam-advisor-{data.domain}", ADVISOR_SYSTEM, prompt)
    except Exception:
        raise HTTPException(status_code=502, detail="Advisor is temporarily unavailable, try again.")
    return {"domain": data.domain, "answer": answer}


# ============================================================================
# PHISHING SIMULATION GENERATOR (authorized awareness campaigns)
# ============================================================================
class PhishInput(BaseModel):
    scenario: str = "IT Support"
    company: str = "Acme Corp"
    role: str = "Employee"
    difficulty: str = "medium"


PHISH_SYSTEM = (
    "You are InsafeLabs Red-Team, crafting a phishing SIMULATION email for an AUTHORIZED security-awareness "
    "exercise (the client has signed written authorization). Return STRICT JSON only: "
    '{"subject": str, "sender_display": str, "preheader": str, "body_text": str, '
    '"red_flags": [str], "teachable_moment": str, "pretext": str}. '
    "The body_text MUST begin with the line '[SIMULATION — AUTHORIZED AWARENESS TEST]'. "
    "Use only https://example.com/ placeholder links — NEVER real or working credential-harvesting URLs. "
    "Make it realistic enough to train employees for the given scenario/company/role/difficulty, but it "
    "must remain a training drill. red_flags = the tells that should make a user suspicious."
)


@router.post("/phishing")
async def phishing(data: PhishInput):
    prompt = (f"scenario={data.scenario}; company={data.company}; target_role={data.role}; "
              f"difficulty={data.difficulty}. Generate the authorized simulation email.")
    try:
        raw = await ai.complete("redteam-phish", PHISH_SYSTEM, prompt)
        parsed = ai.parse_json(raw)
    except Exception:
        raise HTTPException(status_code=502, detail="Generator temporarily unavailable, try again.")
    parsed["_disclaimer"] = "For authorized security-awareness simulation only. Not for real phishing."
    return parsed


# ============================================================================
# CLOUD EXPOSURE CHECKER (S3 / GCS public bucket misconfig)
# ============================================================================
class CloudInput(BaseModel):
    target: str = Field(min_length=2)


KEY_RE = re.compile(r"<Key>([^<]+)</Key>")


def _bucket_name(target: str) -> str:
    t = target.strip().rstrip("/")
    t = re.sub(r"^https?://", "", t)
    for suf in [".s3.amazonaws.com", ".s3.us-east-1.amazonaws.com"]:
        if t.endswith(suf):
            return t[: -len(suf)]
    if t.startswith("s3.amazonaws.com/"):
        return t.split("/", 1)[1].split("/")[0]
    if t.startswith("storage.googleapis.com/"):
        return t.split("/", 1)[1].split("/")[0]
    return t.split("/")[0]


def _s3_fetch(url: str):
    try:
        r = requests.get(url, timeout=10, headers=UA, allow_redirects=True)
        body = r.text[:20000]
        if "PermanentRedirect" in body:
            m = re.search(r"<Endpoint>([^<]+)</Endpoint>", body)
            if m:
                r = requests.get(f"http://{m.group(1)}/", timeout=10, headers=UA)
                body = r.text[:20000]
        return r.status_code, body
    except Exception as e:
        return None, f"__error__:{str(e)[:60]}"


def _cloud_scan(target: str) -> dict:
    name = _bucket_name(target)
    providers = [
        ("AWS S3", f"https://s3.amazonaws.com/{name}/"),
        ("Google Cloud Storage", f"https://storage.googleapis.com/{name}/"),
    ]
    checks, findings = [], []
    for label, url in providers:
        entry = {"provider": label, "url": url, "state": "unknown", "objects": []}
        code, body = _s3_fetch(url)
        if code is None or body.startswith("__error__:"):
            entry["state"] = "error: " + body.replace("__error__:", "")
        elif code == 200 and ("ListBucketResult" in body or "<Contents>" in body):
            entry["state"] = "PUBLIC LISTING"
            keys = KEY_RE.findall(body)[:15]
            entry["objects"] = keys
            findings.append(recon_lib.mk(
                f"Publicly listable cloud bucket ({label})", 7.5,
                "Cloud Misconfiguration / CWE-732",
                f"{url} allows anonymous object listing. Sample keys: {', '.join(keys[:6]) or 'n/a'}",
                "Disable public/anonymous access; enforce bucket-owner-only ACLs and block public access.",
                label))
        elif code == 403 or "AccessDenied" in body or "Access denied" in body.lower():
            entry["state"] = "exists (private / access denied)"
        elif code == 404 or "NoSuchBucket" in body or "does not exist" in body.lower():
            entry["state"] = "not found"
        else:
            entry["state"] = f"http {code}"
        checks.append(entry)

    max_cvss = max([f["cvss"] for f in findings], default=0.0)
    return {
        "id": str(uuid.uuid4()), "target": target, "bucket": name, "checks": checks,
        "findings": findings, "finding_count": len(findings),
        "posture": severity_from_cvss(max_cvss) if max_cvss else "info",
        "created_at": _now(),
    }


@router.post("/cloud")
async def cloud(data: CloudInput):
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, _cloud_scan, data.target)
    await db.cloud_scans.insert_one(dict(result))
    result.pop("_id", None)
    return result


# ============================================================================
# APK STATIC ANALYSIS (mini-MobSF: manifest + secrets + URLs)
# ============================================================================
DANGEROUS_PERMS = {
    "SEND_SMS": 6.5, "READ_SMS": 6.5, "RECEIVE_SMS": 6.5, "READ_CONTACTS": 5.3,
    "WRITE_CONTACTS": 5.3, "ACCESS_FINE_LOCATION": 5.3, "ACCESS_BACKGROUND_LOCATION": 6.5,
    "RECORD_AUDIO": 6.5, "CAMERA": 5.3, "READ_CALL_LOG": 6.5, "READ_PHONE_STATE": 4.3,
    "READ_EXTERNAL_STORAGE": 4.0, "WRITE_EXTERNAL_STORAGE": 4.0, "SYSTEM_ALERT_WINDOW": 5.3,
    "REQUEST_INSTALL_PACKAGES": 6.5, "QUERY_ALL_PACKAGES": 4.0, "MANAGE_EXTERNAL_STORAGE": 6.5,
}
SCAN_EXT = (".xml", ".json", ".js", ".properties", ".txt", ".html", ".cfg", ".ini",
            ".yml", ".yaml", ".env", ".gradle", ".kt", ".java", ".smali")
_URL_RE = re.compile(r"https?://[a-zA-Z0-9\.\-]+(?:/[a-zA-Z0-9_\-/\.\?=&%]{0,90})?")
_STR_RE = re.compile(rb"[\x20-\x7e]{6,}")


def _scan_text(text, source, secrets, urls):
    for name, cvss, pat in recon_lib.SECRET_PATTERNS:
        m = pat.search(text)
        if m:
            secrets.append({"type": name, "source": source,
                            "match": recon_lib._redact(m.group(0)), "cvss": cvss})
    for u in _URL_RE.findall(text):
        if not any(x in u for x in ["schemas.android", "w3.org", "apache.org", "googleapis.com/auth",
                                     "example.com", "android.com"]):
            urls.add(u)


TRACKERS = {
    "com.google.android.gms.ads": "Google AdMob", "com.google.firebase": "Firebase",
    "com.facebook": "Facebook SDK", "com.flurry": "Flurry", "com.appsflyer": "AppsFlyer",
    "com.adjust.sdk": "Adjust", "io.branch": "Branch", "com.mixpanel": "Mixpanel",
    "com.amplitude": "Amplitude", "com.crashlytics": "Crashlytics", "com.unity3d.ads": "Unity Ads",
    "com.mopub": "MoPub", "com.chartboost": "Chartboost", "com.applovin": "AppLovin",
    "com.ironsource": "ironSource", "com.onesignal": "OneSignal", "com.segment": "Segment",
    "com.yandex.metrica": "Yandex Metrica", "com.umeng": "Umeng", "com.bytedance": "ByteDance/Pangle",
    "com.startapp": "StartApp", "com.inmobi": "InMobi", "com.vungle": "Vungle",
}

SPYWARE_PERMS = {"SEND_SMS", "READ_SMS", "RECEIVE_SMS", "READ_CALL_LOG", "RECORD_AUDIO",
                 "CAMERA", "ACCESS_FINE_LOCATION", "READ_CONTACTS", "ACCESS_BACKGROUND_LOCATION"}


def _cert_info(apkobj):
    out = []
    if not apkobj:
        return out
    try:
        certs = apkobj.get_certificates() or []
    except Exception:
        certs = []
    for c in certs:
        try:
            subj = c.subject.human_friendly
        except Exception:
            subj = ""
        try:
            iss = c.issuer.human_friendly
        except Exception:
            iss = ""
        try:
            nb = c["tbs_certificate"]["validity"]["not_before"].native
            na = c["tbs_certificate"]["validity"]["not_after"].native
            vf = nb.isoformat() if nb else None
            vt = na.isoformat() if na else None
        except Exception:
            vf = vt = None
        try:
            sha256 = c.sha256.hex()
        except Exception:
            sha256 = None
        try:
            serial = str(c.serial_number)
        except Exception:
            serial = None
        out.append({
            "subject": subj, "issuer": iss, "serial": serial, "sha256": sha256,
            "valid_from": vf, "valid_to": vt,
            "is_debug": "Android Debug" in (subj or ""),
            "self_signed": bool(subj) and subj == iss,
        })
    return out


def _categorize_urls(urls):
    api, docs, other, domains = [], [], [], set()
    for u in urls:
        host = re.sub(r"^https?://", "", u).split("/")[0]
        domains.add(host)
        lu = u.lower()
        if any(k in lu for k in ["/api", "api.", "/graphql", "/v1/", "/v2/", "/v3/", "/rest", "/gateway"]):
            api.append(u)
        elif any(k in lu for k in ["swagger", "/docs", "readme", "openapi", "postman", "apidoc"]):
            docs.append(u)
        else:
            other.append(u)
    return {"api": api[:50], "docs": docs[:20], "other": other[:50], "domains": sorted(domains)[:50]}


def _verdict(info, flags, certs, dperms, manifest_xml, secret_count, max_cvss=0.0):
    reasons, score = [], 0
    perms = set(dperms)
    if flags.get("debuggable"):
        score += 15; reasons.append("Debuggable release build (debugger can attach)")
    if flags.get("cleartext_traffic"):
        score += 8; reasons.append("Allows cleartext HTTP traffic")
    if flags.get("allow_backup"):
        score += 4; reasons.append("Android backup allowed")
    if any(c.get("is_debug") for c in certs):
        score += 12; reasons.append("Signed with a DEBUG certificate — not a Play-Store / official build")
    elif certs and all(c.get("self_signed") for c in certs):
        score += 3; reasons.append("Self-signed certificate (normal for sideloaded apps)")
    sms = {"SEND_SMS", "READ_SMS", "RECEIVE_SMS"} & perms
    if sms:
        score += 15; reasons.append("SMS access: " + ", ".join(sorted(sms)) + " (SMS-trojan pattern)")
    if "READ_CALL_LOG" in perms:
        score += 8; reasons.append("Reads call log")
    if "RECORD_AUDIO" in perms and "CAMERA" in perms:
        score += 12; reasons.append("Mic + camera access (surveillance-capable)")
    if "REQUEST_INSTALL_PACKAGES" in perms:
        score += 12; reasons.append("Can install other apps (dropper capability)")
    if "SYSTEM_ALERT_WINDOW" in perms:
        score += 8; reasons.append("Draws overlays (tapjacking / overlay-phishing risk)")
    if manifest_xml:
        if "BIND_ACCESSIBILITY_SERVICE" in manifest_xml:
            score += 18; reasons.append("Uses Accessibility Service (high-abuse: reads screen / auto-clicks)")
        if "BIND_DEVICE_ADMIN" in manifest_xml:
            score += 12; reasons.append("Requests Device Admin (can lock/wipe device)")
    if max_cvss >= 9:
        score += 20; reasons.append("Critical hardcoded secret / live API key embedded (e.g. AWS/Stripe live)")
    elif max_cvss >= 7:
        score += 10; reasons.append("High-severity hardcoded secret embedded")
    elif secret_count:
        score += 4; reasons.append(f"{secret_count} hardcoded secret(s) embedded")
    if score >= 45:
        level, label = "high", "HIGH RISK — behaves like malware / spyware"
    elif score >= 22:
        level, label = "suspicious", "Suspicious — review carefully before trusting"
    elif score >= 8:
        level, label = "low", "Low risk — minor security issues"
    else:
        level, label = "clean", "Looks clean / standard app"
    if not reasons:
        reasons.append("No high-risk indicators detected.")
    return {"level": level, "label": label, "score": min(100, score), "reasons": reasons}


def _analyze_apk(content: bytes) -> dict:
    if not content or content[:2] != b"PK":
        raise HTTPException(status_code=400, detail="Not a valid APK/ZIP file")
    tmp = tempfile.NamedTemporaryFile(suffix=".apk", delete=False)
    try:
        tmp.write(content)
        tmp.close()
        info = {"package": None, "app_name": None, "version_name": None, "version_code": None,
                "min_sdk": None, "target_sdk": None, "main_activity": None, "permissions": []}
        components = {"activities": [], "services": [], "receivers": [], "providers": []}
        manifest_xml = ""
        apkobj = None
        try:
            from pyaxmlparser import APK
            a = APK(tmp.name)
            apkobj = a
            info["package"] = a.package
            info["version_name"] = a.version_name
            info["version_code"] = a.version_code
            try: info["app_name"] = a.get_app_name()
            except Exception: pass
            try: info["main_activity"] = a.get_main_activity()
            except Exception: pass
            try:
                info["permissions"] = sorted(set(a.permissions or []))
            except Exception:
                info["permissions"] = []
            try:
                info["min_sdk"] = a.get_min_sdk_version()
                info["target_sdk"] = a.get_target_sdk_version() or a.get_effective_target_sdk_version()
            except Exception:
                pass
            for key, fn in (("activities", "get_activities"), ("services", "get_services"),
                            ("receivers", "get_receivers"), ("providers", "get_providers")):
                try:
                    components[key] = sorted(set(getattr(a, fn)() or []))
                except Exception:
                    components[key] = []
            try:
                manifest_xml = a.get_android_manifest_axml().get_xml().decode("utf-8", "ignore")
            except Exception:
                manifest_xml = ""
        except Exception:
            pass

        secrets, urls, trackers = [], set(), set()
        seen = set()
        scanned = 0
        files_summary = {"total": 0, "dex": 0, "native_libs": 0, "abis": [], "assets": 0,
                         "has_native": False, "top_files": []}
        try:
            with zipfile.ZipFile(tmp.name) as z:
                infos = z.infolist()
                names = [i.filename for i in infos]
                so_files = [n for n in names if n.lower().endswith(".so")]
                abis = sorted(set(n.split("/")[1] for n in so_files if n.startswith("lib/") and len(n.split("/")) > 2))
                files_summary = {
                    "total": len(names),
                    "dex": sum(1 for n in names if n.lower().endswith(".dex")),
                    "native_libs": len(so_files),
                    "abis": abis,
                    "assets": sum(1 for n in names if n.startswith("assets/")),
                    "has_native": bool(so_files),
                    "top_files": [{"name": i.filename, "size_kb": round(i.file_size / 1024, 1)}
                                  for i in sorted(infos, key=lambda x: x.file_size, reverse=True)[:12]],
                }
                for nm in names:
                    low = nm.lower()
                    is_dex = low.endswith(".dex")
                    if not (is_dex or low.endswith(SCAN_EXT)):
                        continue
                    if scanned > 45 * 1024 * 1024:
                        break
                    try:
                        with z.open(nm) as fh:
                            data = fh.read(8 * 1024 * 1024)
                    except Exception:
                        continue
                    scanned += len(data)
                    if is_dex:
                        text = b"\n".join(_STR_RE.findall(data)).decode("utf-8", "ignore")
                        for pref, tname in TRACKERS.items():
                            if pref in text:
                                trackers.add(tname)
                    else:
                        text = data.decode("utf-8", "ignore")
                    src = nm.split("/")[-1] or nm
                    _scan_text(text, src, secrets, urls)
        except Exception:
            pass

        uniq = []
        for s in secrets:
            k = (s["type"], s["match"])
            if k not in seen:
                seen.add(k)
                uniq.append(s)

        certs = _cert_info(apkobj)
        endpoints = _categorize_urls(urls)

        findings = []
        for s in uniq[:25]:
            findings.append(recon_lib.mk(
                f"Hardcoded secret in APK: {s['type']}", s["cvss"],
                "Insecure Data Storage / CWE-798",
                f"Found in {s['source']} (redacted): {s['match']}",
                "Remove hardcoded credentials; use server-side secrets and the Android Keystore.", s["source"]))

        dperms = [p.split(".")[-1] for p in info["permissions"] if p.split(".")[-1] in DANGEROUS_PERMS]
        if dperms:
            cvss = max(DANGEROUS_PERMS[p] for p in dperms)
            findings.append(recon_lib.mk(
                "Dangerous runtime permissions requested", cvss,
                "Excessive Permissions / CWE-250",
                "App requests sensitive permissions: " + ", ".join(sorted(set(dperms))),
                "Request only the minimum permissions required; justify each in the privacy review.", "manifest"))

        if any(c.get("is_debug") for c in certs):
            findings.append(recon_lib.mk(
                "Signed with a debug certificate", 5.0, "Code Signing / CWE-347",
                "The APK is signed by 'Android Debug' — it is not an official Play-Store build and may be repackaged.",
                "Only trust store-signed builds; verify the signing certificate against the vendor's known key.", "certificate"))
        if manifest_xml and "BIND_ACCESSIBILITY_SERVICE" in manifest_xml:
            findings.append(recon_lib.mk(
                "Declares an Accessibility Service", 7.0, "Privilege Abuse / CWE-250",
                "Accessibility services can read all on-screen content and perform actions — heavily abused by banking trojans.",
                "Only grant accessibility to fully trusted apps; review the service's purpose.", "manifest"))
        if "REQUEST_INSTALL_PACKAGES" in [p.split(".")[-1] for p in info["permissions"]]:
            findings.append(recon_lib.mk(
                "Can install other applications (dropper capability)", 6.5, "Malware Behaviour / CWE-250",
                "REQUEST_INSTALL_PACKAGES lets the app install further APKs — common dropper/loader behaviour.",
                "Verify why the app needs to install packages; treat as high-risk if unexpected.", "manifest"))

        flags = {}
        if manifest_xml:
            flags["debuggable"] = 'android:debuggable="true"' in manifest_xml or ':debuggable="true"' in manifest_xml
            flags["cleartext_traffic"] = ('usesCleartextTraffic="true"' in manifest_xml
                                          or 'cleartextTrafficPermitted="true"' in manifest_xml)
            flags["allow_backup"] = 'android:allowBackup="true"' in manifest_xml or ':allowBackup="true"' in manifest_xml
            flags["exported_components"] = manifest_xml.count(':exported="true"')
            if flags.get("debuggable"):
                findings.append(recon_lib.mk("App is debuggable in release", 7.4,
                    "Security Misconfiguration / CWE-489",
                    "android:debuggable=\"true\" — attackers can attach a debugger and extract data/runtime state.",
                    "Set android:debuggable=\"false\" for release builds.", "manifest"))
            if flags.get("cleartext_traffic"):
                findings.append(recon_lib.mk("Cleartext (HTTP) traffic permitted", 5.9,
                    "Insecure Communication / CWE-319",
                    "usesCleartextTraffic=\"true\" allows unencrypted HTTP — MITM / credential interception risk.",
                    "Disable cleartext traffic; enforce HTTPS and certificate pinning.", "manifest"))
            if flags.get("allow_backup"):
                findings.append(recon_lib.mk("Android backup allowed", 4.0,
                    "Insecure Data Storage / CWE-530",
                    "android:allowBackup=\"true\" lets adb backup extract app data on many devices.",
                    "Set android:allowBackup=\"false\" or exclude sensitive data from backup.", "manifest"))

        findings.sort(key=lambda f: f["cvss"], reverse=True)
        max_cvss = max([f["cvss"] for f in findings], default=0.0)
        verdict = _verdict(info, flags, certs, sorted(set(dperms)), manifest_xml, len(uniq), max_cvss)
        return {
            "id": str(uuid.uuid4()),
            "app": info,
            "components": components,
            "components_count": {k: len(v) for k, v in components.items()},
            "certificates": certs,
            "files": files_summary,
            "trackers": sorted(trackers),
            "flags": flags,
            "dangerous_permissions": sorted(set(dperms)),
            "secrets": uniq[:25],
            "endpoints": endpoints,
            "urls": sorted(urls)[:60],
            "verdict": verdict,
            "findings": findings,
            "finding_count": len(findings),
            "posture": severity_from_cvss(max_cvss) if max_cvss else "info",
            "size_kb": round(len(content) / 1024, 1),
            "created_at": _now(),
        }
    finally:
        try:
            os.unlink(tmp.name)
        except Exception:
            pass


async def _save_apk(result: dict) -> dict:
    await db.apk_scans.insert_one(dict(result))
    result.pop("_id", None)
    return result


class ApkUrlInput(BaseModel):
    apk_url: str = Field(min_length=5)


@router.post("/apk/url")
async def apk_url(data: ApkUrlInput):
    if not data.apk_url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="Provide a valid http(s) APK URL")
    guard_url(data.apk_url)
    try:
        r = requests.get(data.apk_url, timeout=45, headers=UA, stream=True)
        content = r.raw.read(160 * 1024 * 1024 + 1, decode_content=True)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Could not fetch APK: {str(e)[:120]}")
    if r.status_code != 200 or not content:
        raise HTTPException(status_code=400, detail="APK URL did not return a file")
    if len(content) > 160 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="APK too large (max 160MB)")
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, _analyze_apk, content)
    return await _save_apk(result)


@router.post("/apk/upload")
async def apk_upload(file: UploadFile = File(...)):
    content = await file.read()
    if len(content) > 160 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="APK too large (max 160MB)")
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, _analyze_apk, content)
    return await _save_apk(result)


@router.get("/apk/scans")
async def list_apk_scans():
    return await db.apk_scans.find({}, {"_id": 0}).sort("created_at", -1).to_list(50)
