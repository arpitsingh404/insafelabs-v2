"""InsafeLabs Offensive Modules — real hands-on tooling for authorized operations only.

  • Active Directory / LDAP enumeration (ldap3): RootDSE, naming contexts, users/groups/
    computers, AS-REP-roastable & Kerberoastable account flagging + AI attack advisor.
  • Network Mapper & Pivoting: async host-discovery + port/service map across a host/CIDR,
    a node/edge graph for the frontend, and an AI pivot-command advisor.
  • Binary Reverse-Engineering Assistant: ELF/PE/Mach-O triage — format/arch, entropy/packing,
    sections, imports, suspicious API calls, embedded strings/URLs/secrets, heuristic verdict + AI summary.

NOTE: the hosted backend only reaches the public internet — private ranges (10./192.168./172.16.)
are unreachable from the cloud and will show as down. No live weaponization.
"""
import io
import re
import math
import time
import uuid
import socket
import asyncio
import ipaddress
import struct
from datetime import datetime, timezone

from pathlib import Path

from fastapi import APIRouter, HTTPException, UploadFile, File, Body
from fastapi.responses import StreamingResponse, FileResponse
from pydantic import BaseModel, Field

from db import db
import ai
import recon_lib

router = APIRouter(prefix="/offensive", tags=["offensive"])

MAX_BIN = 40 * 1024 * 1024  # 40 MB upload cap
_STATIC_DIR = Path(__file__).resolve().parent.parent / "static"


def _now():
    return datetime.now(timezone.utc).isoformat()


@router.get("/gesture/local-script")
async def gesture_local_script():
    """Serve the native PC gesture-control Python script for download."""
    p = _STATIC_DIR / "local_gesture_control.py"
    if not p.exists():
        raise HTTPException(status_code=404, detail="script not found")
    return FileResponse(
        str(p),
        media_type="text/x-python",
        filename="insafelabs_pc_control.py",
    )


@router.get("/gesture/local-config")
async def gesture_local_config():
    """Serve the editable sample gesture config (JSON) for download."""
    p = _STATIC_DIR / "insafelabs_gestures.json"
    if not p.exists():
        raise HTTPException(status_code=404, detail="config not found")
    return FileResponse(
        str(p),
        media_type="application/json",
        filename="insafelabs_gestures.json",
    )


# ============================================================================
# 1) ACTIVE DIRECTORY / LDAP ENUMERATION
# ============================================================================
UAC_FLAGS = {
    0x0002: "DISABLED",
    0x0010: "LOCKOUT",
    0x0020: "PASSWD_NOTREQD",
    0x0200: "NORMAL_ACCOUNT",
    0x10000: "DONT_EXPIRE_PASSWORD",
    0x80000: "TRUSTED_FOR_DELEGATION",
    0x100000: "NOT_DELEGATED",
    0x400000: "DONT_REQ_PREAUTH",
}


class ADInput(BaseModel):
    host: str = Field(min_length=2)
    port: int = 389
    use_ssl: bool = False
    base_dn: str | None = None
    username: str | None = None
    password: str | None = None


def _sid_to_str(b):
    if b is None:
        return None
    if isinstance(b, str):
        return b if b.startswith("S-") else None
    try:
        rev = b[0]
        cnt = b[1]
        authority = int.from_bytes(b[2:8], "big")
        sid = f"S-{rev}-{authority}"
        for i in range(cnt):
            sid += "-" + str(int.from_bytes(b[8 + i * 4:12 + i * 4], "little"))
        return sid
    except Exception:
        return None


def _dn_to_fqdn(dn):
    parts = [p.strip()[3:] for p in (dn or "").split(",") if p.strip().lower().startswith("dc=")]
    return ".".join(parts).upper()


def _entry_dn(entry):
    try:
        return str(entry.entry_dn)
    except Exception:
        return None


def _ad_enumerate_sync(data: ADInput) -> dict:
    from ldap3 import Server, Connection, ALL, ANONYMOUS, SIMPLE, NTLM, SUBTREE
    from ldap3.core.exceptions import LDAPException

    out = {"host": data.host, "port": data.port, "reachable": False, "bound": False,
           "auth": "anonymous", "notes": []}
    try:
        server = Server(data.host, port=data.port, use_ssl=data.use_ssl, get_info=ALL, connect_timeout=8)
        if data.username:
            auth = NTLM if "\\" in data.username else SIMPLE
            out["auth"] = "ntlm" if auth == NTLM else "simple"
            conn = Connection(server, user=data.username, password=data.password or "",
                              authentication=auth, auto_bind=True, receive_timeout=12)
        else:
            conn = Connection(server, authentication=ANONYMOUS, auto_bind=True, receive_timeout=12)
        out["reachable"] = True
        out["bound"] = True
    except LDAPException as e:
        out["error"] = f"LDAP bind failed: {e}"
        out["reachable"] = "socket" not in str(e).lower()
        return out
    except Exception as e:
        out["error"] = f"Could not reach {data.host}:{data.port} — {e}"
        return out

    info = server.info
    ncs = [str(n) for n in (info.naming_contexts or [])] if info else []
    root = {}
    if info:
        try:
            for k in ("defaultNamingContext", "dnsHostName", "domainFunctionality",
                      "forestFunctionality", "domainControllerFunctionality",
                      "ldapServiceName", "serverName", "supportedSASLMechanisms"):
                v = getattr(info, "other", {}).get(k) if hasattr(info, "other") else None
                if v:
                    root[k] = v[0] if isinstance(v, list) and len(v) == 1 else v
        except Exception:
            pass
    out["naming_contexts"] = ncs
    out["rootdse"] = root

    base_dn = data.base_dn or root.get("defaultNamingContext") or (ncs[0] if ncs else "")
    out["base_dn"] = base_dn
    if not base_dn:
        out["notes"].append("No base DN available — AD usually blocks anonymous enumeration. Provide credentials or a base DN.")
        try: conn.unbind()
        except Exception: pass
        return out

    def _search(flt, attrs, cap=250):
        try:
            conn.search(base_dn, flt, SUBTREE, attributes=attrs, size_limit=cap)
            return list(conn.entries)
        except Exception as e:
            out["notes"].append(f"search {flt} failed: {e}")
            return []

    def _val(entry, attr):
        try:
            v = entry[attr].value
            return v
        except Exception:
            return None

    def _sid(e):
        return _sid_to_str(_val(e, "objectSid"))

    users, kerberoastable, asrep = [], [], []
    for e in _search("(&(objectClass=user)(objectCategory=person))",
                     ["sAMAccountName", "userPrincipalName", "userAccountControl",
                      "servicePrincipalName", "adminCount", "description", "memberOf",
                      "objectSid", "primaryGroupID"]):
        sam = _val(e, "sAMAccountName")
        uac = _val(e, "userAccountControl") or 0
        try: uac = int(uac)
        except Exception: uac = 0
        flags = [name for bit, name in UAC_FLAGS.items() if uac & bit]
        spn = _val(e, "servicePrincipalName")
        spn = spn if isinstance(spn, list) else ([spn] if spn else [])
        mof = _val(e, "memberOf")
        mof = mof if isinstance(mof, list) else ([mof] if mof else [])
        rec = {
            "sam": sam,
            "upn": _val(e, "userPrincipalName"),
            "admin": bool(_val(e, "adminCount")),
            "flags": flags,
            "desc": _val(e, "description"),
            "spn_count": len(spn),
            "spns": spn,
            "sid": _sid(e),
            "dn": _entry_dn(e),
            "primary_group_id": _val(e, "primaryGroupID"),
            "member_of": mof,
            "enabled": not bool(uac & 0x0002),
            "dontreqpreauth": bool(uac & 0x400000),
        }
        users.append(rec)
        if uac & 0x400000:
            asrep.append(sam)
        if spn and sam and sam.lower() != "krbtgt":
            kerberoastable.append({"sam": sam, "spns": spn[:4]})

    groups = []
    for e in _search("(objectClass=group)", ["cn", "sAMAccountName", "description", "adminCount", "member", "objectSid"]):
        mem = _val(e, "member")
        mem = mem if isinstance(mem, list) else ([mem] if mem else [])
        groups.append({"cn": _val(e, "cn"), "sam": _val(e, "sAMAccountName"),
                       "admin": bool(_val(e, "adminCount")), "desc": _val(e, "description"),
                       "sid": _sid(e), "dn": _entry_dn(e), "members": mem})

    computers = []
    for e in _search("(objectClass=computer)", ["cn", "sAMAccountName", "operatingSystem", "dNSHostName", "objectSid"]):
        computers.append({"cn": _val(e, "cn"), "sam": _val(e, "sAMAccountName"),
                          "os": _val(e, "operatingSystem"), "dns": _val(e, "dNSHostName"),
                          "sid": _sid(e), "dn": _entry_dn(e)})

    domain_fqdn = _dn_to_fqdn(base_dn)
    domain_sid = None
    for r in users + computers:
        if r.get("sid") and r["sid"].count("-") >= 6:
            domain_sid = r["sid"].rsplit("-", 1)[0]
            break

    out["domain_fqdn"] = domain_fqdn
    out["domain_sid"] = domain_sid
    out["counts"] = {"users": len(users), "groups": len(groups), "computers": len(computers),
                     "asrep_roastable": len(asrep), "kerberoastable": len(kerberoastable)}
    out["users"] = users[:150]
    out["groups"] = groups[:150]
    out["computers"] = computers[:150]
    out["asrep_roastable"] = asrep[:80]
    out["kerberoastable"] = kerberoastable[:80]
    try: conn.unbind()
    except Exception: pass
    return out


@router.post("/ad/enumerate")
async def ad_enumerate(data: ADInput):
    res = await asyncio.to_thread(_ad_enumerate_sync, data)
    return res


class ADAdviseInput(BaseModel):
    question: str = Field(min_length=3)
    context: str | None = None


AD_ADVISOR_SYSTEM = (
    "You are InsafeLabs AD Attack Advisor, an expert in AUTHORIZED Active Directory penetration testing. "
    "Given the operator's situation, give concise practical guidance mapped to MITRE ATT&CK: enumeration "
    "(ldapsearch, BloodHound/bloodhound-python, CrackMapExec/nxc), credential attacks (AS-REP roasting via "
    "impacket GetNPUsers.py, Kerberoasting via GetUserSPNs.py, password spraying), lateral movement "
    "(pass-the-hash, secretsdump.py, evil-winrm), and privesc paths (ACL abuse, delegation, DCSync). "
    "Provide the exact commands with placeholder values. Add blue-team detection notes. "
    "STRICT SAFETY: assume written authorization; never produce malware or attacks on unauthorized targets. "
    "Keep under ~320 words, dense markdown with headers/bullets and code blocks."
)


@router.post("/ad/advise")
async def ad_advise(data: ADAdviseInput):
    prompt = f"SITUATION: {data.question}"
    if data.context:
        prompt += f"\nCONTEXT: {data.context}"
    try:
        answer = await ai.complete("ad-advisor", AD_ADVISOR_SYSTEM, prompt)
    except Exception:
        raise HTTPException(status_code=502, detail="Advisor temporarily unavailable.")
    return {"answer": answer}


# ---- BloodHound export (SharpHound v4-compatible, best-effort) ----
def _build_bloodhound_zip(res: dict) -> bytes:
    import zipfile
    import json
    dom = res.get("domain_fqdn") or "DOMAIN"
    dsid = res.get("domain_sid")
    users = res.get("users", [])
    groups = res.get("groups", [])
    computers = res.get("computers", [])

    dn_map = {}
    for u in users:
        if u.get("dn"):
            dn_map[u["dn"].lower()] = (u.get("sid"), "User")
    for g in groups:
        if g.get("dn"):
            dn_map[g["dn"].lower()] = (g.get("sid"), "Group")
    for c in computers:
        if c.get("dn"):
            dn_map[c["dn"].lower()] = (c.get("sid"), "Computer")

    def _name(sam):
        return f"{(sam or '').upper()}@{dom}"

    users_data = []
    for u in users:
        pg = f"{dsid}-{u['primary_group_id']}" if dsid and u.get("primary_group_id") else None
        users_data.append({
            "Properties": {
                "name": _name(u.get("sam")), "domain": dom, "distinguishedname": u.get("dn"),
                "enabled": u.get("enabled", True), "dontreqpreauth": u.get("dontreqpreauth", False),
                "hasspn": bool(u.get("spn_count")), "admincount": u.get("admin", False),
                "description": u.get("desc"), "serviceprincipalnames": u.get("spns", []),
            },
            "ObjectIdentifier": u.get("sid") or _name(u.get("sam")),
            "PrimaryGroupSID": pg, "Aces": [], "SPNTargets": [], "HasSIDHistory": [],
            "AllowedToDelegate": [], "IsDeleted": False, "IsACLProtected": False,
        })

    groups_data = []
    for g in groups:
        members = []
        for dn in g.get("members", []):
            sid, typ = dn_map.get((dn or "").lower(), (None, None))
            if sid:
                members.append({"ObjectIdentifier": sid, "ObjectType": typ})
        groups_data.append({
            "Properties": {"name": _name(g.get("sam") or g.get("cn")), "domain": dom,
                           "distinguishedname": g.get("dn"), "admincount": g.get("admin", False),
                           "description": g.get("desc")},
            "ObjectIdentifier": g.get("sid") or _name(g.get("sam") or g.get("cn")),
            "Members": members, "Aces": [], "IsDeleted": False, "IsACLProtected": False,
        })

    computers_data = []
    for c in computers:
        computers_data.append({
            "Properties": {"name": (c.get("dns") or _name(c.get("sam") or c.get("cn"))), "domain": dom,
                           "distinguishedname": c.get("dn"), "operatingsystem": c.get("os")},
            "ObjectIdentifier": c.get("sid") or _name(c.get("sam") or c.get("cn")),
            "Aces": [], "Sessions": {"Results": [], "Collected": False},
            "LocalAdmins": {"Results": [], "Collected": False},
            "IsDeleted": False, "IsACLProtected": False,
        })

    domains_data = [{
        "Properties": {"name": dom, "domain": dom, "distinguishedname": res.get("base_dn")},
        "ObjectIdentifier": dsid or dom, "Aces": [], "Trusts": [], "Links": [],
        "ChildObjects": [], "IsDeleted": False, "IsACLProtected": False,
    }]

    files = {
        "users.json": {"data": users_data, "meta": {"methods": 0, "type": "users", "count": len(users_data), "version": 4}},
        "groups.json": {"data": groups_data, "meta": {"methods": 0, "type": "groups", "count": len(groups_data), "version": 4}},
        "computers.json": {"data": computers_data, "meta": {"methods": 0, "type": "computers", "count": len(computers_data), "version": 4}},
        "domains.json": {"data": domains_data, "meta": {"methods": 0, "type": "domains", "count": len(domains_data), "version": 4}},
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, obj in files.items():
            z.writestr(name, json.dumps(obj, indent=2, default=str))
    return buf.getvalue()


@router.post("/ad/bloodhound")
async def ad_bloodhound(data: ADInput):
    res = await asyncio.to_thread(_ad_enumerate_sync, data)
    if not res.get("bound"):
        raise HTTPException(status_code=400, detail=res.get("error") or "Bind failed — cannot export.")
    zip_bytes = await asyncio.to_thread(_build_bloodhound_zip, res)
    return StreamingResponse(io.BytesIO(zip_bytes), media_type="application/zip",
                             headers={"Content-Disposition": 'attachment; filename="insafelabs-bloodhound.zip"'})


# ---- SMB / share enumeration (pysmb, SMB2, null/guest/authenticated) ----
class SMBInput(BaseModel):
    host: str = Field(min_length=2)
    username: str | None = None
    password: str | None = None
    domain: str | None = ""


def _smb_enum_sync(data: SMBInput) -> dict:
    from smb.SMBConnection import SMBConnection
    out = {"host": data.host, "connected": False,
           "session": "authenticated" if data.username else "null/guest", "shares": [], "notes": []}
    conn = SMBConnection(data.username or "", data.password or "", "insafelabs", data.host,
                         domain=(data.domain or ""), use_ntlm_v2=True, is_direct_tcp=True)
    try:
        ok = conn.connect(data.host, 445, timeout=12)
        if not ok:
            out["error"] = "SMB session setup rejected (null/guest likely disabled)."
            return out
        out["connected"] = True
    except Exception as e:
        out["error"] = f"Could not connect to {data.host}:445 — {e}"
        return out
    try:
        shares = conn.listShares(timeout=15)
    except Exception as e:
        out["error"] = f"listShares failed: {str(e).splitlines()[0][:140]}"
        try: conn.close()
        except Exception: pass
        return out
    for sh in shares:
        entry = {"name": sh.name, "special": bool(sh.isSpecial), "comments": sh.comments,
                 "readable": False, "files": [], "file_count": 0}
        if not sh.isSpecial:
            try:
                items = conn.listPath(sh.name, "/", timeout=15)
                names = [i.filename for i in items if i.filename not in (".", "..")]
                entry["readable"] = True
                entry["files"] = names[:40]
                entry["file_count"] = len(names)
            except Exception as e:
                entry["error"] = str(e).splitlines()[0][:120]
        out["shares"].append(entry)
    try: conn.close()
    except Exception: pass
    if not out["shares"]:
        out["notes"].append("No shares enumerable — server may block null/guest sessions (modern Windows default).")
    return out


@router.post("/smb/enumerate")
async def smb_enumerate(data: SMBInput):
    return await asyncio.to_thread(_smb_enum_sync, data)


# ============================================================================
# 2) NETWORK MAPPER & PIVOTING
# ============================================================================
PORT_CATALOG = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP", 69: "TFTP",
    80: "HTTP", 88: "Kerberos", 110: "POP3", 111: "RPCbind", 123: "NTP", 135: "MSRPC",
    137: "NetBIOS", 139: "NetBIOS", 143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 500: "IKE-VPN", 514: "Syslog", 515: "LPD-Printer",
    548: "AFP", 554: "RTSP", 587: "SMTP-Sub", 631: "IPP-Printer", 636: "LDAPS",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 1723: "PPTP-VPN",
    1883: "MQTT", 2049: "NFS", 2082: "cPanel", 2375: "Docker", 3000: "Dev-HTTP",
    3306: "MySQL", 3389: "RDP", 4444: "Meterpreter", 5000: "UPnP/Dev", 5060: "SIP",
    5432: "PostgreSQL", 5555: "Android-ADB", 5601: "Kibana", 5900: "VNC", 5985: "WinRM",
    6379: "Redis", 7547: "TR-069-CPE", 8000: "HTTP-Dev", 8006: "Proxmox", 8080: "HTTP-Alt",
    8081: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt", 9000: "HTTP-Dev",
    9090: "Prometheus", 9100: "RAW-Printer", 9200: "Elasticsearch", 10000: "Webmin",
    11211: "Memcached", 27017: "MongoDB", 32400: "Plex", 49152: "UPnP",
}

PORT_PROFILES = {
    "quick": [80, 443, 22, 3389, 445, 8080, 21, 3306],
    "standard": [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 1433,
                 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017],
    "deep": sorted(PORT_CATALOG.keys()),
    "stealth": [80, 443, 22, 445, 3389, 8080, 21, 25, 23, 8443],
}
DISCOVERY_PORTS = [80, 443, 22, 445, 3389, 8080, 21, 25, 23, 3306]

PROFILE_TUNING = {
    "quick":    {"conc": 200, "timeout": 1.5, "banners": False},
    "standard": {"conc": 120, "timeout": 2.5, "banners": True},
    "deep":     {"conc": 80,  "timeout": 3.0, "banners": True},
    "stealth":  {"conc": 12,  "timeout": 4.0, "banners": True},
    "custom":   {"conc": 100, "timeout": 2.5, "banners": True},
}
MAX_NET_HOSTS = 64


class NetScanInput(BaseModel):
    target: str = Field(min_length=3)
    profile: str = "standard"       # quick | standard | deep | stealth | custom
    ports: str = ""                 # custom port spec, e.g. "22,80,8000-8100"
    neighborhood: bool = False      # expand a single IP to its /24 to map nearby devices
    rdns: bool = True
    banners: bool = True
    os_guess: bool = True


def _parse_ports(spec):
    out = set()
    for part in re.split(r"[,\s]+", (spec or "").strip()):
        if not part:
            continue
        if "-" in part:
            try:
                a, b = part.split("-", 1)
                for p in range(max(1, int(a)), min(65535, int(b)) + 1):
                    out.add(p)
            except Exception:
                pass
        else:
            try:
                out.add(int(part))
            except Exception:
                pass
    return sorted(p for p in out if 1 <= p <= 65535)[:200]


def _local_segments():
    """Backend's own reachable IPv4 addresses → /24 segments (server vantage point)."""
    segs, seen, addrs = [], set(), []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        addrs.append(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            addrs.append(info[4][0])
    except Exception:
        pass
    for ip in addrs:
        try:
            a = ipaddress.ip_address(ip)
            if a.is_loopback:
                continue
            net = ipaddress.ip_network(ip + "/24", strict=False)
            if str(net) not in seen:
                seen.add(str(net))
                segs.append({"ip": ip, "cidr": str(net), "private": a.is_private})
        except Exception:
            pass
    return segs


ROUTER_KW = ("mikrotik", "routeros", "cisco", "ubiquiti", "unifi", "dd-wrt", "openwrt",
             "pfsense", "fortigate", "fortinet", "draytek", "tp-link", "tplink", "netgear",
             "asuswrt", "huawei", "zyxel", "juniper", "sonicwall", "dlink", "d-link")
CAMERA_KW = ("rtsp", "hikvision", "dahua", "axis", "camera", "webcam", "ipcam", "nvr", "onvif")

# ---- device vendor detection + default-credential / access knowledge base (authorized testing) ----
VENDOR_KW = {
    "Hikvision": ("hikvision", "dvrdvs", "app-webs", "dnvrs", "hipcam"),
    "Dahua": ("dahua", "webdvr", "lechange"),
    "Axis": ("axis",),
    "Foscam": ("foscam",),
    "Reolink": ("reolink",),
    "Amcrest": ("amcrest",),
    "Vivotek": ("vivotek", "network camera"),
    "Bosch": ("bosch",),
    "Mikrotik": ("mikrotik", "routeros"),
    "Ubiquiti": ("ubiquiti", "unifi", "ubnt", "edgeos", "airos"),
    "TP-Link": ("tp-link", "tplink", "archer"),
    "Netgear": ("netgear",),
    "D-Link": ("d-link", "dlink"),
    "Cisco": ("cisco",),
    "pfSense": ("pfsense",),
    "Fortinet": ("fortigate", "fortinet"),
    "Zyxel": ("zyxel",),
    "Huawei": ("huawei", "hg8"),
    "Tomcat": ("tomcat", "coyote"),
}
CAM_VENDORS = {"Hikvision", "Dahua", "Axis", "Foscam", "Reolink", "Amcrest", "Vivotek", "Bosch"}
ROUTER_VENDORS = {"Mikrotik", "Ubiquiti", "TP-Link", "Netgear", "D-Link", "Cisco", "pfSense", "Fortinet", "Zyxel", "Huawei"}

CAM_CREDS = {
    "Hikvision": [("admin", "12345"), ("admin", ""), ("admin", "Admin12345"), ("admin", "admin12345")],
    "Dahua": [("admin", "admin"), ("888888", "888888"), ("666666", "666666"), ("admin", "")],
    "Axis": [("root", "pass"), ("root", "root"), ("admin", "admin")],
    "Foscam": [("admin", ""), ("admin", "foscam")],
    "Reolink": [("admin", "")],
    "Amcrest": [("admin", "admin")],
    "Vivotek": [("root", "")],
    "Bosch": [("service", "service")],
    "_generic": [("admin", "admin"), ("admin", "1234"), ("admin", "12345"), ("root", "root"), ("admin", ""), ("admin", "password")],
}
ROUTER_CREDS = {
    "Mikrotik": [("admin", "")],
    "Ubiquiti": [("ubnt", "ubnt")],
    "TP-Link": [("admin", "admin")],
    "Netgear": [("admin", "password"), ("admin", "1234")],
    "D-Link": [("admin", ""), ("admin", "admin")],
    "Cisco": [("cisco", "cisco"), ("admin", "admin")],
    "pfSense": [("admin", "pfsense")],
    "Fortinet": [("admin", "")],
    "Zyxel": [("admin", "1234"), ("supervisor", "zyad1234")],
    "Huawei": [("admin", "admin"), ("root", "admin"), ("telecomadmin", "admintelecom")],
    "_generic": [("admin", "admin"), ("admin", "password"), ("admin", ""), ("root", "root")],
}
SERVICE_CREDS = {
    3306: [("root", ""), ("root", "root"), ("root", "toor")],
    5432: [("postgres", "postgres"), ("postgres", "")],
    1433: [("sa", ""), ("sa", "sa")],
    23: [("admin", "admin"), ("root", "root"), ("admin", ""), ("root", "")],
    21: [("anonymous", ""), ("ftp", "ftp"), ("admin", "admin")],
    5900: [("", "<shared VNC password>")],
    10000: [("admin", "admin")],
    8080: [("tomcat", "tomcat"), ("admin", "admin")],
    5985: [("administrator", "<domain/local pw>")],
}
SERVICE_NOTES = {
    27017: "MongoDB is frequently exposed with NO authentication — try: mongosh mongodb://IP:27017",
    6379: "Redis is frequently exposed with NO authentication — try: redis-cli -h IP",
    9200: "Elasticsearch is often unauthenticated — try: curl http://IP:9200/_cat/indices",
    2375: "Docker API often exposed unauthenticated — try: docker -H tcp://IP:2375 ps",
    11211: "Memcached often unauthenticated — try: telnet IP 11211 then 'stats'",
    5555: "Android ADB open — try: adb connect IP:5555 && adb shell",
}
RTSP_PATHS = {
    "Hikvision": ["/Streaming/Channels/101", "/Streaming/Channels/102", "/h264/ch1/main/av_stream"],
    "Dahua": ["/cam/realmonitor?channel=1&subtype=0", "/cam/realmonitor?channel=1&subtype=1"],
    "Axis": ["/axis-media/media.amp", "/mpeg4/media.amp"],
    "Foscam": ["/videoMain", "/videoSub"],
    "Reolink": ["/h264Preview_01_main", "/h264Preview_01_sub"],
    "Amcrest": ["/cam/realmonitor?channel=1&subtype=0"],
    "Vivotek": ["/live.sdp"],
    "_generic": ["/", "/live", "/live.sdp", "/ch0", "/stream1", "/onvif1"],
}


def _detect_vendor(blob):
    for vendor, kws in VENDOR_KW.items():
        if any(k in blob for k in kws):
            return vendor
    return None



def _fingerprint(services, rdns):
    ports = {s["port"] for s in services}
    blob = (" ".join((s.get("banner") or "") for s in services) + " " + (rdns or "")).lower()

    def has(*ps):
        return any(p in ports for p in ps)

    tags = []
    if has(80, 443, 8080, 8443, 8000, 8888, 8081, 3000, 9000):
        tags.append("web")
    if has(3306, 5432, 1433, 27017, 6379, 9200, 1521, 11211):
        tags.append("database")
    if has(445, 139, 135, 3389, 5985):
        tags.append("windows")
    if has(22):
        tags.append("ssh")
    if has(25, 110, 143, 465, 587, 993, 995):
        tags.append("mail")
    if has(53):
        tags.append("dns")
    if has(161, 7547, 500, 1723, 1883, 5060):
        tags.append("network-infra")
    if has(631, 9100, 515):
        tags.append("printer")
    if has(554, 5000, 49152, 32400, 1883):
        tags.append("iot/media")
    if has(23):
        tags.append("telnet")

    dev = "Host"
    if any(k in blob for k in ROUTER_KW) or has(7547) or (has(161) and has(80, 443)):
        dev = "Router / Firewall"
    elif has(631, 9100, 515) or "jetdirect" in blob or "printer" in blob:
        dev = "Printer"
    elif has(554) or any(k in blob for k in CAMERA_KW):
        dev = "IP Camera / NVR"
    elif has(1883, 5000) or "mqtt" in blob:
        dev = "IoT Device"
    elif has(3306, 5432, 1433, 27017, 6379, 9200, 1521):
        dev = "Database Server"
    elif has(25, 110, 143, 587, 993):
        dev = "Mail Server"
    elif has(53) and not has(80, 443):
        dev = "DNS Server"
    elif has(3389) or has(445, 5985):
        dev = "Windows Machine"
    elif has(80, 443, 8080, 8443):
        dev = "Web Server"
    elif has(22):
        dev = "Linux / Unix Host"

    os_guess = "Unknown"
    if any(k in blob for k in ("ubuntu", "debian", "centos", "linux", "openssh", "nginx", "apache")):
        os_guess = "Linux"
    if "windows" in blob or "microsoft" in blob or "iis" in blob or has(3389, 5985) or has(135, 445):
        os_guess = "Windows"
    if any(k in blob for k in ("routeros", "openwrt", "dd-wrt", "vxworks", "busybox", "lighttpd")):
        os_guess = "Embedded / RTOS"

    vendor = _detect_vendor(blob)
    if vendor in CAM_VENDORS:
        dev = "IP Camera / NVR"
    elif vendor in ROUTER_VENDORS and dev in ("Host", "Web Server"):
        dev = "Router / Firewall"
    return {"device_type": dev, "os_guess": os_guess, "tags": tags, "vendor": vendor}


def _device_access(ip, services, device_type, vendor):
    ports = {s["port"] for s in services}
    access, creds_raw, notes, cmds = [], [], [], []
    is_cam = device_type == "IP Camera / NVR"
    is_router = device_type == "Router / Firewall"

    for p, scheme in ((443, "https"), (80, "http"), (8443, "https"), (8080, "http"), (8000, "http"), (10000, "http")):
        if p in ports:
            base = f"{scheme}://{ip}" + ("" if p in (80, 443) else f":{p}")
            access.append({"type": "Web UI", "url": base + "/", "note": "admin / login portal"})

    if is_cam or 554 in ports:
        paths = RTSP_PATHS.get(vendor, RTSP_PATHS["_generic"])
        for pth in paths[:4]:
            access.append({"type": "RTSP", "url": f"rtsp://{ip}:554{pth}", "note": f"{vendor or 'generic'} video stream"})
        cmds.append(f"ffplay -rtsp_transport tcp 'rtsp://USER:PASS@{ip}:554{paths[0]}'")
        cmds.append(f"hydra -s 554 -L users.txt -P pass.txt rtsp://{ip}")

    if is_cam:
        creds_raw += CAM_CREDS.get(vendor, CAM_CREDS["_generic"])
    if is_router:
        creds_raw += ROUTER_CREDS.get(vendor, ROUTER_CREDS["_generic"])
    for p in ports:
        creds_raw += SERVICE_CREDS.get(p, [])
        if p in SERVICE_NOTES:
            notes.append(SERVICE_NOTES[p].replace("IP", ip))
    if not creds_raw and (80 in ports or 443 in ports or 8080 in ports):
        creds_raw += [("admin", "admin"), ("admin", "password"), ("admin", "")]

    seen, creds = set(), []
    for u, pw in creds_raw:
        if (u, pw) in seen:
            continue
        seen.add((u, pw))
        creds.append({"user": u, "pass": pw})

    if 22 in ports: cmds.append(f"hydra -l root -P pass.txt ssh://{ip}")
    if 3389 in ports: cmds.append(f"xfreerdp /u:administrator /p:PASS /v:{ip}")
    if 445 in ports: cmds.append(f"crackmapexec smb {ip} -u users.txt -p pass.txt")
    if 3306 in ports: cmds.append(f"mysql -h {ip} -u root -p''")
    if 21 in ports: cmds.append(f"ftp {ip}   # try anonymous / anonymous")

    return {"vendor": vendor, "creds": creds[:14], "access": access[:12], "notes": notes[:8], "commands": cmds[:8]}


async def _tcp_open(host, port, timeout=2.5, grab_banner=True):
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        banner = ""
        if grab_banner:
            try:
                data = await asyncio.wait_for(reader.read(128), timeout=0.8)
                banner = data.decode("latin-1", "ignore").strip().split("\n")[0][:80]
            except Exception:
                pass
        writer.close()
        try: await asyncio.wait_for(writer.wait_closed(), timeout=1)
        except Exception: pass
        return True, banner
    except Exception:
        return False, ""


async def _scan_host(ip, ports, timeout, grab_banners, sem):
    async def one(p):
        async with sem:
            ok, banner = await _tcp_open(ip, p, timeout, grab_banners)
            return p, ok, banner
    results = await asyncio.gather(*[one(p) for p in ports])
    services = [{"port": p, "service": PORT_CATALOG.get(p, "unknown"), "banner": banner}
                for p, ok, banner in results if ok]
    services.sort(key=lambda s: s["port"])
    return services


def _expand_target(target: str, neighborhood=False, cap=MAX_NET_HOSTS):
    t = target.strip()
    hosts, note = [], None
    if "/" in t:
        net = ipaddress.ip_network(t, strict=False)
        allh = list(net.hosts()) if net.num_addresses > 2 else list(net)
        if len(allh) > cap:
            allh = allh[:cap]
            note = f"Range capped to first {cap} hosts."
        hosts = [str(h) for h in allh]
    else:
        try:
            ip = socket.gethostbyname(t)
        except Exception:
            ip = t
        if neighborhood and _is_ip(ip):
            net = ipaddress.ip_network(ip + "/24", strict=False)
            allh = [str(h) for h in net.hosts()][:cap]
            hosts = allh
            note = f"Neighborhood sweep: mapping {len(hosts)} nearby hosts in {net}."
        else:
            hosts = [ip]
    private = False
    try:
        private = any(ipaddress.ip_address(h).is_private for h in hosts if _is_ip(h))
    except Exception:
        pass
    return hosts, private, note


def _is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except Exception:
        return False


async def _perform_net_scan(scan_id, target, opts):
    profile = (opts.get("profile") or "standard").lower()
    tuning = PROFILE_TUNING.get(profile, PROFILE_TUNING["standard"])
    grab = bool(opts.get("banners", tuning["banners"])) and tuning["banners"]
    timeout = tuning["timeout"]
    conc = tuning["conc"]
    if profile == "custom":
        ports = _parse_ports(opts.get("ports", "")) or PORT_PROFILES["standard"]
    else:
        ports = PORT_PROFILES.get(profile, PORT_PROFILES["standard"])

    hosts, private, note = _expand_target(target, neighborhood=bool(opts.get("neighborhood")))
    notes = []
    if note:
        notes.append(note)
    if private:
        notes.append("Target is a PRIVATE/RFC1918 range — this cloud backend cannot reach your local LAN directly. "
                     "Results reflect the server's reachability. Use the Pivoting Advisor for reaching internal segments.")

    opt_summary = {"profile": profile, "port_count": len(ports),
                   "neighborhood": bool(opts.get("neighborhood")), "banners": grab}
    await db.network_scans.update_one({"id": scan_id}, {"$set": {
        "phase": "discovery", "progress": 20, "scanned": len(hosts), "options": opt_summary}})

    disc_sem = asyncio.Semaphore(conc)

    async def alive(ip):
        async with disc_sem:
            t0 = time.perf_counter()
            checks = await asyncio.gather(*[_tcp_open(ip, p, timeout, False) for p in DISCOVERY_PORTS])
            up = any(ok for ok, _ in checks)
            ms = int((time.perf_counter() - t0) * 1000) if up else None
            return ip, up, ms
    disc = await asyncio.gather(*[alive(h) for h in hosts])
    up_hosts = [(ip, ms) for ip, ok, ms in disc if ok]

    await db.network_scans.update_one({"id": scan_id}, {"$set": {
        "phase": "fingerprinting", "progress": 60, "hosts_up": len(up_hosts)}})

    host_records = []
    port_sem = asyncio.Semaphore(conc)
    for ip, ms in up_hosts:
        services = await _scan_host(ip, ports, timeout, grab, port_sem)
        rdns = ""
        if opts.get("rdns", True):
            try:
                rdns = await asyncio.to_thread(lambda i=ip: socket.gethostbyaddr(i)[0])
            except Exception:
                pass
        if opts.get("os_guess", True):
            fp = _fingerprint(services, rdns)
        else:
            fp = {"device_type": "Host", "os_guess": "Unknown", "tags": [], "vendor": None}
        access = _device_access(ip, services, fp["device_type"], fp.get("vendor"))
        host_records.append({"ip": ip, "rdns": rdns, "latency_ms": ms,
                             "services": services, "service_count": len(services),
                             "device_type": fp["device_type"], "os_guess": fp["os_guess"],
                             "tags": fp["tags"], "vendor": fp.get("vendor"), "access": access})
    host_records.sort(key=lambda h: h["service_count"], reverse=True)

    # build graph
    nodes = [{"id": "operator", "type": "operator", "label": "OPERATOR"}]
    edges = []
    for h in host_records:
        nid = f"host:{h['ip']}"
        nodes.append({"id": nid, "type": "host", "label": h["rdns"] or h["ip"], "ip": h["ip"],
                      "services": h["service_count"], "device_type": h["device_type"]})
        edges.append({"from": "operator", "to": nid})
        for s in h["services"]:
            sid = f"svc:{h['ip']}:{s['port']}"
            nodes.append({"id": sid, "type": "service", "label": f"{s['service']}:{s['port']}",
                          "port": s["port"], "service": s["service"], "banner": s["banner"]})
            edges.append({"from": nid, "to": sid})

    device_summary = {}
    for h in host_records:
        device_summary[h["device_type"]] = device_summary.get(h["device_type"], 0) + 1

    doc = {
        "id": scan_id, "target": target, "status": "completed", "phase": "done", "progress": 100,
        "scanned": len(hosts), "hosts_up": len(up_hosts),
        "hosts": host_records, "nodes": nodes, "edges": edges,
        "device_summary": device_summary, "options": opt_summary,
        "notes": notes, "created_at": _now(),
    }
    await db.network_scans.replace_one({"id": scan_id}, doc, upsert=True)


@router.post("/network/scan")
async def network_scan(data: NetScanInput):
    scan_id = str(uuid.uuid4())
    opts = {"profile": data.profile, "ports": data.ports, "neighborhood": data.neighborhood,
            "rdns": data.rdns, "banners": data.banners, "os_guess": data.os_guess}
    await db.network_scans.insert_one({
        "id": scan_id, "target": data.target, "status": "running",
        "phase": "queued", "progress": 5, "created_at": _now(),
    })

    async def _bg():
        try:
            await _perform_net_scan(scan_id, data.target, opts)
        except Exception as e:
            await db.network_scans.update_one({"id": scan_id}, {"$set": {"status": "failed", "error": str(e)[:200]}})

    asyncio.create_task(_bg())
    return {"id": scan_id, "status": "running"}


@router.get("/network/interfaces")
async def network_interfaces():
    """Backend's own reachable segments (server vantage) for one-click local-segment discovery."""
    return {"segments": _local_segments()}


@router.get("/network/scan/{scan_id}")
async def network_scan_get(scan_id: str):
    doc = await db.network_scans.find_one({"id": scan_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Scan not found")
    return doc


class PivotInput(BaseModel):
    scenario: str = Field(min_length=3)


PIVOT_SYSTEM = (
    "You are InsafeLabs Pivoting Advisor for AUTHORIZED network penetration tests. Given a foothold/pivot "
    "scenario, output concrete, copy-pasteable pivoting recipes with placeholder IPs/ports for: SSH dynamic "
    "port-forward + proxychains, chisel (server/client), ligolo-ng, Metasploit autoroute + socks_proxy, and "
    "plink/netsh for Windows. Explain when to use each, and how to route tools (nmap/CrackMapExec) through the "
    "tunnel. Add OPSEC/detection notes. STRICT SAFETY: authorized use only, no malware. "
    "Under ~340 words, dense markdown with code blocks."
)


@router.post("/network/pivot")
async def network_pivot(data: PivotInput):
    try:
        answer = await ai.complete("pivot-advisor", PIVOT_SYSTEM, f"SCENARIO: {data.scenario}")
    except Exception:
        raise HTTPException(status_code=502, detail="Advisor temporarily unavailable.")
    return {"answer": answer}


NET_ANALYZE_SYSTEM = (
    "You are InsafeLabs Network Triage AI for AUTHORIZED penetration tests. Given a discovered host/service "
    "inventory with device-type guesses, produce a concise operator briefing: (1) highest-value targets and WHY, "
    "(2) the most likely weaknesses per exposed service (default creds, known CVEs, misconfig), (3) a prioritized "
    "attack path from initial foothold to domain/network takeover, and (4) concrete next-step commands "
    "(nmap -sV/scripts, hydra, crackmapexec, msf modules) with placeholder values. STRICT SAFETY: authorized use "
    "only, no destructive actions. Under ~320 words, dense markdown with short code blocks."
)


@router.post("/network/analyze/{scan_id}")
async def network_analyze(scan_id: str):
    doc = await db.network_scans.find_one({"id": scan_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Scan not found")
    hosts = doc.get("hosts") or []
    if not hosts:
        raise HTTPException(status_code=400, detail="No live hosts to analyze.")
    lines = []
    for h in hosts[:30]:
        svc = ", ".join(f"{s['service']}:{s['port']}" + (f" ({s['banner']})" if s.get("banner") else "")
                        for s in h.get("services", []))
        lines.append(f"- {h['ip']} ({h.get('rdns') or 'no-rdns'}) "
                     f"[{h.get('device_type', 'Host')}, OS~{h.get('os_guess', 'Unknown')}]: {svc or 'no open ports'}")
    ctx = (f"TARGET: {doc['target']}\nHOSTS UP: {doc.get('hosts_up', 0)}/{doc.get('scanned', 0)}\n"
           f"DEVICE SUMMARY: {doc.get('device_summary', {})}\n\nHOSTS:\n" + "\n".join(lines))
    try:
        answer = await ai.complete("net-analyze", NET_ANALYZE_SYSTEM, ctx)
    except Exception:
        raise HTTPException(status_code=502, detail="Analyzer temporarily unavailable.")
    await db.network_scans.update_one({"id": scan_id}, {"$set": {"ai_summary": answer}})
    return {"answer": answer}


# ============================================================================
# 3) BINARY REVERSE-ENGINEERING ASSISTANT
# ============================================================================
SUSPICIOUS_APIS = [
    "VirtualAlloc", "VirtualProtect", "CreateRemoteThread", "WriteProcessMemory",
    "ReadProcessMemory", "OpenProcess", "LoadLibrary", "GetProcAddress", "WinExec",
    "ShellExecute", "CreateProcess", "URLDownloadToFile", "InternetOpen", "InternetConnect",
    "HttpSendRequest", "WSAStartup", "socket", "connect", "bind", "recv", "send",
    "RegSetValue", "RegCreateKey", "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "CryptEncrypt", "CryptDecrypt", "SetWindowsHookEx", "GetAsyncKeyState",
    "AdjustTokenPrivileges", "NtUnmapViewOfSection", "QueueUserAPC", "system", "exec",
    "fork", "ptrace", "dlopen", "mprotect", "execve",
]


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    ent = 0.0
    n = len(data)
    for f in freq:
        if f:
            p = f / n
            ent -= p * math.log2(p)
    return round(ent, 2)


def _extract_strings(data: bytes, minlen=4, cap=800):
    out = []
    cur = bytearray()
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= minlen:
                out.append(cur.decode("latin-1"))
                if len(out) >= cap:
                    break
            cur = bytearray()
    if len(cur) >= minlen and len(out) < cap:
        out.append(cur.decode("latin-1"))
    return out


def _detect_format(data: bytes) -> str:
    if data[:4] == b"\x7fELF":
        return "ELF"
    if data[:2] == b"MZ":
        return "PE"
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return "Mach-O"
    if data[:4] == b"PK\x03\x04":
        return "ZIP/APK/JAR"
    return "raw/data"


def _analyze_elf(data: bytes) -> dict:
    from elftools.elf.elffile import ELFFile
    elf = ELFFile(io.BytesIO(data))
    hdr = elf.header
    info = {
        "arch": elf.get_machine_arch(),
        "bits": elf.elfclass,
        "endian": "little" if elf.little_endian else "big",
        "type": str(hdr["e_type"]),
        "entry": hex(hdr["e_entry"]),
        "sections": [], "imports": [], "libraries": [], "stripped": True,
    }
    for sec in elf.iter_sections():
        try:
            info["sections"].append({"name": sec.name, "size": sec["sh_size"]})
        except Exception:
            pass
        if sec.name == ".symtab":
            info["stripped"] = False
    from elftools.elf.dynamic import DynamicSection
    from elftools.elf.sections import SymbolTableSection
    for sec in elf.iter_sections():
        if isinstance(sec, DynamicSection):
            for tag in sec.iter_tags():
                if tag.entry.d_tag == "DT_NEEDED":
                    info["libraries"].append(str(tag.needed))
        if isinstance(sec, SymbolTableSection) and sec.name == ".dynsym":
            for sym in sec.iter_symbols():
                if sym.name and sym["st_info"]["type"] == "STT_FUNC" and sym["st_shndx"] == "SHN_UNDEF":
                    info["imports"].append(sym.name)
    info["imports"] = sorted(set(info["imports"]))[:200]
    info["sections"] = info["sections"][:40]
    return info


def _analyze_pe(data: bytes) -> dict:
    import pefile
    pe = pefile.PE(data=data, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    machine = pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, str(pe.FILE_HEADER.Machine))
    subsystem = pefile.SUBSYSTEM_TYPE.get(pe.OPTIONAL_HEADER.Subsystem, str(pe.OPTIONAL_HEADER.Subsystem))
    ts = pe.FILE_HEADER.TimeDateStamp
    info = {
        "machine": str(machine), "subsystem": str(subsystem),
        "dll": bool(pe.FILE_HEADER.Characteristics & 0x2000),
        "compile_time": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat() if ts else None,
        "sections": [], "imports": [], "libraries": [],
    }
    for s in pe.sections:
        try:
            nm = s.Name.decode("latin-1", "ignore").rstrip("\x00")
            info["sections"].append({"name": nm, "size": s.SizeOfRawData, "entropy": round(s.get_entropy(), 2)})
        except Exception:
            pass
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("latin-1", "ignore") if entry.dll else ""
            info["libraries"].append(dll)
            for imp in entry.imports:
                if imp.name:
                    info["imports"].append(imp.name.decode("latin-1", "ignore"))
    info["imports"] = sorted(set(info["imports"]))[:250]
    info["libraries"] = sorted(set(info["libraries"]))[:40]
    return info


def _binary_verdict(fmt, entropy, suspicious, secrets, urls, packed_sections):
    score = 0
    reasons = []
    if entropy >= 7.2:
        score += 30; reasons.append(f"High overall entropy ({entropy}) — likely packed/encrypted")
    if packed_sections:
        score += 20; reasons.append(f"{packed_sections} high-entropy section(s) — packing indicator")
    if len(suspicious) >= 8:
        score += 25; reasons.append(f"{len(suspicious)} suspicious API references (injection/network/anti-debug)")
    elif len(suspicious) >= 3:
        score += 12; reasons.append(f"{len(suspicious)} suspicious API references")
    if secrets:
        score += 18; reasons.append(f"{len(secrets)} embedded secret(s)/key(s)")
    if len(urls) >= 3:
        score += 10; reasons.append(f"{len(urls)} embedded URL(s)/host(s) — possible C2/exfil")
    score = min(100, score)
    level = "high" if score >= 65 else "suspicious" if score >= 35 else "low" if score >= 12 else "clean"
    label = {"high": "HIGH RISK — likely malicious", "suspicious": "SUSPICIOUS — manual review advised",
             "low": "LOW RISK — minor indicators", "clean": "CLEAN — no strong indicators"}[level]
    return {"level": level, "label": label, "score": score, "reasons": reasons}


BIN_SYSTEM = (
    "You are InsafeLabs Reverse-Engineering Assistant. Given a binary triage summary (format, arch, imports, "
    "suspicious APIs, strings/URLs, entropy), write a concise expert assessment: what the binary most likely "
    "does, notable capabilities (network, injection, persistence, anti-analysis, crypto), a suggested next-step "
    "RE workflow (Ghidra/IDA/radare2/x64dbg/strace), and IOCs to pivot on. Under ~230 words, markdown bullets. "
    "Be factual; do not fabricate. Authorized malware-analysis context."
)


@router.post("/binary/analyze")
async def binary_analyze(file: UploadFile = File(...)):
    raw = await file.read()
    if len(raw) > MAX_BIN:
        raise HTTPException(status_code=413, detail="Binary exceeds 40 MB cap.")
    if not raw:
        raise HTTPException(status_code=400, detail="Empty file.")

    fmt = _detect_format(raw)
    out = {
        "filename": file.filename, "size": len(raw), "size_kb": round(len(raw) / 1024, 1),
        "format": fmt, "entropy": _entropy(raw[:2_000_000]),
        "sha256": __import__("hashlib").sha256(raw).hexdigest(),
        "notes": [], "elf": None, "pe": None,
    }

    if fmt == "ZIP/APK/JAR":
        out["notes"].append("This is a ZIP/APK/JAR container — use the Static APK Analyzer (Mobile / USB Bridge) for full APK triage.")

    try:
        if fmt == "ELF":
            out["elf"] = await asyncio.to_thread(_analyze_elf, raw)
        elif fmt == "PE":
            out["pe"] = await asyncio.to_thread(_analyze_pe, raw)
    except Exception as e:
        out["notes"].append(f"Structured parse failed: {e}")

    strings = _extract_strings(raw)
    out["string_count"] = len(strings)
    imports = (out.get("elf") or {}).get("imports", []) + (out.get("pe") or {}).get("imports", [])
    hay = "\n".join(strings + imports)
    low = hay.lower()
    suspicious = sorted({a for a in SUSPICIOUS_APIS if a.lower() in low})
    out["suspicious_apis"] = suspicious

    # URLs / IPs / domains from strings
    import re
    urls = re.findall(r"https?://[^\s\"'<>]{4,120}", hay)
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", hay)
    out["urls"] = sorted(set(urls))[:40]
    out["ips"] = sorted({i for i in ips if not i.startswith(("0.", "255."))})[:40]

    # secrets via recon patterns
    secrets = []
    try:
        for pat_name, _cvss, rx in recon_lib.SECRET_PATTERNS:
            for m in rx.findall(hay):
                mv = m if isinstance(m, str) else (m[0] if m else "")
                if mv:
                    secrets.append({"type": pat_name, "match": recon_lib._redact(mv)})
            if len(secrets) >= 25:
                break
    except Exception:
        pass
    out["secrets"] = secrets[:25]

    # interesting strings sample (urls/paths/keys-ish)
    interesting = [s for s in strings if any(t in s.lower() for t in
                   ("http", "cmd", ".dll", ".exe", "/bin/", "password", "token", "key", "\\", "reg", "http"))]
    out["strings_sample"] = interesting[:60] or strings[:60]

    packed = 0
    for sec in ((out.get("pe") or {}).get("sections") or []):
        if sec.get("entropy", 0) >= 7.2:
            packed += 1
    out["verdict"] = _binary_verdict(fmt, out["entropy"], suspicious, secrets, out["urls"], packed)

    try:
        summary = (f"format={fmt}; entropy={out['entropy']}; suspicious_apis={suspicious[:20]}; "
                   f"libs={(out.get('pe') or out.get('elf') or {}).get('libraries', [])[:12]}; "
                   f"urls={out['urls'][:8]}; ips={out['ips'][:8]}; secrets={len(secrets)}")
        out["ai_summary"] = await ai.complete("bin-re", BIN_SYSTEM, summary)
    except Exception:
        out["ai_summary"] = None

    out["id"] = str(uuid.uuid4())
    out["created_at"] = _now()
    try:
        store = {k: out.get(k) for k in ("id", "created_at", "filename", "size_kb", "format",
                 "entropy", "sha256", "suspicious_apis", "urls", "ips", "secrets", "verdict", "ai_summary")}
        await db.binary_scans.insert_one(store)
    except Exception:
        pass

    return out



def _esc(s):
    return str(s if s is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _build_bin_pdf(res: dict) -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=16 * mm, bottomMargin=16 * mm,
                            leftMargin=16 * mm, rightMargin=16 * mm, title="InsafeLabs RE Report")
    ss = getSampleStyleSheet()
    H = ParagraphStyle("H", parent=ss["Title"], fontSize=18, textColor=colors.HexColor("#111111"))
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], fontSize=12, textColor=colors.HexColor("#B45309"))
    body = ParagraphStyle("b", parent=ss["Normal"], fontSize=9, leading=13)
    small = ParagraphStyle("s", parent=ss["Normal"], fontSize=8, textColor=colors.grey)
    mono = ParagraphStyle("m", parent=ss["Normal"], fontName="Courier", fontSize=8, leading=11)

    el = [Paragraph("InsafeLabs — Reverse Engineering Report", H)]
    v = res.get("verdict") or {}
    el.append(Paragraph(f"Verdict: <b>{_esc(v.get('label', ''))}</b> &middot; risk {v.get('score', '?')}/100", h2))
    el.append(Spacer(1, 6))

    bin_ = res.get("pe") or res.get("elf") or {}
    ident = [
        ["Filename", res.get("filename", "")],
        ["Format", res.get("format", "")],
        ["Size (KB)", res.get("size_kb", "")],
        ["Entropy", res.get("entropy", "")],
        ["Arch / Machine", bin_.get("arch") or bin_.get("machine") or ""],
        ["SHA-256", res.get("sha256", "")],
    ]
    t = Table(ident, colWidths=[35 * mm, 143 * mm])
    t.setStyle(TableStyle([("FONTSIZE", (0, 0), (-1, -1), 8), ("FONTNAME", (1, 0), (1, -1), "Courier"),
                           ("TEXTCOLOR", (0, 0), (0, -1), colors.grey), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                           ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                           ("LINEBELOW", (0, 0), (-1, -1), 0.3, colors.HexColor("#DDDDDD"))]))
    el.append(t)
    el.append(Spacer(1, 8))

    def section(title, items):
        items = [i for i in (items or []) if i]
        if not items:
            return
        el.append(Paragraph(_esc(title), h2))
        for it in items[:60]:
            el.append(Paragraph(_esc(it), mono))
        el.append(Spacer(1, 6))

    section("Verdict Reasons", v.get("reasons"))
    section("Suspicious APIs", res.get("suspicious_apis"))
    section("IOC — URLs", res.get("urls"))
    section("IOC — IPs", res.get("ips"))
    section("Embedded Secrets", [f"{s.get('type')}: {s.get('match')}" for s in (res.get("secrets") or [])])

    if res.get("ai_summary"):
        el.append(Paragraph("AI Capability Assessment", h2))
        for line in str(res["ai_summary"]).split("\n"):
            if line.strip():
                el.append(Paragraph(_esc(line), body))
        el.append(Spacer(1, 6))

    el.append(Spacer(1, 10))
    el.append(Paragraph("Generated by InsafeLabs Reverse Engineering Assistant &middot; For authorized analysis only", small))
    doc.build(el)
    return buf.getvalue()


@router.post("/binary/report")
async def binary_report(payload: dict = Body(...)):
    pdf = await asyncio.to_thread(_build_bin_pdf, payload)
    fn = (payload.get("filename") or "binary").replace("/", "_").replace(" ", "_")[:40]
    return StreamingResponse(io.BytesIO(pdf), media_type="application/pdf",
                             headers={"Content-Disposition": f'attachment; filename="insafelabs-RE-{fn}.pdf"'})


# ============================================================================
# 4) UNIFIED OPERATION REPORT — consolidate Scanner + Network Map + RE findings
# ============================================================================
def _sev_color(sev):
    return {"critical": "#DC2626", "high": "#EA580C", "medium": "#D97706",
            "low": "#65A30D", "info": "#6B7280"}.get(sev, "#6B7280")


@router.get("/operation/sources")
async def operation_sources():
    recon = await db.recon_scans.find(
        {"status": "completed"},
        {"_id": 0, "id": 1, "ref": 1, "host": 1, "target": 1, "risk_score": 1,
         "posture": 1, "finding_count": 1, "created_at": 1},
    ).sort("created_at", -1).to_list(120)
    network = await db.network_scans.find(
        {"status": "completed"},
        {"_id": 0, "id": 1, "target": 1, "hosts_up": 1, "scanned": 1, "created_at": 1},
    ).sort("created_at", -1).to_list(120)
    binaries = await db.binary_scans.find(
        {}, {"_id": 0, "id": 1, "filename": 1, "format": 1, "verdict": 1, "created_at": 1},
    ).sort("created_at", -1).to_list(120)
    return {"recon": recon, "network": network, "binaries": binaries}


class OperationReportInput(BaseModel):
    title: str | None = None
    operator: str | None = None
    cover_notes: str | None = None
    logo: str | None = None  # data URL (base64) — embedded on the cover, not stored
    recon_ids: list[str] = []
    network_ids: list[str] = []
    binary_ids: list[str] = []


def _build_operation_pdf(title, operator, recon, network, binaries, cover_notes=None, logo=None):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=16 * mm, bottomMargin=16 * mm,
                            leftMargin=16 * mm, rightMargin=16 * mm, title="InsafeLabs Operation Report")
    ss = getSampleStyleSheet()
    H = ParagraphStyle("OH", parent=ss["Title"], fontSize=24, textColor=colors.HexColor("#0A0A0A"))
    h2 = ParagraphStyle("Oh2", parent=ss["Heading2"], fontSize=13, textColor=colors.HexColor("#B45309"), spaceBefore=10)
    h3 = ParagraphStyle("Oh3", parent=ss["Heading3"], fontSize=10.5, textColor=colors.HexColor("#1F2937"), spaceBefore=6)
    body = ParagraphStyle("Ob", parent=ss["Normal"], fontSize=9, leading=13)
    small = ParagraphStyle("Os", parent=ss["Normal"], fontSize=8, textColor=colors.grey)
    mono = ParagraphStyle("Om", parent=ss["Normal"], fontName="Courier", fontSize=8, leading=11)

    def tbl(rows, widths, header=False):
        t = Table(rows, colWidths=widths)
        style = [("FONTSIZE", (0, 0), (-1, -1), 8), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                 ("BOTTOMPADDING", (0, 0), (-1, -1), 3), ("TOPPADDING", (0, 0), (-1, -1), 3),
                 ("LINEBELOW", (0, 0), (-1, -1), 0.3, colors.HexColor("#E5E7EB"))]
        if header:
            style += [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111111")),
                      ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold")]
        t.setStyle(TableStyle(style))
        return t

    el = []
    # ---- cover ----
    el.append(Spacer(1, 60))
    if logo and isinstance(logo, str) and "," in logo and len(logo) < 3_000_000:
        try:
            import base64
            from reportlab.platypus import Image as RLImage
            raw = base64.b64decode(logo.split(",", 1)[1])
            img = RLImage(io.BytesIO(raw))
            maxw = 45 * mm
            if img.imageWidth and img.imageWidth > maxw:
                scale = maxw / img.imageWidth
                img.drawWidth = maxw
                img.drawHeight = img.imageHeight * scale
            img.hAlign = "LEFT"
            el.append(img)
            el.append(Spacer(1, 12))
        except Exception:
            pass
    el.append(Paragraph(_esc(title or "Operation Report"), H))
    el.append(Spacer(1, 6))
    el.append(Paragraph("InsafeLabs — Unified Offensive Dossier", h2))
    el.append(Spacer(1, 14))
    cover = [
        ["Operator", _esc(operator or "—")],
        ["Generated", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")],
        ["Attack-surface scans", str(len(recon))],
        ["Network maps", str(len(network))],
        ["Binary analyses", str(len(binaries))],
    ]
    el.append(tbl([[k, v] for k, v in cover], [50 * mm, 120 * mm]))
    el.append(Spacer(1, 14))
    if cover_notes and str(cover_notes).strip():
        el.append(Paragraph("Notes", h2))
        for line in str(cover_notes).split("\n"):
            if line.strip():
                el.append(Paragraph(_esc(line), body))
        el.append(Spacer(1, 10))
    el.append(Paragraph("CONFIDENTIAL — authorized security assessment only.", small))

    # ---- executive summary ----
    agg = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    total_findings = 0
    worst = "info"
    order = ["info", "low", "medium", "high", "critical"]
    for r in recon:
        for k in agg:
            agg[k] += (r.get("severity_counts") or {}).get(k, 0)
        total_findings += r.get("finding_count", 0)
        p = r.get("posture") or "info"
        if p in order and order.index(p) > order.index(worst):
            worst = p
    hosts_up = sum(n.get("hosts_up", 0) for n in network)
    risky_bins = [b for b in binaries if (b.get("verdict") or {}).get("level") in ("high", "suspicious")]

    el.append(PageBreak())
    el.append(Paragraph("Executive Summary", h2))
    el.append(Paragraph(
        f"This operation consolidates {len(recon)} attack-surface scan(s), {len(network)} network map(s) "
        f"and {len(binaries)} binary analysis(es). A total of {total_findings} finding(s) were identified "
        f"(highest posture: {worst.upper()}). {hosts_up} live host(s) were mapped across the network scope, "
        f"and {len(risky_bins)} binary(ies) were flagged suspicious/high-risk.", body))
    el.append(Spacer(1, 8))
    el.append(tbl([["Critical", "High", "Medium", "Low", "Info"],
                   [str(agg["critical"]), str(agg["high"]), str(agg["medium"]), str(agg["low"]), str(agg["info"])]],
                  [34 * mm] * 5, header=True))

    # ---- attack-surface sections ----
    for r in recon:
        el.append(PageBreak())
        el.append(Paragraph(f"Attack Surface — {_esc(r.get('host') or r.get('target'))}", h2))
        sc = r.get("scorecard") or {}
        meta = [
            ["Ref", _esc(r.get("ref") or r.get("id"))],
            ["Target", _esc(r.get("target"))],
            ["Risk score", f"{r.get('risk_score', 0)}/100"],
            ["Posture", (r.get("posture") or "").upper()],
            ["Scorecard", f"{sc.get('overall_grade', '—')} ({sc.get('overall_score', '—')}/100)" if sc else "—"],
            ["Findings", str(r.get("finding_count", 0))],
            ["Scanned", _esc(r.get("created_at"))],
        ]
        el.append(tbl([[k, v] for k, v in meta], [40 * mm, 130 * mm]))
        el.append(Spacer(1, 4))
        ports = r.get("ports") or []
        if ports:
            el.append(Paragraph("Open Ports", h3))
            el.append(Paragraph(_esc(", ".join(f"{p.get('port')}/{p.get('service', '')}" for p in ports[:30])), mono))
        if sc.get("categories"):
            el.append(Paragraph("Security Scorecard", h3))
            rows = [["Category", "Grade", "Score"]] + [[_esc(c["category"]), c["grade"], f"{c['score']}/100"] for c in sc["categories"]]
            el.append(tbl(rows, [90 * mm, 40 * mm, 40 * mm], header=True))
        fs = r.get("findings") or []
        if fs:
            el.append(Paragraph("Top Findings", h3))
            rows = [["Severity", "CVSS", "Finding"]]
            for f in fs[:14]:
                sev = f.get("severity", "info")
                sevp = Paragraph(f'<font color="{_sev_color(sev)}"><b>{sev.upper()}</b></font>', mono)
                rows.append([sevp, str(f.get("cvss", "")), Paragraph(_esc(f.get("title", "")), body)])
            el.append(tbl(rows, [26 * mm, 16 * mm, 128 * mm], header=True))
        secs = (r.get("secrets") or {}).get("secrets") or []
        if secs:
            el.append(Paragraph(f"Exposed Secrets ({len(secs)})", h3))
            for s in secs[:12]:
                label = s.get("type") or s.get("name") or s.get("pattern") or "secret"
                val = s.get("match") or s.get("value") or s.get("sample") or ""
                el.append(Paragraph(_esc(f"{label}: {val}"), mono))

    # ---- network map sections ----
    for n in network:
        el.append(PageBreak())
        el.append(Paragraph(f"Network Map — {_esc(n.get('target'))}", h2))
        meta = [["Scanned hosts", str(n.get("scanned", 0))], ["Live hosts", str(n.get("hosts_up", 0))],
                ["Mapped", _esc(n.get("created_at"))]]
        el.append(tbl([[k, v] for k, v in meta], [40 * mm, 130 * mm]))
        el.append(Spacer(1, 4))
        hosts = n.get("hosts") or []
        for h in hosts[:30]:
            th = f"{h.get('ip')}" + (f" ({h.get('rdns')})" if h.get("rdns") else "")
            el.append(Paragraph(_esc(th), h3))
            svs = h.get("services") or []
            if svs:
                el.append(Paragraph(_esc(", ".join(f"{s.get('port')}/{s.get('service', '')}" for s in svs)), mono))
            else:
                el.append(Paragraph("no open services detected", small))
        if not hosts:
            el.append(Paragraph("No live hosts mapped (target may be private/unreachable from cloud).", small))

    # ---- reverse-engineering sections ----
    for b in binaries:
        el.append(PageBreak())
        el.append(Paragraph(f"Reverse Engineering — {_esc(b.get('filename'))}", h2))
        v = b.get("verdict") or {}
        meta = [["Verdict", _esc(v.get("label", ""))], ["Risk", f"{v.get('score', '?')}/100"],
                ["Format", _esc(b.get("format", ""))], ["Size (KB)", str(b.get("size_kb", ""))],
                ["Entropy", str(b.get("entropy", ""))], ["SHA-256", _esc(b.get("sha256", ""))],
                ["Analyzed", _esc(b.get("created_at"))]]
        el.append(tbl([[k, v2] for k, v2 in meta], [40 * mm, 130 * mm]))
        el.append(Spacer(1, 4))

        def bsec(t, items):
            items = [i for i in (items or []) if i]
            if not items:
                return
            el.append(Paragraph(t, h3))
            for it in items[:40]:
                el.append(Paragraph(_esc(it), mono))

        bsec("Verdict Reasons", v.get("reasons"))
        bsec("Suspicious APIs", b.get("suspicious_apis"))
        bsec("IOC — URLs", b.get("urls"))
        bsec("IOC — IPs", b.get("ips"))
        bsec("Embedded Secrets", [f"{s.get('type')}: {s.get('match')}" for s in (b.get("secrets") or [])])

    el.append(Spacer(1, 16))
    el.append(Paragraph("Generated by InsafeLabs — Unified Operation Report · For authorized use only", small))
    doc.build(el)
    return buf.getvalue()


@router.post("/operation/report")
async def operation_report(data: OperationReportInput):
    recon, network, binaries = [], [], []
    for rid in data.recon_ids[:20]:
        d = await db.recon_scans.find_one({"id": rid}, {"_id": 0, "raw": 0})
        if d:
            recon.append(d)
    for nid in data.network_ids[:20]:
        d = await db.network_scans.find_one({"id": nid}, {"_id": 0})
        if d:
            network.append(d)
    for bid in data.binary_ids[:20]:
        d = await db.binary_scans.find_one({"id": bid}, {"_id": 0})
        if d:
            binaries.append(d)
    if not (recon or network or binaries):
        raise HTTPException(status_code=400, detail="Select at least one Scanner, Network Map, or RE result to include.")
    pdf = await asyncio.to_thread(_build_operation_pdf, data.title, data.operator, recon, network, binaries, data.cover_notes, data.logo)
    return StreamingResponse(io.BytesIO(pdf), media_type="application/pdf",
                             headers={"Content-Disposition": 'attachment; filename="insafelabs-operation-report.pdf"'})
