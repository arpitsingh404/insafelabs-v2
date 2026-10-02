"""Legal document generator — NDA, Penetration-Testing Authorization / RoE and
Scope letters. Produces Markdown (and PDF) you can hand to a client to sign.

Templates are generic and NOT legal advice — review with counsel before use.
"""
import io
import re
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, Field

from db import db

router = APIRouter(prefix="/legal", tags=["legal"])

UA = {"User-Agent": "InsafeLabs-Legal/1.0"}


class ProfileBody(BaseModel):
    provider_name: str = ""
    provider_org: str = ""
    contact_email: str = ""
    jurisdiction: str = ""


@router.get("/profile")
async def get_profile():
    doc = await db.legal_profile.find_one({"_id": "profile"}) or {}
    doc.pop("_id", None)
    return doc


@router.post("/profile")
async def set_profile(body: ProfileBody):
    await db.legal_profile.update_one({"_id": "profile"}, {"$set": body.model_dump()}, upsert=True)
    return {"ok": True}


def _strip_site(site: str) -> str:
    s = (site or "").strip()
    if "@" in s and "://" not in s:
        s = s.split("@")[-1]
    s = re.sub(r"^https?://", "", s).split("/")[0].split("?")[0].split(":")[0]
    return s.lower().lstrip(".")


def _root_domain(host: str) -> str:
    parts = [p for p in host.split(".") if p]
    if len(parts) <= 2:
        return ".".join(parts)
    if parts[-2] in ("co", "com", "org", "net", "gov", "ac") and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


class AutofillBody(BaseModel):
    site: str = Field(min_length=2, max_length=2048)


@router.post("/autofill")
async def autofill(body: AutofillBody):
    host = _strip_site(body.site)
    if "." not in host:
        raise HTTPException(status_code=400, detail="Enter a valid domain, e.g. acme.com")
    root = _root_domain(host)
    label = root.split(".")[0]

    title = None
    try:
        import requests
        from netguard import guard_url
        url = body.site.strip() if body.site.strip().startswith("http") else f"https://{host}"
        guard_url(url)
        r = requests.get(url, timeout=8, headers=UA, verify=False)
        m = re.search(r"<title[^>]*>(.*?)</title>", r.text or "", re.S | re.I)
        if m:
            title = re.sub(r"\s+", " ", m.group(1)).strip()[:80] or None
    except Exception:
        pass

    contact, jurisdiction, registrant = f"security@{root}", "", ""
    try:
        import asyncio
        import whois as _whois
        loop = asyncio.get_event_loop()
        w = await asyncio.wait_for(loop.run_in_executor(None, _whois.whois, root), timeout=8)
        if w:
            em = w.get("emails")
            if isinstance(em, list) and em:
                contact = em[0]
            elif isinstance(em, str) and em:
                contact = em
            registrant = (w.get("org") or w.get("registrant_name") or "") or ""
            jurisdiction = (w.get("country") or "") or ""
    except Exception:
        pass

    prof = await db.legal_profile.find_one({"_id": "profile"}) or {}
    return {
        "template": "pentest_authorization",
        "provider_name": prof.get("provider_name", ""),
        "provider_org": prof.get("provider_org", ""),
        "client_name": "",
        "client_org": title or registrant.strip() or label.capitalize(),
        "effective_date": datetime.now(timezone.utc).strftime("%d %B %Y"),
        "jurisdiction": prof.get("jurisdiction") or jurisdiction,
        "purpose": "security assessment",
        "scope": f"{root}, www.{root}, *.{root}",
        "duration": "",
        "contact_email": contact,
        "detected": {"host": host, "root": root, "title": title, "whois_org": registrant, "whois_country": jurisdiction},
    }


TEMPLATES = [
    {"id": "nda", "name": "Mutual NDA", "desc": "Mutual Non-Disclosure Agreement between two parties."},
    {"id": "pentest_authorization", "name": "Pentest Authorization / RoE",
     "desc": "Authorization + Rules of Engagement for a penetration test (scope, window, permitted/prohibited)."},
    {"id": "scope_letter", "name": "Scope & Authorization Letter",
     "desc": "Short one-page authorization letter for a target/scope."},
]


class LegalBody(BaseModel):
    template: str
    provider_name: str = ""
    provider_org: str = ""
    client_name: str = ""
    client_org: str = ""
    effective_date: str = ""
    jurisdiction: str = ""
    purpose: str = "security assessment"
    scope: str = ""
    duration: str = ""
    contact_email: str = ""


def _date(v):
    return v or datetime.now(timezone.utc).strftime("%d %B %Y")


def _signatures(provider, client, provider_org, client_org):
    return f"""
| | Provider | Client |
|---|---|---|
| Name | {provider or '________________'} | {client or '________________'} |
| Organisation | {provider_org or '________________'} | {client_org or '________________'} |
| Signature | ______________________ | ______________________ |
| Date | ______________________ | ______________________ |
"""


def _nda(b: LegalBody) -> str:
    return f"""# MUTUAL NON-DISCLOSURE AGREEMENT

This Mutual Non-Disclosure Agreement (the "Agreement") is entered into as of **{_date(b.effective_date)}**
between **{b.provider_org or b.provider_name or 'Provider'}** ("{b.provider_name or 'Provider'}") and
**{b.client_org or b.client_name or 'Client'}** ("{b.client_name or 'Client'}"), collectively the "Parties".

## 1. Purpose
The Parties wish to exchange information for the purpose of {b.purpose}.

## 2. Confidential Information
"Confidential Information" means any non-public information disclosed by one Party to the other,
whether oral, written or electronic, including security findings, vulnerabilities, technical data,
business plans, and credentials, that is designated confidential or would reasonably be understood to be confidential.

## 3. Obligations
Each Party shall: (a) hold Confidential Information in strict confidence; (b) use it solely for the Purpose;
(c) not disclose it to third parties without prior written consent; (d) protect it with at least the same
care it uses for its own confidential information, and not less than reasonable care.

## 4. Exclusions
Confidential Information does not include information that: (a) is or becomes public through no fault of
the receiving Party; (b) was rightfully known before disclosure; (c) is rightfully received from a third
party without duty of confidence; or (d) is independently developed without use of the Confidential Information.

## 5. Term
This Agreement takes effect on {_date(b.effective_date)} and continues for **{b.duration or 'two (2) years'}**,
unless terminated earlier. Confidentiality obligations survive termination.

## 6. Legal Compulsion
A Party compelled by law to disclose Confidential Information shall, where permitted, give prompt notice
to the other Party and disclose only the minimum required.

## 7. Remedies
The Parties agree that breach may cause irreparable harm and that injunctive relief is an appropriate remedy,
in addition to any other remedies available at law.

## 8. Governing Law
This Agreement is governed by the laws of **{b.jurisdiction or 'the agreed jurisdiction'}**.

## 9. No Warranty / No License
Confidential Information is provided "as is". No licence or intellectual-property right is granted except as stated.

## 10. Security Testing Context
Where the Purpose includes security testing, all testing is performed only against **in-scope assets** and
only within the agreed time window, and is subject to the separate Authorization / Rules of Engagement.

## 11. Entire Agreement
This Agreement is the entire agreement between the Parties regarding its subject matter.

## Signatures
{_signatures(b.provider_name, b.client_name, b.provider_org, b.client_org)}

_This document is a template and not legal advice._
"""


def _roe(b: LegalBody) -> str:
    return f"""# PENETRATION TEST AUTHORIZATION & RULES OF ENGAGEMENT

**Client:** {b.client_org or b.client_name or '________________'}
**Provider:** {b.provider_org or b.provider_name or '________________'}
**Effective date:** {_date(b.effective_date)}
**Contact:** {b.contact_email or '________________'}

## 1. Authorization
The Client authorizes the Provider to perform a penetration test against the assets listed in Section 2.
The Client confirms it is the owner, or is authorized by the owner, of these assets, and grants the
Provider written permission to conduct the agreed testing.

## 2. Scope (in-scope assets)
{b.scope or '_List the exact domains / IP ranges / applications (e.g. *.acme.com, 10.0.0.0/24)._ '}

## 3. Time window
Testing is permitted between **{b.duration or 'the agreed dates/times'}** ({b.jurisdiction or 'local time'}).

## 4. Permitted activities
Reconnaissance, vulnerability scanning, safe/validated exploitation, and reporting.

## 5. Prohibited activities
Denial-of-service, data destruction or modification, social engineering of staff (unless separately agreed),
testing out-of-scope assets, and any activity that could disrupt production without prior approval.

## 6. Emergency stop
If a critical impact is discovered, the Provider will stop immediately and notify the Client contact above.

## 7. Data handling
Any data accessed is treated as confidential; evidence is retained only as needed and deleted on request.

## 8. Legal authority
Both Parties confirm the testing is lawful and authorized. This document is the authority relied upon.

## Signatures
{_signatures(b.provider_name, b.client_name, b.provider_org, b.client_org)}

_This document is a template and not legal advice._
"""


def _scope_letter(b: LegalBody) -> str:
    return f"""# SCOPE & AUTHORIZATION LETTER

Date: {_date(b.effective_date)}

To whom it may concern,

**{b.client_org or b.client_name or 'The Client'}** hereby authorizes
**{b.provider_org or b.provider_name or 'the Provider'}** to conduct a security assessment
({b.purpose}) against the following in-scope assets:

{b.scope or '_____________________________'}

Testing is permitted during: **{b.duration or 'the agreed period'}**.
Prohibited: denial-of-service, data modification/destruction, and any out-of-scope activity.

Authorized signatory: {b.client_name or '____________________'} ({b.client_org or 'Client'})
Contact: {b.contact_email or '____________________'}

{_signatures(b.provider_name, b.client_name, b.provider_org, b.client_org)}

_This document is a template and not legal advice._
"""


_BUILDERS = {"nda": _nda, "pentest_authorization": _roe, "scope_letter": _scope_letter}


@router.get("/templates")
async def templates():
    return {"templates": TEMPLATES}


@router.post("/generate")
async def generate(body: LegalBody):
    fn = _BUILDERS.get(body.template)
    if not fn:
        raise HTTPException(status_code=404, detail="Unknown template")
    md = fn(body)
    name = TEMPLATES[[t["id"] for t in TEMPLATES].index(body.template)]["name"]
    fname = f"{body.template}-{_date('')[:10].replace(' ', '-')}.md"
    return {"title": name, "filename": fname, "markdown": md}


@router.post("/generate.pdf")
async def generate_pdf(body: LegalBody):
    fn = _BUILDERS.get(body.template)
    if not fn:
        raise HTTPException(status_code=404, detail="Unknown template")
    md = fn(body)
    try:
        from markdown_it import MarkdownIt
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF engine unavailable: {str(e)[:120]}")

    html = MarkdownIt().render(md)
    # very small html->reportlab: split on block tags
    import re as _re
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Title"], fontSize=18)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=12)
    body_s = ParagraphStyle("b", parent=styles["Normal"], fontSize=9.5, leading=13)
    story = []
    for block in _re.split(r"</(?:h1|h2|p|li|tr|table|ul|ol|blockquote)>", html):
        b = block.strip()
        if not b:
            continue
        text = _re.sub(r"<[^>]+>", "", b).strip()
        if not text:
            continue
        if "<h1" in b:
            story += [Paragraph(text, h1), Spacer(1, 6)]
        elif "<h2" in b:
            story += [Paragraph(text, h2), Spacer(1, 4)]
        else:
            story.append(Paragraph(text.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">"), body_s))
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=18 * mm, bottomMargin=16 * mm, leftMargin=18 * mm, rightMargin=18 * mm,
                            title=body.template)
    doc.build(story)
    data = buf.getvalue()
    return Response(content=data, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{body.template}.pdf"'})
