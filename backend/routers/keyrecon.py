"""InsafeLabs Payment Key Recon — read-only impact assessment for discovered/leaked
payment-provider API keys. Given a key (Stripe / Paystack / Flutterwave / Razorpay /
PayPal / Square) it queries the provider's OWN api, read-only, to reveal what the key
exposes: account identity, balance, pending funds, last transactions, refunds and
chargebacks/disputes.

Strictly READ-ONLY: it never issues refunds, charges, payouts or moves money. This is
secret-validation recon for authorized assessments only.
"""
import asyncio

import requests
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/keyrecon", tags=["keyrecon"])

T = 12  # request timeout


class KeyInspectInput(BaseModel):
    provider: str = "auto"
    key: str
    secret: str | None = None


def _mask(k: str) -> str:
    k = (k or "").strip()
    if len(k) <= 12:
        return (k[:4] + "…") if k else ""
    return f"{k[:8]}…{k[-4:]}"


def detect_provider(key: str) -> str:
    k = (key or "").strip()
    if k.startswith("rzp_"):
        return "razorpay"
    if k.upper().startswith("FLWSECK") or k.upper().startswith("FLWPUBK"):
        return "flutterwave"
    if k.startswith("sk_") or k.startswith("rk_") or k.startswith("pk_"):
        return "stripe"  # falls back to paystack on 401
    if k.startswith("EAAA") or k.startswith("sq0"):
        return "square"
    return "unknown"


def _mode_from(key: str) -> str:
    if "_test" in key or "TEST" in key.upper() or key.startswith("sk_test") or key.startswith("rzp_test"):
        return "test"
    if "_live" in key or key.startswith("sk_live") or key.startswith("rzp_live"):
        return "live"
    return "unknown"


# ----------------------------- Stripe -----------------------------
def stripe_inspect(key: str) -> dict:
    h = {"Authorization": f"Bearer {key}"}
    out = {"provider": "stripe", "valid": False, "mode": _mode_from(key),
           "summary": {}, "capabilities": {}, "notes": []}

    def g(path):
        try:
            return requests.get(f"https://api.stripe.com/v1/{path}", headers=h, timeout=T)
        except Exception as e:
            out["notes"].append(f"{path}: {e}")
            return None

    acct = g("account")
    if acct is not None and acct.status_code == 401:
        out["error"] = "Invalid or revoked Stripe key (401 Unauthorized)."
        return out
    if acct is not None and acct.status_code == 200:
        a = acct.json()
        out["valid"] = True
        bp = a.get("business_profile") or {}
        settings = a.get("settings") or {}
        dash = (settings.get("dashboard") or {})
        out["summary"] = {
            "id": a.get("id"),
            "name": bp.get("name") or dash.get("display_name"),
            "email": a.get("email"),
            "phone": bp.get("support_phone"),
            "website": bp.get("url") or bp.get("support_url"),
            "country": a.get("country"),
            "currency": (a.get("default_currency") or "").upper() or None,
            "type": a.get("business_type"),
        }
        out["capabilities"] = {
            "charges_enabled": a.get("charges_enabled"),
            "payouts_enabled": a.get("payouts_enabled"),
            "details_submitted": a.get("details_submitted"),
        }
    elif acct is not None and acct.status_code == 403:
        out["notes"].append("Restricted key: cannot read account object (403).")

    bal = g("balance")
    if bal is not None and bal.status_code == 200:
        out["valid"] = True
        b = bal.json()
        fmt = lambda arr: [{"amount": x["amount"] / 100, "currency": x["currency"].upper()} for x in arr]
        out["balance"] = {"available": fmt(b.get("available", [])), "pending": fmt(b.get("pending", []))}

    ch = g("charges?limit=6")
    if ch is not None and ch.status_code == 200:
        out["valid"] = True
        out["transactions"] = [{
            "id": c["id"], "amount": c["amount"] / 100, "currency": c["currency"].upper(),
            "status": c.get("status"), "paid": c.get("paid"),
            "email": c.get("receipt_email") or (c.get("billing_details") or {}).get("email"),
            "desc": c.get("description"), "created": c.get("created"),
        } for c in ch.json().get("data", [])]

    rf = g("refunds?limit=6")
    if rf is not None and rf.status_code == 200:
        out["refunds"] = [{
            "id": r["id"], "amount": r["amount"] / 100, "currency": r["currency"].upper(),
            "status": r.get("status"), "reason": r.get("reason"), "created": r.get("created"),
        } for r in rf.json().get("data", [])]

    dp = g("disputes?limit=6")
    if dp is not None and dp.status_code == 200:
        out["chargebacks"] = [{
            "id": d["id"], "amount": d["amount"] / 100, "currency": d["currency"].upper(),
            "status": d.get("status"), "reason": d.get("reason"), "created": d.get("created"),
        } for d in dp.json().get("data", [])]

    po = g("payouts?limit=6")
    if po is not None and po.status_code == 200:
        out["payouts"] = [{
            "id": p["id"], "amount": p["amount"] / 100, "currency": p["currency"].upper(),
            "status": p.get("status"), "arrival": p.get("arrival_date"),
        } for p in po.json().get("data", [])]

    if not out["valid"] and "error" not in out:
        out["error"] = "Key did not authorize against Stripe."
    return out


# ----------------------------- Paystack -----------------------------
def paystack_inspect(key: str) -> dict:
    h = {"Authorization": f"Bearer {key}"}
    base = "https://api.paystack.co"
    out = {"provider": "paystack", "valid": False, "mode": _mode_from(key),
           "summary": {}, "capabilities": {}, "notes": []}
    try:
        bal = requests.get(f"{base}/balance", headers=h, timeout=T)
    except Exception as e:
        out["error"] = f"Network error: {e}"
        return out
    if bal.status_code == 401:
        out["error"] = "Invalid Paystack key (401)."
        return out
    if bal.status_code == 200:
        out["valid"] = True
        data = bal.json().get("data", [])
        out["balance"] = {"available": [{"amount": d.get("balance", 0) / 100, "currency": d.get("currency")} for d in data], "pending": []}
    try:
        tx = requests.get(f"{base}/transaction?perPage=6", headers=h, timeout=T)
        if tx.status_code == 200:
            out["valid"] = True
            out["transactions"] = [{
                "id": str(t.get("reference") or t.get("id")), "amount": (t.get("amount") or 0) / 100,
                "currency": t.get("currency"), "status": t.get("status"),
                "email": (t.get("customer") or {}).get("email"), "created": t.get("created_at"),
            } for t in tx.json().get("data", [])]
    except Exception as e:
        out["notes"].append(f"transactions: {e}")
    try:
        rf = requests.get(f"{base}/refund?perPage=6", headers=h, timeout=T)
        if rf.status_code == 200:
            out["refunds"] = [{
                "id": str(r.get("id")), "amount": (r.get("amount") or 0) / 100,
                "currency": r.get("currency"), "status": r.get("status"),
            } for r in rf.json().get("data", [])]
    except Exception:
        pass
    if not out["valid"] and "error" not in out:
        out["error"] = "Key did not authorize against Paystack."
    return out


# ----------------------------- Flutterwave -----------------------------
def flutterwave_inspect(key: str) -> dict:
    h = {"Authorization": f"Bearer {key}"}
    base = "https://api.flutterwave.com/v3"
    out = {"provider": "flutterwave", "valid": False, "mode": _mode_from(key),
           "summary": {}, "capabilities": {}, "notes": []}
    try:
        bal = requests.get(f"{base}/balances", headers=h, timeout=T)
    except Exception as e:
        out["error"] = f"Network error: {e}"
        return out
    if bal.status_code in (401, 403):
        out["error"] = f"Invalid Flutterwave key ({bal.status_code})."
        return out
    if bal.status_code == 200:
        out["valid"] = True
        data = bal.json().get("data", [])
        out["balance"] = {
            "available": [{"amount": d.get("available_balance", 0), "currency": d.get("currency")} for d in data],
            "pending": [{"amount": d.get("ledger_balance", 0), "currency": d.get("currency")} for d in data],
        }
    try:
        tx = requests.get(f"{base}/transactions?page=1", headers=h, timeout=T)
        if tx.status_code == 200:
            out["valid"] = True
            out["transactions"] = [{
                "id": str(t.get("tx_ref") or t.get("id")), "amount": t.get("amount"),
                "currency": t.get("currency"), "status": t.get("status"),
                "email": (t.get("customer") or {}).get("email"), "created": t.get("created_at"),
            } for t in tx.json().get("data", [])[:6]]
    except Exception as e:
        out["notes"].append(f"transactions: {e}")
    if not out["valid"] and "error" not in out:
        out["error"] = "Key did not authorize against Flutterwave."
    return out


# ----------------------------- Razorpay -----------------------------
def razorpay_inspect(key: str, secret: str | None) -> dict:
    out = {"provider": "razorpay", "valid": False, "mode": _mode_from(key),
           "summary": {}, "capabilities": {}, "notes": []}
    if not secret:
        out["error"] = "Razorpay needs BOTH key_id and key_secret. Paste the secret in the second field."
        return out
    base = "https://api.razorpay.com/v1"
    auth = (key.strip(), secret.strip())
    try:
        pay = requests.get(f"{base}/payments?count=6", auth=auth, timeout=T)
    except Exception as e:
        out["error"] = f"Network error: {e}"
        return out
    if pay.status_code == 401:
        out["error"] = "Invalid Razorpay key_id / key_secret (401)."
        return out
    if pay.status_code == 200:
        out["valid"] = True
        out["transactions"] = [{
            "id": p.get("id"), "amount": (p.get("amount") or 0) / 100, "currency": p.get("currency"),
            "status": p.get("status"), "email": p.get("email"), "created": p.get("created_at"),
        } for p in pay.json().get("items", [])]
    try:
        rf = requests.get(f"{base}/refunds?count=6", auth=auth, timeout=T)
        if rf.status_code == 200:
            out["refunds"] = [{
                "id": r.get("id"), "amount": (r.get("amount") or 0) / 100, "currency": r.get("currency"),
                "status": r.get("status"), "created": r.get("created_at"),
            } for r in rf.json().get("items", [])]
    except Exception:
        pass
    try:
        st = requests.get(f"{base}/settlements?count=6", auth=auth, timeout=T)
        if st.status_code == 200:
            out["payouts"] = [{
                "id": s.get("id"), "amount": (s.get("amount") or 0) / 100, "currency": "INR",
                "status": s.get("status"), "created": s.get("created_at"),
            } for s in st.json().get("items", [])]
    except Exception:
        pass
    if not out["valid"] and "error" not in out:
        out["error"] = "Key did not authorize against Razorpay."
    return out


# ----------------------------- PayPal -----------------------------
def paypal_inspect(key: str, secret: str | None) -> dict:
    out = {"provider": "paypal", "valid": False, "mode": "unknown",
           "summary": {}, "capabilities": {}, "notes": []}
    if not secret:
        out["error"] = "PayPal needs client_id + client_secret. Paste the secret in the second field."
        return out
    token = None
    for base, mode in [("https://api-m.paypal.com", "live"), ("https://api-m.sandbox.paypal.com", "sandbox")]:
        try:
            tok = requests.post(f"{base}/v1/oauth2/token", auth=(key.strip(), secret.strip()),
                                data={"grant_type": "client_credentials"},
                                headers={"Accept": "application/json"}, timeout=T)
        except Exception as e:
            out["notes"].append(f"{mode}: {e}")
            continue
        if tok.status_code == 200:
            j = tok.json()
            token = j.get("access_token")
            out["valid"] = True
            out["mode"] = mode
            out["summary"] = {"app_id": j.get("app_id"), "scope": j.get("scope", "")[:400], "token_type": j.get("token_type")}
            out["capabilities"] = {"expires_in_s": j.get("expires_in")}
            api_base = base
            break
    if not token:
        out["error"] = "Invalid PayPal client_id / client_secret."
        return out
    try:
        bal = requests.get(f"{api_base}/v1/reporting/balances",
                           headers={"Authorization": f"Bearer {token}"}, timeout=T)
        if bal.status_code == 200:
            data = bal.json().get("balances", [])
            out["balance"] = {"available": [{"amount": (b.get("total_balance") or {}).get("value"),
                                             "currency": (b.get("total_balance") or {}).get("currency_code")} for b in data], "pending": []}
        else:
            out["notes"].append(f"balances: needs Transaction-Search/reporting scope ({bal.status_code}).")
    except Exception as e:
        out["notes"].append(f"balances: {e}")
    return out


# ----------------------------- Square -----------------------------
def square_inspect(key: str) -> dict:
    h = {"Authorization": f"Bearer {key}", "Square-Version": "2024-01-18"}
    base = "https://connect.squareup.com/v2"
    out = {"provider": "square", "valid": False, "mode": _mode_from(key),
           "summary": {}, "capabilities": {}, "notes": []}
    try:
        loc = requests.get(f"{base}/locations", headers=h, timeout=T)
    except Exception as e:
        out["error"] = f"Network error: {e}"
        return out
    if loc.status_code in (401, 403):
        out["error"] = f"Invalid Square access token ({loc.status_code})."
        return out
    if loc.status_code == 200:
        out["valid"] = True
        locs = loc.json().get("locations", [])
        if locs:
            l0 = locs[0]
            out["summary"] = {
                "name": l0.get("business_name") or l0.get("name"),
                "phone": l0.get("phone_number"),
                "website": l0.get("website_url"),
                "country": l0.get("country"),
                "currency": l0.get("currency"),
                "email": (l0.get("business_email")),
            }
    try:
        pay = requests.get(f"{base}/payments", headers=h, timeout=T)
        if pay.status_code == 200:
            out["transactions"] = [{
                "id": p.get("id"), "amount": (p.get("amount_money") or {}).get("amount", 0) / 100,
                "currency": (p.get("amount_money") or {}).get("currency"), "status": p.get("status"),
                "created": p.get("created_at"),
            } for p in pay.json().get("payments", [])[:6]]
    except Exception:
        pass
    if not out["valid"] and "error" not in out:
        out["error"] = "Token did not authorize against Square."
    return out


def _inspect_sync(provider: str, key: str, secret: str | None) -> dict:
    p = provider
    if p == "auto":
        p = detect_provider(key)
    if p == "payu":
        return {"provider": "payu", "valid": None, "summary": {}, "capabilities": {}, "notes": [],
                "error": "PayU merchant APIs are region-specific and require merchant key + salt with per-request SHA-512 hashing — a single key can't be enumerated read-only. Verify manually in the PayU dashboard."}
    if p == "stripe":
        res = stripe_inspect(key)
        # sk_ keys are shared by Stripe and Paystack — fall back on hard auth failure
        if not res.get("valid") and (key.startswith("sk_") or key.startswith("pk_")):
            ps = paystack_inspect(key)
            if ps.get("valid"):
                ps["notes"] = (ps.get("notes") or []) + ["Auto-detected as Paystack (Stripe auth failed)."]
                return ps
        return res
    if p == "paystack":
        return paystack_inspect(key)
    if p == "flutterwave":
        return flutterwave_inspect(key)
    if p == "razorpay":
        return razorpay_inspect(key, secret)
    if p == "paypal":
        return paypal_inspect(key, secret)
    if p == "square":
        return square_inspect(key)
    return {"provider": "unknown", "valid": False, "summary": {}, "capabilities": {}, "notes": [],
            "error": "Could not detect provider from this key. Pick a provider from the dropdown."}


@router.post("/inspect")
async def inspect(data: KeyInspectInput):
    key = (data.key or "").strip()
    if not key:
        return {"provider": data.provider, "valid": False, "error": "No key provided.", "notes": []}
    res = await asyncio.to_thread(_inspect_sync, data.provider, key, data.secret)
    res["masked_key"] = _mask(key)
    return res
