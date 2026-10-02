from fastapi import APIRouter, Request, HTTPException
import requests

router = APIRouter(prefix="/tools", tags=["tools"])

FIELDS = ("status,message,country,countryCode,region,regionName,city,zip,lat,lon,"
          "timezone,isp,org,as,query,proxy,hosting,mobile")


def _client_ip(request: Request) -> str:
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else ""


@router.get("/ipinfo")
async def ipinfo(request: Request, ip: str = ""):
    target = ip.strip()
    detected_self = False
    if not target:
        target = _client_ip(request)
        detected_self = True
    try:
        r = requests.get(f"http://ip-api.com/json/{target}?fields={FIELDS}", timeout=8,
                         headers={"User-Agent": "InsafeLabs-Scanner/1.0"})
        data = r.json()
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Geo lookup failed: {str(e)[:120]}")
    if data.get("status") != "success":
        raise HTTPException(status_code=404, detail=data.get("message", "Lookup failed"))
    data["is_self"] = detected_self
    return data
