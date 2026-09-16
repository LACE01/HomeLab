"""Item 55 -- IPinfo as an IP enrichment source (Lite tier).

IPinfo is not threat intel; it's IP *context* -- country and ASN/organization.
That context is exactly what the enrichment pipelines were missing: the Albert /
CTI IP-enrichment path (albert_enrichment.enrich_ip) ran threat-intel lookups but
had no geolocation at all, and attack telemetry had Cloudflare's ASN *number* but
not the human-readable owner. IPinfo fills both.

Lite tier is free and returns country + ASN (no city/privacy flags -- those are
paid). Endpoint: GET https://api.ipinfo.io/lite/{ip}?token=...  Configured like
every other connector, under Integrations -> IPinfo (token stored as api_key).

Results are cached in db.ipinfo_cache so a busy attacker IP or a repeated Albert
destination is looked up once, not on every observation -- the free tier is
generous but not unlimited, and caching keeps ingest cheap.
"""
import ipaddress
import httpx
from datetime import datetime, timezone, timedelta
from typing import Optional

CACHE_TTL_DAYS = 30
DEFAULT_ENDPOINT = "https://api.ipinfo.io"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def is_public_ip(ip: str) -> bool:
    """Only public, routable IPs are worth (or possible) to geolocate."""
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (obj.is_private or obj.is_loopback or obj.is_reserved
                or obj.is_link_local or obj.is_multicast or obj.is_unspecified)


def _normalize(ip: str, data: dict) -> dict:
    """One shape regardless of tier, only the fields Lite guarantees."""
    asn = data.get("asn")
    return {
        "ip": ip,
        "country": data.get("country"),
        "country_code": data.get("country_code"),
        "continent": data.get("continent"),
        "asn": asn,
        "as_name": data.get("as_name"),
        "as_domain": data.get("as_domain"),
        "org": " ".join(x for x in [asn, data.get("as_name")] if x) or None,
        "source": "IPinfo (Lite)",
    }


async def _config(db) -> dict:
    integration = await db.integrations.find_one({"name": "IPinfo"}, {"_id": 0})
    return (integration or {}).get("config") or {}


def _cache_fresh(doc: dict) -> bool:
    ts = doc.get("cached_at")
    if not ts:
        return False
    try:
        when = datetime.fromisoformat(ts)
    except ValueError:
        return False
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return when > datetime.now(timezone.utc) - timedelta(days=CACHE_TTL_DAYS)


async def lookup_ip(db, ip: str, *, use_cache: bool = True) -> Optional[dict]:
    """Geo/ASN for one IP. Returns None for a private/invalid IP (nothing to
    geolocate -- not an error). Raises ValueError if IPinfo isn't configured, and
    RuntimeError on a reachable-but-failed call, so callers can distinguish
    'not set up' from 'broke' -- the same convention as the other connectors."""
    if not is_public_ip(ip):
        return None
    if use_cache:
        cached = await db.ipinfo_cache.find_one({"ip": ip}, {"_id": 0})
        if cached and _cache_fresh(cached):
            return {k: v for k, v in cached.items() if k != "cached_at"}

    cfg = await _config(db)
    token = cfg.get("api_key")
    if not token:
        raise ValueError("IPinfo isn't configured yet -- add your API token under Integrations → IPinfo first.")
    endpoint = (cfg.get("endpoint") or DEFAULT_ENDPOINT).rstrip("/")

    url = f"{endpoint}/lite/{ip}"
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.get(url, params={"token": token})
    except httpx.HTTPError as e:
        raise RuntimeError(f"Could not reach IPinfo: {e}")
    if r.status_code in (401, 403):
        raise RuntimeError("IPinfo rejected this token -- check it under Integrations → IPinfo.")
    if r.status_code == 429:
        raise RuntimeError("IPinfo rate limit hit (429).")
    if r.status_code != 200:
        raise RuntimeError(f"IPinfo HTTP {r.status_code}: {r.text[:200]}")

    out = _normalize(ip, r.json())
    await db.ipinfo_cache.update_one({"ip": ip}, {"$set": {**out, "cached_at": _now_iso()}}, upsert=True)
    return out


async def enrich_quietly(db, ip: str) -> Optional[dict]:
    """Best-effort geo/ASN for use inside another pipeline (attack telemetry
    ingest, etc.): returns the context or None, and NEVER raises -- an unconfigured
    or failing IPinfo must not block the pipeline it's enriching."""
    try:
        return await lookup_ip(db, ip)
    except Exception:
        return None


async def test_connection(cfg: dict) -> dict:
    """Validate the token with a real Lite lookup of a well-known IP."""
    token = cfg.get("api_key")
    if not token:
        return {"ok": False, "message": "No API token set. Add your IPinfo token (Integrations → IPinfo)."}
    endpoint = (cfg.get("endpoint") or DEFAULT_ENDPOINT).rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.get(f"{endpoint}/lite/8.8.8.8", params={"token": token})
    except httpx.HTTPError as e:
        return {"ok": False, "message": f"Could not reach IPinfo: {e}"}
    if r.status_code in (401, 403):
        return {"ok": False, "message": "IPinfo rejected this token (check it's a valid Lite/API token)."}
    if r.status_code != 200:
        return {"ok": False, "message": f"IPinfo HTTP {r.status_code}: {r.text[:150]}"}
    data = r.json()
    return {"ok": True, "message": f"Connected — resolved 8.8.8.8 to {data.get('as_name') or data.get('asn')} "
                                    f"in {data.get('country') or '?'}."}
