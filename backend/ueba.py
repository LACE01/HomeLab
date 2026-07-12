"""UEBA (user/entity behavior analytics) signals -- looks at each successful login
against the account's own recent history and raises a security_event for a new IP,
a new country, or "impossible travel" (two logins from genuinely different places
closer together in time than any real trip between them could be).

This is intentionally best-effort enrichment, never a login gate: every check
here runs AFTER a login has already fully succeeded (see routes/auth.py's
_complete_login, which fires this as a background task, not something the
request waits on), and every failure mode (no history yet, geo lookup
unreachable, malformed timestamp) just skips the specific signal rather than
raising -- a user's login must never fail or be delayed because a third-party
geolocation lookup timed out.

Geolocation comes from ip-api.com's free endpoint (no API key, generous enough
rate limit for a self-hosted app's login volume) and is cached in
db.ip_geo_cache since the same IPs recur constantly (home/office IPs, VPN
egress, etc.) -- there's no reason to re-look-up an IP that hasn't moved.
"""
from datetime import datetime, timezone
from math import radians, sin, cos, sqrt, atan2

import httpx

_PLAUSIBLE_KMH = 900  # generous upper bound -- faster than any commercial flight's average speed
_LOCAL_IPS = {"unknown", "127.0.0.1", "testclient", "::1"}


async def _geo_lookup(db, ip: str) -> dict | None:
    if not ip or ip in _LOCAL_IPS:
        return None
    cached = await db.ip_geo_cache.find_one({"ip": ip}, {"_id": 0})
    if cached:
        return cached
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.get(f"http://ip-api.com/json/{ip}",
                                  params={"fields": "status,country,countryCode,lat,lon"})
            data = r.json()
        if data.get("status") != "success":
            return None
        doc = {
            "ip": ip, "country": data.get("country"), "country_code": data.get("countryCode"),
            "lat": data.get("lat"), "lon": data.get("lon"),
            "cached_at": datetime.now(timezone.utc).isoformat(),
        }
        await db.ip_geo_cache.update_one({"ip": ip}, {"$set": doc}, upsert=True)
        return doc
    except Exception:
        return None


def _haversine_km(lat1, lon1, lat2, lon2) -> float:
    R = 6371.0
    dlat, dlon = radians(lat2 - lat1), radians(lon2 - lon1)
    a = sin(dlat / 2) ** 2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon / 2) ** 2
    return R * 2 * atan2(sqrt(a), sqrt(1 - a))


def _parse_ts(ts: str):
    try:
        return datetime.fromisoformat((ts or "").replace("Z", "+00:00"))
    except Exception:
        return None


async def check_login_signals(db, user_id: str, email: str, ip: str, timestamp: str) -> None:
    """Run once, right after a login fully completes. Never raises."""
    from security_events import emit_event
    try:
        recent = await db.login_audit.find(
            {"user_id": user_id, "success": True}, {"_id": 0, "ip": 1, "timestamp": 1},
        ).sort("timestamp", -1).limit(20).to_list(20)

        prior_ips = {r["ip"] for r in recent if r.get("ip") and r["ip"] != ip}
        if not prior_ips:
            return  # nothing on record yet to compare this login against

        if ip not in prior_ips and ip not in _LOCAL_IPS:
            await emit_event(
                db, source="ueba", event_type="new_ip_login", severity="Low",
                title=f"{email} logged in from a new IP: {ip}",
                entity_type="user", entity_id=email, entity_label=email,
                description=f"First successful login from {ip} for this account.",
                dedupe_window_minutes=24 * 60,
            )

        geo_now = await _geo_lookup(db, ip)
        if not geo_now:
            return

        for row in recent:
            prior_ip = row.get("ip")
            if not prior_ip or prior_ip == ip:
                continue
            geo_prev = await _geo_lookup(db, prior_ip)
            if not geo_prev or not geo_prev.get("country_code") or not geo_now.get("country_code"):
                continue
            if geo_prev["country_code"] == geo_now["country_code"]:
                continue  # same country -- not a signal, keep looking further back

            t_now, t_prev = _parse_ts(timestamp), _parse_ts(row.get("timestamp"))
            hours = abs((t_now - t_prev).total_seconds()) / 3600 if (t_now and t_prev) else None

            if (hours and hours > 0 and geo_prev.get("lat") is not None and geo_now.get("lat") is not None):
                dist_km = _haversine_km(geo_prev["lat"], geo_prev["lon"], geo_now["lat"], geo_now["lon"])
                implied_kmh = dist_km / hours
                if implied_kmh > _PLAUSIBLE_KMH:
                    await emit_event(
                        db, source="ueba", event_type="impossible_travel", severity="High",
                        title=f"Impossible travel for {email}: {geo_prev['country']} -> {geo_now['country']} in {hours:.1f}h",
                        entity_type="user", entity_id=email, entity_label=email,
                        description=f"{dist_km:.0f}km between two logins {hours:.1f}h apart (~{implied_kmh:.0f}km/h implied).",
                        dedupe_window_minutes=60,
                    )
                    break
            await emit_event(
                db, source="ueba", event_type="new_country_login", severity="Medium",
                title=f"{email} logged in from a new country: {geo_now['country']}",
                entity_type="user", entity_id=email, entity_label=email,
                description=f"Previously seen country: {geo_prev['country']}.",
                dedupe_window_minutes=24 * 60,
            )
            break
    except Exception:
        pass
