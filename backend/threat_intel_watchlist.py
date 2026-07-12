"""Threat intel watchlist -- a persistent, growing list of known-bad IOCs (IPs,
domains, hashes) that gets checked automatically against new assets/findings/
files, instead of the existing recon-ng threat-intel modules which only check
one target at a time when someone remembers to run them.

Two ways IOCs land here: manually added/pasted by an analyst (source="manual"),
or pulled in bulk from abuse.ch's ThreatFox feed on a schedule
(source="abuse.ch_threatfox_feed", via sync_threatfox_feed below) -- reusing the
same "abuse.ch (ThreatFox)" integration config (Auth-Key) the existing on-demand
recon-ng module already uses, just calling ThreatFox's bulk `get_iocs` query
instead of a per-target `search_ioc` lookup.

match_ioc() is the one function other modules call to check a value against this
list -- see its call sites in qualys_sync.py (new asset IP) and yara_scan.py (file
hash) for the pattern to copy when wiring up a new one.
"""
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

IOC_TYPES = ["ip", "domain", "hash", "url"]

# ThreatFox's own ioc_type values, normalized down to our 4 buckets.
_THREATFOX_TYPE_MAP = {
    "ip:port": "ip", "ip": "ip", "domain": "domain", "url": "url",
    "md5_hash": "hash", "sha1_hash": "hash", "sha256_hash": "hash",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize(value: str) -> str:
    # "1.2.3.4:8080" (ThreatFox's ip:port shape) -> just the IP, since that's what
    # we'll actually be comparing asset/finding IPs against.
    v = (value or "").strip().lower()
    if v.count(":") == 1 and v.split(":")[0].replace(".", "").isdigit():
        v = v.split(":")[0]
    return v


async def add_ioc(db, *, ioc_type: str, value: str, source: str = "manual", severity: str = "High",
                   notes: Optional[str] = None, added_by: Optional[str] = None) -> dict:
    from routes.common import _clean
    value_norm = _normalize(value)
    existing = await db.ioc_watchlist.find_one({"value": value_norm}, {"_id": 0})
    if existing:
        return existing
    doc = {
        "id": str(uuid.uuid4()), "ioc_type": ioc_type, "value": value_norm, "source": source,
        "severity": severity, "notes": notes, "added_by": added_by, "added_at": _now_iso(),
        "hits": 0, "last_hit_at": None,
    }
    await db.ioc_watchlist.insert_one(doc)
    return _clean(doc)


async def match_ioc(db, value: str) -> Optional[dict]:
    """Exact, case-insensitive match. Bumps hit count/last_hit_at on the watchlist
    entry itself so 'how often has this actually been seen' is visible from the
    watchlist page, not just from the security_events it generates."""
    if not value:
        return None
    value_norm = _normalize(value)
    doc = await db.ioc_watchlist.find_one({"value": value_norm}, {"_id": 0})
    if not doc:
        return None
    await db.ioc_watchlist.update_one({"value": value_norm}, {"$set": {"last_hit_at": _now_iso()}, "$inc": {"hits": 1}})
    doc["hits"] = doc.get("hits", 0) + 1
    return doc


async def check_and_emit(db, value: str, *, entity_type: str, entity_id: str, entity_label: str) -> Optional[dict]:
    """Convenience wrapper: match_ioc() + emit_event() together, since every call
    site wants both. Returns the matched watchlist doc, or None."""
    match = await match_ioc(db, value)
    if not match:
        return None
    from security_events import emit_event
    await emit_event(
        db, source="threat_intel", event_type="ioc_match", severity=match.get("severity", "High"),
        title=f"Known-bad {match['ioc_type']} matched: {match['value']}",
        entity_type=entity_type, entity_id=entity_id, entity_label=entity_label,
        description=f"{entity_label or entity_id} matched a watchlisted {match['ioc_type']} "
                    f"(source: {match['source']}){' -- ' + match['notes'] if match.get('notes') else ''}.",
        raw={"watchlist_id": match["id"], "matched_value": match["value"]},
    )
    return match


async def sync_threatfox_feed(db, days: int = 3) -> dict:
    """Pulls ThreatFox's recent-IOCs bulk feed (their documented `get_iocs` query,
    not the per-target `search_ioc` the recon-ng module uses) and upserts everything
    into the watchlist. Requires the same Auth-Key already configured under
    Integrations -> abuse.ch (ThreatFox) for the on-demand lookup module."""
    import httpx
    integration = await db.integrations.find_one({"name": "abuse.ch (ThreatFox)"}, {"_id": 0})
    cfg = (integration or {}).get("config") or {}
    endpoint = cfg.get("endpoint") or "https://threatfox-api.abuse.ch"
    auth_key = cfg.get("api_key")
    if not auth_key:
        raise ValueError("abuse.ch (ThreatFox) isn't configured -- add an Auth-Key under Integrations -> "
                          "abuse.ch (ThreatFox) first (free at https://auth.abuse.ch/).")

    url = f"{endpoint.rstrip('/')}/api/v1/"
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(url, headers={"Auth-Key": auth_key}, json={"query": "get_iocs", "days": days})
    r.raise_for_status()
    data = r.json()
    if data.get("query_status") != "ok":
        return {"ok": True, "added": 0, "note": "no IOCs returned for this window"}

    added = 0
    for ioc in data.get("data") or []:
        ioc_type = _THREATFOX_TYPE_MAP.get(ioc.get("ioc_type"), None)
        if not ioc_type:
            continue
        value = _normalize(ioc.get("ioc", ""))
        if not value:
            continue
        existing = await db.ioc_watchlist.find_one({"value": value})
        if existing:
            continue
        await db.ioc_watchlist.insert_one({
            "id": str(uuid.uuid4()), "ioc_type": ioc_type, "value": value,
            "source": "abuse.ch_threatfox_feed", "severity": "High",
            "notes": f"{ioc.get('malware_printable') or ioc.get('threat_type', 'malware IOC')} "
                     f"(confidence {ioc.get('confidence_level', '?')})",
            "added_by": None, "added_at": _now_iso(), "hits": 0, "last_hit_at": None,
        })
        added += 1
    return {"ok": True, "added": added, "seen": len(data.get("data") or [])}
