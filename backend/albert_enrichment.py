"""On-demand + auto-triggered enrichment of Albert alert destination IPs against
the app's existing threat-intel connectors -- reuses the exact same single-
indicator lookup functions the recon-ng OSINT hub uses (see reconng.py), so
results behave identically to a manual recon-ng run and land in the same
db.osint_findings collection, not a parallel one only Albert knows about.

Deliberately excludes Shodan/Censys here -- those are asset/host-exposure tools
(open ports, banners, on-prem inventory matching) rather than threat-intel
classification, and this feature is about "does anything already think this IP
is bad", not "what does this host expose". Shodan/Censys are still available
from the Recon & OSINT hub for anyone who wants a broader lookup on a specific
IP by hand.

Rate-limit posture: these are real external APIs, several with tight free-tier
quotas (GreyNoise Community in particular -- "a handful of lookups per week").
Automatic enrichment at import time is therefore capped to a small number of
the most-frequently-seen public destination IPs (see auto_enrich_top_ips),
spaced out with a short delay between each; anything beyond that cap is left
for a deliberate, one-at-a-time "Enrich now" click.
"""
import asyncio
import uuid
from datetime import datetime, timezone
from typing import Optional

CONNECTOR_NAMES = ["OpenCTI", "GreyNoise", "AlienVault OTX", "abuse.ch (ThreatFox)"]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def enrich_ip(db, ip: str) -> dict:
    """Runs every threat-intel connector against a single IP and stores/returns
    a consolidated result. Each connector's outcome is one of:
      - "found"          -- the connector returned one or more hits
      - "clean"          -- reachable, configured, nothing on record for this IP
      - "not_configured" -- connector has no endpoint/API key set yet (not an error)
      - "error"          -- reachable connector call failed (bad key, rate limit, etc.)
    A single connector being unconfigured or erroring never blocks the others."""
    from reconng import run_opencti_lookup, run_greynoise_lookup, run_otx_lookup, run_abusech_lookup

    lookups = [
        ("OpenCTI", run_opencti_lookup(ip)),
        ("GreyNoise", run_greynoise_lookup(ip)),
        ("AlienVault OTX", run_otx_lookup(ip, "ip")),
        ("abuse.ch (ThreatFox)", run_abusech_lookup(ip)),
    ]
    results = []
    for source, coro in lookups:
        try:
            rows = await coro
            results.append({"source": source, "status": "found" if rows else "clean", "rows": rows, "error": None})
        except ValueError as e:
            results.append({"source": source, "status": "not_configured", "rows": [], "error": str(e)})
        except Exception as e:
            results.append({"source": source, "status": "error", "rows": [], "error": str(e)})

    doc = {"ip": ip, "results": results, "checked_at": _now_iso()}
    await db.albert_ip_enrichment.update_one({"ip": ip}, {"$set": doc}, upsert=True)

    # Mirror any real hits into db.osint_findings -- the same collection the
    # recon-ng hub writes to -- so a finding shows up in one place regardless of
    # whether it was discovered via a manual recon-ng run or an Albert import.
    for r in results:
        for row in r["rows"]:
            key = f"albert:{r['source']}:{ip}:{row.get('name','')}"
            existing = await db.osint_findings.find_one({"key": key}, {"_id": 0})
            if existing:
                continue
            await db.osint_findings.insert_one({
                "id": str(uuid.uuid4()), "key": key, "module": "albert-enrichment",
                "module_label": f"Albert -> {r['source']}", "target": ip,
                "label": row.get("name"), "detail": row.get("detail"), "raw": row,
                "found_at": _now_iso(), "acknowledged": False,
            })
    return doc


async def get_enrichment(db, ip: str) -> Optional[dict]:
    return await db.albert_ip_enrichment.find_one({"ip": ip}, {"_id": 0})


async def auto_enrich_top_ips(db, ips: list, max_ips: int = 8) -> dict:
    """Bounded automatic enrichment run, meant to be scheduled as a background
    task right after an Albert import finishes -- only the top `max_ips` (by
    caller-supplied order, expected to be "most frequent public destination IP
    first") get auto-checked, one at a time with a short delay between each, so
    a large import doesn't burn through a tight free-tier quota in one shot."""
    enriched = []
    for i, ip in enumerate(ips[:max_ips]):
        if i > 0:
            await asyncio.sleep(1)
        try:
            doc = await enrich_ip(db, ip)
            hit_count = sum(len(r["rows"]) for r in doc["results"])
            enriched.append({"ip": ip, "ok": True, "hit_count": hit_count})
        except Exception as e:
            enriched.append({"ip": ip, "ok": False, "error": str(e)})
    return {"enriched": enriched}
