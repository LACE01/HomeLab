"""Threat-intel enrichers — pull KEV (CISA) and EPSS (FIRST.org) and stamp on findings.

These are called from the admin endpoints and the nightly rescore loop.
"""
import logging
from datetime import datetime, timezone

import httpx

logger = logging.getLogger("vulnops.enrichers")

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def sync_kev(db) -> dict:
    """Download CISA KEV catalog, set kev_flag=True on every finding whose CVE matches.
    Stores the catalog snapshot in `kev_catalog` collection for audit + offline lookup."""
    try:
        async with httpx.AsyncClient(timeout=60) as c:
            r = await c.get(CISA_KEV_URL)
            r.raise_for_status()
            data = r.json()
    except Exception as e:
        return {"status": "failed", "error": str(e), "matched": 0, "catalog_size": 0}

    catalog = data.get("vulnerabilities") or []
    kev_cves = {v["cveID"]: v for v in catalog if v.get("cveID")}

    # Persist catalog snapshot
    await db.kev_catalog.delete_many({})
    if kev_cves:
        await db.kev_catalog.insert_many(
            [{"cve_id": k, "vendor": v.get("vendorProject"), "product": v.get("product"),
              "name": v.get("vulnerabilityName"), "date_added": v.get("dateAdded"),
              "ransomware": v.get("knownRansomwareCampaignUse") == "Known",
              "required_action": v.get("requiredAction"), "due_date": v.get("dueDate"),
              "synced_at": _now_iso()} for k, v in kev_cves.items()]
        )

    # Stamp findings
    matched = await db.findings.update_many(
        {"cve": {"$in": list(kev_cves.keys())}},
        {"$set": {"kev_flag": True, "kev_synced_at": _now_iso()}},
    )
    # Clear stale flags
    await db.findings.update_many(
        {"kev_flag": True, "cve": {"$nin": list(kev_cves.keys())}},
        {"$set": {"kev_flag": False}},
    )
    return {"status": "success", "catalog_size": len(kev_cves), "matched": matched.modified_count, "synced_at": _now_iso()}


async def sync_epss(db) -> dict:
    """Pull EPSS scores from FIRST.org for every unique CVE currently in our findings.
    EPSS is free / no key. We chunk requests (100 CVEs per call) and stamp `epss_score`."""
    raw = await db.findings.distinct("cve")
    cves = [c for c in raw if c and isinstance(c, str) and c.startswith("CVE-")]
    if not cves:
        return {"status": "success", "matched": 0, "lookups": 0, "synced_at": _now_iso()}

    matched = 0
    lookups = 0
    epss_map: dict = {}
    try:
        async with httpx.AsyncClient(timeout=60) as c:
            for i in range(0, len(cves), 100):
                chunk = cves[i:i + 100]
                r = await c.get(EPSS_URL, params={"cve": ",".join(chunk)})
                lookups += 1
                if r.status_code != 200:
                    continue
                for row in (r.json().get("data") or []):
                    if row.get("cve") and row.get("epss") is not None:
                        epss_map[row["cve"]] = float(row["epss"])
    except Exception as e:
        return {"status": "failed", "error": str(e), "matched": 0, "lookups": lookups}

    # Bulk update findings
    for cve, score in epss_map.items():
        # Active-attack heuristic: EPSS >= 0.50 → flag as "active_attacks"
        r = await db.findings.update_many(
            {"cve": cve},
            {"$set": {"epss_score": score,
                      "rti": ["active_attacks"] if score >= 0.50 else []}}
        )
        matched += r.modified_count

    return {"status": "success", "matched": matched, "lookups": lookups,
            "cves_with_score": len(epss_map), "synced_at": _now_iso()}


async def flag_active_attacks(db, recency_days: int = 45) -> dict:
    """Practical proxy for 'active exploitation' since there's no dedicated threat-intel
    feed wired up: a finding is flagged rti=active_attacks if it's KEV-listed (confirmed
    exploited in the wild by CISA) AND was first observed recently in our own environment
    (still an open, fresh exposure rather than something already long remediated/stale).
    Also honors EPSS>=0.50 (very high near-term exploitation probability) as an
    independent trigger, since sync_epss already computes that signal."""
    from datetime import timedelta
    cutoff = (datetime.now(timezone.utc) - timedelta(days=recency_days)).isoformat()
    open_states = ['New', 'Needs triage', 'Valid', 'Reopened', 'Fixed pending validation']

    kev_recent = await db.findings.update_many(
        {'kev_flag': True, 'first_seen_at': {'$gte': cutoff}, 'status': {'$in': open_states}},
        {'$set': {'rti': ['active_attacks']}},
    )
    high_epss = await db.findings.update_many(
        {'epss_score': {'$gte': 0.50}, 'status': {'$in': open_states},
         'rti': {'$ne': ['active_attacks']}},
        {'$set': {'rti': ['active_attacks']}},
    )
    # Clear the flag for anything that no longer qualifies (KEV cleared, aged out, EPSS dropped)
    cleared = await db.findings.update_many(
        {'rti': ['active_attacks'], 'status': {'$in': open_states},
         '$and': [
             {'$or': [{'kev_flag': {'$ne': True}}, {'first_seen_at': {'$lt': cutoff}}]},
             {'$or': [{'epss_score': None}, {'epss_score': {'$lt': 0.50}}]},
         ]},
        {'$set': {'rti': []}},
    )
    return {'status': 'success', 'flagged_kev_recent': kev_recent.modified_count,
            'flagged_high_epss': high_epss.modified_count, 'cleared': cleared.modified_count,
            'synced_at': _now_iso()}
