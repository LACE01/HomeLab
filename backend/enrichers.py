"""Threat-intel enrichers — pull KEV (CISA), EPSS (FIRST.org), and Exploit-DB
(community-maintained public exploit index) and stamp results on findings.

These are called from the admin endpoints and the nightly rescore loop.
"""
import csv
import io
import logging
import re
from datetime import datetime, timezone

import httpx

logger = logging.getLogger("vulnops.enrichers")

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
# Community-maintained CSV index (no API key required). Same project that runs
# exploit-db.com / searchsploit -- "codes" column carries CVE/OSVDB/etc references.
EXPLOITDB_CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
CVE_IN_CODES_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
OPEN_STATES = ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]


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
    EPSS is free / no key. We chunk requests (100 CVEs per call) and stamp `epss_score`.
    Non-200 responses used to be swallowed silently (just `continue`), which meant a
    rate limit, an outbound-network block, or an API change would report back
    status="success", matched=0 -- indistinguishable from "nothing needed scoring" and
    with nothing for an admin to act on. Failed chunks are now recorded and surfaced,
    and the call is marked "failed" if every chunk failed so the sync-now button
    actually shows an error instead of a quiet false "success"."""
    raw = await db.findings.distinct("cve")
    cves = [c for c in raw if c and isinstance(c, str) and c.startswith("CVE-")]
    if not cves:
        return {"status": "success", "matched": 0, "lookups": 0, "synced_at": _now_iso()}

    matched = 0
    lookups = 0
    chunk_errors: list = []
    epss_map: dict = {}
    try:
        async with httpx.AsyncClient(timeout=60) as c:
            for i in range(0, len(cves), 100):
                chunk = cves[i:i + 100]
                r = await c.get(EPSS_URL, params={"cve": ",".join(chunk)})
                lookups += 1
                if r.status_code != 200:
                    chunk_errors.append(f"HTTP {r.status_code} for {len(chunk)} CVE(s): {r.text[:200]}")
                    continue
                for row in (r.json().get("data") or []):
                    if row.get("cve") and row.get("epss") is not None:
                        epss_map[row["cve"]] = float(row["epss"])
    except Exception as e:
        return {"status": "failed", "error": str(e), "matched": 0, "lookups": lookups, "chunk_errors": chunk_errors}

    if lookups > 0 and len(chunk_errors) == lookups:
        # Every single chunk failed -- this is a real failure (network/API/rate-limit
        # issue), not "no CVEs matched", so don't report status="success".
        return {"status": "failed", "error": chunk_errors[0], "chunk_errors": chunk_errors,
                "matched": 0, "lookups": lookups, "synced_at": _now_iso()}

    # Bulk update findings. Uses $addToSet/$pull on rti rather than overwriting the
    # whole array, since a blind `{"rti": [...]}` $set here used to wipe out any other
    # rti flags (e.g. "zero_day"/"wormable" set elsewhere) every time EPSS synced.
    for cve, score in epss_map.items():
        update: dict = {"$set": {"epss_score": score}}
        if score >= 0.50:
            update["$addToSet"] = {"rti": "active_attacks"}
        else:
            update["$pull"] = {"rti": "active_attacks"}
        r = await db.findings.update_many({"cve": cve}, update)
        matched += r.modified_count

    result = {"status": "success", "matched": matched, "lookups": lookups,
              "cves_with_score": len(epss_map), "synced_at": _now_iso()}
    if chunk_errors:
        result["chunk_errors"] = chunk_errors  # partial failure -- some chunks still worked
    return result


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

    # rti is a multi-membership flag array (scoring.py checks several flags independently --
    # active_attacks, public_exploit, zero_day, etc.) so these use $addToSet/$pull on the
    # single 'active_attacks' member rather than overwriting the whole array, which would
    # wipe out unrelated flags like public_exploit set by sync_exploitdb.
    kev_recent = await db.findings.update_many(
        {'kev_flag': True, 'first_seen_at': {'$gte': cutoff}, 'status': {'$in': open_states}},
        {'$addToSet': {'rti': 'active_attacks'}},
    )
    high_epss = await db.findings.update_many(
        {'epss_score': {'$gte': 0.50}, 'status': {'$in': open_states}},
        {'$addToSet': {'rti': 'active_attacks'}},
    )
    # Clear the flag for anything that no longer qualifies (KEV cleared, aged out, EPSS dropped)
    cleared = await db.findings.update_many(
        {'rti': 'active_attacks', 'status': {'$in': open_states},
         '$and': [
             {'$or': [{'kev_flag': {'$ne': True}}, {'first_seen_at': {'$lt': cutoff}}]},
             {'$or': [{'epss_score': None}, {'epss_score': {'$lt': 0.50}}]},
         ]},
        {'$pull': {'rti': 'active_attacks'}},
    )
    return {'status': 'success', 'flagged_kev_recent': kev_recent.modified_count,
            'flagged_high_epss': high_epss.modified_count, 'cleared': cleared.modified_count,
            'synced_at': _now_iso()}


async def sync_exploitdb(db) -> dict:
    """Download the Exploit-DB CSV index (community-maintained, no API key needed --
    the same source that powers exploit-db.com / searchsploit) and match entries to
    findings by CVE. Adds exploit_references (concrete public PoC/exploit links) and
    flags rti += public_exploit, then recomputes risk_score for matched findings so
    the extra context is visible immediately instead of waiting for the next nightly
    rescore. Findings whose CVE drops out of the catalog (rare -- exploit-db only
    grows, but a finding's CVE could get corrected) have their references cleared."""
    try:
        async with httpx.AsyncClient(timeout=120, follow_redirects=True) as c:
            r = await c.get(EXPLOITDB_CSV_URL)
            r.raise_for_status()
            text = r.text
    except Exception as e:
        return {"status": "failed", "error": str(e), "matched": 0}

    cve_map: dict = {}
    try:
        reader = csv.DictReader(io.StringIO(text))
        for row in reader:
            codes = row.get("codes") or row.get("Codes") or ""
            cves = set(m.upper() for m in CVE_IN_CODES_RE.findall(codes))
            if not cves:
                continue
            edb_id = row.get("id") or row.get("ID")
            entry = {
                "edb_id": edb_id,
                "title": (row.get("description") or row.get("Description") or "").strip()[:200],
                "url": f"https://www.exploit-db.com/exploits/{edb_id}" if edb_id else None,
                "date_published": row.get("date_published") or row.get("Date Published"),
                "verified": (row.get("verified") or row.get("Verified") or "").strip() in ("1", "True", "true"),
                "type": row.get("type") or row.get("Type"),
                "platform": row.get("platform") or row.get("Platform"),
            }
            for cve in cves:
                cve_map.setdefault(cve, []).append(entry)
    except Exception as e:
        return {"status": "failed", "error": f"CSV parse error: {e}", "matched": 0}

    if not cve_map:
        return {"status": "failed", "error": "No CVE-tagged entries parsed from the Exploit-DB CSV", "matched": 0}

    await db.exploitdb_catalog.delete_many({})
    await db.exploitdb_catalog.insert_many(
        [{"cve_id": cve, "exploits": entries[:10], "synced_at": _now_iso()} for cve, entries in cve_map.items()]
    )

    from scoring import compute_risk
    matched = 0
    cursor = db.findings.find({"cve": {"$in": list(cve_map.keys())}, "status": {"$in": OPEN_STATES}}, {"_id": 0})
    async for f in cursor:
        entries = cve_map.get(f.get("cve"), [])[:5]
        asset = await db.assets.find_one({"id": f.get("asset_id")}, {"_id": 0}) or {}
        new_rti = list(dict.fromkeys((f.get("rti") or []) + ["public_exploit"]))
        f_tmp = {**f, "exploit_references": entries, "rti": new_rti}
        risk = compute_risk(f_tmp, asset)
        await db.findings.update_one({"id": f["id"]}, {"$set": {
            "exploit_references": entries, "risk_score": risk["score"], "risk_breakdown": risk["breakdown"],
            "exploitdb_synced_at": _now_iso(),
        }, "$addToSet": {"rti": "public_exploit"}})
        matched += 1

    stale = await db.findings.update_many(
        {"exploit_references": {"$exists": True, "$ne": []}, "cve": {"$nin": list(cve_map.keys())}},
        {"$set": {"exploit_references": []}, "$pull": {"rti": "public_exploit"}},
    )

    return {"status": "success", "catalog_cves": len(cve_map), "matched": matched,
            "cleared": stale.modified_count, "synced_at": _now_iso()}
