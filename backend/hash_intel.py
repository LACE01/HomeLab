"""Automated file-hash reputation checking against VirusTotal, wired into every
place this app already computes a sha256 (currently just yara_scan.py's upload
scanner) -- closes the gap between "we have a hash" and "someone remembered to
paste it into the Recon & OSINT hub" that existed before this module.

Reuses reconng.run_virustotal_lookup (the same VT hash-reputation call the
manual on-demand lookup uses) rather than a second VT client, so behavior/rate
limit handling stays identical between the manual and automated paths.

A real VT hit doesn't just get logged -- it's auto-added to the IOC watchlist
(threat_intel_watchlist.add_ioc) so the exact same hash is instantly caught by
match_ioc() everywhere else in the app going forward, without waiting for
another VT lookup.

Rate-limit posture: VT's free tier is ~4 requests/minute. A single file scan
is one hash, one call -- fine inline. The nightly backlog sweep (for hashes
seen before this feature existed, or checked before VT was configured) is
capped and spaced out the same way albert_enrichment.auto_enrich_top_ips is.
"""
import uuid
from datetime import datetime, timezone
from typing import Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def check_hash_virustotal(db, sha256: str, *, entity_type: str = "file",
                                 entity_id: Optional[str] = None,
                                 entity_label: Optional[str] = None) -> dict:
    """Checks one sha256 against VirusTotal and records the outcome. Never
    raises -- a missing/misconfigured VT integration or a transient API error
    is recorded as a status, not an exception, since this is meant to run
    automatically alongside a scan the user is actively waiting on (or fully
    in the background for the nightly sweep) and shouldn't ever break the
    calling flow."""
    entity_id = entity_id or sha256
    from reconng import run_virustotal_lookup

    try:
        rows = await run_virustotal_lookup(sha256, "hash")
        status = "malicious" if rows else "clean"
        error = None
    except ValueError as e:
        # Not configured -- a normal, expected state until VirusTotal is set
        # up under Integrations, not a failure worth alarming about.
        rows, status, error = [], "not_configured", str(e)
    except Exception as e:
        rows, status, error = [], "error", str(e)

    doc = {
        "sha256": sha256, "status": status, "rows": rows, "error": error,
        "entity_type": entity_type, "entity_id": entity_id, "entity_label": entity_label,
        "checked_at": _now_iso(),
    }
    await db.hash_intel_checks.update_one({"sha256": sha256}, {"$set": doc}, upsert=True)

    if status == "malicious":
        from threat_intel_watchlist import add_ioc
        detail = "; ".join(r.get("detail", "") for r in rows if r.get("detail"))
        await add_ioc(
            db, ioc_type="hash", value=sha256, source="virustotal_auto",
            severity="High", notes=detail or "VirusTotal flagged this hash as malicious",
        )
        from security_events import emit_event
        await emit_event(
            db, source="virustotal", event_type="hash_reputation_hit", severity="High",
            title=f"VirusTotal flagged a scanned file's hash as malicious",
            entity_type=entity_type, entity_id=entity_id,
            entity_label=entity_label or sha256,
            description=f"{entity_label or sha256} (sha256 {sha256[:16]}...) matched VirusTotal's "
                        f"aggregated multi-engine detections. {detail}",
            raw={"sha256": sha256, "rows": rows},
        )
    return doc


async def get_hash_check(db, sha256: str) -> Optional[dict]:
    return await db.hash_intel_checks.find_one({"sha256": sha256}, {"_id": 0})


async def auto_check_hash_backlog(db, max_checks: int = 5) -> dict:
    """Nightly bounded sweep: picks up sha256 hashes seen in yara_scan_history
    that don't have a hash_intel_checks record yet (either scanned before this
    feature existed, or VT wasn't configured at scan time) and checks a small
    batch of the most recent ones, spaced out to stay well under VT's free-tier
    rate limit -- same shape as albert_enrichment.auto_enrich_top_ips."""
    import asyncio

    recent_scans = await db.yara_scan_history.find(
        {}, {"_id": 0, "sha256": 1, "filename": 1, "asset_id": 1, "asset_hostname": 1}
    ).sort("scanned_at", -1).to_list(500)

    seen_hashes = set()
    candidates = []
    for s in recent_scans:
        sha = s.get("sha256")
        if not sha or sha in seen_hashes:
            continue
        seen_hashes.add(sha)
        candidates.append(s)

    already_checked = await db.hash_intel_checks.distinct("sha256")
    already_checked_set = set(already_checked)
    pending = [s for s in candidates if s["sha256"] not in already_checked_set][:max_checks]

    checked = []
    for i, s in enumerate(pending):
        if i > 0:
            await asyncio.sleep(15)  # ~4/min VT free-tier ceiling
        doc = await check_hash_virustotal(
            db, s["sha256"], entity_type="asset" if s.get("asset_id") else "file",
            entity_id=s.get("asset_id") or s["sha256"],
            entity_label=s.get("asset_hostname") or s.get("filename"),
        )
        checked.append({"sha256": s["sha256"], "status": doc["status"]})

    return {
        "checked": len(checked), "results": checked,
        "candidates_seen": len(candidates), "already_checked": len(already_checked_set),
    }
