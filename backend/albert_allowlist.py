"""Known-good allowlist for Albert alerts -- lets an admin mark a source IP (a
patch-management server, an automation/admin jump host, an RMM agent, etc.) as
known-good so its routine PowerShell-over-SMB activity (the dominant, and
noisiest, signature family in a typical Albert export) doesn't have to be
triaged as if it were unexplained. This mirrors the threat-intel watchlist's
IOC concept but inverted -- "known good" instead of "known bad" -- and lives in
its own collection since the two lists are reviewed by different people for
different reasons and conflating them would be confusing.

Suppression happens at two points: (1) new alerts are checked against the
current allowlist at import time, and (2) reapply_allowlist() re-scans every
already-stored alert, for when an admin adds an allowlist entry after alerts
matching it have already been imported.
"""
import uuid
from datetime import datetime, timezone
from typing import Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def list_allowlist(db) -> list:
    return await db.albert_allowlist.find({}, {"_id": 0}).sort("created_at", -1).to_list(500)


async def add_allowlist_entry(db, source_ip: str, notes: Optional[str] = None, added_by: Optional[str] = None) -> dict:
    source_ip = (source_ip or "").strip()
    if not source_ip:
        raise ValueError("A source IP is required")
    existing = await db.albert_allowlist.find_one({"source_ip": source_ip}, {"_id": 0})
    if existing:
        return existing
    doc = {"id": str(uuid.uuid4()), "source_ip": source_ip, "notes": notes, "added_by": added_by, "created_at": _now_iso()}
    await db.albert_allowlist.insert_one(doc)
    doc.pop("_id", None)  # insert_one mutates `doc` in place, adding an ObjectId _id -- strip it before returning
    return doc


async def delete_allowlist_entry(db, entry_id: str) -> bool:
    result = await db.albert_allowlist.delete_one({"id": entry_id})
    return bool(getattr(result, "deleted_count", 0))


async def _allowlisted_ips(db) -> set:
    entries = await db.albert_allowlist.find({}, {"_id": 0, "source_ip": 1}).to_list(500)
    return {e["source_ip"] for e in entries if e.get("source_ip")}


async def check_suppressed(db, source_ip: Optional[str]) -> Optional[str]:
    """Returns a human-readable suppression reason if `source_ip` is allowlisted,
    else None. A single small query per import batch (not per-row) is done by
    the caller via _allowlisted_ips -- this helper is for the reapply path where
    checking one alert at a time against an already-fetched set is convenient."""
    if not source_ip:
        return None
    ips = await _allowlisted_ips(db)
    if source_ip in ips:
        return f"Source IP {source_ip} is on the known-good allowlist"
    return None


async def reapply_allowlist(db) -> dict:
    """Re-scans every stored Albert alert against the current allowlist and
    updates the suppressed flag accordingly -- both suppressing newly-matched
    alerts and un-suppressing ones whose allowlist entry was since removed, so
    this is safe to run any time the allowlist changes."""
    ips = await _allowlisted_ips(db)
    suppressed = 0
    unsuppressed = 0
    if ips:
        result = await db.albert_alerts.update_many(
            {"source_ip": {"$in": list(ips)}, "suppressed": {"$ne": True}},
            {"$set": {"suppressed": True, "suppressed_reason": "Source IP is on the known-good allowlist"}},
        )
        suppressed = getattr(result, "modified_count", 0)
    result2 = await db.albert_alerts.update_many(
        {"source_ip": {"$nin": list(ips)}, "suppressed": True},
        {"$set": {"suppressed": False, "suppressed_reason": None}},
    )
    unsuppressed = getattr(result2, "modified_count", 0)
    return {"suppressed": suppressed, "unsuppressed": unsuppressed, "allowlist_size": len(ips)}
