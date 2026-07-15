"""Known-good allowlist for Albert alerts -- lets an admin mark traffic (a
patch-management server, an automation/admin jump host, an RMM agent, etc.) as
known-good so its routine PowerShell-over-SMB activity (the dominant, and
noisiest, signature family in a typical Albert export) doesn't have to be
triaged as if it were unexplained. This mirrors the threat-intel watchlist's
IOC concept but inverted -- "known good" instead of "known bad" -- and lives in
its own collection since the two lists are reviewed by different people for
different reasons and conflating them would be confusing.

An entry can match on source_ip, destination_ip, or both:
  - source_ip only: suppress this host's traffic no matter where it talks to
    (the original behavior).
  - destination_ip only: suppress traffic *to* a known-good target (e.g. a
    patch/update server) no matter which host initiates it -- this is what
    catches an automation account that moves to a new source address, since
    the thing that stays constant is the service it talks to.
  - both: suppress only that specific source->destination pair, for a tighter
    match when a broader rule would be too permissive.
At least one of the two fields is required.

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


async def add_allowlist_entry(db, source_ip: Optional[str] = None, destination_ip: Optional[str] = None,
                               notes: Optional[str] = None, added_by: Optional[str] = None) -> dict:
    source_ip = (source_ip or "").strip() or None
    destination_ip = (destination_ip or "").strip() or None
    if not source_ip and not destination_ip:
        raise ValueError("A source IP and/or destination IP is required")
    existing = await db.albert_allowlist.find_one({"source_ip": source_ip, "destination_ip": destination_ip}, {"_id": 0})
    if existing:
        return existing
    doc = {
        "id": str(uuid.uuid4()), "source_ip": source_ip, "destination_ip": destination_ip,
        "notes": notes, "added_by": added_by, "created_at": _now_iso(),
    }
    await db.albert_allowlist.insert_one(doc)
    doc.pop("_id", None)  # insert_one mutates `doc` in place, adding an ObjectId _id -- strip it before returning
    return doc


async def delete_allowlist_entry(db, entry_id: str) -> bool:
    result = await db.albert_allowlist.delete_one({"id": entry_id})
    return bool(getattr(result, "deleted_count", 0))


async def _allowlist_entries(db) -> list:
    return await db.albert_allowlist.find({}, {"_id": 0}).to_list(500)


def _matches_entry(entry: dict, source_ip: Optional[str], destination_ip: Optional[str]) -> bool:
    e_src = entry.get("source_ip")
    e_dst = entry.get("destination_ip")
    if not e_src and not e_dst:
        return False
    if e_src and e_src != source_ip:
        return False
    if e_dst and e_dst != destination_ip:
        return False
    return True


def _reason_for_entry(entry: dict) -> str:
    parts = []
    if entry.get("source_ip"):
        parts.append(f"source IP {entry['source_ip']}")
    if entry.get("destination_ip"):
        parts.append(f"destination IP {entry['destination_ip']}")
    return f"{' and '.join(parts)} on the known-good allowlist"


def suppression_reason(entries: list, source_ip: Optional[str], destination_ip: Optional[str]) -> Optional[str]:
    """Pure sync helper (no DB access) so callers that already fetched the
    entries list once -- e.g. the row loop during import -- don't re-query per
    row. Returns the human-readable reason for the first matching entry, or
    None."""
    for entry in entries:
        if _matches_entry(entry, source_ip, destination_ip):
            return _reason_for_entry(entry)
    return None


async def check_suppressed(db, source_ip: Optional[str], destination_ip: Optional[str] = None) -> Optional[str]:
    """Returns a human-readable suppression reason if the given source/destination
    IP pair matches an allowlist entry, else None."""
    if not source_ip and not destination_ip:
        return None
    entries = await _allowlist_entries(db)
    return suppression_reason(entries, source_ip, destination_ip)


async def reapply_allowlist(db) -> dict:
    """Re-scans every stored Albert alert against the current allowlist and
    updates the suppressed flag accordingly -- both suppressing newly-matched
    alerts and un-suppressing ones whose allowlist entry was since removed, so
    this is safe to run any time the allowlist changes. Match logic now covers
    source_ip, destination_ip, or both, so this evaluates each alert in Python
    rather than relying on a single $in query."""
    entries = await _allowlist_entries(db)
    suppressed = 0
    unsuppressed = 0
    cursor = db.albert_alerts.find({}, {"_id": 0, "id": 1, "source_ip": 1, "destination_ip": 1, "suppressed": 1})
    alerts = await cursor.to_list(100000)
    for alert in alerts:
        reason = suppression_reason(entries, alert.get("source_ip"), alert.get("destination_ip"))
        should_suppress = reason is not None
        currently_suppressed = bool(alert.get("suppressed"))
        if should_suppress and not currently_suppressed:
            await db.albert_alerts.update_one({"id": alert["id"]}, {"$set": {"suppressed": True, "suppressed_reason": reason}})
            suppressed += 1
        elif not should_suppress and currently_suppressed:
            await db.albert_alerts.update_one({"id": alert["id"]}, {"$set": {"suppressed": False, "suppressed_reason": None}})
            unsuppressed += 1
    return {"suppressed": suppressed, "unsuppressed": unsuppressed, "allowlist_size": len(entries)}
