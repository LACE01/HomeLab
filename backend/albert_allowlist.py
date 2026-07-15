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

Review/expiry (mirrors how Exceptions force a renewal decision instead of
silently persisting forever): an entry can carry review_days (default 180) --
once review_by passes, the entry stops matching (suppression pauses) until an
admin calls confirm_review(), so a stale "known good" host can't quietly keep
suppressing alerts indefinitely if nobody ever revisits it. review_days=None
means "permanent, no review needed" for cases where that's a deliberate call.

Every add/remove/review action is written to db.activity_log (entity_type
"albert_allowlist") so it shows up in the existing Global Audit Log view
without any new UI, the same collection routes/risk_register.py already logs
to for risk changes.

Suppression happens at two points: (1) new alerts are checked against the
current allowlist at import time, and (2) reapply_allowlist() re-scans every
already-stored alert, for when an admin adds an allowlist entry, or a review
lapses/gets confirmed, after alerts matching it have already been imported.
"""
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _log(db, action: str, entry_id: str, actor: Optional[str], details: str) -> None:
    await db.activity_log.insert_one({
        "id": str(uuid.uuid4()), "entity_type": "albert_allowlist", "entity_id": entry_id,
        "action": f"albert_allowlist_{action}", "actor": actor or "system",
        "timestamp": _now_iso(), "details": details,
    })


async def list_allowlist(db) -> list:
    return await db.albert_allowlist.find({}, {"_id": 0}).sort("created_at", -1).to_list(500)


async def add_allowlist_entry(db, source_ip: Optional[str] = None, destination_ip: Optional[str] = None,
                               notes: Optional[str] = None, added_by: Optional[str] = None,
                               review_days: Optional[int] = 180) -> dict:
    source_ip = (source_ip or "").strip() or None
    destination_ip = (destination_ip or "").strip() or None
    if not source_ip and not destination_ip:
        raise ValueError("A source IP and/or destination IP is required")
    existing = await db.albert_allowlist.find_one({"source_ip": source_ip, "destination_ip": destination_ip}, {"_id": 0})
    if existing:
        return existing
    now = _now_iso()
    review_by = (datetime.now(timezone.utc) + timedelta(days=review_days)).isoformat() if review_days else None
    doc = {
        "id": str(uuid.uuid4()), "source_ip": source_ip, "destination_ip": destination_ip,
        "notes": notes, "added_by": added_by, "created_at": now,
        "review_days": review_days, "review_by": review_by, "last_reviewed_at": now,
        "review_reminder_sent": False,
    }
    await db.albert_allowlist.insert_one(doc)
    doc.pop("_id", None)  # insert_one mutates `doc` in place, adding an ObjectId _id -- strip it before returning
    label = f"src {source_ip}" if source_ip else ""
    label += (" + " if label and destination_ip else "") + (f"dst {destination_ip}" if destination_ip else "")
    await _log(db, "added", doc["id"], added_by, f"Allowlisted {label}" + (f" ({notes})" if notes else ""))
    return doc


async def delete_allowlist_entry(db, entry_id: str, deleted_by: Optional[str] = None) -> bool:
    entry = await db.albert_allowlist.find_one({"id": entry_id}, {"_id": 0})
    result = await db.albert_allowlist.delete_one({"id": entry_id})
    ok = bool(getattr(result, "deleted_count", 0))
    if ok and entry:
        label = f"src {entry.get('source_ip')}" if entry.get("source_ip") else ""
        label += (" + " if label and entry.get("destination_ip") else "") + (f"dst {entry['destination_ip']}" if entry.get("destination_ip") else "")
        await _log(db, "removed", entry_id, deleted_by, f"Removed allowlist entry ({label})")
    return ok


async def confirm_allowlist_review(db, entry_id: str, actor: Optional[str] = None) -> dict:
    """Admin confirms a (possibly lapsed) entry is still valid -- pushes review_by
    forward by the entry's own review_days interval and resumes suppression."""
    entry = await db.albert_allowlist.find_one({"id": entry_id}, {"_id": 0})
    if not entry:
        raise ValueError("Allowlist entry not found")
    now = _now_iso()
    review_days = entry.get("review_days")
    review_by = (datetime.now(timezone.utc) + timedelta(days=review_days)).isoformat() if review_days else None
    update = {"last_reviewed_at": now, "review_by": review_by, "review_reminder_sent": False}
    await db.albert_allowlist.update_one({"id": entry_id}, {"$set": update})
    await _log(db, "reviewed", entry_id, actor, "Reviewed and confirmed still valid" + (f" -- next review {review_by[:10]}" if review_by else " (no further review needed)"))
    # Matching criteria changed (entry may have been lapsed and non-matching just now) --
    # reapply so any alerts that should resume being suppressed are.
    await reapply_allowlist(db)
    return {**entry, **update}


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
    review_by = entry.get("review_by")
    if review_by and review_by < _now_iso():
        return False  # review lapsed -- don't suppress until an admin re-confirms
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
    alerts and un-suppressing ones whose allowlist entry was since removed (or
    whose review has lapsed), so this is safe to run any time the allowlist
    changes. Match logic now covers source_ip, destination_ip, or both, plus
    the review-lapse check, so this evaluates each alert in Python rather than
    relying on a single $in query."""
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


async def check_allowlist_reviews(db) -> dict:
    """Called from the nightly loop (mirrors check_exception_expirations): finds
    entries whose review_by has passed and haven't been reminded yet, sends a
    one-time notification + audit log entry, then reapplies suppression so any
    alerts that should stop being suppressed by a now-lapsed entry actually do."""
    from notifier import dispatch
    now = _now_iso()
    reminded = 0
    async for entry in db.albert_allowlist.find(
        {"review_by": {"$ne": None, "$lt": now}, "review_reminder_sent": {"$ne": True}}, {"_id": 0}
    ):
        label = entry.get("source_ip") or entry.get("destination_ip") or entry["id"]
        try:
            await dispatch("albert_allowlist_review_due", {
                "label": label, "source_ip": entry.get("source_ip") or "—",
                "destination_ip": entry.get("destination_ip") or "—",
                "added_by": entry.get("added_by") or "—", "review_by": (entry.get("review_by") or "")[:10],
                "url": "/admin/albert",
            }, db)
        except Exception:
            pass
        await db.albert_allowlist.update_one({"id": entry["id"]}, {"$set": {"review_reminder_sent": True}})
        await _log(db, "review_due", entry["id"], "system",
                   f"Review overdue for {label} -- suppression paused until re-confirmed.")
        reminded += 1
    reapply_result = await reapply_allowlist(db)
    return {"reminded": reminded, **reapply_result}
