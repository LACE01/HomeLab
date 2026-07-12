"""Data retention & archival -- purges old records out of high-growth collections
on a schedule (or on demand), never silently: everything purged is written to a
gzip-compressed JSON archive file on disk first (same bson.json_util round-trip
approach backup.py uses), so a purge moves data out of the live database rather
than just deleting it. Every run is logged to db.retention_runs so there's an
audit trail of what was purged, when, and by what policy -- useful evidence for
"do you actually enforce your stated retention period" during an audit.

Policies are per-collection and independently enabled. A few (login audit, closed
alerts, scan/job history) default to enabled since they're pure operational
exhaust; closed IR cases default to *disabled* since those often carry their own
legal/regulatory retention requirements that shouldn't be auto-purged without an
admin deliberately opting in.
"""
import gzip
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from bson import json_util

ARCHIVE_DIR = Path(os.environ.get("ARCHIVE_DIR", "/app/archives"))

DEFAULT_POLICIES = [
    {"id": "security_events_closed", "label": "Closed security alerts", "collection": "security_events",
     "date_field": "closed_at", "status_filter": {"status": "closed"}, "default_days": 180, "enabled_default": True},
    {"id": "login_audit", "label": "Login attempt audit log", "collection": "login_audit",
     "date_field": "timestamp", "status_filter": None, "default_days": 180, "enabled_default": True},
    {"id": "yara_scan_history", "label": "YARA scan history", "collection": "yara_scan_history",
     "date_field": "scanned_at", "status_filter": None, "default_days": 365, "enabled_default": True},
    {"id": "import_jobs", "label": "Import job history", "collection": "import_jobs",
     "date_field": "started_at", "status_filter": None, "default_days": 90, "enabled_default": True},
    {"id": "notifications_outbox", "label": "Notification delivery log", "collection": "notifications_outbox",
     "date_field": "created_at", "status_filter": None, "default_days": 90, "enabled_default": True},
    {"id": "ir_cases_closed", "label": "Closed incident response cases", "collection": "ir_cases",
     "date_field": "closed_at", "status_filter": {"status": "closed"}, "default_days": 730, "enabled_default": False},
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_path(filename: str) -> Path:
    candidate = (ARCHIVE_DIR / filename).resolve()
    base = ARCHIVE_DIR.resolve()
    if candidate != base and base not in candidate.parents:
        raise ValueError("Invalid archive filename")
    return candidate


async def get_policies(db) -> list:
    """Merges DEFAULT_POLICIES with any admin overrides (days/enabled) stored in
    db.retention_policies, seeding the defaults on first read."""
    stored = {p["id"]: p async for p in db.retention_policies.find({}, {"_id": 0})}
    result = []
    for base in DEFAULT_POLICIES:
        override = stored.get(base["id"], {})
        result.append({
            **base,
            "days": override.get("days", base["default_days"]),
            "enabled": override.get("enabled", base["enabled_default"]),
            "last_run_at": override.get("last_run_at"),
            "last_purged_count": override.get("last_purged_count"),
        })
    return result


async def update_policy(db, policy_id: str, *, days: int = None, enabled: bool = None) -> dict:
    base = next((p for p in DEFAULT_POLICIES if p["id"] == policy_id), None)
    if not base:
        raise ValueError(f"Unknown retention policy '{policy_id}'")
    update = {}
    if days is not None:
        if days < 1:
            raise ValueError("days must be at least 1")
        update["days"] = days
    if enabled is not None:
        update["enabled"] = enabled
    if update:
        await db.retention_policies.update_one({"id": policy_id}, {"$set": update}, upsert=True)
    policies = await get_policies(db)
    return next(p for p in policies if p["id"] == policy_id)


def _write_archive(policy_id: str, records: list) -> str:
    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    filename = f"{policy_id}_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}_{uuid.uuid4().hex[:8]}.json.gz"
    path = _safe_path(filename)
    payload = json_util.dumps(records).encode()
    with gzip.open(path, "wb") as f:
        f.write(payload)
    return filename


def read_archive_file(filename: str) -> bytes:
    path = _safe_path(filename)
    if not path.exists():
        raise FileNotFoundError(f"Archive file '{filename}' not found")
    with open(path, "rb") as f:
        return f.read()


async def run_purge(db, policy_id: str, *, archive: bool = True, triggered_by: str = "scheduled") -> dict:
    policies = await get_policies(db)
    policy = next((p for p in policies if p["id"] == policy_id), None)
    if not policy:
        raise ValueError(f"Unknown retention policy '{policy_id}'")

    cutoff = (datetime.now(timezone.utc) - timedelta(days=policy["days"])).isoformat()
    flt = {**(policy["status_filter"] or {}), policy["date_field"]: {"$lt": cutoff}}
    coll = db[policy["collection"]]

    matched = await coll.find(flt, {"_id": 0}).to_list(200000)
    count = len(matched)

    archive_filename = None
    if count > 0:
        if archive:
            archive_filename = _write_archive(policy_id, matched)
        await coll.delete_many(flt)

    run_record = {
        "id": str(uuid.uuid4()), "policy_id": policy_id, "policy_label": policy["label"],
        "purged_count": count, "archived": bool(archive_filename), "filename": archive_filename,
        "cutoff": cutoff, "run_at": _now_iso(), "triggered_by": triggered_by,
    }
    await db.retention_runs.insert_one(run_record)
    await db.retention_policies.update_one(
        {"id": policy_id},
        {"$set": {"last_run_at": run_record["run_at"], "last_purged_count": count}},
        upsert=True,
    )
    run_record.pop("_id", None)
    return run_record


async def run_due_policies(db) -> list:
    """Runs every enabled policy -- called by the scheduled loop. No per-policy
    interval bookkeeping (unlike the scanner loops) since a purge is cheap and
    idempotent to run daily regardless of when it last ran."""
    results = []
    policies = await get_policies(db)
    for policy in policies:
        if not policy["enabled"]:
            continue
        try:
            results.append(await run_purge(db, policy["id"], archive=True, triggered_by="scheduled"))
        except Exception as e:
            results.append({"policy_id": policy["id"], "error": str(e)})
    return results


async def retention_loop(db, interval_hours: float = 24):
    import asyncio
    import logging
    logger = logging.getLogger("retention_loop")
    await asyncio.sleep(120)  # stagger well past other startup loops
    while True:
        try:
            results = await run_due_policies(db)
            logger.info(f"Retention purge run: {results}")
        except Exception as e:
            logger.warning(f"Retention purge run failed: {e}")
        await asyncio.sleep(interval_hours * 3600)
