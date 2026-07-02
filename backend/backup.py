"""Database backup/restore -- pure pymongo/bson, no mongodump/mongorestore binary
needed (recent official Mongo images don't reliably ship the database-tools package,
and this avoids adding it to either container). Dumps every collection to a single
gzip-compressed JSON file using bson.json_util, which round-trips Mongo-native types
(dates, etc.) correctly, then writes to a mounted volume so backups survive the
backend container being recreated -- the container filesystem itself is ephemeral.
"""
import gzip
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from bson import json_util

BACKUP_DIR = Path(os.environ.get("BACKUP_DIR", "/app/backups"))
DEFAULT_RETENTION = 14  # keep the last N backups when pruning


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_path(filename: str) -> Path:
    """Rejects path traversal -- filename must resolve to a plain file directly
    inside BACKUP_DIR, nothing above or beside it."""
    candidate = (BACKUP_DIR / filename).resolve()
    base = BACKUP_DIR.resolve()
    if candidate != base and base not in candidate.parents:
        raise ValueError("Invalid backup filename")
    return candidate


async def create_backup(db, label: str | None = None) -> dict:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    filename = f"vulnops-backup-{ts}.json.gz"
    path = _safe_path(filename)

    collection_names = [c for c in await db.list_collection_names() if c != "backup_history"]
    dump = {}
    total_docs = 0
    for name in collection_names:
        docs = await db[name].find({}).to_list(length=None)
        dump[name] = docs
        total_docs += len(docs)

    payload = json_util.dumps({"created_at": ts, "collections": dump}).encode("utf-8")
    with gzip.open(path, "wb") as f:
        f.write(payload)

    record = {
        "id": str(uuid.uuid4()), "filename": filename, "label": label,
        "collections": len(collection_names), "documents": total_docs,
        "size_bytes": path.stat().st_size, "created_at": _now_iso(),
    }
    await db.backup_history.insert_one(dict(record))
    return record


async def list_backups(db) -> list:
    records = await db.backup_history.find({}, {"_id": 0}).sort("created_at", -1).to_list(500)
    # Cross-check against what's actually still on disk (a pruned/deleted file
    # shouldn't offer a download link that 404s).
    for r in records:
        r["file_exists"] = _safe_path(r["filename"]).exists() if r.get("filename") else False
    return records


def read_backup_file(filename: str) -> bytes:
    path = _safe_path(filename)
    if not path.exists():
        raise FileNotFoundError(f"Backup file '{filename}' not found on disk")
    return path.read_bytes()


async def restore_backup(db, content: bytes) -> dict:
    """DESTRUCTIVE: replaces each collection's contents with what's in the backup.
    Meant for disaster recovery, not merging -- there's no partial/dry-run mode."""
    try:
        raw = gzip.decompress(content)
        data = json_util.loads(raw.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"Not a valid VulnOps backup file: {e}")

    collections = data.get("collections")
    if collections is None:
        raise ValueError("Not a valid VulnOps backup file (missing 'collections' key)")

    restored = {}
    for name, docs in collections.items():
        await db[name].delete_many({})
        if docs:
            await db[name].insert_many(docs)
        restored[name] = len(docs)

    return {"collections_restored": len(collections), "documents_restored": sum(restored.values()), "detail": restored}


async def prune_old_backups(db, retention: int = DEFAULT_RETENTION) -> dict:
    records = await db.backup_history.find({}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    to_prune = records[retention:]
    removed = 0
    for r in to_prune:
        try:
            path = _safe_path(r["filename"])
            if path.exists():
                path.unlink()
        except Exception:
            pass
        await db.backup_history.delete_one({"id": r["id"]})
        removed += 1
    return {"pruned": removed, "kept": min(len(records), retention)}


async def delete_backup(db, backup_id: str) -> None:
    record = await db.backup_history.find_one({"id": backup_id}, {"_id": 0})
    if not record:
        return
    try:
        path = _safe_path(record["filename"])
        if path.exists():
            path.unlink()
    except Exception:
        pass
    await db.backup_history.delete_one({"id": backup_id})


async def backup_loop(db, interval_hours: int = 24, retention: int = DEFAULT_RETENTION):
    """Optional scheduled backup -- only runs if BACKUP_SCHEDULE_ENABLED is set, so a
    fresh install doesn't silently start writing to disk before someone's decided
    where that disk should be (i.e. mounted a real volume for it)."""
    import asyncio
    import logging
    from heartbeat import record_heartbeat
    logger = logging.getLogger("vulnops")
    if os.environ.get("BACKUP_SCHEDULE_ENABLED", "false").lower() not in ("true", "1", "yes"):
        logger.info("Scheduled backups disabled (set BACKUP_SCHEDULE_ENABLED=true to enable)")
        return
    await asyncio.sleep(90)
    while True:
        ok, detail = True, {}
        try:
            record = await create_backup(db, label="scheduled")
            prune_result = await prune_old_backups(db, retention)
            logger.info(f"Scheduled backup: {record['filename']} ({record['documents']} docs) — {prune_result}")
            detail = {"backup": record["filename"], "documents": record["documents"], "prune": prune_result}
        except Exception as e:
            logger.exception(f"Scheduled backup failed: {e}")
            ok, detail["error"] = False, str(e)
        await record_heartbeat(db, "backup_loop", "ok" if ok else "error", detail)
        await asyncio.sleep(interval_hours * 3600)
