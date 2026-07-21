"""Database backup/restore -- pure pymongo/bson, no mongodump/mongorestore binary
needed (recent official Mongo images don't reliably ship the database-tools package,
and this avoids adding it to either container). Dumps every collection to a single
gzip-compressed JSON file using bson.json_util, which round-trips Mongo-native types
(dates, etc.) correctly, then writes to a mounted volume so backups survive the
backend container being recreated -- the container filesystem itself is ephemeral.

Also supports an optional off-site destination (any S3-compatible object store --
AWS S3, MinIO, Backblaze B2, Wasabi, etc., configured entirely via env vars) and a
non-destructive restore-verification pass that runs automatically after every
backup. See upload_offsite()/verify_backup() below for what each actually checks
and why a full restore-drill against a second live database isn't in scope for a
single self-hosted deployment.
"""
import gzip
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from bson import json_util

logger = logging.getLogger("vulnops")

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


# --- Off-site destination (S3-compatible: AWS S3, MinIO, Backblaze B2, Wasabi,
# etc.) -- configured entirely via env vars so a fresh install with none of these
# set just keeps writing local-only backups, same "quietly no-op until
# configured" convention as BACKUP_SCHEDULE_ENABLED and every optional connector
# in this app. Off-site upload is opt-in, never required to use local backups. ---

def offsite_configured() -> bool:
    return bool(os.environ.get("BACKUP_S3_BUCKET"))


def offsite_status() -> dict:
    return {
        "configured": offsite_configured(),
        "bucket": os.environ.get("BACKUP_S3_BUCKET"),
        "endpoint_url": os.environ.get("BACKUP_S3_ENDPOINT_URL") or None,
        "prefix": os.environ.get("BACKUP_S3_PREFIX", "nightwatch-backups"),
    }


def _s3_client():
    import boto3
    kwargs = {}
    if os.environ.get("BACKUP_S3_ENDPOINT_URL"):
        kwargs["endpoint_url"] = os.environ["BACKUP_S3_ENDPOINT_URL"]
    if os.environ.get("BACKUP_S3_REGION"):
        kwargs["region_name"] = os.environ["BACKUP_S3_REGION"]
    if os.environ.get("BACKUP_S3_ACCESS_KEY_ID") and os.environ.get("BACKUP_S3_SECRET_ACCESS_KEY"):
        kwargs["aws_access_key_id"] = os.environ["BACKUP_S3_ACCESS_KEY_ID"]
        kwargs["aws_secret_access_key"] = os.environ["BACKUP_S3_SECRET_ACCESS_KEY"]
    return boto3.client("s3", **kwargs)


def upload_offsite(filename: str, content: bytes) -> dict:
    """Uploads one backup file to the configured S3-compatible bucket. Returns a
    result dict rather than raising -- a network hiccup or misconfigured bucket
    degrades to "off-site upload failed" without ever undoing or blocking the
    local backup itself, which has already succeeded by the time this runs."""
    if not offsite_configured():
        return {"attempted": False, "ok": False, "reason": "not configured"}
    bucket = os.environ["BACKUP_S3_BUCKET"]
    prefix = os.environ.get("BACKUP_S3_PREFIX", "nightwatch-backups").strip("/")
    key = f"{prefix}/{filename}" if prefix else filename
    try:
        client = _s3_client()
        client.put_object(Bucket=bucket, Key=key, Body=content)
        return {"attempted": True, "ok": True, "bucket": bucket, "key": key, "uploaded_at": _now_iso()}
    except Exception as e:
        logger.warning(f"Off-site backup upload failed: {e}")
        return {"attempted": True, "ok": False, "bucket": bucket, "key": key, "error": str(e)}


def verify_backup(content: bytes, expected_collections: int | None = None,
                   expected_documents: int | None = None) -> dict:
    """Restore-verification without touching the live database: decompresses and
    fully parses the archive exactly as restore_backup() would, then (when the
    original dump counts are known) cross-checks that the archive's collection/
    document counts match what was actually dumped.

    This is deliberately NOT a full restore drill against a second, disposable
    database -- provisioning and tearing down a spare Mongo instance safely on
    every backup isn't in scope for a single self-hosted deployment. What it does
    catch is the two failure modes that actually matter for a backup file: "this
    archive is corrupt/truncated" and "this archive doesn't contain what we think
    it does" -- both of which a real restore would otherwise discover the hard
    way, mid-disaster, when it's too late to do anything but panic.
    """
    try:
        raw = gzip.decompress(content)
        data = json_util.loads(raw.decode("utf-8"))
    except Exception as e:
        return {"valid": False, "error": f"Archive is corrupt or unreadable: {e}", "verified_at": _now_iso()}

    collections = data.get("collections")
    if collections is None or not isinstance(collections, dict):
        return {"valid": False, "error": "Missing or malformed 'collections' key", "verified_at": _now_iso()}

    doc_count = sum(len(v) for v in collections.values() if isinstance(v, list))
    result = {"valid": True, "collections": len(collections), "documents": doc_count, "verified_at": _now_iso()}

    if expected_collections is not None and len(collections) != expected_collections:
        result["valid"] = False
        result["error"] = f"Collection count mismatch: archive has {len(collections)}, expected {expected_collections}"
    elif expected_documents is not None and doc_count != expected_documents:
        result["valid"] = False
        result["error"] = f"Document count mismatch: archive has {doc_count}, expected {expected_documents}"
    return result


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

    # Read the actual bytes written to disk back (not the in-memory payload) so
    # verification and off-site upload both operate on exactly what a real
    # restore would read, catching a truncated/corrupt write too.
    written = path.read_bytes()
    verification = verify_backup(written, expected_collections=len(collection_names), expected_documents=total_docs)
    offsite = upload_offsite(filename, written)

    record = {
        "id": str(uuid.uuid4()), "filename": filename, "label": label,
        "collections": len(collection_names), "documents": total_docs,
        "size_bytes": path.stat().st_size, "created_at": _now_iso(),
        "verified": verification["valid"], "verification_error": verification.get("error"),
        "verified_at": verification["verified_at"],
        "offsite_attempted": offsite["attempted"], "offsite_ok": offsite["ok"],
        "offsite_bucket": offsite.get("bucket"), "offsite_key": offsite.get("key"),
        "offsite_error": offsite.get("error"), "offsite_uploaded_at": offsite.get("uploaded_at"),
    }
    await db.backup_history.insert_one(dict(record))
    return record


async def verify_backup_by_id(db, backup_id: str) -> dict:
    """Re-reads an existing backup off disk and re-runs verification -- useful
    after the fact (e.g. checking an older backup is still intact) without
    needing to create a new one."""
    record = await db.backup_history.find_one({"id": backup_id}, {"_id": 0})
    if not record:
        raise ValueError("Backup not found")
    content = read_backup_file(record["filename"])
    result = verify_backup(content, expected_collections=record.get("collections"), expected_documents=record.get("documents"))
    await db.backup_history.update_one({"id": backup_id}, {"$set": {
        "verified": result["valid"], "verification_error": result.get("error"), "verified_at": result["verified_at"],
    }})
    return result


async def upload_offsite_by_id(db, backup_id: str) -> dict:
    """Manual (re-)upload of an existing backup to the configured off-site
    destination -- used both for a first-time backfill after off-site is
    configured, and to retry one that failed."""
    record = await db.backup_history.find_one({"id": backup_id}, {"_id": 0})
    if not record:
        raise ValueError("Backup not found")
    content = read_backup_file(record["filename"])
    result = upload_offsite(record["filename"], content)
    await db.backup_history.update_one({"id": backup_id}, {"$set": {
        "offsite_attempted": result["attempted"], "offsite_ok": result["ok"],
        "offsite_bucket": result.get("bucket"), "offsite_key": result.get("key"),
        "offsite_error": result.get("error"), "offsite_uploaded_at": result.get("uploaded_at"),
    }})
    return result


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
            logger.info(
                f"Scheduled backup: {record['filename']} ({record['documents']} docs, "
                f"verified={record['verified']}, offsite_ok={record['offsite_ok']}) — {prune_result}"
            )
            detail = {
                "backup": record["filename"], "documents": record["documents"], "prune": prune_result,
                "verified": record["verified"], "offsite_attempted": record["offsite_attempted"],
                "offsite_ok": record["offsite_ok"],
            }
        except Exception as e:
            logger.exception(f"Scheduled backup failed: {e}")
            ok, detail["error"] = False, str(e)
        await record_heartbeat(db, "backup_loop", "ok" if ok else "error", detail)
        await asyncio.sleep(interval_hours * 3600)
