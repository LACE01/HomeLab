"""Database backup/restore admin endpoints."""
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from db import db
from rbac import require_module
from auth_utils import require_role
from routes.common import now_iso

router = APIRouter()


class BackupBody(BaseModel):
    label: Optional[str] = None
    encrypt: bool = False


@router.get("/v1/admin/backups")
async def list_backups(user: dict = Depends(require_role("admin")), _rbac: dict = Depends(require_module("/admin/backups"))):
    from backup import list_backups as _list
    items = await _list(db)
    return {"items": items}


@router.post("/v1/admin/backups")
async def create_backup_now(body: BackupBody, user: dict = Depends(require_role("admin"))):
    # ENQUEUED, not run inline. On a large database, dumping every collection took
    # longer than Cloudflare's ~100s proxy timeout, so an inline backup 520'd. The
    # worker runs it; the client polls GET /v1/jobs/{job_id}. For an encrypted
    # backup the passphrase lands in a read-once vault; fetch it once from
    # /v1/admin/backups/{backup_id}/passphrase after the job completes.
    from jobqueue import enqueue
    import job_handlers  # noqa: F401 -- registers the handler
    job = await enqueue(db, "backup_create",
                        {"label": body.label, "encrypt": body.encrypt},
                        requested_by=user.get("email") or user.get("id"))
    return {"status": "queued", "job_id": job["id"], "deduped": job.get("deduped", False),
            "encrypt": body.encrypt,
            "message": ("A backup is already in progress." if job.get("deduped")
                         else "Backup queued — poll GET /v1/jobs/{} for progress.".format(job["id"]))}


@router.get("/v1/admin/backups/{backup_id}/passphrase")
async def get_backup_passphrase(backup_id: str, user: dict = Depends(require_role("admin"))):
    """Read the one-time passphrase for an encrypted async backup. Returns it
    ONCE and deletes it -- after this call it is gone from the server."""
    from backup import claim_passphrase
    return await claim_passphrase(db, backup_id)


@router.get("/v1/admin/backups/{backup_id}/download")
async def download_backup(backup_id: str, user: dict = Depends(require_role("admin"))):
    from backup import read_backup_file
    record = await db.backup_history.find_one({"id": backup_id}, {"_id": 0})
    if not record:
        raise HTTPException(404, "Backup not found")
    try:
        content = read_backup_file(record["filename"])
    except FileNotFoundError as e:
        raise HTTPException(404, str(e))
    return StreamingResponse(
        iter([content]), media_type="application/gzip",
        headers={"Content-Disposition": f"attachment; filename={record['filename']}"},
    )


@router.delete("/v1/admin/backups/{backup_id}")
async def delete_backup_endpoint(backup_id: str, user: dict = Depends(require_role("admin"))):
    from backup import delete_backup
    await delete_backup(db, backup_id)
    return {"ok": True}


@router.get("/v1/admin/backups/db-size")
async def backup_db_size(user: dict = Depends(require_role("admin"))):
    """Item 34 -- live database size: document/collection counts and on-disk
    bytes, plus the backup volume's usage/free space. Answers "how big is the
    thing I'm backing up, and will the next backup fit" without shelling into
    the container.

    Uses Mongo's dbStats/collStats. Under mongomock (tests) those commands
    aren't implemented, so this degrades to counting documents rather than
    failing -- the numbers are still true, just without byte sizes."""
    import os
    import shutil

    stats = {}
    collections_detail = []
    try:
        raw = await db.command("dbStats")
        stats = {
            "data_size_bytes": int(raw.get("dataSize") or 0),
            "storage_size_bytes": int(raw.get("storageSize") or 0),
            "index_size_bytes": int(raw.get("indexSize") or 0),
            "total_size_bytes": int(raw.get("totalSize") or (raw.get("storageSize") or 0) + (raw.get("indexSize") or 0)),
            "collection_count": int(raw.get("collections") or 0),
            "document_count": int(raw.get("objects") or 0),
            "avg_object_size_bytes": int(raw.get("avgObjSize") or 0),
            "source": "dbStats",
        }
    except Exception:
        stats = {"source": "counted", "data_size_bytes": None, "storage_size_bytes": None,
                 "index_size_bytes": None, "total_size_bytes": None,
                 "avg_object_size_bytes": None}

    try:
        names = await db.list_collection_names()
    except Exception:
        names = []
    total_docs = 0
    for name in sorted(names):
        try:
            count = await db[name].count_documents({})
        except Exception:
            continue
        total_docs += count
        entry = {"name": name, "documents": count}
        try:
            cs = await db.command({"collStats": name})
            entry["size_bytes"] = int(cs.get("size") or 0)
            entry["storage_size_bytes"] = int(cs.get("storageSize") or 0)
        except Exception:
            pass
        collections_detail.append(entry)
    collections_detail.sort(key=lambda c: -(c.get("size_bytes") or c.get("documents") or 0))
    stats.setdefault("collection_count", len(names))
    if not stats.get("document_count"):
        stats["document_count"] = total_docs
    stats["collection_count"] = stats.get("collection_count") or len(names)

    volume = None
    backup_dir = os.environ.get("BACKUP_DIR", "/data/backups")
    try:
        if os.path.isdir(backup_dir):
            usage = shutil.disk_usage(backup_dir)
            backup_bytes = 0
            backup_files = 0
            for root, _dirs, files in os.walk(backup_dir):
                for fn in files:
                    try:
                        backup_bytes += os.path.getsize(os.path.join(root, fn))
                        backup_files += 1
                    except OSError:
                        pass
            volume = {
                "path": backup_dir,
                "total_bytes": usage.total, "used_bytes": usage.used, "free_bytes": usage.free,
                "used_pct": round(100 * usage.used / usage.total, 1) if usage.total else None,
                "backup_files": backup_files, "backup_bytes": backup_bytes,
            }
    except Exception:
        volume = None

    return {"database": stats, "collections": collections_detail[:40],
            "backup_volume": volume, "generated_at": now_iso()}


@router.get("/v1/admin/backups/offsite-status")
async def get_offsite_status(user: dict = Depends(require_role("admin"))):
    from backup import offsite_status
    return offsite_status()


@router.post("/v1/admin/backups/{backup_id}/verify")
async def verify_backup_endpoint(backup_id: str, user: dict = Depends(require_role("admin"))):
    from backup import verify_backup_by_id
    try:
        return await verify_backup_by_id(db, backup_id)
    except ValueError as e:
        raise HTTPException(404, str(e))
    except FileNotFoundError as e:
        raise HTTPException(404, str(e))


@router.post("/v1/admin/backups/{backup_id}/upload-offsite")
async def upload_offsite_endpoint(backup_id: str, user: dict = Depends(require_role("admin"))):
    from backup import upload_offsite_by_id, offsite_configured
    if not offsite_configured():
        raise HTTPException(400, "Off-site storage isn't configured -- set BACKUP_S3_BUCKET (and related BACKUP_S3_* vars) in your .env")
    try:
        return await upload_offsite_by_id(db, backup_id)
    except ValueError as e:
        raise HTTPException(404, str(e))
    except FileNotFoundError as e:
        raise HTTPException(404, str(e))


@router.post("/v1/admin/backups/restore")
async def restore_backup_endpoint(
    file: UploadFile = File(...),
    confirm: str = Form(...),
    passphrase: str = Form(""),
    user: dict = Depends(require_role("admin")),
):
    """Restoring replaces the entire database contents -- requires typing the literal
    word RESTORE in the confirm field as a lightweight guard against fat-fingering
    this from the UI (there's no undo). An encrypted backup additionally requires
    the passphrase shown when it was created; a wrong passphrase fails BEFORE
    anything is deleted.

    ENQUEUED, not run inline. Restoring a large database inline blew past
    Cloudflare's ~100s proxy timeout (520) and could OOM the API -- the mirror of
    the create-backup bug. The upload is streamed to the shared backups volume,
    the worker runs the restore, and the client polls GET /v1/jobs/{job_id}. The
    passphrase (if any) goes to a read-once vault so it never lands on the job
    row."""
    if confirm != "RESTORE":
        raise HTTPException(400, "Type RESTORE (all caps) to confirm -- this replaces all current data")
    import uuid
    from backup import BACKUP_DIR, _safe_path, stash_passphrase
    from jobqueue import enqueue
    import job_handlers  # noqa: F401 -- registers the handler

    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    restore_id = uuid.uuid4().hex
    stash_path = _safe_path(f".restore-{restore_id}.bin")
    # Stream the upload to disk in chunks -- don't pull the whole (potentially
    # large) file into the API's memory.
    size = 0
    try:
        with open(stash_path, "wb") as out:
            while True:
                chunk = await file.read(1 << 20)
                if not chunk:
                    break
                out.write(chunk)
                size += len(chunk)
    except Exception:
        try:
            stash_path.unlink()
        except OSError:
            pass
        raise
    if size == 0:
        try:
            stash_path.unlink()
        except OSError:
            pass
        raise HTTPException(400, "The uploaded backup file is empty")

    has_passphrase = bool(passphrase)
    if has_passphrase:
        await stash_passphrase(db, restore_id, passphrase)

    job = await enqueue(db, "backup_restore",
                        {"restore_file": str(stash_path), "restore_id": restore_id,
                         "has_passphrase": has_passphrase},
                        requested_by=user.get("email") or user.get("id"))
    return {"status": "queued", "job_id": job["id"],
            "message": "Restore queued — poll GET /v1/jobs/{} for progress.".format(job["id"])}
