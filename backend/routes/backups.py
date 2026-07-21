"""Database backup/restore admin endpoints."""
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from db import db
from rbac import require_module
from auth_utils import require_role

router = APIRouter()


class BackupBody(BaseModel):
    label: Optional[str] = None


@router.get("/v1/admin/backups")
async def list_backups(user: dict = Depends(require_role("admin")), _rbac: dict = Depends(require_module("/admin/backups"))):
    from backup import list_backups as _list
    items = await _list(db)
    return {"items": items}


@router.post("/v1/admin/backups")
async def create_backup_now(body: BackupBody, user: dict = Depends(require_role("admin"))):
    from backup import create_backup
    return await create_backup(db, label=body.label)


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
    user: dict = Depends(require_role("admin")),
):
    """Restoring replaces the entire database contents -- requires typing the literal
    word RESTORE in the confirm field as a lightweight guard against fat-fingering
    this from the UI (there's no undo)."""
    if confirm != "RESTORE":
        raise HTTPException(400, "Type RESTORE (all caps) to confirm -- this replaces all current data")
    from backup import restore_backup
    content = await file.read()
    try:
        return await restore_backup(db, content)
    except ValueError as e:
        raise HTTPException(400, str(e))
