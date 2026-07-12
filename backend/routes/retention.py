"""Data retention & archival admin endpoints -- see retention.py for the actual
purge/archive logic. Mirrors the backups.py pattern (metadata in Mongo, files on
a mounted volume, download via a safe-path-checked read)."""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from db import db
from rbac import require_module
from auth_utils import require_role, get_current_user

router = APIRouter()


@router.get("/v1/admin/retention/policies")
async def list_policies(user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/admin/retention"))):
    from retention import get_policies
    return {"items": await get_policies(db)}


class PolicyUpdateBody(BaseModel):
    days: Optional[int] = None
    enabled: Optional[bool] = None


@router.patch("/v1/admin/retention/policies/{policy_id}")
async def patch_policy(policy_id: str, body: PolicyUpdateBody, user: dict = Depends(require_role("admin"))):
    from retention import update_policy
    try:
        return await update_policy(db, policy_id, days=body.days, enabled=body.enabled)
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/v1/admin/retention/policies/{policy_id}/run-now")
async def run_policy_now(policy_id: str, user: dict = Depends(require_role("admin"))):
    from retention import run_purge
    try:
        return await run_purge(db, policy_id, archive=True, triggered_by=f"manual:{user['email']}")
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.get("/v1/admin/retention/runs")
async def list_runs(user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/admin/retention"))):
    items = await db.retention_runs.find({}, {"_id": 0}).sort("run_at", -1).limit(100).to_list(100)
    return {"items": items}


@router.get("/v1/admin/retention/runs/{run_id}/download")
async def download_archive(run_id: str, user: dict = Depends(require_role("admin"))):
    from retention import read_archive_file
    record = await db.retention_runs.find_one({"id": run_id}, {"_id": 0})
    if not record:
        raise HTTPException(404, "Retention run not found")
    if not record.get("filename"):
        raise HTTPException(404, "This run didn't produce an archive file (nothing was purged, or archiving was skipped)")
    try:
        content = read_archive_file(record["filename"])
    except FileNotFoundError as e:
        raise HTTPException(404, str(e))
    return StreamingResponse(
        iter([content]), media_type="application/gzip",
        headers={"Content-Disposition": f"attachment; filename={record['filename']}"},
    )
