"""Secrets/credential leak scanning -- CRUD for watch targets + scan-now +
scan-all. Mirrors routes/certs.py's structure."""
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from db import db
from rbac import require_module
from auth_utils import get_current_user, require_role
from routes.common import now_iso, record_engagement

router = APIRouter()


class RepoTargetBody(BaseModel):
    repo_url: str
    branch: Optional[str] = None
    token: Optional[str] = None  # only for private repos; masked in list responses
    label: Optional[str] = None
    asset_id: Optional[str] = None
    enabled: bool = True


def _validate(body: RepoTargetBody):
    url = (body.repo_url or "").strip()
    if not url:
        raise HTTPException(400, "Repository URL is required")
    if not (url.startswith("https://") or url.startswith("git@") or url.startswith("ssh://")):
        raise HTTPException(400, "Repository URL must start with https://, git@, or ssh://")


def _mask(target: dict) -> dict:
    if target.get("token"):
        target = {**target, "token": "•••"}
    return target


@router.get("/v1/admin/secrets-scan/targets")
async def list_repo_targets(user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/admin/secrets-scan"))):
    targets = await db.secrets_scan_targets.find({}, {"_id": 0}).sort("created_at", -1).to_list(500)
    urls = [t["repo_url"] for t in targets]
    scans = await db.secrets_scan_history.find({"repo_url": {"$in": urls}}, {"_id": 0}).to_list(500)
    scan_by_url = {s["repo_url"]: s for s in scans}
    for t in targets:
        t["latest"] = scan_by_url.get(t["repo_url"])
    return {"items": [_mask(t) for t in targets]}


@router.post("/v1/admin/secrets-scan/targets")
async def create_repo_target(body: RepoTargetBody, user: dict = Depends(require_role("admin"))):
    _validate(body)
    doc = {
        "id": str(uuid.uuid4()), "repo_url": body.repo_url.strip(), "branch": body.branch,
        "token": body.token, "label": body.label, "asset_id": body.asset_id, "enabled": body.enabled,
        "created_at": now_iso(), "created_by": user["email"],
    }
    await db.secrets_scan_targets.insert_one(doc)
    doc.pop("_id", None)
    return _mask(doc)


@router.put("/v1/admin/secrets-scan/targets/{target_id}")
async def update_repo_target(target_id: str, body: RepoTargetBody, user: dict = Depends(require_role("admin"))):
    _validate(body)
    existing = await db.secrets_scan_targets.find_one({"id": target_id}, {"_id": 0})
    if not existing:
        raise HTTPException(404, "Watch target not found")
    update = body.model_dump()
    update["repo_url"] = body.repo_url.strip()
    if update.get("token") == "•••":
        update["token"] = existing.get("token")  # unchanged -- the masked placeholder was echoed back
    await db.secrets_scan_targets.update_one({"id": target_id}, {"$set": update})
    return _mask({**existing, **update})


@router.delete("/v1/admin/secrets-scan/targets/{target_id}")
async def delete_repo_target(target_id: str, user: dict = Depends(require_role("admin"))):
    await db.secrets_scan_targets.delete_one({"id": target_id})
    return {"ok": True}


@router.post("/v1/admin/secrets-scan/targets/{target_id}/scan-now")
async def scan_repo_now(target_id: str, user: dict = Depends(require_role("admin"))):
    # Enqueued, not awaited. detect-secrets clones the whole repo, which is heavy;
    # doing it in the API process risks OOM-killing the backend. See
    # job_handlers._secrets.
    t = await db.secrets_scan_targets.find_one({"id": target_id}, {"_id": 0})
    if not t:
        raise HTTPException(404, "Watch target not found")
    from jobqueue import enqueue
    import job_handlers  # noqa: F401
    job = await enqueue(db, "secrets_scan", {"target_id": target_id},
                         requested_by=user.get("email") or user.get("id"))
    return {"status": "queued", "job_id": job["id"], "deduped": job.get("deduped", False),
            "message": ("This repo scan was already queued." if job.get("deduped")
                         else "Repo scan queued — poll GET /v1/jobs/{} for progress".format(job["id"]))}


@router.post("/v1/admin/secrets-scan/scan-all")
async def scan_all_repos_now(user: dict = Depends(require_role("admin"))):
    from secrets_scan import run_all_repo_scans
    return await run_all_repo_scans(db)
