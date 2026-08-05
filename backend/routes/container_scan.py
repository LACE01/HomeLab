"""Container image vulnerability scanning -- CRUD for watch targets +
scan-now + scan-all. Mirrors routes/certs.py's structure."""
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from db import db
from rbac import require_module
from auth_utils import get_current_user, require_role
from routes.common import now_iso, record_engagement

router = APIRouter()


class ImageTargetBody(BaseModel):
    image_ref: str
    label: Optional[str] = None
    asset_id: Optional[str] = None
    enabled: bool = True


def _validate(body: ImageTargetBody):
    if not (body.image_ref or "").strip():
        raise HTTPException(400, "Image reference is required (e.g. 'nginx:1.25', 'ghcr.io/org/app:latest')")


@router.get("/v1/admin/container-scan/targets")
async def list_image_targets(user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/admin/container-scan"))):
    targets = await db.container_image_watch_targets.find({}, {"_id": 0}).sort("created_at", -1).to_list(500)
    refs = [t["image_ref"] for t in targets]
    scans = await db.container_image_scans.find({"image_ref": {"$in": refs}}, {"_id": 0}).to_list(500)
    scan_by_ref = {s["image_ref"]: s for s in scans}
    for t in targets:
        t["latest"] = scan_by_ref.get(t["image_ref"])
    return {"items": targets}


@router.post("/v1/admin/container-scan/targets")
async def create_image_target(body: ImageTargetBody, user: dict = Depends(require_role("admin"))):
    _validate(body)
    doc = {
        "id": str(uuid.uuid4()), "image_ref": body.image_ref.strip(), "label": body.label,
        "asset_id": body.asset_id, "enabled": body.enabled,
        "created_at": now_iso(), "created_by": user["email"],
    }
    await db.container_image_watch_targets.insert_one(doc)
    doc.pop("_id", None)
    return doc


@router.put("/v1/admin/container-scan/targets/{target_id}")
async def update_image_target(target_id: str, body: ImageTargetBody, user: dict = Depends(require_role("admin"))):
    _validate(body)
    existing = await db.container_image_watch_targets.find_one({"id": target_id}, {"_id": 0})
    if not existing:
        raise HTTPException(404, "Watch target not found")
    update = body.model_dump()
    update["image_ref"] = body.image_ref.strip()
    await db.container_image_watch_targets.update_one({"id": target_id}, {"$set": update})
    return {**existing, **update}


@router.delete("/v1/admin/container-scan/targets/{target_id}")
async def delete_image_target(target_id: str, user: dict = Depends(require_role("admin"))):
    await db.container_image_watch_targets.delete_one({"id": target_id})
    return {"ok": True}


@router.post("/v1/admin/container-scan/targets/{target_id}/scan-now")
async def scan_image_now(target_id: str, user: dict = Depends(require_role("admin"))):
    # Enqueued, not awaited. trivy pulls the entire container image (often
    # hundreds of MB) -- doing that in the API process is a memory spike that can
    # OOM-kill the backend. See job_handlers._container.
    t = await db.container_image_watch_targets.find_one({"id": target_id}, {"_id": 0})
    if not t:
        raise HTTPException(404, "Watch target not found")
    from jobqueue import enqueue
    import job_handlers  # noqa: F401
    job = await enqueue(db, "container_scan", {"target_id": target_id},
                         requested_by=user.get("email") or user.get("id"))
    return {"status": "queued", "job_id": job["id"], "deduped": job.get("deduped", False),
            "message": ("This image scan was already queued." if job.get("deduped")
                         else "Image scan queued — poll GET /v1/jobs/{} for progress".format(job["id"]))}


@router.post("/v1/admin/container-scan/scan-all")
async def scan_all_images_now(user: dict = Depends(require_role("admin"))):
    from container_scan import run_all_container_scans
    return await run_all_container_scans(db)
