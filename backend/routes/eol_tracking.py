"""End-of-life software/OS tracking -- CRUD for watch targets + run-now +
status list + an "auto-scan assets" action. Mirrors routes/certs.py's
structure."""
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from db import db
from rbac import require_module
from auth_utils import get_current_user, require_role
from routes.common import now_iso

router = APIRouter()


class EolTargetBody(BaseModel):
    product: str
    cycle: str
    label: Optional[str] = None
    asset_id: Optional[str] = None
    enabled: bool = True


def _validate(body: EolTargetBody):
    if not (body.product or "").strip():
        raise HTTPException(400, "Product is required (the exact endoflife.date identifier, e.g. 'ubuntu')")
    if not (body.cycle or "").strip():
        raise HTTPException(400, "Cycle is required (e.g. '22.04', '11', '2019')")


@router.get("/v1/admin/eol/targets")
async def list_eol_targets(user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/admin/eol-tracking"))):
    targets = await db.eol_watch_targets.find({}, {"_id": 0}).sort("created_at", -1).to_list(500)
    keys = [f"{t['product']}:{t['cycle']}" for t in targets]
    statuses = await db.eol_software_status.find({"id": {"$in": keys}}, {"_id": 0}).to_list(500)
    status_by_key = {s["id"]: s for s in statuses}
    for t in targets:
        t["latest"] = status_by_key.get(f"{t['product']}:{t['cycle']}")
    return {"items": targets}


@router.post("/v1/admin/eol/targets")
async def create_eol_target(body: EolTargetBody, user: dict = Depends(require_role("admin"))):
    _validate(body)
    doc = {
        "id": str(uuid.uuid4()), "product": body.product.strip().lower(), "cycle": body.cycle.strip(),
        "label": body.label, "asset_id": body.asset_id, "enabled": body.enabled,
        "source": "manual", "created_at": now_iso(), "created_by": user["email"],
    }
    await db.eol_watch_targets.insert_one(doc)
    doc.pop("_id", None)
    return doc


@router.put("/v1/admin/eol/targets/{target_id}")
async def update_eol_target(target_id: str, body: EolTargetBody, user: dict = Depends(require_role("admin"))):
    _validate(body)
    existing = await db.eol_watch_targets.find_one({"id": target_id}, {"_id": 0})
    if not existing:
        raise HTTPException(404, "Watch target not found")
    update = body.model_dump()
    update["product"] = body.product.strip().lower()
    update["cycle"] = body.cycle.strip()
    await db.eol_watch_targets.update_one({"id": target_id}, {"$set": update})
    return {**existing, **update}


@router.delete("/v1/admin/eol/targets/{target_id}")
async def delete_eol_target(target_id: str, user: dict = Depends(require_role("admin"))):
    await db.eol_watch_targets.delete_one({"id": target_id})
    return {"ok": True}


@router.post("/v1/admin/eol/targets/{target_id}/check-now")
async def check_eol_now(target_id: str, user: dict = Depends(require_role("admin"))):
    from eol_tracking import run_eol_check
    t = await db.eol_watch_targets.find_one({"id": target_id}, {"_id": 0})
    if not t:
        raise HTTPException(404, "Watch target not found")
    try:
        return await run_eol_check(db, t["product"], t["cycle"], t.get("asset_id"), t.get("label"))
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/v1/admin/eol/check-all")
async def check_all_eol_now(user: dict = Depends(require_role("admin"))):
    from eol_tracking import run_all_eol_checks
    return await run_all_eol_checks(db)


@router.post("/v1/admin/eol/scan-assets")
async def scan_assets_for_eol_now(user: dict = Depends(require_role("admin"))):
    """Auto-detects Ubuntu/Debian/CentOS/RHEL assets from the inventory's `os`
    field, adds watch targets for any not already tracked, then checks
    everything. See eol_tracking.py's docstring for exactly what is/isn't
    auto-detected and why."""
    from eol_tracking import scan_assets_for_eol
    return await scan_assets_for_eol(db)
