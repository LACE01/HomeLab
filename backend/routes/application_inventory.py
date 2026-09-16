"""Item 54 -- Software / SaaS Application Inventory routes."""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query

from db import db
from rbac import require_module
import application_inventory as ai

router = APIRouter()
MODULE_KEY = "/app-inventory"


@router.get("/v1/app-inventory")
async def list_apps(
    q: Optional[str] = None,
    source: Optional[str] = None,
    category: Optional[str] = None,
    shadow_it: Optional[bool] = None,
    reviewed: Optional[bool] = None,
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    user: dict = Depends(require_module(MODULE_KEY)),
):
    flt: dict = {}
    if q:
        flt["$or"] = [{"name": {"$regex": q, "$options": "i"}},
                      {"vendor": {"$regex": q, "$options": "i"}}]
    if source:
        flt["sources"] = source
    if category:
        flt["category"] = category
    if shadow_it is not None:
        flt["shadow_it"] = shadow_it
    if reviewed is not None:
        flt["reviewed"] = reviewed
    total = await db.application_inventory.count_documents(flt)
    items = await db.application_inventory.find(flt, {"_id": 0}) \
        .sort("install_count", -1).skip(offset).limit(limit).to_list(limit)
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/v1/app-inventory/stats")
async def app_stats(user: dict = Depends(require_module(MODULE_KEY))):
    return await ai.stats(db)


@router.post("/v1/app-inventory/rebuild")
async def rebuild(user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    """Recompute the inventory from EDR/Qualys installed software, SBOM components,
    and completed Security Reviews. Bounded reads, so it's safe to run inline."""
    return await ai.rebuild_inventory(db)


@router.get("/v1/app-inventory/{app_id}")
async def app_detail(app_id: str, user: dict = Depends(require_module(MODULE_KEY))):
    doc = await db.application_inventory.find_one({"id": app_id}, {"_id": 0})
    if not doc:
        raise HTTPException(404, "Application not found")
    # hydrate host hostnames for the IR use-case ("which hosts run this?")
    if doc.get("hosts"):
        assets = await db.assets.find({"id": {"$in": doc["hosts"]}},
                                      {"_id": 0, "id": 1, "hostname": 1, "ip": 1}).to_list(50)
        doc["host_details"] = assets
    return doc
