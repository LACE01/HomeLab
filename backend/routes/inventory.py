"""Inventory routes: assets and products."""
import uuid
from datetime import datetime, timezone
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from db import db
from auth_utils import get_current_user, require_role

router = APIRouter()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------- ASSETS ---------------------------
@router.get("/v1/assets")
async def list_assets(user: dict = Depends(get_current_user),
                     q: Optional[str] = None, criticality: Optional[str] = None,
                     environment: Optional[str] = None, exposure: Optional[str] = None,
                     product_id: Optional[str] = None,
                     limit: int = 100, offset: int = 0):
    flt: dict = {}
    if criticality:
        flt["criticality"] = criticality
    if environment:
        flt["environment"] = environment
    if exposure:
        flt["exposure"] = exposure
    if product_id:
        flt["product_id"] = product_id
    if q:
        flt["$or"] = [
            {"hostname": {"$regex": q, "$options": "i"}},
            {"ip": {"$regex": q, "$options": "i"}},
            {"fqdn": {"$regex": q, "$options": "i"}},
        ]
    items = await db.assets.find(flt, {"_id": 0}).skip(offset).limit(limit).to_list(limit)
    total = await db.assets.count_documents(flt)

    for a in items:
        a["open_findings"] = await db.findings.count_documents({
            "asset_id": a["id"],
            "status": {"$in": ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]},
        })
        a["critical_findings"] = await db.findings.count_documents({
            "asset_id": a["id"], "severity": "Critical",
            "status": {"$in": ["New", "Needs triage", "Valid", "Reopened"]},
        })
    return {"items": items, "total": total}


@router.get("/v1/assets/{asset_id}")
async def get_asset(asset_id: str, user: dict = Depends(get_current_user)):
    a = await db.assets.find_one({"id": asset_id}, {"_id": 0})
    if not a:
        raise HTTPException(404, "Asset not found")
    return a


@router.get("/v1/assets/{asset_id}/findings")
async def asset_findings(asset_id: str, user: dict = Depends(get_current_user)):
    items = await db.findings.find({"asset_id": asset_id}, {"_id": 0}).sort("risk_score", -1).to_list(500)
    return {"items": items}


@router.get("/v1/assets/{asset_id}/tickets")
async def asset_tickets(asset_id: str, user: dict = Depends(get_current_user)):
    items = await db.tickets.find({"asset_id": asset_id}, {"_id": 0}).to_list(100)
    return {"items": items}


@router.get("/v1/assets/{asset_id}/history")
async def asset_history(asset_id: str, user: dict = Depends(get_current_user)):
    items = await db.activity_log.find({"entity_id": asset_id}, {"_id": 0}).sort("timestamp", -1).to_list(200)
    obs = await db.observations.find({"asset_id": asset_id}, {"_id": 0}).sort("observed_at", -1).to_list(200)
    return {"activity": items, "observations": obs}


class AssignProductBody(BaseModel):
    product_id: Optional[str] = None  # None clears the assignment


async def _apply_product_to_assets(asset_ids: List[str], product_id: Optional[str]) -> int:
    """Set product_id/product_name on assets and propagate to their open findings
    (findings snapshot product_id/product_name at ingestion time, so re-assigning
    an asset after the fact needs to push the change down to its findings too)."""
    product_name = None
    if product_id:
        p = await db.products.find_one({"id": product_id}, {"_id": 0})
        if not p:
            raise HTTPException(404, "Product not found")
        product_name = p["name"]
    r = await db.assets.update_many({"id": {"$in": asset_ids}},
        {"$set": {"product_id": product_id, "product_name": product_name}})
    await db.findings.update_many({"asset_id": {"$in": asset_ids}},
        {"$set": {"product_id": product_id, "product_name": product_name}})
    return r.modified_count


@router.post("/v1/assets/{asset_id}/product")
async def assign_asset_product(asset_id: str, body: AssignProductBody,
                                user: dict = Depends(require_role("admin", "manager"))):
    a = await db.assets.find_one({"id": asset_id}, {"_id": 0})
    if not a:
        raise HTTPException(404, "Asset not found")
    await _apply_product_to_assets([asset_id], body.product_id)
    return {"ok": True}


class BulkAssignProductBody(BaseModel):
    asset_ids: List[str]
    product_id: Optional[str] = None


@router.post("/v1/assets/bulk-assign-product")
async def bulk_assign_product(body: BulkAssignProductBody,
                               user: dict = Depends(require_role("admin", "manager"))):
    if not body.asset_ids:
        raise HTTPException(400, "asset_ids is required")
    updated = await _apply_product_to_assets(body.asset_ids, body.product_id)
    return {"updated_assets": updated}


# --------------------------- PRODUCTS ---------------------------
@router.get("/v1/products")
async def list_products(user: dict = Depends(get_current_user)):
    items = await db.products.find({}, {"_id": 0}).to_list(200)
    for p in items:
        p["asset_count"] = await db.assets.count_documents({"product_id": p["id"]})
        p["open_findings"] = await db.findings.count_documents({
            "product_id": p["id"],
            "status": {"$in": ["New", "Needs triage", "Valid", "Reopened"]},
        })
        p["critical_findings"] = await db.findings.count_documents({
            "product_id": p["id"], "severity": "Critical",
            "status": {"$in": ["New", "Needs triage", "Valid", "Reopened"]},
        })
    return {"items": items}


@router.get("/v1/products/{product_id}")
async def get_product(product_id: str, user: dict = Depends(get_current_user)):
    p = await db.products.find_one({"id": product_id}, {"_id": 0})
    if not p:
        raise HTTPException(404, "Product not found")
    p["assets"] = await db.assets.find({"product_id": product_id}, {"_id": 0}).to_list(200)
    p["findings"] = await db.findings.find({"product_id": product_id}, {"_id": 0}).sort("risk_score", -1).limit(100).to_list(100)
    return p


class ProductBody(BaseModel):
    name: str
    description: Optional[str] = ""
    business_owner: Optional[str] = ""
    criticality: Optional[str] = "medium"  # crown_jewel|critical|medium|low
    sla_profile: Optional[str] = "standard"
    environments: Optional[List[str]] = []


@router.post("/v1/products")
async def create_product(body: ProductBody, user: dict = Depends(require_role("admin", "manager"))):
    doc = {"id": str(uuid.uuid4()), **body.model_dump(), "created_at": _now_iso()}
    await db.products.insert_one(doc)
    return _clean_out(doc)


@router.put("/v1/products/{product_id}")
async def update_product(product_id: str, body: ProductBody,
                          user: dict = Depends(require_role("admin", "manager"))):
    p = await db.products.find_one({"id": product_id}, {"_id": 0})
    if not p:
        raise HTTPException(404, "Product not found")
    update = body.model_dump()
    await db.products.update_one({"id": product_id}, {"$set": update})
    # Keep denormalized product_name in sync on assets/findings that reference it
    await db.assets.update_many({"product_id": product_id}, {"$set": {"product_name": update["name"]}})
    await db.findings.update_many({"product_id": product_id}, {"$set": {"product_name": update["name"]}})
    return {**p, **update}


@router.delete("/v1/products/{product_id}")
async def delete_product(product_id: str, user: dict = Depends(require_role("admin"))):
    p = await db.products.find_one({"id": product_id}, {"_id": 0})
    if not p:
        raise HTTPException(404, "Product not found")
    # Unassign rather than orphan — findings/assets keep existing, just lose the link.
    await db.assets.update_many({"product_id": product_id}, {"$set": {"product_id": None, "product_name": None}})
    await db.findings.update_many({"product_id": product_id}, {"$set": {"product_id": None, "product_name": None}})
    await db.products.delete_one({"id": product_id})
    return {"ok": True}


def _clean_out(doc: dict) -> dict:
    d = dict(doc)
    d.pop("_id", None)
    return d
