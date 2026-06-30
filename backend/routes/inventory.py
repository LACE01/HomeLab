"""Inventory routes: assets and products."""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException

from db import db
from auth_utils import get_current_user

router = APIRouter()


# --------------------------- ASSETS ---------------------------
@router.get("/v1/assets")
async def list_assets(user: dict = Depends(get_current_user),
                     q: Optional[str] = None, criticality: Optional[str] = None,
                     environment: Optional[str] = None, exposure: Optional[str] = None,
                     limit: int = 100, offset: int = 0):
    flt: dict = {}
    if criticality:
        flt["criticality"] = criticality
    if environment:
        flt["environment"] = environment
    if exposure:
        flt["exposure"] = exposure
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
