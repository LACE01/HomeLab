"""Vendor & Third-Party Risk Management routes -- see vendor_management.py for
the domain logic (matching, scoring, monitoring) this wires up to HTTP."""
import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from db import db
from rbac import require_module
from routes.common import now_iso
from vendor_management import (
    CATEGORIES, MONITOR_MODULE_IDS, DPA_STATUSES, QUESTIONNAIRE_STATUSES, RENEWAL_WARN_DAYS,
    suggest_vendors, compute_vendor_risk, check_vendor_compromise, enable_vendor_monitoring,
    disable_vendor_monitoring, get_vendor_risk_history, _clean, _log,
)

router = APIRouter()


class VendorBody(BaseModel):
    name: str
    category: str = "Software"
    domain: Optional[str] = None
    website: Optional[str] = None
    description: Optional[str] = ""
    match_terms: List[str] = []
    org_criticality: int = 3
    status: str = "active"
    tags: List[str] = []
    notes: Optional[str] = ""
    contract_start_date: Optional[str] = None
    contract_end_date: Optional[str] = None
    renewal_date: Optional[str] = None
    contract_owner: Optional[str] = None
    dpa_status: str = "not_required"
    security_questionnaire_status: str = "not_started"


class VendorUpdateBody(BaseModel):
    name: Optional[str] = None
    category: Optional[str] = None
    domain: Optional[str] = None
    website: Optional[str] = None
    description: Optional[str] = None
    match_terms: Optional[List[str]] = None
    org_criticality: Optional[int] = None
    status: Optional[str] = None
    tags: Optional[List[str]] = None
    notes: Optional[str] = None
    contract_start_date: Optional[str] = None
    contract_end_date: Optional[str] = None
    renewal_date: Optional[str] = None
    contract_owner: Optional[str] = None
    dpa_status: Optional[str] = None
    security_questionnaire_status: Optional[str] = None


class BulkVendorBody(BaseModel):
    vendors: List[VendorBody]


class BulkIds(BaseModel):
    ids: List[str]


class MonitorBody(BaseModel):
    enabled: bool


@router.get("/v1/vendors/meta")
async def vendors_meta(user: dict = Depends(require_module("/vendors"))):
    return {"categories": CATEGORIES, "criticality_levels": [1, 2, 3, 4, 5], "monitor_modules": MONITOR_MODULE_IDS}


@router.get("/v1/vendors/suggestions")
async def get_vendor_suggestions(user: dict = Depends(require_module("/vendors"))):
    return await suggest_vendors(db)


async def _create_vendor(body: VendorBody, actor: str) -> dict:
    if body.category not in CATEGORIES:
        raise HTTPException(400, f"category must be one of {CATEGORIES}")
    if not (1 <= body.org_criticality <= 5):
        raise HTTPException(400, "org_criticality must be 1-5")
    if body.dpa_status not in DPA_STATUSES:
        raise HTTPException(400, f"dpa_status must be one of {DPA_STATUSES}")
    if body.security_questionnaire_status not in QUESTIONNAIRE_STATUSES:
        raise HTTPException(400, f"security_questionnaire_status must be one of {QUESTIONNAIRE_STATUSES}")
    existing = await db.vendors.find_one({"name": {"$regex": f"^{body.name.strip()}$", "$options": "i"}}, {"_id": 0})
    if existing:
        return existing
    doc = {
        "id": str(uuid.uuid4()), **body.model_dump(),
        "monitoring_enabled": False, "renewal_reminder_sent": False,
        "created_at": now_iso(), "created_by": actor, "updated_at": now_iso(),
    }
    await db.vendors.insert_one(doc)
    await _log(db, "added", doc["id"], actor, f"Vendor added: {doc['name']} ({doc['category']})")
    return _clean(doc)


@router.post("/v1/vendors")
async def create_vendor(body: VendorBody, user: dict = Depends(require_module("/vendors", level="edit"))):
    return await _create_vendor(body, user["email"])


@router.post("/v1/vendors/bulk")
async def create_vendors_bulk(body: BulkVendorBody, user: dict = Depends(require_module("/vendors", level="edit"))):
    created = []
    for v in body.vendors:
        created.append(await _create_vendor(v, user["email"]))
    return {"ok": True, "created": len(created), "vendors": created}


@router.get("/v1/vendors")
async def list_vendors(category: Optional[str] = None, status: Optional[str] = None,
                        band: Optional[str] = None, q: Optional[str] = None,
                        user: dict = Depends(require_module("/vendors"))):
    flt: dict = {}
    if category:
        flt["category"] = category
    if status:
        flt["status"] = status
    if q:
        flt["$or"] = [
            {"name": {"$regex": q, "$options": "i"}},
            {"domain": {"$regex": q, "$options": "i"}},
            {"tags": {"$regex": q, "$options": "i"}},
        ]
    items = await db.vendors.find(flt, {"_id": 0}).sort("name", 1).to_list(2000)
    out = []
    for v in items:
        risk = await compute_vendor_risk(db, v)
        if band and risk["risk_band"] != band:
            continue
        out.append({
            **v, "asset_count": risk["asset_count"], "finding_count": risk["finding_count"],
            "severity_counts": risk["severity_counts"], "risk_score": risk["risk_score"], "risk_band": risk["risk_band"],
        })
    return {"items": out, "total": len(out)}


@router.get("/v1/vendors/stats")
async def vendor_stats(user: dict = Depends(require_module("/vendors"))):
    items = await db.vendors.find({}, {"_id": 0}).to_list(2000)
    by_category: dict = {}
    by_band: dict = {}
    top_exposure = []
    for v in items:
        by_category[v["category"]] = by_category.get(v["category"], 0) + 1
        risk = await compute_vendor_risk(db, v)
        by_band[risk["risk_band"]] = by_band.get(risk["risk_band"], 0) + 1
        crit_high = risk["severity_counts"].get("Critical", 0) + risk["severity_counts"].get("High", 0)
        if crit_high > 0:
            top_exposure.append({"id": v["id"], "name": v["name"], "critical_high_count": crit_high, "risk_band": risk["risk_band"]})
    top_exposure.sort(key=lambda x: -x["critical_high_count"])
    return {
        "total_vendors": len(items), "by_category": by_category, "by_band": by_band,
        "top_exposure": top_exposure[:10],
    }


@router.get("/v1/vendors/renewals")
async def vendor_renewals(days: int = RENEWAL_WARN_DAYS, user: dict = Depends(require_module("/vendors"))):
    """Upcoming/overdue contract renewals across all vendors, for the Vendor Mgmt
    list page's Contracts panel -- distinct from the nightly reminder sweep (which
    only fires once per renewal_date); this is a live read, always current."""
    cutoff = (datetime.now(timezone.utc) + timedelta(days=days)).date().isoformat()
    items = await db.vendors.find(
        {"renewal_date": {"$ne": None, "$lte": cutoff}}, {"_id": 0}
    ).sort("renewal_date", 1).to_list(500)
    today = datetime.now(timezone.utc).date().isoformat()
    out = []
    for v in items:
        out.append({
            "id": v["id"], "name": v["name"], "category": v["category"],
            "renewal_date": v["renewal_date"], "overdue": v["renewal_date"] < today,
            "contract_owner": v.get("contract_owner"), "dpa_status": v.get("dpa_status") or "not_required",
            "security_questionnaire_status": v.get("security_questionnaire_status") or "not_started",
        })
    return {"items": out, "total": len(out)}


@router.get("/v1/vendors/{vendor_id}/risk-history")
async def vendor_risk_history(vendor_id: str, days: int = 180, user: dict = Depends(require_module("/vendors"))):
    v = await db.vendors.find_one({"id": vendor_id}, {"_id": 0})
    if not v:
        raise HTTPException(404, "Vendor not found")
    items = await get_vendor_risk_history(db, vendor_id, days=days)
    return {"items": items}


@router.get("/v1/vendors/{vendor_id}")
async def get_vendor(vendor_id: str, user: dict = Depends(require_module("/vendors"))):
    v = await db.vendors.find_one({"id": vendor_id}, {"_id": 0})
    if not v:
        raise HTTPException(404, "Vendor not found")
    risk = await compute_vendor_risk(db, v)
    exposure = []
    if v.get("domain"):
        exposure = await db.osint_findings.find({"target": v["domain"]}, {"_id": 0}).sort("found_at", -1).to_list(200)
    return {**v, **risk, "exposure": exposure}


@router.patch("/v1/vendors/{vendor_id}")
async def update_vendor(vendor_id: str, body: VendorUpdateBody, user: dict = Depends(require_module("/vendors", level="edit"))):
    v = await db.vendors.find_one({"id": vendor_id}, {"_id": 0})
    if not v:
        raise HTTPException(404, "Vendor not found")
    updates = {k: val for k, val in body.model_dump().items() if val is not None}
    if "category" in updates and updates["category"] not in CATEGORIES:
        raise HTTPException(400, f"category must be one of {CATEGORIES}")
    if "org_criticality" in updates and not (1 <= updates["org_criticality"] <= 5):
        raise HTTPException(400, "org_criticality must be 1-5")
    if "dpa_status" in updates and updates["dpa_status"] not in DPA_STATUSES:
        raise HTTPException(400, f"dpa_status must be one of {DPA_STATUSES}")
    if "security_questionnaire_status" in updates and updates["security_questionnaire_status"] not in QUESTIONNAIRE_STATUSES:
        raise HTTPException(400, f"security_questionnaire_status must be one of {QUESTIONNAIRE_STATUSES}")
    # Pushing the renewal date out (or setting one for the first time) should re-arm
    # the reminder sweep for the new date rather than staying silent forever because
    # an old renewal was already reminded-and-acknowledged.
    if "renewal_date" in updates and updates["renewal_date"] != v.get("renewal_date"):
        updates["renewal_reminder_sent"] = False
    updates["updated_at"] = now_iso()
    await db.vendors.update_one({"id": vendor_id}, {"$set": updates})
    await _log(db, "updated", vendor_id, user["email"], f"Updated: {', '.join(k for k in updates if k != 'updated_at')}")
    return {**v, **updates}


@router.delete("/v1/vendors/{vendor_id}")
async def delete_vendor(vendor_id: str, user: dict = Depends(require_module("/vendors", level="edit"))):
    v = await db.vendors.find_one({"id": vendor_id}, {"_id": 0})
    if not v:
        raise HTTPException(404, "Vendor not found")
    await disable_vendor_monitoring(db, v)
    await db.vendors.delete_one({"id": vendor_id})
    await _log(db, "removed", vendor_id, user["email"], f"Vendor removed: {v['name']}")
    return {"ok": True}


@router.post("/v1/vendors/bulk-delete")
async def bulk_delete_vendors(body: BulkIds, user: dict = Depends(require_module("/vendors", level="edit"))):
    if not body.ids:
        raise HTTPException(400, "No vendors selected")
    deleted = 0
    for vid in body.ids:
        v = await db.vendors.find_one({"id": vid}, {"_id": 0})
        if not v:
            continue
        await disable_vendor_monitoring(db, v)
        await db.vendors.delete_one({"id": vid})
        await _log(db, "removed", vid, user["email"], f"Vendor removed (bulk): {v['name']}")
        deleted += 1
    return {"ok": True, "deleted": deleted}


@router.post("/v1/vendors/{vendor_id}/monitor")
async def set_vendor_monitoring(vendor_id: str, body: MonitorBody, user: dict = Depends(require_module("/vendors", level="edit"))):
    v = await db.vendors.find_one({"id": vendor_id}, {"_id": 0})
    if not v:
        raise HTTPException(404, "Vendor not found")
    if body.enabled and not v.get("domain"):
        raise HTTPException(400, "Vendor needs a domain set before monitoring can be enabled")
    if body.enabled:
        created = await enable_vendor_monitoring(db, v)
        await _log(db, "monitoring_enabled", vendor_id, user["email"], f"Compromise monitoring enabled ({created} schedule(s) created)")
    else:
        removed = await disable_vendor_monitoring(db, v)
        await _log(db, "monitoring_disabled", vendor_id, user["email"], f"Compromise monitoring disabled ({removed} schedule(s) removed)")
    await db.vendors.update_one({"id": vendor_id}, {"$set": {"monitoring_enabled": body.enabled, "updated_at": now_iso()}})
    return {"ok": True, "monitoring_enabled": body.enabled}


@router.post("/v1/vendors/{vendor_id}/check-now")
async def check_vendor_now(vendor_id: str, user: dict = Depends(require_module("/vendors", level="edit"))):
    v = await db.vendors.find_one({"id": vendor_id}, {"_id": 0})
    if not v:
        raise HTTPException(404, "Vendor not found")
    if not v.get("domain"):
        raise HTTPException(400, "Vendor needs a domain set to check for compromise")
    results = await check_vendor_compromise(db, v)
    return {"ok": True, "results": results}


@router.get("/v1/vendors/{vendor_id}/exposure")
async def get_vendor_exposure(vendor_id: str, user: dict = Depends(require_module("/vendors"))):
    v = await db.vendors.find_one({"id": vendor_id}, {"_id": 0})
    if not v:
        raise HTTPException(404, "Vendor not found")
    if not v.get("domain"):
        return {"items": []}
    items = await db.osint_findings.find({"target": v["domain"]}, {"_id": 0}).sort("found_at", -1).to_list(200)
    return {"items": items}
