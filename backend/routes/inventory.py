"""Inventory routes: assets and products."""
import uuid
from datetime import datetime, timezone
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from db import db
from rbac import require_module
from auth_utils import get_current_user, require_role
from routes.common import user_teams

router = APIRouter()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------- ASSETS ---------------------------
@router.get("/v1/assets")
async def list_assets(user: dict = Depends(get_current_user),
                     q: Optional[str] = None, criticality: Optional[str] = None,
                     environment: Optional[str] = None, exposure: Optional[str] = None,
                     product_id: Optional[str] = None,
                     limit: int = 100, offset: int = 0,
                     _rbac: dict = Depends(require_module("/assets"))):
    flt: dict = {}
    if criticality:
        flt["criticality"] = criticality
    if environment:
        flt["environment"] = environment
    if exposure:
        flt["exposure"] = exposure
    if product_id:
        flt["product_id"] = product_id
    # Team scoping: analyst/executive users only see assets owned by (any of) their
    # own team(s), OR assets with no team yet -- unlike findings (which are scoped
    # strictly to the user's teams with no "unassigned" carve-out), an unowned asset
    # needs to stay visible to *someone* or it could never get claimed by anyone in
    # the first place. admin + manager are unrestricted, same convention as findings.
    # Built as an `$and` clause (not a second top-level `$or`) specifically so it
    # composes with the search box's own `$or` below instead of one silently
    # clobbering the other -- two `$or` keys on the same dict is just the second
    # write winning, which would have quietly widened visibility past the user's
    # own team the moment they typed anything into the search box.
    and_clauses = []
    if user.get("role") in ("analyst", "executive"):
        teams = user_teams(user)
        and_clauses.append({"$or": [
            {"owner_team": {"$in": teams}} if teams else {"owner_team": {"$in": []}},
            {"owner_team": {"$in": [None, "Unassigned", ""]}},
        ]})
    if q:
        and_clauses.append({"$or": [
            {"hostname": {"$regex": q, "$options": "i"}},
            {"ip": {"$regex": q, "$options": "i"}},
            {"fqdn": {"$regex": q, "$options": "i"}},
        ]})
    if and_clauses:
        flt["$and"] = and_clauses
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


@router.get("/v1/assets/{asset_id}/software")
async def asset_software_inventory(asset_id: str, user: dict = Depends(get_current_user)):
    """Per-asset installed-software list, populated by the Microsoft Defender for
    Endpoint EDR connector's per-device sync (see defender_sync.py) and/or Qualys
    GAV/CSAM's per-host software pull (see qualys_gav.py) -- see
    vendor_management.DEVICE_SOFTWARE_SOURCES for the exact source list this
    accepts. Distinct from SBOM component data (sbom.py) -- this is agent-/
    scanner-reported OS-level installed software, not application dependency
    manifests."""
    from vendor_management import DEVICE_SOFTWARE_SOURCES
    items = await db.software_inventory.find(
        {"source": {"$in": DEVICE_SOFTWARE_SOURCES}, "asset_id": asset_id}, {"_id": 0},
    ).sort("vendor", 1).to_list(2000)
    return {"items": items, "total": len(items)}


@router.get("/v1/patch-compliance/summary")
async def patch_compliance_summary(user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/assets"))):
    """Aggregate Intune-managed-device compliance view -- see intune_sync.py's
    get_patch_compliance_summary for what counts as 'managed' vs 'unmanaged'."""
    from intune_sync import get_patch_compliance_summary
    return await get_patch_compliance_summary(db)


@router.get("/v1/assets/{asset_id}/albert-alerts")
async def asset_albert_alerts(asset_id: str, days: int = 90, user: dict = Depends(get_current_user)):
    """Albert (CIS/MS-ISAC) network sensor alerts linked to this asset -- same shape
    as the Vulnerabilities panel above, but for network-detection alerts instead of
    scanner findings. An alert is "linked" the same way routes/albert.py's single-alert
    view resolves source/destination assets: a manual link override
    (source_asset_id_override / destination_asset_id_override) always wins, falling
    back to a plain IP match against this asset's ip field."""
    a = await db.assets.find_one({"id": asset_id}, {"_id": 0, "ip": 1})
    ip = (a or {}).get("ip")

    ors = [{"source_asset_id_override": asset_id}, {"destination_asset_id_override": asset_id}]
    if ip:
        ors += [{"source_ip": ip}, {"destination_ip": ip}]

    candidates = await db.albert_alerts.find({"$or": ors}, {"_id": 0}).sort("time_gmt", -1).to_list(2000)

    def _resolves_here(alert, ip_field, override_field):
        override = alert.get(override_field)
        if override:
            return override == asset_id
        return ip is not None and alert.get(ip_field) == ip

    items = [
        al for al in candidates
        if _resolves_here(al, "source_ip", "source_asset_id_override")
        or _resolves_here(al, "destination_ip", "destination_asset_id_override")
    ]

    from datetime import datetime, timezone, timedelta
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    severity_counts: dict = {}
    daily_counts: dict = {}
    for al in items:
        severity_counts[al.get("severity") or "Unknown"] = severity_counts.get(al.get("severity") or "Unknown", 0) + 1
        t = al.get("time_gmt") or ""
        if t >= cutoff:
            day = t[:10]
            daily_counts[day] = daily_counts.get(day, 0) + 1

    return {
        "items": items[:200], "total": len(items),
        "severity_counts": severity_counts,
        "daily_trend": [{"day": d, "count": c} for d, c in sorted(daily_counts.items())],
    }


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
                                user: dict = Depends(require_role("admin", "manager")),
                                _rbac: dict = Depends(require_module("/products", level="edit"))):
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
                               user: dict = Depends(require_role("admin", "manager")),
                               _rbac: dict = Depends(require_module("/products", level="edit"))):
    if not body.asset_ids:
        raise HTTPException(400, "asset_ids is required")
    updated = await _apply_product_to_assets(body.asset_ids, body.product_id)
    return {"updated_assets": updated}


ENVIRONMENT_OPTIONS = ["production", "staging", "development", "test", "unknown"]


class EnvironmentBody(BaseModel):
    environment: str


@router.patch("/v1/assets/{asset_id}/environment")
async def set_asset_environment(asset_id: str, body: EnvironmentBody, user: dict = Depends(get_current_user),
                                 _rbac: dict = Depends(require_module("/assets", level="edit"))):
    a = await db.assets.find_one({"id": asset_id}, {"_id": 0})
    if not a:
        raise HTTPException(404, "Asset not found")
    env = body.environment.strip().lower()
    if not env:
        raise HTTPException(400, "environment is required")
    await db.assets.update_one({"id": asset_id}, {"$set": {"environment": env}})
    return {"ok": True, "environment": env}


class BulkSetEnvironmentBody(BaseModel):
    asset_ids: List[str]
    environment: str


@router.post("/v1/assets/bulk-set-environment")
async def bulk_set_environment(body: BulkSetEnvironmentBody, user: dict = Depends(get_current_user),
                                _rbac: dict = Depends(require_module("/assets", level="edit"))):
    if not body.asset_ids:
        raise HTTPException(400, "asset_ids is required")
    env = body.environment.strip().lower()
    if not env:
        raise HTTPException(400, "environment is required")
    r = await db.assets.update_many({"id": {"$in": body.asset_ids}}, {"$set": {"environment": env}})
    return {"updated_assets": r.modified_count, "environment": env}


class AssetTypeBody(BaseModel):
    asset_type: Optional[str] = None  # set to manually override + lock
    locked: Optional[bool] = None      # set locked=False (with asset_type omitted) to unlock + resume auto-classification


@router.patch("/v1/assets/{asset_id}/type")
async def set_asset_type(asset_id: str, body: AssetTypeBody, user: dict = Depends(get_current_user),
                          _rbac: dict = Depends(require_module("/assets", level="edit"))):
    from asset_classify import TYPES
    a = await db.assets.find_one({"id": asset_id}, {"_id": 0})
    if not a:
        raise HTTPException(404, "Asset not found")

    if body.asset_type is not None:
        if body.asset_type not in TYPES:
            raise HTTPException(400, f"asset_type must be one of {TYPES}")
        await db.assets.update_one({"id": asset_id}, {"$set": {
            "asset_type": body.asset_type, "asset_type_locked": True,
        }})
        return {"ok": True, "asset_type": body.asset_type, "locked": True}

    if body.locked is False:
        await db.assets.update_one({"id": asset_id}, {"$set": {"asset_type_locked": False}})
        return {"ok": True, "locked": False}

    raise HTTPException(400, "Provide asset_type to set+lock, or locked=false to unlock")


@router.post("/v1/admin/assets/recompute-types")
async def recompute_asset_types(user: dict = Depends(require_role("admin", "manager")),
                                 _rbac: dict = Depends(require_module("/assets", level="edit"))):
    """Backfills asset_type from each asset's already-known OS fields -- for assets
    created before this classifier existed, or by an importer that had no OS info
    yet at creation time. Safe to re-run any time; skips manually-locked assets."""
    from asset_classify import recompute_all_asset_types
    return await recompute_all_asset_types(db)


class ClaimAssetBody(BaseModel):
    team: Optional[str] = None  # required only if the user belongs to more than one team


@router.post("/v1/assets/{asset_id}/claim")
async def claim_asset(asset_id: str, body: ClaimAssetBody, user: dict = Depends(get_current_user),
                       _rbac: dict = Depends(require_module("/assets", level="edit"))):
    """Lets any user claim an unassigned asset for one of their own teams -- the
    other half of team-scoped asset visibility: an analyst/executive only sees
    assets on their own team(s) plus unassigned ones (see list_assets above)
    specifically so there's a way to pull an unowned asset into their team instead
    of it being permanently invisible to everyone once assets are scoped. Findings
    already attached to the asset move to the same team so they don't end up
    orphaned from it. Admin/manager aren't team-scoped for visibility, but can still
    use this to claim on a team's behalf."""
    asset = await db.assets.find_one({"id": asset_id}, {"_id": 0})
    if not asset:
        raise HTTPException(404, "Asset not found")
    current_owner = asset.get("owner_team")
    if current_owner and current_owner != "Unassigned":
        raise HTTPException(409, f"Already owned by '{current_owner}' -- ask that team (or an admin) to reassign it instead of claiming.")

    teams = user_teams(user)
    team = body.team or (teams[0] if len(teams) == 1 else None)
    if not team:
        if not teams:
            raise HTTPException(400, "You're not on any team yet -- ask an admin to add you to one before claiming assets.")
        raise HTTPException(400, f"You belong to more than one team -- specify which: {', '.join(teams)}")
    if team not in teams and user.get("role") not in ("admin", "manager"):
        raise HTTPException(403, "You can only claim assets for a team you belong to.")

    await db.assets.update_one({"id": asset_id}, {"$set": {
        "owner_team": team, "ownership_confidence": 1.0,
        "ownership_rationale": f"Claimed by {user.get('email')}",
    }})
    await db.findings.update_many({"asset_id": asset_id}, {"$set": {"owner_team": team}})
    return {"ok": True, "owner_team": team}


# --------------------------- PRODUCTS ---------------------------
@router.get("/v1/products")
async def list_products(user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/products"))):
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
async def create_product(body: ProductBody, user: dict = Depends(require_role("admin", "manager")),
                          _rbac: dict = Depends(require_module("/products", level="edit"))):
    doc = {"id": str(uuid.uuid4()), **body.model_dump(), "created_at": _now_iso()}
    await db.products.insert_one(doc)
    return _clean_out(doc)


@router.put("/v1/products/{product_id}")
async def update_product(product_id: str, body: ProductBody,
                          user: dict = Depends(require_role("admin", "manager")),
                          _rbac: dict = Depends(require_module("/products", level="edit"))):
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
