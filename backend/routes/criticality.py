"""Routes for the asset criticality auto-scoring engine -- see backend/criticality.py
for the scoring logic itself and its rationale."""
import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from db import db
from rbac import require_module
from auth_utils import get_current_user, require_role
from routes.common import now_iso

router = APIRouter()


@router.get("/v1/admin/criticality-rules")
async def list_rules(user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/admin/criticality-scoring"))):
    from criticality import FIELD_META
    items = await db.criticality_rules.find({}, {"_id": 0}).sort("created_at", 1).to_list(500)
    return {"items": items, "field_meta": FIELD_META}


class RuleBody(BaseModel):
    name: str
    field: str
    values: List[str]
    points: int
    enabled: bool = True


def _validate_rule(body: RuleBody):
    from criticality import FIELD_META
    if body.field not in FIELD_META:
        raise HTTPException(400, f"Unknown field '{body.field}' -- must be one of {list(FIELD_META)}")
    if not [v for v in body.values if str(v).strip()]:
        raise HTTPException(400, "At least one value is required")
    if not (-100 <= body.points <= 100):
        raise HTTPException(400, "points must be between -100 and 100")


@router.post("/v1/admin/criticality-rules")
async def create_rule(body: RuleBody, user: dict = Depends(require_role("admin"))):
    _validate_rule(body)
    doc = {"id": str(uuid.uuid4()), **body.model_dump(), "created_at": now_iso()}
    await db.criticality_rules.insert_one(doc)
    return {k: v for k, v in doc.items() if k != "_id"}


@router.put("/v1/admin/criticality-rules/{rule_id}")
async def update_rule(rule_id: str, body: RuleBody, user: dict = Depends(require_role("admin"))):
    _validate_rule(body)
    existing = await db.criticality_rules.find_one({"id": rule_id}, {"_id": 0})
    if not existing:
        raise HTTPException(404, "Rule not found")
    update = body.model_dump()
    update["updated_at"] = now_iso()
    await db.criticality_rules.update_one({"id": rule_id}, {"$set": update})
    return {**existing, **update}


@router.delete("/v1/admin/criticality-rules/{rule_id}")
async def delete_rule(rule_id: str, user: dict = Depends(require_role("admin"))):
    await db.criticality_rules.delete_one({"id": rule_id})
    return {"ok": True}


@router.post("/v1/admin/criticality-rules/reset-defaults")
async def reset_defaults(user: dict = Depends(require_role("admin"))):
    """Wipes custom rules and reinstalls the starter set -- an escape hatch if an org
    has edited these into a broken state and just wants the example baseline back."""
    from criticality import _default_rules
    await db.criticality_rules.delete_many({})
    await db.criticality_rules.insert_many(_default_rules(now_iso()))
    items = await db.criticality_rules.find({}, {"_id": 0}).to_list(500)
    return {"items": items}


class ThresholdsBody(BaseModel):
    crown_jewel: int
    critical: int
    high: int
    medium: int


@router.get("/v1/admin/criticality-thresholds")
async def get_thresholds(user: dict = Depends(get_current_user)):
    from criticality import DEFAULT_THRESHOLDS
    doc = await db.criticality_config.find_one({}, {"_id": 0})
    return {"thresholds": (doc or {}).get("thresholds") or DEFAULT_THRESHOLDS}


@router.put("/v1/admin/criticality-thresholds")
async def set_thresholds(body: ThresholdsBody, user: dict = Depends(require_role("admin"))):
    vals = body.model_dump()
    ordered = ["crown_jewel", "critical", "high", "medium"]
    for a, b in zip(ordered, ordered[1:]):
        if vals[a] <= vals[b]:
            raise HTTPException(400, f"'{a}' threshold ({vals[a]}) must be greater than '{b}' threshold ({vals[b]})")
    await db.criticality_config.update_one({}, {"$set": {"thresholds": vals, "updated_at": now_iso()}}, upsert=True)
    return {"thresholds": vals}


@router.post("/v1/admin/assets/recompute-criticality")
async def bulk_recompute(user: dict = Depends(require_role("admin", "manager"))):
    from criticality import recompute_all
    return await recompute_all(db)


class CriticalityOverrideBody(BaseModel):
    criticality: Optional[str] = None   # set to manually override + lock
    locked: Optional[bool] = None       # set locked=False (with criticality omitted) to unlock + re-auto-score


@router.patch("/v1/assets/{asset_id}/criticality")
async def set_asset_criticality(asset_id: str, body: CriticalityOverrideBody, user: dict = Depends(require_role("admin", "manager"))):
    from criticality import TIERS, recompute_asset_criticality
    asset = await db.assets.find_one({"id": asset_id}, {"_id": 0})
    if not asset:
        raise HTTPException(404, "Asset not found")

    if body.criticality is not None:
        if body.criticality not in TIERS:
            raise HTTPException(400, f"criticality must be one of {TIERS}")
        await db.assets.update_one({"id": asset_id}, {"$set": {
            "criticality": body.criticality, "criticality_locked": True,
            "criticality_rationale": [{"name": f"Manually set by {user['email']}", "points": None}],
            "criticality_computed_at": now_iso(),
        }})
        return {"ok": True, "criticality": body.criticality, "locked": True}

    if body.locked is False:
        await db.assets.update_one({"id": asset_id}, {"$set": {"criticality_locked": False}})
        result = await recompute_asset_criticality(db, asset_id)
        return {"ok": True, "locked": False, **result}

    raise HTTPException(400, "Provide either 'criticality' (to set + lock) or 'locked: false' (to unlock + resume auto-scoring)")
