"""Item 62 -- Remediation Campaign / Patch Tracker routes."""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from db import db
from rbac import require_module
import remediation_campaigns as rc

router = APIRouter()
MODULE_KEY = "/remediation-campaigns"


class CampaignBody(BaseModel):
    name: str
    description: str = ""
    owner_team: Optional[str] = None
    due_date: Optional[str] = None
    finding_ids: Optional[list] = None
    filter: Optional[dict] = None       # {severity, owner_team, kev, cve, asset_id}


@router.get("/v1/remediation-campaigns")
async def list_campaigns(owner_team: Optional[str] = None,
                         user: dict = Depends(require_module(MODULE_KEY))):
    return {"items": await rc.list_campaigns(db, owner_team=owner_team)}


@router.get("/v1/remediation-campaigns/alerts")
async def campaign_alerts(user: dict = Depends(require_module(MODULE_KEY))):
    return await rc.alerts(db)


@router.post("/v1/remediation-campaigns")
async def create_campaign(body: CampaignBody,
                          user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    if not body.name.strip():
        raise HTTPException(400, "A campaign name is required")
    if not body.finding_ids and not body.filter:
        raise HTTPException(400, "Provide finding_ids or a filter to populate the campaign")
    camp = await rc.create_campaign(
        db, name=body.name.strip(), description=body.description, owner_team=body.owner_team,
        due_date=body.due_date, finding_ids=body.finding_ids, filt=body.filter,
        created_by=user.get("email") or user.get("id"))
    if not camp["finding_ids"]:
        await db.remediation_campaigns.delete_one({"id": camp["id"]})
        raise HTTPException(400, "Nothing matched — the campaign would be empty")
    return camp


@router.get("/v1/remediation-campaigns/{campaign_id}")
async def get_campaign(campaign_id: str, user: dict = Depends(require_module(MODULE_KEY))):
    camp = await rc.campaign_detail(db, campaign_id)
    if not camp:
        raise HTTPException(404, "Campaign not found")
    return camp


class CampaignPatch(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    due_date: Optional[str] = None
    status: Optional[str] = None
    add_finding_ids: Optional[list] = None
    remove_finding_ids: Optional[list] = None


@router.patch("/v1/remediation-campaigns/{campaign_id}")
async def update_campaign(campaign_id: str, body: CampaignPatch,
                          user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    camp = await db.remediation_campaigns.find_one({"id": campaign_id}, {"_id": 0})
    if not camp:
        raise HTTPException(404, "Campaign not found")
    patch = {}
    for fld in ("name", "description", "due_date", "status"):
        v = getattr(body, fld)
        if v is not None:
            patch[fld] = v
    ids = set(camp.get("finding_ids") or [])
    if body.add_finding_ids:
        ids |= set(body.add_finding_ids)
    if body.remove_finding_ids:
        ids -= set(body.remove_finding_ids)
    if body.add_finding_ids or body.remove_finding_ids:
        patch["finding_ids"] = sorted(ids)
    if patch:
        await db.remediation_campaigns.update_one({"id": campaign_id}, {"$set": patch})
    return await rc.campaign_detail(db, campaign_id)


@router.delete("/v1/remediation-campaigns/{campaign_id}")
async def delete_campaign(campaign_id: str,
                          user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    await db.remediation_campaigns.delete_one({"id": campaign_id})
    return {"ok": True}
