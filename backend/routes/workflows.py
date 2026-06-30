"""Workflows routes: engagements, tickets, exceptions."""
import uuid
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from db import db
from auth_utils import get_current_user
from routes.common import now_iso, _clean

router = APIRouter()


# --------------------------- ENGAGEMENTS ---------------------------
@router.get("/v1/engagements")
async def list_engagements(user: dict = Depends(get_current_user)):
    items = await db.engagements.find({}, {"_id": 0}).sort("started_at", -1).to_list(100)
    return {"items": items}


# --------------------------- TICKETS ---------------------------
@router.get("/v1/tickets")
async def list_tickets(user: dict = Depends(get_current_user), status: Optional[str] = None):
    flt = {}
    if status:
        flt["status"] = status
    items = await db.tickets.find(flt, {"_id": 0}).sort("updated_at", -1).to_list(500)
    return {"items": items}


# --------------------------- EXCEPTIONS ---------------------------
@router.get("/v1/exceptions")
async def list_exceptions(user: dict = Depends(get_current_user)):
    items = await db.exceptions.find({}, {"_id": 0}).to_list(200)
    for e in items:
        f = await db.findings.find_one({"id": e["finding_id"]}, {"_id": 0, "title": 1, "severity": 1, "asset_hostname": 1, "cve": 1})
        if f:
            e["finding_title"] = f.get("title")
            e["severity"] = f.get("severity")
            e["asset_hostname"] = f.get("asset_hostname")
            e["cve"] = f.get("cve")
    return {"items": items}


class ExceptionCreate(BaseModel):
    finding_id: str
    rationale: str
    expires_at: str
    compensating_controls: List[str] = []


@router.post("/v1/exceptions")
async def create_exception(body: ExceptionCreate, user: dict = Depends(get_current_user)):
    f = await db.findings.find_one({"id": body.finding_id})
    if not f:
        raise HTTPException(404, "Finding not found")
    exc = {
        "id": str(uuid.uuid4()), "finding_id": body.finding_id, "asset_id": f.get("asset_id"),
        "rationale": body.rationale, "approver": user["email"], "approved_at": now_iso(),
        "expires_at": body.expires_at, "renewal_history": [],
        "compensating_controls": body.compensating_controls, "evidence_files": [], "status": "active",
    }
    await db.exceptions.insert_one(exc)
    await db.findings.update_one({"id": body.finding_id}, {"$set": {"status": "Accepted risk", "last_changed_at": now_iso()}})
    return _clean(exc)
