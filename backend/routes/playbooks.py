"""Remediation playbooks — step-by-step fix guidance, rollback notes, and validation
checks that can be attached to a specific CVE or a whole CWE class of finding, so
analysts get "how do I actually fix this" instead of just "here's a CVE"."""
import uuid
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from db import db
from auth_utils import get_current_user, require_role
from routes.common import now_iso, _clean

router = APIRouter()


class PlaybookBody(BaseModel):
    title: str
    description: Optional[str] = ""
    cve: Optional[str] = None          # exact-match, takes priority over cwe
    cwe: Optional[str] = None          # fallback match for the whole weakness class
    steps: List[str] = []
    rollback_notes: Optional[str] = ""
    validation_checks: List[str] = []


@router.get("/v1/playbooks")
async def list_playbooks(user: dict = Depends(get_current_user), q: Optional[str] = None):
    flt = {}
    if q:
        flt["$or"] = [{"title": {"$regex": q, "$options": "i"}}, {"cve": {"$regex": q, "$options": "i"}},
                      {"cwe": {"$regex": q, "$options": "i"}}]
    items = await db.playbooks.find(flt, {"_id": 0}).sort("title", 1).to_list(500)
    return {"items": items}


@router.get("/v1/playbooks/{playbook_id}")
async def get_playbook(playbook_id: str, user: dict = Depends(get_current_user)):
    p = await db.playbooks.find_one({"id": playbook_id}, {"_id": 0})
    if not p:
        raise HTTPException(404, "Playbook not found")
    return p


@router.post("/v1/playbooks")
async def create_playbook(body: PlaybookBody, user: dict = Depends(require_role("admin", "manager"))):
    doc = {"id": str(uuid.uuid4()), **body.model_dump(), "created_at": now_iso(), "created_by": user["email"]}
    await db.playbooks.insert_one(doc)
    return _clean(doc)


@router.put("/v1/playbooks/{playbook_id}")
async def update_playbook(playbook_id: str, body: PlaybookBody, user: dict = Depends(require_role("admin", "manager"))):
    p = await db.playbooks.find_one({"id": playbook_id}, {"_id": 0})
    if not p:
        raise HTTPException(404, "Playbook not found")
    update = body.model_dump()
    update["updated_at"] = now_iso()
    await db.playbooks.update_one({"id": playbook_id}, {"$set": update})
    return {**p, **update}


@router.delete("/v1/playbooks/{playbook_id}")
async def delete_playbook(playbook_id: str, user: dict = Depends(require_role("admin", "manager"))):
    await db.playbooks.delete_one({"id": playbook_id})
    return {"ok": True}


@router.get("/v1/findings/{finding_id}/playbook")
async def playbook_for_finding(finding_id: str, user: dict = Depends(get_current_user)):
    """Best-match lookup: exact CVE match wins, otherwise fall back to a CWE-level
    playbook (a general 'how to fix SQL injection' guide covers every CVE of that
    weakness class), otherwise no playbook exists yet for this finding."""
    f = await db.findings.find_one({"id": finding_id}, {"_id": 0})
    if not f:
        raise HTTPException(404, "Finding not found")
    match = None
    match_basis = None
    if f.get("cve"):
        match = await db.playbooks.find_one({"cve": f["cve"]}, {"_id": 0})
        if match:
            match_basis = "cve"
    if not match and f.get("cwe"):
        match = await db.playbooks.find_one({"cwe": f["cwe"]}, {"_id": 0})
        if match:
            match_basis = "cwe"
    if not match:
        return {"playbook": None, "match_basis": None}
    return {"playbook": match, "match_basis": match_basis}
