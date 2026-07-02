"""Remediation playbooks — step-by-step fix guidance, rollback notes, and validation
checks that can be attached to a specific CVE or a whole CWE class of finding, so
analysts get "how do I actually fix this" instead of just "here's a CVE".

Besides the CVE/CWE auto-match, a specific finding can also have a playbook manually
attached (playbook_override_id on the finding doc) -- useful when auto-match picks the
wrong one or finds nothing. Per-finding checklist progress (which steps/validation
checks are done) is persisted on the finding too, so it survives a page refresh instead
of resetting every time you open the flow view."""
import uuid
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from db import db
from auth_utils import get_current_user, require_role
from routes.common import now_iso, _clean

router = APIRouter()


# Visual grouping for the Playbooks board -- each maps to an icon/color on the frontend.
PLAYBOOK_CATEGORIES = ["patching", "appsec", "identity", "cloud", "crypto", "network", "other"]


class PlaybookBody(BaseModel):
    title: str
    description: Optional[str] = ""
    category: Optional[str] = "other"  # one of PLAYBOOK_CATEGORIES, drives icon/color
    cve: Optional[str] = None          # exact-match, takes priority over cwe
    cwe: Optional[str] = None          # fallback match for the whole weakness class
    steps: List[str] = []
    rollback_notes: Optional[str] = ""
    validation_checks: List[str] = []


@router.get("/v1/playbooks")
async def list_playbooks(user: dict = Depends(get_current_user), q: Optional[str] = None, category: Optional[str] = None):
    flt = {}
    if q:
        flt["$or"] = [{"title": {"$regex": q, "$options": "i"}}, {"cve": {"$regex": q, "$options": "i"}},
                      {"cwe": {"$regex": q, "$options": "i"}}]
    if category:
        flt["category"] = category
    items = await db.playbooks.find(flt, {"_id": 0}).sort("title", 1).to_list(500)
    return {"items": items, "categories": PLAYBOOK_CATEGORIES}


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


class PlaybookAttachBody(BaseModel):
    playbook_id: Optional[str] = None  # None/omitted clears the override, reverting to auto CVE/CWE match


class PlaybookProgressBody(BaseModel):
    playbook_id: str
    steps_done: List[int] = []
    validated_checks: List[int] = []
    validated: bool = False


@router.get("/v1/findings/{finding_id}/playbook")
async def playbook_for_finding(finding_id: str, user: dict = Depends(get_current_user)):
    """Best-match lookup: a manually-attached playbook (see PUT .../playbook-attach)
    wins over everything, then exact CVE match, then a CWE-level playbook (a general
    'how to fix SQL injection' guide covers every CVE of that weakness class), otherwise
    no playbook exists yet for this finding. Always includes this finding's persisted
    checklist progress so the frontend doesn't need a second round-trip."""
    f = await db.findings.find_one({"id": finding_id}, {"_id": 0})
    if not f:
        raise HTTPException(404, "Finding not found")
    match = None
    match_basis = None
    if f.get("playbook_override_id"):
        match = await db.playbooks.find_one({"id": f["playbook_override_id"]}, {"_id": 0})
        if match:
            match_basis = "manual"
    if not match and f.get("cve"):
        match = await db.playbooks.find_one({"cve": f["cve"]}, {"_id": 0})
        if match:
            match_basis = "cve"
    if not match and f.get("cwe"):
        match = await db.playbooks.find_one({"cwe": f["cwe"]}, {"_id": 0})
        if match:
            match_basis = "cwe"
    if not match:
        return {"playbook": None, "match_basis": None, "progress": None}
    progress = f.get("playbook_progress")
    if progress and progress.get("playbook_id") != match["id"]:
        progress = None  # stale progress from a since-replaced playbook -- don't show it as if it applies
    return {"playbook": match, "match_basis": match_basis, "progress": progress}


@router.put("/v1/findings/{finding_id}/playbook-attach")
async def attach_playbook(finding_id: str, body: PlaybookAttachBody, user: dict = Depends(get_current_user)):
    """Manually pin (or un-pin) which playbook applies to this finding, overriding the
    automatic CVE/CWE match. Clears any existing checklist progress on attach/detach
    since progress against a different playbook's steps doesn't carry over."""
    f = await db.findings.find_one({"id": finding_id}, {"_id": 0})
    if not f:
        raise HTTPException(404, "Finding not found")
    update: dict = {"playbook_progress": None}
    if body.playbook_id:
        pb = await db.playbooks.find_one({"id": body.playbook_id}, {"_id": 0})
        if not pb:
            raise HTTPException(404, "Playbook not found")
        update["playbook_override_id"] = body.playbook_id
        action, details = "playbook_attached", f"Attached playbook '{pb['title']}'"
    else:
        update["playbook_override_id"] = None
        action, details = "playbook_detached", "Removed manually-attached playbook (reverted to auto-match)"
    await db.findings.update_one({"id": finding_id}, {"$set": update})
    await db.activity_log.insert_one({
        "id": str(uuid.uuid4()), "entity_type": "finding", "entity_id": finding_id,
        "action": action, "actor": user["email"], "details": details, "timestamp": now_iso(),
    })
    return {"ok": True}


@router.put("/v1/findings/{finding_id}/playbook-progress")
async def update_playbook_progress(finding_id: str, body: PlaybookProgressBody, user: dict = Depends(get_current_user)):
    """Persists which steps/validation checks are checked off for this finding's
    playbook, so it survives a page refresh instead of resetting every time (the flow
    view used to keep this in local component state only)."""
    f = await db.findings.find_one({"id": finding_id}, {"_id": 0})
    if not f:
        raise HTTPException(404, "Finding not found")
    pb = await db.playbooks.find_one({"id": body.playbook_id}, {"_id": 0})
    if not pb:
        raise HTTPException(404, "Playbook not found")
    n_steps = len(pb.get("steps") or [])
    n_checks = len(pb.get("validation_checks") or [])
    steps_done = sorted({i for i in body.steps_done if 0 <= i < n_steps})
    validated_checks = sorted({i for i in body.validated_checks if 0 <= i < n_checks})
    progress = {
        "playbook_id": body.playbook_id, "steps_done": steps_done, "validated_checks": validated_checks,
        "validated": bool(body.validated), "updated_at": now_iso(), "updated_by": user["email"],
    }
    await db.findings.update_one({"id": finding_id}, {"$set": {"playbook_progress": progress}})
    await db.activity_log.insert_one({
        "id": str(uuid.uuid4()), "entity_type": "finding", "entity_id": finding_id,
        "action": "playbook_progress_updated", "actor": user["email"],
        "details": f"{len(steps_done)}/{n_steps} step(s) checked" + (", marked validated" if body.validated else ""),
        "timestamp": now_iso(),
    })
    return progress
