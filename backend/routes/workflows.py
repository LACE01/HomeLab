"""Workflows routes: engagements, tickets, exceptions.

Exceptions follow a governance workflow rather than self-approval:
  requested (pending_approval) -> approved (active) | rejected
  active -> expired (automatic, past expires_at) or renewed (re-enters pending_approval)
"""
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from db import db
from auth_utils import get_current_user, require_role
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
def _enrich_finding_fields(e: dict, f: Optional[dict]) -> None:
    if f:
        e["finding_title"] = f.get("title")
        e["severity"] = f.get("severity")
        e["asset_hostname"] = f.get("asset_hostname")
        e["cve"] = f.get("cve")


@router.get("/v1/exceptions")
async def list_exceptions(user: dict = Depends(get_current_user), status: Optional[str] = None):
    flt = {}
    if status:
        flt["status"] = status
    items = await db.exceptions.find(flt, {"_id": 0}).sort("requested_at", -1).to_list(200)
    now = now_iso()
    for e in items:
        f = await db.findings.find_one({"id": e["finding_id"]}, {"_id": 0, "title": 1, "severity": 1, "asset_hostname": 1, "cve": 1})
        _enrich_finding_fields(e, f)
        if e.get("status") == "active" and e.get("expires_at"):
            e["days_until_expiry"] = max(0, (datetime.fromisoformat(e["expires_at"].replace("Z", "+00:00"))
                                              - datetime.now(timezone.utc)).days)
    return {"items": items}


class ExceptionCreate(BaseModel):
    finding_id: str
    business_justification: str
    expires_at: str
    compensating_controls: List[str] = []


@router.post("/v1/exceptions")
async def request_exception(body: ExceptionCreate, user: dict = Depends(get_current_user)):
    """Request a time-bound risk exception. Does NOT immediately accept the risk --
    the finding stays in its current status until an admin/manager approves."""
    f = await db.findings.find_one({"id": body.finding_id})
    if not f:
        raise HTTPException(404, "Finding not found")
    exc = {
        "id": str(uuid.uuid4()), "finding_id": body.finding_id, "asset_id": f.get("asset_id"),
        "business_justification": body.business_justification,
        "rationale": body.business_justification,  # kept for backward compatibility with older UI/reports
        "requested_by": user["email"], "requested_at": now_iso(),
        "approver": None, "approved_at": None, "rejection_reason": None,
        "expires_at": body.expires_at, "renewal_history": [],
        "compensating_controls": body.compensating_controls, "evidence_files": [],
        "status": "pending_approval", "reminder_sent": False,
    }
    await db.exceptions.insert_one(exc)
    await db.activity_log.insert_one({
        "id": str(uuid.uuid4()), "entity_type": "finding", "entity_id": body.finding_id,
        "action": "exception_requested", "actor": user["email"], "timestamp": now_iso(),
        "details": f"Risk exception requested, expires {body.expires_at[:10]}",
    })
    return _clean(exc)


@router.post("/v1/exceptions/{exception_id}/approve")
async def approve_exception(exception_id: str, user: dict = Depends(require_role("admin", "manager"))):
    exc = await db.exceptions.find_one({"id": exception_id}, {"_id": 0})
    if not exc:
        raise HTTPException(404, "Exception not found")
    if exc["status"] not in ("pending_approval",):
        raise HTTPException(400, f"Cannot approve an exception in status '{exc['status']}'")
    await db.exceptions.update_one({"id": exception_id}, {"$set": {
        "status": "active", "approver": user["email"], "approved_at": now_iso(), "reminder_sent": False,
    }})
    await db.findings.update_one({"id": exc["finding_id"]},
        {"$set": {"status": "Accepted risk", "last_changed_at": now_iso()}})
    await db.activity_log.insert_one({
        "id": str(uuid.uuid4()), "entity_type": "finding", "entity_id": exc["finding_id"],
        "action": "exception_approved", "actor": user["email"], "timestamp": now_iso(),
        "details": f"Risk exception approved by {user['email']}, expires {exc['expires_at'][:10]}",
    })
    return {"ok": True}


class RejectBody(BaseModel):
    reason: str


@router.post("/v1/exceptions/{exception_id}/reject")
async def reject_exception(exception_id: str, body: RejectBody, user: dict = Depends(require_role("admin", "manager"))):
    exc = await db.exceptions.find_one({"id": exception_id}, {"_id": 0})
    if not exc:
        raise HTTPException(404, "Exception not found")
    if exc["status"] not in ("pending_approval",):
        raise HTTPException(400, f"Cannot reject an exception in status '{exc['status']}'")
    await db.exceptions.update_one({"id": exception_id}, {"$set": {
        "status": "rejected", "approver": user["email"], "approved_at": now_iso(),
        "rejection_reason": body.reason,
    }})
    await db.activity_log.insert_one({
        "id": str(uuid.uuid4()), "entity_type": "finding", "entity_id": exc["finding_id"],
        "action": "exception_rejected", "actor": user["email"], "timestamp": now_iso(),
        "details": f"Risk exception rejected by {user['email']}: {body.reason}",
    })
    return {"ok": True}


class RenewBody(BaseModel):
    new_expires_at: str
    justification: str


@router.post("/v1/exceptions/{exception_id}/renew")
async def request_renewal(exception_id: str, body: RenewBody, user: dict = Depends(get_current_user)):
    """Re-opens approval on an active (or recently expired) exception with a new expiry
    date. Goes back through the same approval gate rather than auto-extending, so long-
    lived exceptions can't silently persist forever without someone re-checking them."""
    exc = await db.exceptions.find_one({"id": exception_id}, {"_id": 0})
    if not exc:
        raise HTTPException(404, "Exception not found")
    if exc["status"] not in ("active", "expired"):
        raise HTTPException(400, f"Cannot renew an exception in status '{exc['status']}'")
    history_entry = {
        "previous_expires_at": exc["expires_at"], "requested_new_expires_at": body.new_expires_at,
        "justification": body.justification, "requested_by": user["email"], "requested_at": now_iso(),
    }
    await db.exceptions.update_one({"id": exception_id}, {"$set": {
        "status": "pending_approval", "expires_at": body.new_expires_at,
        "requested_by": user["email"], "requested_at": now_iso(),
        "approver": None, "approved_at": None, "reminder_sent": False,
    }, "$push": {"renewal_history": history_entry}})
    await db.activity_log.insert_one({
        "id": str(uuid.uuid4()), "entity_type": "finding", "entity_id": exc["finding_id"],
        "action": "exception_renewal_requested", "actor": user["email"], "timestamp": now_iso(),
        "details": f"Renewal requested, new expiry {body.new_expires_at[:10]}",
    })
    return {"ok": True}


async def check_exception_expirations(db) -> dict:
    """Called from the nightly loop: expire anything past its expires_at (and reopen the
    underlying finding rather than leaving it silently marked 'Accepted risk' forever),
    and send a one-time reminder notification for anything expiring within 7 days."""
    from notifier import dispatch
    now = now_iso()
    expired_count = 0
    async for exc in db.exceptions.find({"status": "active", "expires_at": {"$lt": now}}, {"_id": 0}):
        await db.exceptions.update_one({"id": exc["id"]}, {"$set": {"status": "expired"}})
        await db.findings.update_one({"id": exc["finding_id"]},
            {"$set": {"status": "Reopened", "last_changed_at": now_iso()}})
        await db.activity_log.insert_one({
            "id": str(uuid.uuid4()), "entity_type": "finding", "entity_id": exc["finding_id"],
            "action": "exception_expired", "actor": "system", "timestamp": now_iso(),
            "details": "Risk exception expired -- finding automatically reopened.",
        })
        expired_count += 1

    reminder_cutoff = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
    reminded = 0
    async for exc in db.exceptions.find(
        {"status": "active", "expires_at": {"$lt": reminder_cutoff, "$gte": now}, "reminder_sent": {"$ne": True}},
        {"_id": 0},
    ):
        f = await db.findings.find_one({"id": exc["finding_id"]}, {"_id": 0})
        try:
            await dispatch("ticket_sla_warning", {
                "severity": (f or {}).get("severity"), "title": f"Exception expiring soon: {(f or {}).get('title', exc['finding_id'])}",
                "cve": (f or {}).get("cve") or "—", "asset": (f or {}).get("asset_hostname"),
                "owner_team": (f or {}).get("owner_team"), "risk_score": (f or {}).get("risk_score"),
                "due_at": exc["expires_at"][:19], "url": f"/findings/{exc['finding_id']}",
            }, db)
        except Exception:
            pass
        await db.exceptions.update_one({"id": exc["id"]}, {"$set": {"reminder_sent": True}})
        reminded += 1

    return {"expired": expired_count, "reminders_sent": reminded}


# --------------------------- ALTERNATE MITIGATIONS ---------------------------
# Lightweight, no-approval-required log of temporary compensating controls applied
# while a real fix/patch is pending -- distinct from Exceptions (which formally
# accepts risk and requires approval). A finding can have both: an exception for the
# formal risk-acceptance paper trail, and mitigations for "here's what we did in the
# meantime to reduce actual exposure."
MITIGATION_TYPES = ["WAF rule", "Network ACL / firewall rule", "Config hardening",
                     "Feature disabled", "Additional monitoring/alerting", "Compensating access control", "Other"]


@router.get("/v1/findings/{finding_id}/mitigations")
async def list_mitigations(finding_id: str, user: dict = Depends(get_current_user)):
    items = await db.mitigations.find({"finding_id": finding_id}, {"_id": 0}).sort("applied_at", -1).to_list(100)
    return {"items": items, "types": MITIGATION_TYPES}


class MitigationCreate(BaseModel):
    control_type: str
    description: str


@router.post("/v1/findings/{finding_id}/mitigations")
async def add_mitigation(finding_id: str, body: MitigationCreate, user: dict = Depends(get_current_user)):
    f = await db.findings.find_one({"id": finding_id}, {"_id": 0})
    if not f:
        raise HTTPException(404, "Finding not found")
    doc = {
        "id": str(uuid.uuid4()), "finding_id": finding_id, "asset_id": f.get("asset_id"),
        "control_type": body.control_type, "description": body.description,
        "applied_by": user["email"], "applied_at": now_iso(),
        "still_in_place": True, "removed_at": None, "removed_by": None,
    }
    await db.mitigations.insert_one(doc)
    await db.activity_log.insert_one({
        "id": str(uuid.uuid4()), "entity_type": "finding", "entity_id": finding_id,
        "action": "mitigation_added", "actor": user["email"], "timestamp": now_iso(),
        "details": f"Compensating control applied: {body.control_type} -- {body.description}",
    })
    return _clean(doc)


class MitigationUpdate(BaseModel):
    still_in_place: Optional[bool] = None
    description: Optional[str] = None


@router.patch("/v1/mitigations/{mitigation_id}")
async def update_mitigation(mitigation_id: str, body: MitigationUpdate, user: dict = Depends(get_current_user)):
    m = await db.mitigations.find_one({"id": mitigation_id}, {"_id": 0})
    if not m:
        raise HTTPException(404, "Mitigation not found")
    update = {}
    if body.description is not None:
        update["description"] = body.description
    if body.still_in_place is not None:
        update["still_in_place"] = body.still_in_place
        if body.still_in_place is False and m.get("still_in_place", True):
            update["removed_at"] = now_iso()
            update["removed_by"] = user["email"]
    if update:
        await db.mitigations.update_one({"id": mitigation_id}, {"$set": update})
    return {"ok": True}


@router.delete("/v1/mitigations/{mitigation_id}")
async def delete_mitigation(mitigation_id: str, user: dict = Depends(get_current_user)):
    await db.mitigations.delete_one({"id": mitigation_id})
    return {"ok": True}
