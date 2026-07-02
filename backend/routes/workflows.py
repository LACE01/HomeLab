"""Workflows routes: engagements, tickets, exceptions.

Exceptions follow a governance workflow rather than self-approval:
  requested (pending_approval) -> approved (active) | rejected
  active -> expired (automatic, past expires_at) or renewed (re-enters pending_approval)

An exception ("risk acceptance") can be attached to more than one finding at once --
by an individual finding, all open findings on a host, all open findings for a CVE, or
all open findings carrying a given tag -- so "accept this CVE across the fleet for 90
days" doesn't require filing one request per finding. finding_id/asset_id are kept as
single-value fields for backward compatibility with older UI and reports (first match);
finding_ids is the authoritative full list every approve/reject/expire/renew operates on.
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

CLOSED_FINDING_STATUSES = {"Fixed validated", "Closed administratively", "False positive", "Accepted risk"}
TARGET_TYPES = ("finding", "host", "cve", "tag")


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


async def _resolve_target_findings(db, target_type: str, target_value: Optional[str],
                                    single_finding_id: Optional[str] = None) -> list:
    """Resolves a risk-acceptance target into the concrete list of open finding docs it
    covers. 'finding' targets a single finding by id (target_value or the legacy
    finding_id alias); 'host', 'cve', and 'tag' resolve to every currently-open finding
    matching that attribute, so one request can cover a whole host, a CVE across the
    fleet, or anything tagged with a given label."""
    target_type = target_type or "finding"
    if target_type not in TARGET_TYPES:
        raise HTTPException(400, f"Unknown target_type '{target_type}' -- expected one of {TARGET_TYPES}")

    if target_type == "finding":
        fid = single_finding_id or target_value
        if not fid:
            raise HTTPException(400, "A finding must be selected for target_type 'finding'")
        f = await db.findings.find_one({"id": fid}, {"_id": 0})
        if not f:
            raise HTTPException(404, "Finding not found")
        return [f]

    if not target_value or not target_value.strip():
        raise HTTPException(400, f"A value is required for target_type '{target_type}'")

    flt: dict = {"status": {"$nin": list(CLOSED_FINDING_STATUSES)}}
    if target_type == "host":
        flt["$or"] = [{"asset_id": target_value}, {"asset_hostname": target_value}]
    elif target_type == "cve":
        flt["cve"] = target_value
    elif target_type == "tag":
        flt["tags"] = target_value

    items = await db.findings.find(flt, {"_id": 0}).to_list(500)
    if not items:
        raise HTTPException(404, f"No open findings match {target_type}='{target_value}'")
    return items


@router.get("/v1/exceptions/target-preview")
async def preview_exception_target(target_type: str = "finding", target_value: str = "",
                                     user: dict = Depends(get_current_user)):
    """Lets the request form show 'this will cover N findings' before submitting,
    rather than the requester finding out the blast radius only after filing."""
    try:
        matched = await _resolve_target_findings(db, target_type, target_value or None)
    except HTTPException as e:
        return {"count": 0, "items": [], "error": e.detail}
    return {
        "count": len(matched),
        "items": [
            {"id": f["id"], "title": f.get("title"), "severity": f.get("severity"),
             "asset_hostname": f.get("asset_hostname"), "cve": f.get("cve")}
            for f in matched[:25]
        ],
    }


@router.get("/v1/exceptions")
async def list_exceptions(user: dict = Depends(get_current_user), status: Optional[str] = None):
    flt = {}
    if status:
        flt["status"] = status
    items = await db.exceptions.find(flt, {"_id": 0}).sort("requested_at", -1).to_list(200)
    for e in items:
        f = await db.findings.find_one({"id": e.get("finding_id")}, {"_id": 0, "title": 1, "severity": 1, "asset_hostname": 1, "cve": 1})
        _enrich_finding_fields(e, f)
        e.setdefault("finding_ids", [e.get("finding_id")] if e.get("finding_id") else [])
        e.setdefault("finding_count", len(e["finding_ids"]))
        e.setdefault("target_type", "finding")
        if e.get("status") == "active" and e.get("expires_at"):
            e["days_until_expiry"] = max(0, (datetime.fromisoformat(e["expires_at"].replace("Z", "+00:00"))
                                              - datetime.now(timezone.utc)).days)
    return {"items": items}


async def _log_exception_event(db, exc: dict, action: str, actor: str, details: str) -> None:
    """Writes one entry to the exception's own timeline (entity_type='exception', shown
    on the risk-acceptance detail page) and mirrors it onto each attached finding's
    activity feed too, capped so a large host/CVE/tag group target doesn't spam dozens
    of finding timelines with the same event."""
    await db.activity_log.insert_one({
        "id": str(uuid.uuid4()), "entity_type": "exception", "entity_id": exc["id"],
        "action": f"exception_{action}", "actor": actor, "timestamp": now_iso(), "details": details,
    })
    for fid in (exc.get("finding_ids") or [exc.get("finding_id")])[:25]:
        if not fid:
            continue
        await db.activity_log.insert_one({
            "id": str(uuid.uuid4()), "entity_type": "finding", "entity_id": fid,
            "action": f"exception_{action}", "actor": actor, "timestamp": now_iso(), "details": details,
        })


def _validate_evidence_files(files: List[dict]) -> None:
    for a in files or []:
        if isinstance(a.get("data_url"), str) and len(a["data_url"]) > 1_400_000:
            raise HTTPException(413, f"Attachment '{a.get('name', '?')}' exceeds 1 MB limit")
        if a.get("mime") and not a["mime"].startswith(("image/", "application/pdf")):
            raise HTTPException(400, f"Only image and PDF attachments allowed (got {a['mime']})")


async def _create_ticket_for_exception(db, exc: dict) -> dict:
    """Every approved risk acceptance gets an internal ticket, so 'active with
    everything tied to the ticket' has an actual ticket to point at even when no
    external Jira/ServiceNow integration is configured."""
    ticket_id = str(uuid.uuid4())
    if exc.get("finding_count", 1) <= 1:
        title = f"Risk acceptance: {exc.get('finding_title') or exc.get('finding_id')}"
    else:
        title = f"Risk acceptance: {exc['finding_count']} findings ({exc.get('target_type')}={exc.get('target_value')})"
    doc = {
        "id": ticket_id, "external_id": f"RA-{ticket_id[:8].upper()}", "system": "internal",
        "title": title[:160], "assignee": exc.get("contact_name") or exc.get("approver") or exc.get("requested_by"),
        "status": "open", "finding_id": exc.get("finding_id"), "asset_id": exc.get("asset_id"),
        "exception_id": exc["id"], "url": f"/exceptions/{exc['id']}",
        "created_at": now_iso(), "updated_at": now_iso(),
    }
    await db.tickets.insert_one(doc)
    return doc


class ExceptionCreate(BaseModel):
    target_type: str = "finding"  # finding | host | cve | tag
    target_value: Optional[str] = None
    finding_id: Optional[str] = None  # back-compat alias for target_type="finding"
    business_justification: str
    duration_days: Optional[int] = None
    expires_at: Optional[str] = None
    compensating_controls: List[str] = []
    contact_name: str = ""
    contact_email: str = ""
    reminder_days_before: int = 7
    evidence_files: List[dict] = []  # [{name, mime, data_url}] -- small images/PDFs only


@router.post("/v1/exceptions")
async def request_exception(body: ExceptionCreate, user: dict = Depends(get_current_user)):
    """Request a time-bound risk exception ("risk acceptance"). Does NOT immediately
    accept the risk -- the finding(s) stay in their current status until an
    admin/manager approves."""
    matched = await _resolve_target_findings(db, body.target_type, body.target_value, body.finding_id)
    finding_ids = [f["id"] for f in matched]
    primary = matched[0]

    expires_at = body.expires_at
    if not expires_at:
        if not body.duration_days:
            raise HTTPException(400, "Either an expiry date or an acceptance duration is required")
        expires_at = (datetime.now(timezone.utc) + timedelta(days=body.duration_days)).isoformat()

    _validate_evidence_files(body.evidence_files)

    exc = {
        "id": str(uuid.uuid4()),
        "target_type": body.target_type or "finding", "target_value": body.target_value,
        "finding_id": primary["id"], "finding_ids": finding_ids, "finding_count": len(finding_ids),
        "finding_title": primary.get("title"), "asset_id": primary.get("asset_id"),
        "business_justification": body.business_justification,
        "rationale": body.business_justification,  # kept for backward compatibility with older UI/reports
        "contact_name": body.contact_name, "contact_email": body.contact_email,
        "requested_by": user["email"], "requested_at": now_iso(),
        "approver": None, "approved_at": None, "approval_justification": None, "rejection_reason": None,
        "expires_at": expires_at, "duration_days": body.duration_days, "renewal_history": [],
        "reminder_days_before": max(1, body.reminder_days_before or 7),
        "compensating_controls": body.compensating_controls, "evidence_files": body.evidence_files or [],
        "status": "pending_approval", "reminder_sent": False, "ticket_id": None,
    }
    await db.exceptions.insert_one(exc)
    scope = primary.get("title") if len(finding_ids) == 1 else f"{len(finding_ids)} findings ({body.target_type}={body.target_value})"
    await _log_exception_event(db, exc, "requested", user["email"],
        f"Risk acceptance requested for {scope}, expires {expires_at[:10]}")
    return _clean(exc)


class ApproveBody(BaseModel):
    justification: Optional[str] = ""


@router.post("/v1/exceptions/{exception_id}/approve")
async def approve_exception(exception_id: str, body: ApproveBody = ApproveBody(),
                             user: dict = Depends(require_role("admin", "manager"))):
    exc = await db.exceptions.find_one({"id": exception_id}, {"_id": 0})
    if not exc:
        raise HTTPException(404, "Exception not found")
    if exc["status"] not in ("pending_approval",):
        raise HTTPException(400, f"Cannot approve an exception in status '{exc['status']}'")
    fids = exc.get("finding_ids") or [exc["finding_id"]]

    await db.exceptions.update_one({"id": exception_id}, {"$set": {
        "status": "active", "approver": user["email"], "approved_at": now_iso(),
        "approval_justification": body.justification or "", "reminder_sent": False,
    }})
    await db.findings.update_many({"id": {"$in": fids}},
        {"$set": {"status": "Accepted risk", "last_changed_at": now_iso()}})

    exc["status"] = "active"
    if exc.get("ticket_id"):
        # Renewal re-approval -- reuse the original ticket rather than spawning a
        # duplicate one, since it's the same risk-acceptance paper trail.
        await db.tickets.update_one({"id": exc["ticket_id"]},
            {"$set": {"status": "open", "updated_at": now_iso()}})
        ticket = await db.tickets.find_one({"id": exc["ticket_id"]}, {"_id": 0})
    else:
        ticket = await _create_ticket_for_exception(db, exc)
        await db.exceptions.update_one({"id": exception_id}, {"$set": {"ticket_id": ticket["id"]}})

    detail = f"Approved by {user['email']}"
    if body.justification:
        detail += f": {body.justification}"
    detail += f" -- {len(fids)} finding(s) accepted, expires {exc['expires_at'][:10]}, ticket {ticket['external_id']}"
    await _log_exception_event(db, exc, "approved", user["email"], detail)
    return {"ok": True, "ticket_id": ticket["id"], "ticket_external_id": ticket["external_id"]}


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
    await _log_exception_event(db, exc, "rejected", user["email"], f"Rejected by {user['email']}: {body.reason}")
    return {"ok": True}


class RenewBody(BaseModel):
    new_expires_at: Optional[str] = None
    duration_days: Optional[int] = None
    justification: str
    reminder_days_before: Optional[int] = None


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

    new_expires_at = body.new_expires_at
    if not new_expires_at:
        if not body.duration_days:
            raise HTTPException(400, "Either a new expiry date or a duration is required")
        new_expires_at = (datetime.now(timezone.utc) + timedelta(days=body.duration_days)).isoformat()

    history_entry = {
        "previous_expires_at": exc["expires_at"], "requested_new_expires_at": new_expires_at,
        "justification": body.justification, "requested_by": user["email"], "requested_at": now_iso(),
    }
    update: dict = {
        "status": "pending_approval", "expires_at": new_expires_at,
        "requested_by": user["email"], "requested_at": now_iso(),
        "approver": None, "approved_at": None, "reminder_sent": False,
    }
    if body.reminder_days_before:
        update["reminder_days_before"] = max(1, body.reminder_days_before)
    await db.exceptions.update_one({"id": exception_id}, {"$set": update, "$push": {"renewal_history": history_entry}})
    if exc.get("ticket_id"):
        await db.tickets.update_one({"id": exc["ticket_id"]},
            {"$set": {"status": "open", "updated_at": now_iso()}})

    await _log_exception_event(db, exc, "renewal_requested", user["email"],
        f"Renewal requested by {user['email']}, new expiry {new_expires_at[:10]}: {body.justification}")
    return {"ok": True}


@router.get("/v1/exceptions/{exception_id}")
async def get_exception(exception_id: str, user: dict = Depends(get_current_user)):
    exc = await db.exceptions.find_one({"id": exception_id}, {"_id": 0})
    if not exc:
        raise HTTPException(404, "Exception not found")
    fids = exc.get("finding_ids") or ([exc["finding_id"]] if exc.get("finding_id") else [])
    findings = await db.findings.find({"id": {"$in": fids}}, {"_id": 0}).to_list(500)
    _enrich_finding_fields(exc, findings[0] if findings else None)
    exc.setdefault("finding_ids", fids)
    exc.setdefault("finding_count", len(fids))
    if exc.get("status") == "active" and exc.get("expires_at"):
        exc["days_until_expiry"] = max(0, (datetime.fromisoformat(exc["expires_at"].replace("Z", "+00:00"))
                                            - datetime.now(timezone.utc)).days)
    ticket = await db.tickets.find_one({"id": exc.get("ticket_id")}, {"_id": 0}) if exc.get("ticket_id") else None
    timeline = await db.activity_log.find(
        {"entity_type": "exception", "entity_id": exception_id}, {"_id": 0}
    ).sort("timestamp", 1).to_list(200)
    return {**exc, "findings": findings, "ticket": ticket, "timeline": timeline}


async def check_exception_expirations(db) -> dict:
    """Called from the nightly loop: expire anything past its expires_at (and reopen every
    attached finding rather than leaving them silently marked 'Accepted risk' forever),
    and send a one-time reminder notification ahead of expiry -- how far ahead is
    configurable per-request via reminder_days_before (defaults to 7 days)."""
    from notifier import dispatch
    now = now_iso()
    expired_count = 0
    async for exc in db.exceptions.find({"status": "active", "expires_at": {"$lt": now}}, {"_id": 0}):
        fids = exc.get("finding_ids") or [exc.get("finding_id")]
        fids = [f for f in fids if f]
        await db.exceptions.update_one({"id": exc["id"]}, {"$set": {"status": "expired"}})
        if fids:
            await db.findings.update_many({"id": {"$in": fids}},
                {"$set": {"status": "Reopened", "last_changed_at": now_iso()}})
        if exc.get("ticket_id"):
            await db.tickets.update_one({"id": exc["ticket_id"]},
                {"$set": {"status": "reopened", "updated_at": now_iso()}})
        await _log_exception_event(db, exc, "expired", "system",
            f"Risk acceptance expired -- {len(fids)} finding(s) automatically reopened.")
        expired_count += 1

    reminded = 0
    async for exc in db.exceptions.find({"status": "active", "reminder_sent": {"$ne": True}}, {"_id": 0}):
        days_before = exc.get("reminder_days_before") or 7
        cutoff = (datetime.now(timezone.utc) + timedelta(days=days_before)).isoformat()
        expires_at = exc.get("expires_at") or ""
        if not (expires_at < cutoff and expires_at >= now):
            continue
        f = await db.findings.find_one({"id": exc.get("finding_id")}, {"_id": 0})
        recipient = exc.get("contact_email") or exc.get("requested_by")
        days_left = max(0, (datetime.fromisoformat(exc["expires_at"].replace("Z", "+00:00")) - datetime.now(timezone.utc)).days)
        try:
            await dispatch("exception_expiring", {
                "title": exc.get("finding_title") or (f or {}).get("title", exc.get("finding_id")),
                "asset": (f or {}).get("asset_hostname") or (exc.get("target_type") == "host" and exc.get("target_value")) or "—",
                "approver": exc.get("approver") or "—", "expires_at": exc["expires_at"][:10],
                "days_left": days_left, "url": f"/exceptions/{exc['id']}",
            }, db)
        except Exception:
            pass
        await db.exceptions.update_one({"id": exc["id"]}, {"$set": {"reminder_sent": True}})
        await _log_exception_event(db, exc, "reminder_sent", "system",
            f"Expiry reminder sent ({days_before}d out) to {recipient or 'requester'}.")
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
