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
from rbac import require_module
from auth_utils import get_current_user, require_role
from routes.common import now_iso, _clean

router = APIRouter()

CLOSED_FINDING_STATUSES = {"Fixed validated", "Closed administratively", "False positive", "Accepted risk"}
TARGET_TYPES = ("finding", "host", "cve", "tag")

# --------------------------- APPROVAL ROUTING ---------------------------
# Who has to sign off on a risk acceptance depends on how severe the findings it
# covers are -- e.g. a Low-severity exception might just need any manager, while a
# Critical one might need a manager AND then admin sign-off in sequence. Routing is
# configured per severity tier (graphically, via the Approval Routing builder) as an
# ordered chain of steps; each step names either a role ("manager"/"admin") or one
# specific person's email. Admins can always act on any step (they're the org's
# superuser role here), which also prevents a named approver leaving the company
# from permanently blocking a chain.
APPROVAL_TIERS = ["Critical", "High", "Medium", "Low"]
TIER_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 1}
STEP_ROLES = ("manager", "admin", "specific")
DEFAULT_CHAIN = [{"step": 1, "role": "manager", "approver_email": None}]


def _tier_for_findings(findings: list) -> str:
    best = "Low"
    for f in findings:
        sev = f.get("severity") or "Low"
        if TIER_RANK.get(sev, 1) > TIER_RANK.get(best, 1):
            best = sev if sev in APPROVAL_TIERS else "Low"
    return best


async def resolve_chain_for_tier(db, tier: str) -> list:
    doc = await db.approval_routes.find_one({"tier": tier}, {"_id": 0})
    chain = (doc or {}).get("chain") or []
    if not chain:
        return [dict(c) for c in DEFAULT_CHAIN]
    return [{"step": i + 1, "role": c["role"], "approver_email": c.get("approver_email")} for i, c in enumerate(chain)]


def _fresh_approval_chain(chain_config: list) -> list:
    return [{"step": c["step"], "role": c["role"], "approver_email": c.get("approver_email"),
              "status": "pending", "by": None, "at": None, "justification": None} for c in chain_config]


def _current_pending_step(approval_chain: list) -> Optional[dict]:
    for step in approval_chain:
        if step.get("status") == "pending":
            return step
    return None


def _user_authorized_for_step(user: dict, step: dict) -> bool:
    if user.get("role") == "admin":
        return True  # admins can act on any step -- see module docstring above
    if step.get("role") == "admin":
        return False  # non-admins can't satisfy an admin-only step
    if step.get("role") == "specific":
        return bool(step.get("approver_email")) and user.get("email") == step["approver_email"]
    return user.get("role") == step.get("role")


def _step_label(step: dict) -> str:
    if step.get("role") == "specific":
        return step.get("approver_email") or "a specific approver"
    return step.get("role", "manager")


class ApprovalStepIn(BaseModel):
    role: str  # "manager" | "admin" | "specific"
    approver_email: Optional[str] = None


class ApprovalRouteBody(BaseModel):
    chain: List[ApprovalStepIn]


@router.get("/v1/admin/approval-routes")
async def list_approval_routes(user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/admin/approval-routing"))):
    docs = {d["tier"]: d async for d in db.approval_routes.find({}, {"_id": 0})}
    out = []
    for tier in APPROVAL_TIERS:
        doc = docs.get(tier)
        chain = (doc or {}).get("chain") or []
        out.append({
            "tier": tier,
            "chain": chain if chain else [dict(c) for c in DEFAULT_CHAIN],
            "is_default": not bool(chain),
            "updated_at": (doc or {}).get("updated_at"), "updated_by": (doc or {}).get("updated_by"),
        })
    return {"tiers": out, "role_options": list(STEP_ROLES)}


@router.put("/v1/admin/approval-routes/{tier}")
async def set_approval_route(tier: str, body: ApprovalRouteBody, user: dict = Depends(require_role("admin"))):
    if tier not in APPROVAL_TIERS:
        raise HTTPException(400, f"tier must be one of {APPROVAL_TIERS}")
    if not body.chain:
        raise HTTPException(400, "Chain must have at least one approval step -- delete the route instead to reset to default")
    chain = []
    for i, step in enumerate(body.chain):
        if step.role not in STEP_ROLES:
            raise HTTPException(400, f"role must be one of {STEP_ROLES}")
        if step.role == "specific" and not (step.approver_email or "").strip():
            raise HTTPException(400, "approver_email is required when role is 'specific'")
        chain.append({"step": i + 1, "role": step.role, "approver_email": step.approver_email if step.role == "specific" else None})
    await db.approval_routes.update_one(
        {"tier": tier},
        {"$set": {"tier": tier, "chain": chain, "updated_at": now_iso(), "updated_by": user["email"]}},
        upsert=True,
    )
    return {"ok": True, "chain": chain}


@router.delete("/v1/admin/approval-routes/{tier}")
async def reset_approval_route(tier: str, user: dict = Depends(require_role("admin"))):
    if tier not in APPROVAL_TIERS:
        raise HTTPException(400, f"tier must be one of {APPROVAL_TIERS}")
    await db.approval_routes.delete_one({"tier": tier})
    return {"ok": True, "chain": [dict(c) for c in DEFAULT_CHAIN]}


# --------------------------- ENGAGEMENTS ---------------------------
@router.get("/v1/engagements")
async def list_engagements(user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/engagements"))):
    items = await db.engagements.find({}, {"_id": 0}).sort("started_at", -1).to_list(100)
    return {"items": items}


# --------------------------- TICKETS ---------------------------
@router.get("/v1/tickets")
async def list_tickets(user: dict = Depends(get_current_user), status: Optional[str] = None,
                        _rbac: dict = Depends(require_module("/tickets"))):
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
async def list_exceptions(user: dict = Depends(get_current_user), status: Optional[str] = None,
                           _rbac: dict = Depends(require_module("/exceptions"))):
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
        if e.get("status") == "pending_approval":
            chain = e.get("approval_chain") or _fresh_approval_chain(DEFAULT_CHAIN)
            cur = _current_pending_step(chain)
            e["awaiting_step_label"] = _step_label(cur) if cur else None
            e["can_current_user_approve"] = bool(cur) and _user_authorized_for_step(user, cur)
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
    epss_threshold: Optional[float] = None  # 0-1; re-notify if EPSS crosses this while active


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

    tier = _tier_for_findings(matched)
    chain_config = await resolve_chain_for_tier(db, tier)
    approval_chain = _fresh_approval_chain(chain_config)

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
        "tier": tier, "approval_chain": approval_chain,
        "revoked_at": None, "revoked_by": None, "revocation_reason": None,
        "epss_threshold": body.epss_threshold, "last_risk_signals": None,
    }
    await db.exceptions.insert_one(exc)
    scope = primary.get("title") if len(finding_ids) == 1 else f"{len(finding_ids)} findings ({body.target_type}={body.target_value})"
    chain_desc = " -> ".join(_step_label(c) for c in chain_config)
    await _log_exception_event(db, exc, "requested", user["email"],
        f"Risk acceptance requested for {scope} ({tier} tier), expires {expires_at[:10]}. Approval route: {chain_desc}.")
    return _clean(exc)


class ApproveBody(BaseModel):
    justification: Optional[str] = ""


@router.post("/v1/exceptions/{exception_id}/approve")
async def approve_exception(exception_id: str, body: ApproveBody = ApproveBody(),
                             user: dict = Depends(get_current_user)):
    exc = await db.exceptions.find_one({"id": exception_id}, {"_id": 0})
    if not exc:
        raise HTTPException(404, "Exception not found")
    if exc["status"] not in ("pending_approval",):
        raise HTTPException(400, f"Cannot approve an exception in status '{exc['status']}'")
    fids = exc.get("finding_ids") or [exc["finding_id"]]

    # Older exceptions requested before approval routing existed won't have an
    # approval_chain -- fall back to the single-step default (any manager or admin),
    # matching the behavior this replaced, without needing a data migration.
    approval_chain = exc.get("approval_chain") or _fresh_approval_chain(DEFAULT_CHAIN)
    step = _current_pending_step(approval_chain)
    if not step:
        raise HTTPException(400, "This exception's approval chain has no pending step")
    if not _user_authorized_for_step(user, step):
        raise HTTPException(403, f"Step {step['step']} of this approval chain requires sign-off from {_step_label(step)}")

    step["status"] = "approved"; step["by"] = user["email"]; step["at"] = now_iso(); step["justification"] = body.justification or ""
    next_step = _current_pending_step(approval_chain)

    if next_step:
        await db.exceptions.update_one({"id": exception_id}, {"$set": {"approval_chain": approval_chain}})
        detail = f"Step {step['step']} of {len(approval_chain)} approved by {user['email']}"
        if body.justification:
            detail += f": {body.justification}"
        detail += f" -- awaiting step {next_step['step']} ({_step_label(next_step)})"
        await _log_exception_event(db, exc, "step_approved", user["email"], detail)
        return {"ok": True, "fully_approved": False, "awaiting": _step_label(next_step), "step": next_step["step"], "of": len(approval_chain)}

    await db.exceptions.update_one({"id": exception_id}, {"$set": {
        "status": "active", "approver": user["email"], "approved_at": now_iso(),
        "approval_justification": body.justification or "", "reminder_sent": False,
        "approval_chain": approval_chain,
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

    detail = f"Final step approved by {user['email']}"
    if body.justification:
        detail += f": {body.justification}"
    detail += f" -- {len(fids)} finding(s) accepted, expires {exc['expires_at'][:10]}, ticket {ticket['external_id']}"
    await _log_exception_event(db, exc, "approved", user["email"], detail)
    return {"ok": True, "fully_approved": True, "ticket_id": ticket["id"], "ticket_external_id": ticket["external_id"]}


class RejectBody(BaseModel):
    reason: str


@router.post("/v1/exceptions/{exception_id}/reject")
async def reject_exception(exception_id: str, body: RejectBody, user: dict = Depends(get_current_user)):
    exc = await db.exceptions.find_one({"id": exception_id}, {"_id": 0})
    if not exc:
        raise HTTPException(404, "Exception not found")
    if exc["status"] not in ("pending_approval",):
        raise HTTPException(400, f"Cannot reject an exception in status '{exc['status']}'")
    approval_chain = exc.get("approval_chain") or _fresh_approval_chain(DEFAULT_CHAIN)
    step = _current_pending_step(approval_chain)
    if step and not _user_authorized_for_step(user, step):
        raise HTTPException(403, f"Step {step['step']} of this approval chain requires sign-off from {_step_label(step)}")
    await db.exceptions.update_one({"id": exception_id}, {"$set": {
        "status": "rejected", "approver": user["email"], "approved_at": now_iso(),
        "rejection_reason": body.reason,
    }})
    await _log_exception_event(db, exc, "rejected", user["email"], f"Rejected by {user['email']}: {body.reason}")
    return {"ok": True}


class RevokeBody(BaseModel):
    reason: str


@router.post("/v1/exceptions/{exception_id}/revoke")
async def revoke_exception(exception_id: str, body: RevokeBody, user: dict = Depends(require_role("admin", "manager")),
                            _rbac: dict = Depends(require_module("/exceptions", level="edit"))):
    """Denies an ALREADY-approved (active) risk acceptance -- distinct from reject,
    which only applies before approval. Used when new information (e.g. escalating
    exploitation activity) means the org no longer wants to carry this risk for the
    remainder of its term. Reopens every attached finding immediately, closes the
    ticket, and notifies the requester/contact plus the owning team -- the same
    audience who'd want to know a fix is needed again."""
    exc = await db.exceptions.find_one({"id": exception_id}, {"_id": 0})
    if not exc:
        raise HTTPException(404, "Exception not found")
    if exc["status"] != "active":
        raise HTTPException(400, f"Cannot revoke an exception in status '{exc['status']}' -- only active ones can be revoked")

    fids = [f for f in (exc.get("finding_ids") or [exc.get("finding_id")]) if f]
    await db.exceptions.update_one({"id": exception_id}, {"$set": {
        "status": "revoked", "revoked_at": now_iso(), "revoked_by": user["email"], "revocation_reason": body.reason,
    }})
    if fids:
        await db.findings.update_many({"id": {"$in": fids}},
            {"$set": {"status": "Reopened", "last_changed_at": now_iso()}})
    if exc.get("ticket_id"):
        await db.tickets.update_one({"id": exc["ticket_id"]},
            {"$set": {"status": "revoked", "updated_at": now_iso()}})

    await _log_exception_event(db, exc, "revoked", user["email"],
        f"Revoked by {user['email']}: {body.reason} -- {len(fids)} finding(s) reopened.")

    from notifier import dispatch
    try:
        await dispatch("exception_revoked", {
            "title": exc.get("finding_title") or exc.get("finding_id"), "revoked_by": user["email"],
            "reason": body.reason, "finding_count": len(fids), "url": f"/exceptions/{exception_id}",
        }, db)
    except Exception:
        pass

    return {"ok": True, "findings_reopened": len(fids)}


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
    # Renewal re-enters approval from scratch -- re-resolve the chain for the current
    # tier (routing config may have changed since the original request) rather than
    # reusing whatever steps were already marked approved last cycle.
    fids = exc.get("finding_ids") or [exc.get("finding_id")]
    findings = await db.findings.find({"id": {"$in": [f for f in fids if f]}}, {"_id": 0, "severity": 1}).to_list(500)
    tier = _tier_for_findings(findings) if findings else (exc.get("tier") or "Low")
    chain_config = await resolve_chain_for_tier(db, tier)
    fresh_chain = _fresh_approval_chain(chain_config)

    update: dict = {
        "status": "pending_approval", "expires_at": new_expires_at,
        "requested_by": user["email"], "requested_at": now_iso(),
        "approver": None, "approved_at": None, "reminder_sent": False,
        "tier": tier, "approval_chain": fresh_chain,
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


class ExceptionCommentBody(BaseModel):
    text: str
    attachments: Optional[List[dict]] = None


@router.get("/v1/exceptions/{exception_id}/comments")
async def list_exception_comments(exception_id: str, user: dict = Depends(get_current_user)):
    items = await db.comments.find({"exception_id": exception_id}, {"_id": 0}).sort("created_at", -1).to_list(200)
    return {"items": items}


@router.post("/v1/exceptions/{exception_id}/comments")
async def add_exception_comment(exception_id: str, body: ExceptionCommentBody, user: dict = Depends(get_current_user)):
    """Free-form notes/updates over the life of a risk acceptance -- separate from the
    approve/reject/renew/revoke audit trail, for context that doesn't map to a formal
    state transition (a link to a vendor patch ETA, a heads-up from another team, etc.)."""
    exc = await db.exceptions.find_one({"id": exception_id}, {"_id": 0})
    if not exc:
        raise HTTPException(404, "Exception not found")
    _validate_evidence_files(body.attachments or [])
    c = {"id": str(uuid.uuid4()), "exception_id": exception_id, "author": user["email"],
         "text": body.text, "attachments": body.attachments or [], "created_at": now_iso()}
    await db.comments.insert_one(c)
    await _log_exception_event(db, exc, "note_added", user["email"], f"Note added: {body.text[:140]}")
    return _clean(c)


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

    approval_chain = exc.get("approval_chain") or _fresh_approval_chain(DEFAULT_CHAIN)
    current_step = _current_pending_step(approval_chain) if exc.get("status") == "pending_approval" else None
    can_act = bool(current_step) and _user_authorized_for_step(user, current_step)

    comments = await db.comments.find({"exception_id": exception_id}, {"_id": 0}).sort("created_at", -1).to_list(200)

    return {**exc, "findings": findings, "ticket": ticket, "timeline": timeline, "comments": comments,
            "approval_chain": approval_chain,
            "awaiting_step_label": _step_label(current_step) if current_step else None,
            "can_current_user_approve": can_act}


def _compute_risk_signals(findings: list) -> dict:
    """Current-state threat signals for the finding(s) an exception covers -- reuses
    data this app already syncs nightly (KEV, EPSS, Exploit-DB, active-attack
    tagging) rather than standing up a separate feed just for this panel."""
    epss_scores = [f.get("epss_score") for f in findings if f.get("epss_score") is not None]
    return {
        "kev_flag": any(f.get("kev_flag") for f in findings),
        "max_epss_score": max(epss_scores) if epss_scores else None,
        "exploit_count": sum(len(f.get("exploit_references") or []) for f in findings),
        "active_attacks": any("active_attacks" in (f.get("rti") or []) for f in findings),
    }


@router.get("/v1/exceptions/{exception_id}/risk-signals")
async def exception_risk_signals(exception_id: str, user: dict = Depends(get_current_user)):
    exc = await db.exceptions.find_one({"id": exception_id}, {"_id": 0})
    if not exc:
        raise HTTPException(404, "Exception not found")
    fids = [f for f in (exc.get("finding_ids") or [exc.get("finding_id")]) if f]
    findings = await db.findings.find({"id": {"$in": fids}}, {"_id": 0}).to_list(500)
    signals = _compute_risk_signals(findings)

    cve = next((f.get("cve") for f in findings if f.get("id") == exc.get("finding_id") and f.get("cve")), None) \
        or next((f.get("cve") for f in findings if f.get("cve")), None)
    opencti = None
    if cve:
        try:
            from routes.findings import threat_intel_for_cve
            opencti = await threat_intel_for_cve(cve, user=user)
        except Exception:
            opencti = None

    return {**signals, "cve": cve, "opencti": opencti,
            "epss_threshold": exc.get("epss_threshold"), "last_checked_signals": exc.get("last_risk_signals")}


async def check_exception_risk_escalations(db) -> dict:
    """Called from the nightly loop: for every active exception, compare current
    threat signals against what was last observed. If exploitation activity has
    clearly gotten worse since approval (newly KEV-listed, a new public exploit,
    active-attack tagging appears, or EPSS crosses the requester's own threshold),
    notify and log it on the timeline so someone re-visits the decision -- without
    auto-revoking it; that stays a deliberate human action."""
    from notifier import dispatch
    escalated = 0
    async for exc in db.exceptions.find({"status": "active"}, {"_id": 0}):
        fids = [f for f in (exc.get("finding_ids") or [exc.get("finding_id")]) if f]
        if not fids:
            continue
        findings = await db.findings.find({"id": {"$in": fids}}, {"_id": 0}).to_list(500)
        if not findings:
            continue
        signals = _compute_risk_signals(findings)
        prev = exc.get("last_risk_signals") or {}
        threshold = exc.get("epss_threshold")

        reasons = []
        if signals["kev_flag"] and not prev.get("kev_flag"):
            reasons.append("now listed in CISA KEV (actively exploited in the wild)")
        if signals["exploit_count"] > (prev.get("exploit_count") or 0):
            reasons.append(f"{signals['exploit_count']} public exploit(s) now indexed (was {prev.get('exploit_count') or 0})")
        if signals["active_attacks"] and not prev.get("active_attacks"):
            reasons.append("now flagged under active attack campaign tracking")
        if (threshold is not None and signals["max_epss_score"] is not None
                and signals["max_epss_score"] >= threshold and (prev.get("max_epss_score") or 0) < threshold):
            reasons.append(f"EPSS crossed your {threshold:.0%} threshold (now {signals['max_epss_score']:.0%})")

        await db.exceptions.update_one({"id": exc["id"]}, {"$set": {"last_risk_signals": signals}})
        if not reasons:
            continue
        reason_text = "; ".join(reasons)
        await _log_exception_event(db, exc, "risk_escalated", "system", f"Threat signal escalation: {reason_text}")
        try:
            await dispatch("exception_risk_escalated", {
                "title": exc.get("finding_title") or exc.get("finding_id"),
                "escalation_reason": reason_text, "expires_at": (exc.get("expires_at") or "")[:10],
                "url": f"/exceptions/{exc['id']}",
            }, db)
        except Exception:
            pass
        escalated += 1
    return {"escalated": escalated}


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
