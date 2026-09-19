"""Item 62 -- Remediation Campaign / Patch Tracker routes (v2)."""
from typing import Optional, List
import csv, io
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from db import db
from rbac import require_module
from auth_utils import get_current_user
import remediation_campaigns as rc

router = APIRouter()
MODULE_KEY = "/remediation-campaigns"


async def _ids_from_findings_filter(user, flt: dict) -> list:
    """Resolve the SAME findings filter the Findings tab uses into a list of ids."""
    from routes.findings import _build_findings_filter
    q = await _build_findings_filter(
        user,
        q=flt.get("q"), severity=flt.get("severity"), status=flt.get("status"),
        kev=flt.get("kev"), internet_facing=flt.get("internet_facing"),
        owner_team=flt.get("owner_team"), asset_id=flt.get("asset_id"),
        tags=flt.get("tags"), asset_type=flt.get("asset_type"),
        exploitability=flt.get("exploitability"),
        include_resolved=flt.get("include_resolved", False),
        cve=flt.get("cve"), cwe=flt.get("cwe"), view=flt.get("view"),
        platform=flt.get("platform"), min_risk_score=flt.get("min_risk_score"),
        source_tool=flt.get("source_tool"), sla=flt.get("sla"),
        age_days=flt.get("age_days"), entity=flt.get("entity"), confidence=flt.get("confidence"),
        qid=flt.get("qid"), hostname=flt.get("hostname"), title=flt.get("title"),
    )
    rows = await db.findings.find(q, {"_id": 0, "id": 1}).limit(100000).to_list(100000)
    return [r["id"] for r in rows]


class CampaignBody(BaseModel):
    name: str
    description: str = ""
    owner_team: Optional[str] = None
    due_date: Optional[str] = None
    assignees: Optional[List[str]] = None
    finding_ids: Optional[list] = None
    findings_filter: Optional[dict] = None   # the full Findings-tab filter set
    require_verification: bool = True
    maintenance_window: Optional[dict] = None   # {start, end} ISO
    change_ticket: Optional[str] = None


@router.get("/v1/remediation-campaigns")
async def list_campaigns(owner_team: Optional[str] = None, mine: bool = False,
                         user: dict = Depends(require_module(MODULE_KEY))):
    items = await rc.list_campaigns(db, owner_team=owner_team)
    if mine:
        teams = set(user.get("teams") or ([user["team"]] if user.get("team") else []))
        email = user.get("email")
        items = [c for c in items if c.get("owner_team") in teams
                 or email in (c.get("assignees") or [])]
    return {"items": items}


@router.get("/v1/remediation-campaigns/alerts")
async def campaign_alerts(user: dict = Depends(require_module(MODULE_KEY))):
    return await rc.alerts(db)


class PreviewBody(BaseModel):
    findings_filter: Optional[dict] = None
    finding_ids: Optional[list] = None


@router.post("/v1/remediation-campaigns/preview")
async def preview_scope(body: PreviewBody, user: dict = Depends(require_module(MODULE_KEY))):
    """Preview what a scope will pull in BEFORE creating the campaign: total, how
    many are open (what you'd actually be committing to patch) vs already resolved,
    a severity breakdown, and a small sample."""
    ids = set(body.finding_ids or [])
    if body.findings_filter:
        ids |= set(await _ids_from_findings_filter(user, body.findings_filter))
    ids = list(ids)
    if not ids:
        return {"total": 0, "to_patch": 0, "already_resolved": 0, "by_severity": {}, "sample": []}
    from routes.common import OPEN_STATUSES
    rows = await db.findings.find(
        {"id": {"$in": ids}},
        {"_id": 0, "id": 1, "title": 1, "cve": 1, "qid": 1, "severity": 1, "status": 1,
         "asset_hostname": 1, "owner_team": 1, "kev_flag": 1, "risk_score": 1}).to_list(100000)
    by_sev = {}
    to_patch = 0
    for f in rows:
        by_sev[f.get("severity") or "Info"] = by_sev.get(f.get("severity") or "Info", 0) + 1
        if f.get("status") in OPEN_STATUSES:
            to_patch += 1
    sample = sorted(rows, key=lambda f: -(f.get("risk_score") or 0))[:12]
    return {"total": len(rows), "to_patch": to_patch, "already_resolved": len(rows) - to_patch,
            "by_severity": by_sev, "sample": sample}


@router.get("/v1/remediation-campaigns/workload")
async def workload(user: dict = Depends(require_module(MODULE_KEY))):
    """Per-assignee workload across all open campaigns: campaigns, open findings,
    and how many of their campaigns are overdue -- so an admin can balance load."""
    agg: dict = {}
    for camp in await rc.list_campaigns(db):
        if camp.get("status") == "closed":
            continue
        p = camp["progress"]
        for a in (camp.get("assignees") or []):
            w = agg.setdefault(a, {"assignee": a, "campaigns": 0, "open": 0, "overdue_campaigns": 0})
            w["campaigns"] += 1
            w["open"] += p["open"]
            if p["overdue"]:
                w["overdue_campaigns"] += 1
    return {"items": sorted(agg.values(), key=lambda w: -w["open"])}


class ScopeTemplateBody(BaseModel):
    name: str
    filter: dict = {}


@router.get("/v1/remediation-campaigns/scope-templates")
async def list_scope_templates(user: dict = Depends(require_module(MODULE_KEY))):
    owner = user.get("email") or user.get("id")
    items = await db.remediation_scope_templates.find(
        {"$or": [{"owner": owner}, {"shared": True}]}, {"_id": 0}).sort("name", 1).to_list(200)
    return {"items": items}


@router.post("/v1/remediation-campaigns/scope-templates")
async def save_scope_template(body: ScopeTemplateBody, user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    if not body.name.strip():
        raise HTTPException(400, "A template name is required")
    owner = user.get("email") or user.get("id")
    doc = {"owner": owner, "name": body.name.strip(), "filter": body.filter or {},
           "updated_at": rc._now_iso()}
    existing = await db.remediation_scope_templates.find_one({"owner": owner, "name": doc["name"]}, {"_id": 0})
    doc["id"] = existing["id"] if existing else __import__("uuid").uuid4().hex
    await db.remediation_scope_templates.update_one({"owner": owner, "name": doc["name"]},
                                                    {"$set": doc}, upsert=True)
    return {"ok": True, "id": doc["id"], "name": doc["name"]}


@router.delete("/v1/remediation-campaigns/scope-templates/{template_id}")
async def delete_scope_template(template_id: str, user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    owner = user.get("email") or user.get("id")
    await db.remediation_scope_templates.delete_one({"owner": owner, "id": template_id})
    return {"ok": True}


class RecurringBody(BaseModel):
    name_template: str
    scope: dict
    cadence: str = "monthly"          # monthly | weekly
    owner_team: Optional[str] = None
    assignees: Optional[List[str]] = None
    due_days: Optional[int] = 30
    require_verification: bool = True
    active: bool = True
    next_run_at: Optional[str] = None


@router.get("/v1/remediation-campaigns/recurring")
async def list_recurring(user: dict = Depends(require_module(MODULE_KEY))):
    return {"items": await db.remediation_recurring.find({}, {"_id": 0}).sort("name_template", 1).to_list(200)}


@router.post("/v1/remediation-campaigns/recurring")
async def create_recurring(body: RecurringBody, user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    import uuid as _uuid
    if not body.name_template.strip():
        raise HTTPException(400, "A name template is required")
    doc = {"id": _uuid.uuid4().hex, **body.dict(), "created_by": user.get("email") or user.get("id"),
           "created_at": rc._now_iso(), "last_run_at": None, "last_campaign_id": None,
           "next_run_at": body.next_run_at or rc._now_iso()}
    await db.remediation_recurring.insert_one(dict(doc))
    return {k: v for k, v in doc.items() if k != "_id"}


@router.patch("/v1/remediation-campaigns/recurring/{rec_id}")
async def update_recurring(rec_id: str, body: dict, user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    allowed = {k: v for k, v in body.items() if k in
               {"name_template", "scope", "cadence", "owner_team", "assignees", "due_days",
                "require_verification", "active", "next_run_at"}}
    await db.remediation_recurring.update_one({"id": rec_id}, {"$set": allowed})
    return {"ok": True}


@router.delete("/v1/remediation-campaigns/recurring/{rec_id}")
async def delete_recurring(rec_id: str, user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    await db.remediation_recurring.delete_one({"id": rec_id})
    return {"ok": True}


@router.post("/v1/remediation-campaigns/recurring/{rec_id}/run-now")
async def run_recurring_now(rec_id: str, user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    rec = await db.remediation_recurring.find_one({"id": rec_id}, {"_id": 0})
    if not rec:
        raise HTTPException(404, "Recurring definition not found")
    async def _resolver(flt): return await _ids_from_findings_filter(user, flt)
    ids = await _resolver(rec.get("scope") or {})
    if not ids:
        raise HTTPException(400, "The scope matched nothing right now")
    camp = await rc.create_campaign(db, name=rc._expand_name(rec.get("name_template")),
        owner_team=rec.get("owner_team"), due_date=rc._due_from(rec.get("due_days")),
        finding_ids=ids, filt=rec.get("scope"), assignees=rec.get("assignees"),
        created_by=user.get("email") or user.get("id"),
        require_verification=rec.get("require_verification", True))
    await db.remediation_recurring.update_one({"id": rec_id}, {"$set": {
        "last_run_at": rc._now_iso(), "next_run_at": rc._advance(rc._now_iso(), rec.get("cadence", "monthly")),
        "last_campaign_id": camp["id"]}})
    return {"campaign_id": camp["id"], "findings": len(ids)}


@router.post("/v1/remediation-campaigns/escalate")
async def run_escalation(user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    return await rc.escalate_overdue(db)


@router.get("/v1/remediation-campaigns/assignable-users")
async def assignable_users(user: dict = Depends(require_module(MODULE_KEY))):
    """Users to pick as campaign assignees (for the assignee dropdown)."""
    rows = await db.users.find({}, {"_id": 0, "email": 1, "name": 1, "team": 1, "teams": 1, "role": 1}).to_list(500)
    return {"items": [{"email": u.get("email"), "name": u.get("name"),
                       "team": u.get("team") or (u.get("teams") or [None])[0]} for u in rows if u.get("email")]}


@router.post("/v1/remediation-campaigns/notify")
async def campaign_notify(user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    """Push current overdue/regression alerts into the notifications outbox."""
    return await rc.notify_alerts(db)


@router.post("/v1/remediation-campaigns")
async def create_campaign(body: CampaignBody,
                          user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    if not body.name.strip():
        raise HTTPException(400, "A campaign name is required")
    finding_ids = list(body.finding_ids or [])
    if body.findings_filter:
        finding_ids += await _ids_from_findings_filter(user, body.findings_filter)
    if not finding_ids:
        raise HTTPException(400, "Provide finding_ids or a findings_filter that matches something")
    camp = await rc.create_campaign(
        db, name=body.name.strip(), description=body.description, owner_team=body.owner_team,
        due_date=body.due_date, finding_ids=finding_ids, filt=body.findings_filter,
        assignees=body.assignees, created_by=user.get("email") or user.get("id"),
        require_verification=body.require_verification, maintenance_window=body.maintenance_window,
        change_ticket=body.change_ticket)
    if not camp["finding_ids"]:
        await db.remediation_campaigns.delete_one({"id": camp["id"]})
        raise HTTPException(400, "Nothing matched — the campaign would be empty")
    return camp


@router.get("/v1/remediation-campaigns/{campaign_id}")
async def get_campaign(campaign_id: str, user: dict = Depends(require_module(MODULE_KEY))):
    camp = await rc.campaign_detail(db, campaign_id, for_user=user)
    if not camp:
        raise HTTPException(404, "Campaign not found")
    return camp


class CampaignPatch(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    due_date: Optional[str] = None
    status: Optional[str] = None
    assignees: Optional[List[str]] = None
    add_finding_ids: Optional[list] = None
    remove_finding_ids: Optional[list] = None
    add_findings_filter: Optional[dict] = None
    require_verification: Optional[bool] = None
    maintenance_window: Optional[dict] = None
    change_ticket: Optional[str] = None


@router.patch("/v1/remediation-campaigns/{campaign_id}")
async def update_campaign(campaign_id: str, body: CampaignPatch,
                          user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    camp = await db.remediation_campaigns.find_one({"id": campaign_id}, {"_id": 0})
    if not camp:
        raise HTTPException(404, "Campaign not found")
    actor = user.get("email") or user.get("id")
    patch = {}
    for fld in ("name", "description", "due_date", "status", "assignees",
                "require_verification", "maintenance_window", "change_ticket"):
        v = getattr(body, fld)
        if v is not None:
            patch[fld] = v
    if body.assignees is not None:
        new_people = set(body.assignees) - set(camp.get("assignees") or [])
        if new_people:
            await rc.notify_assignees(db, {**camp, **patch}, list(new_people), "assigned",
                                      f"You've been assigned to remediation campaign '{camp.get('name')}'")
    ids = set(camp.get("finding_ids") or [])
    add = set(body.add_finding_ids or [])
    if body.add_findings_filter:
        add |= set(await _ids_from_findings_filter(user, body.add_findings_filter))
    if add:
        ids |= add
        # extend the baseline with the newly-added findings that are OPEN now,
        # so "what we need to patch" grows with them (patched-since-added holds).
        new_open = await rc._open_subset(db, list(add))
        base = set(camp.get("baseline_open_ids") or [])
        base |= set(new_open)
        patch["baseline_open_ids"] = sorted(base)
        await rc.log_activity(db, campaign_id, actor, "added_findings",
                              f"Added {len(add)} finding(s) ({len(new_open)} open to patch)")
    if body.remove_finding_ids:
        ids -= set(body.remove_finding_ids)
        await rc.log_activity(db, campaign_id, actor, "removed_findings",
                              f"Removed {len(body.remove_finding_ids)} finding(s)")
    if add or body.remove_finding_ids:
        patch["finding_ids"] = sorted(ids)
    if patch:
        await db.remediation_campaigns.update_one({"id": campaign_id}, {"$set": patch})
    return await rc.campaign_detail(db, campaign_id, for_user=user)


@router.delete("/v1/remediation-campaigns/{campaign_id}")
async def delete_campaign(campaign_id: str,
                          user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    await db.remediation_campaigns.delete_one({"id": campaign_id})
    await db.remediation_campaign_activity.delete_many({"campaign_id": campaign_id})
    return {"ok": True}


class NoteBody(BaseModel):
    text: str
    attachments: Optional[List[dict]] = None   # [{name, mime, data_url}]
    links: Optional[List[str]] = None


@router.post("/v1/remediation-campaigns/{campaign_id}/notes")
async def add_campaign_note(campaign_id: str, body: NoteBody,
                            user: dict = Depends(require_module(MODULE_KEY))):
    if not body.text.strip() and not body.attachments and not body.links:
        raise HTTPException(400, "A note, attachment, or link is required")
    for a in body.attachments or []:
        if isinstance(a.get("data_url"), str) and len(a["data_url"]) > 1_400_000:
            raise HTTPException(413, f"Attachment '{a.get('name','?')}' exceeds 1 MB")
        if a.get("mime") and not a["mime"].startswith(("image/", "application/pdf")):
            raise HTTPException(400, "Only image and PDF attachments allowed")
    return await rc.add_note(db, campaign_id, actor=user.get("email") or user.get("id"),
                             text=body.text, attachments=body.attachments, links=body.links)


class MassNoteBody(BaseModel):
    finding_ids: List[str]
    text: str
    attachments: Optional[List[dict]] = None


@router.post("/v1/remediation-campaigns/{campaign_id}/mass-note")
async def mass_note(campaign_id: str, body: MassNoteBody,
                    user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    """Write one note to many findings at once (no opening each vulnerability)."""
    actor = user.get("email") or user.get("id")
    n = await rc.mass_note_findings(db, finding_ids=body.finding_ids, actor=actor,
                                    text=body.text, attachments=body.attachments)
    await rc.log_activity(db, campaign_id, actor, "note",
                          f"Mass note added to {n} finding(s): {body.text[:80]}")
    return {"noted": n}


class BulkStatusBody(BaseModel):
    finding_ids: List[str]
    status: str
    note: Optional[str] = None


@router.post("/v1/remediation-campaigns/{campaign_id}/bulk-status")
async def bulk_status(campaign_id: str, body: BulkStatusBody,
                      user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    """Set a built-in status on many findings at once (e.g. mark Fixed pending
    validation, or Accepted risk for the ones going to an exception)."""
    from routes.common import now_iso
    actor = user.get("email") or user.get("id")
    await db.findings.update_many({"id": {"$in": body.finding_ids}},
                                  {"$set": {"status": body.status, "last_changed_at": now_iso()}})
    await rc.log_activity(db, campaign_id, actor, "status_change",
                          f"{len(body.finding_ids)} finding(s) → {body.status}"
                          + (f" ({body.note})" if body.note else ""))
    if body.status == "Accepted risk":
        await rc.log_activity(db, campaign_id, actor, "exception_filed",
                              f"{len(body.finding_ids)} finding(s) routed to a risk-acceptance exception")
    camp = await db.remediation_campaigns.find_one({"id": campaign_id}, {"_id": 0})
    if camp:
        await rc.maybe_autoclose(db, camp)
    return {"updated": len(body.finding_ids)}


class ExceptionReqBody(BaseModel):
    finding_ids: List[str]
    business_justification: str
    duration_days: int = 90
    compensating_controls: Optional[List[str]] = None


@router.post("/v1/remediation-campaigns/{campaign_id}/request-exceptions")
async def request_exceptions(campaign_id: str, body: ExceptionReqBody,
                             user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    """Can't-patch path: file REAL risk-acceptance exceptions through the built-in
    exceptions workflow (approval chain + ticket), one per finding, instead of just
    flipping a status. The findings stay in their current status until approved."""
    if not body.business_justification.strip():
        raise HTTPException(400, "A business justification is required for a risk exception")
    from routes.workflows import request_exception as _req_exc, ExceptionCreate
    actor = user.get("email") or user.get("id")
    created = []
    for fid in body.finding_ids:
        try:
            exc = await _req_exc(ExceptionCreate(
                target_type="finding", finding_id=fid,
                business_justification=body.business_justification,
                duration_days=body.duration_days,
                compensating_controls=body.compensating_controls or []), user)
            created.append(exc.get("id"))
        except HTTPException:
            continue
    await rc.log_activity(db, campaign_id, actor, "exception_filed",
                          f"Filed {len(created)} risk-acceptance exception(s) via the exceptions workflow "
                          f"({body.duration_days}d): {body.business_justification[:80]}")
    return {"requested": len(created), "exception_ids": created}


@router.post("/v1/remediation-campaigns/{campaign_id}/close")
async def close_campaign(campaign_id: str, force: bool = False,
                         user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    """Verification-gated: won't close until every baseline finding is scanner-
    verified (Fixed validated) or formally accepted (exception) -- unless force."""
    camp = await rc.campaign_detail(db, campaign_id)
    if not camp:
        raise HTTPException(404, "Campaign not found")
    if camp.get("require_verification", True) and not camp["progress"]["closeable"] and not force:
        raise HTTPException(400,
            f"Cannot close: {camp['progress']['unverified_resolved']} finding(s) are resolved but not "
            f"scanner-verified, and {camp['progress']['open']} still open. Wait for the next scan to "
            f"confirm the fixes, route unpatchable ones to an exception (Accepted risk), or force-close.")
    await rc.close_campaign(db, campaign_id, user.get("email") or user.get("id"),
                            "Force-closed" if force else "Closed (all verified/accepted)")
    return {"ok": True}


@router.get("/v1/remediation-campaigns/{campaign_id}/export.csv")
async def export_campaign_csv(campaign_id: str, user: dict = Depends(require_module(MODULE_KEY))):
    camp = await rc.campaign_detail(db, campaign_id)
    if not camp:
        raise HTTPException(404, "Campaign not found")
    out = io.StringIO(); w = csv.writer(out)
    w.writerow(["Title", "CVE", "QID", "Severity", "Status", "Asset", "Owner Team",
                "Assigned To", "Due", "Open Days", "Priority", "Ticket"])
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    for f in camp.get("findings", []):
        age = ""
        if f.get("first_seen_at"):
            try:
                age = (now - datetime.fromisoformat(str(f["first_seen_at"]).replace("Z","+00:00")).replace(tzinfo=timezone.utc)).days
            except Exception:
                age = ""
        w.writerow([f.get("title"), f.get("cve") or "", f.get("qid") or "", f.get("severity"),
                    f.get("status"), f.get("asset_hostname") or "", f.get("owner_team") or "",
                    f.get("assigned_to") or "", f.get("due_at") or "", age, f.get("priority_score"),
                    (f.get("ticket_ref") or {}).get("external_id") or ""])
    out.seek(0)
    return StreamingResponse(iter([out.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=campaign-{campaign_id[:8]}.csv"})


@router.get("/v1/remediation-campaigns/{campaign_id}/report")
async def campaign_report(campaign_id: str, user: dict = Depends(require_module(MODULE_KEY))):
    """Leadership status report payload (progress, overdue, exceptions, timeline)."""
    camp = await rc.campaign_detail(db, campaign_id)
    if not camp:
        raise HTTPException(404, "Campaign not found")
    p = camp["progress"]
    exceptions = [e for e in camp.get("activity", []) if e.get("action") == "exception_filed"]
    return {
        "id": camp["id"], "name": camp["name"], "owner_team": camp.get("owner_team"),
        "status": camp.get("status"), "due_date": camp.get("due_date"),
        "generated_at": rc._now_iso(), "progress": p,
        "groups": camp.get("groups", {}), "timeline": camp.get("timeline", []),
        "exceptions": exceptions,
    }


class CampaignAssignBody(BaseModel):
    finding_ids: List[str]
    assignee: str


@router.post("/v1/remediation-campaigns/{campaign_id}/bulk-assign")
async def campaign_bulk_assign(campaign_id: str, body: CampaignAssignBody,
                               user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    from routes.common import now_iso as _ni
    await db.findings.update_many({"id": {"$in": body.finding_ids}},
                                  {"$set": {"assigned_to": body.assignee, "last_changed_at": _ni()}})
    await rc.log_activity(db, campaign_id, user.get("email") or user.get("id"), "reassigned",
                          f"{len(body.finding_ids)} finding(s) reassigned to {body.assignee}")
    return {"updated": len(body.finding_ids)}


@router.get("/v1/remediation-campaigns/{campaign_id}/burndown")
async def campaign_burndown(campaign_id: str, user: dict = Depends(require_module(MODULE_KEY))):
    return {"series": await rc.burndown(db, campaign_id)}


@router.post("/v1/remediation-campaigns/snapshot-progress")
async def snapshot_progress(user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    """Record today's progress for every campaign (nightly-style; also runnable now)."""
    return await rc.snapshot_progress(db)
