"""Item 62 -- Remediation Campaign / Patch Tracker routes (v2)."""
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException
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


@router.get("/v1/remediation-campaigns/{campaign_id}/burndown")
async def campaign_burndown(campaign_id: str, user: dict = Depends(require_module(MODULE_KEY))):
    return {"series": await rc.burndown(db, campaign_id)}


@router.post("/v1/remediation-campaigns/snapshot-progress")
async def snapshot_progress(user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    """Record today's progress for every campaign (nightly-style; also runnable now)."""
    return await rc.snapshot_progress(db)
