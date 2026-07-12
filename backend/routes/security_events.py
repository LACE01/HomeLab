"""Security Alerts -- the triage queue backed by security_events.py's event bus.
See that module's docstring for what writes here and how correlation works; this
file is just the read/ack/close API + summary stats over that collection."""
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from db import db
from rbac import require_module
from auth_utils import get_current_user
from routes.common import now_iso

router = APIRouter()


@router.get("/v1/security-events")
async def list_events(
    status: Optional[str] = None, severity: Optional[str] = None, source: Optional[str] = None,
    entity_id: Optional[str] = None, q: Optional[str] = None,
    limit: int = 50, offset: int = 0,
    user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/alerts")),
):
    flt: dict = {}
    if status:
        flt["status"] = status
    if severity:
        flt["severity"] = severity
    if source:
        flt["source"] = source
    if entity_id:
        flt["entity_id"] = entity_id
    if q:
        flt["$or"] = [
            {"title": {"$regex": q, "$options": "i"}},
            {"entity_label": {"$regex": q, "$options": "i"}},
            {"description": {"$regex": q, "$options": "i"}},
        ]
    total = await db.security_events.count_documents(flt)
    items = await db.security_events.find(flt, {"_id": 0}).sort("last_seen_at", -1).skip(max(0, offset)).limit(min(max(1, limit), 200)).to_list(200)
    return {"items": items, "total": total}


@router.get("/v1/security-events/stats")
async def event_stats(user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/alerts"))):
    open_by_severity = {}
    async for row in db.security_events.aggregate([
        {"$match": {"status": "open"}},
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
    ]):
        open_by_severity[row["_id"]] = row["count"]
    open_total = sum(open_by_severity.values())
    correlated_open = await db.security_events.count_documents({"status": "open", "event_type": "correlated_alert"})
    return {"open_total": open_total, "open_by_severity": open_by_severity, "correlated_open": correlated_open}


@router.get("/v1/security-events/{event_id}")
async def get_event(event_id: str, user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/alerts"))):
    event = await db.security_events.find_one({"id": event_id}, {"_id": 0})
    if not event:
        raise HTTPException(404, "Event not found")
    related = []
    if event.get("event_type") == "correlated_alert":
        ids = (event.get("raw") or {}).get("related_event_ids") or []
        related = await db.security_events.find({"id": {"$in": ids}}, {"_id": 0}).to_list(50)
    return {**event, "related_events": related}


class CloseBody(BaseModel):
    reason: Optional[str] = None


@router.post("/v1/security-events/{event_id}/acknowledge")
async def acknowledge_event(event_id: str, user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/alerts", level="edit"))):
    res = await db.security_events.update_one(
        {"id": event_id},
        {"$set": {"status": "acknowledged", "acknowledged_by": user["email"], "acknowledged_at": now_iso()}},
    )
    if res.matched_count == 0:
        raise HTTPException(404, "Event not found")
    return {"ok": True}


@router.post("/v1/security-events/{event_id}/close")
async def close_event(event_id: str, body: CloseBody, user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/alerts", level="edit"))):
    res = await db.security_events.update_one(
        {"id": event_id},
        {"$set": {"status": "closed", "closed_by": user["email"], "closed_at": now_iso(), "close_reason": body.reason}},
    )
    if res.matched_count == 0:
        raise HTTPException(404, "Event not found")
    return {"ok": True}


@router.post("/v1/security-events/{event_id}/reopen")
async def reopen_event(event_id: str, user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/alerts", level="edit"))):
    res = await db.security_events.update_one(
        {"id": event_id},
        {"$set": {"status": "open", "last_seen_at": now_iso()}},
    )
    if res.matched_count == 0:
        raise HTTPException(404, "Event not found")
    return {"ok": True}


class ExportBody(BaseModel):
    target: str  # "jira" | "webhook"
    webhook_id: Optional[str] = None


@router.post("/v1/security-events/{event_id}/export")
async def export_event(event_id: str, body: ExportBody, user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/alerts", level="edit"))):
    """Manually push a single alert out to Jira or a configured webhook -- see
    ticketing.py for what actually gets sent. Deliberately manual/per-event rather
    than auto-forwarding everything, so someone decides what's actually worth
    filing externally instead of flooding Jira/the SOAR queue with every Low."""
    event = await db.security_events.find_one({"id": event_id}, {"_id": 0})
    if not event:
        raise HTTPException(404, "Event not found")
    from ticketing import create_jira_issue, send_to_webhook
    try:
        if body.target == "jira":
            ticket = await create_jira_issue(db, event)
        elif body.target == "webhook":
            if not body.webhook_id:
                raise HTTPException(400, "webhook_id is required for target=webhook")
            ticket = await send_to_webhook(db, event, body.webhook_id)
        else:
            raise HTTPException(400, "target must be 'jira' or 'webhook'")
    except ValueError as e:
        raise HTTPException(400, str(e))
    except RuntimeError as e:
        raise HTTPException(502, str(e))
    return {"ok": True, "ticket": ticket}
