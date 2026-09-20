"""Global audit log -- admin-wide view over db.activity_log, which every module in
the app already writes to (status changes, assignments, exceptions, automation runs,
ChatOps actions, verification sweeps) but which was previously only ever queried
per-entity (a single finding's or asset's own history).

Two slightly different document shapes exist in this collection (most write
entity_type/entity_id/timestamp/details; the automation rule-note logger writes
finding_id/created_at/detail instead) -- normalized here rather than migrating old
data or touching automation.py's existing per-finding query that depends on its
current field names.
"""
import csv
import io
from typing import Optional

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse

from db import db
from rbac import require_module
from auth_utils import require_role

router = APIRouter()


def _normalize(doc: dict) -> dict:
    return {
        "id": doc.get("id"),
        "entity_type": doc.get("entity_type") or ("finding" if doc.get("finding_id") else None),
        "entity_id": doc.get("entity_id") or doc.get("finding_id"),
        "action": doc.get("action"),
        "actor": doc.get("actor"),
        "details": doc.get("details") or doc.get("detail"),
        "timestamp": doc.get("timestamp") or doc.get("created_at"),
    }


def _activity_filter(actor, action, entity_type, entity_id, start, end) -> dict:
    and_clauses: list = []
    flt: dict = {}
    if actor:
        flt["actor"] = {"$regex": actor, "$options": "i"}
    if action:
        flt["action"] = action
    if entity_type:
        if entity_type == "finding":
            and_clauses.append({"$or": [{"entity_type": "finding"}, {"entity_type": {"$exists": False}, "finding_id": {"$exists": True}}]})
        else:
            and_clauses.append({"entity_type": entity_type})
    if entity_id:
        and_clauses.append({"$or": [{"entity_id": entity_id}, {"finding_id": entity_id}]})
    tf: dict = {}
    if start:
        tf["$gte"] = start
    if end:
        tf["$lte"] = end
    if tf:
        and_clauses.append({"$or": [{"timestamp": tf}, {"created_at": tf}]})
    if and_clauses:
        flt["$and"] = and_clauses
    return flt


def _login_filter(email, success, ip) -> dict:
    flt: dict = {}
    if email:
        flt["email"] = {"$regex": email, "$options": "i"}
    if success is not None:
        flt["success"] = success
    if ip:
        flt["ip"] = ip
    return flt


def _csv_response(rows: list, columns: list, filename: str) -> StreamingResponse:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=columns, extrasaction="ignore")
    w.writeheader()
    for r in rows:
        w.writerow({c: r.get(c, "") for c in columns})
    buf.seek(0)
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": f"attachment; filename={filename}"})


@router.get("/v1/admin/audit-log")
async def audit_log(
    actor: Optional[str] = None,
    action: Optional[str] = None,
    entity_type: Optional[str] = None,
    entity_id: Optional[str] = None,
    start: Optional[str] = None,
    end: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    user: dict = Depends(require_role("admin", "manager")),
    _rbac: dict = Depends(require_module("/admin/audit-log")),
):
    flt = _activity_filter(actor, action, entity_type, entity_id, start, end)

    pipeline = [
        {"$match": flt},
        {"$addFields": {"_when": {"$ifNull": ["$timestamp", "$created_at"]}}},
        {"$sort": {"_when": -1}},
        {"$skip": max(0, offset)},
        {"$limit": min(max(1, limit), 500)},
    ]
    total = await db.activity_log.count_documents(flt)
    docs = [d async for d in db.activity_log.aggregate(pipeline)]
    items = [_normalize(d) for d in docs]

    actions = await db.activity_log.distinct("action")
    return {"items": items, "total": total, "actions": sorted(a for a in actions if a)}


@router.get("/v1/admin/login-audit")
async def login_audit(
    email: Optional[str] = None,
    success: Optional[bool] = None,
    ip: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    user: dict = Depends(require_role("admin")),
    _rbac: dict = Depends(require_module("/admin/audit-log")),
):
    """Every login attempt, successful or not (see routes/auth.py:_log_login_attempt),
    with whatever metadata a standard web login actually exposes -- IP (from
    X-Forwarded-For/X-Real-IP if this is behind a reverse proxy, which it is in every
    self-hosted deployment so far), user-agent, accept-language, and the reason for
    a failure. A MAC address is genuinely not obtainable here -- it's link-layer
    information that never survives even a single router hop, and there's no browser
    API that exposes it, so it isn't tracked (this was raised and confirmed, not
    overlooked). Admin-only, since this is effectively a security log covering every
    account, not just the viewer's own activity."""
    flt = _login_filter(email, success, ip)
    total = await db.login_audit.count_documents(flt)
    items = await db.login_audit.find(flt, {"_id": 0}).sort("timestamp", -1).skip(max(0, offset)).limit(min(max(1, limit), 500)).to_list(500)
    return {"items": items, "total": total}


@router.get("/v1/admin/audit-log.csv")
async def audit_log_csv(
    actor: Optional[str] = None,
    action: Optional[str] = None,
    entity_type: Optional[str] = None,
    entity_id: Optional[str] = None,
    start: Optional[str] = None,
    end: Optional[str] = None,
    user: dict = Depends(require_role("admin", "manager")),
    _rbac: dict = Depends(require_module("/admin/audit-log")),
):
    """Export the activity audit log (respecting the current filters) as CSV for
    compliance/records. Capped at 50k rows so an unbounded export can't OOM."""
    flt = _activity_filter(actor, action, entity_type, entity_id, start, end)
    pipeline = [
        {"$match": flt},
        {"$addFields": {"_when": {"$ifNull": ["$timestamp", "$created_at"]}}},
        {"$sort": {"_when": -1}},
        {"$limit": 50000},
    ]
    rows = [_normalize(d) async for d in db.activity_log.aggregate(pipeline)]
    return _csv_response(rows, ["timestamp", "actor", "action", "entity_type", "entity_id", "details"],
                         "audit-log.csv")


@router.get("/v1/admin/login-audit.csv")
async def login_audit_csv(
    email: Optional[str] = None,
    success: Optional[bool] = None,
    ip: Optional[str] = None,
    user: dict = Depends(require_role("admin")),
    _rbac: dict = Depends(require_module("/admin/audit-log")),
):
    """Export login attempts (respecting the current filters) as CSV. Capped at 50k."""
    flt = _login_filter(email, success, ip)
    rows = await db.login_audit.find(flt, {"_id": 0}).sort("timestamp", -1).limit(50000).to_list(50000)
    return _csv_response(rows, ["timestamp", "email", "success", "ip", "user_agent",
                                "accept_language", "reason"], "login-audit.csv")
