"""Admin routes: users, notifications (channels + rules + outbox + meta),
assignment-rules, ownership-mappings, sla-policies, api-keys, nightly-rescore."""
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr

from db import db
from auth_utils import hash_password, get_current_user, require_role
from routes.common import now_iso, _clean

router = APIRouter()


# --------------------------- USERS ---------------------------
@router.get("/v1/admin/users")
async def list_users(user: dict = Depends(require_role("admin"))):
    items = await db.users.find({}, {"_id": 0, "password_hash": 0}).to_list(100)
    return {"items": items}


class UserCreate(BaseModel):
    email: EmailStr
    name: str
    role: str = "analyst"
    team: Optional[str] = None
    department: Optional[str] = None
    password: Optional[str] = None


@router.post("/v1/admin/users")
async def create_user(body: UserCreate, user: dict = Depends(require_role("admin"))):
    existing = await db.users.find_one({"email": body.email.lower()})
    if existing:
        raise HTTPException(409, "Email already exists")
    if body.role not in ["admin", "analyst", "manager", "executive"]:
        raise HTTPException(400, "Invalid role")
    new = {
        "id": str(uuid.uuid4()), "email": body.email.lower(), "name": body.name,
        "role": body.role, "team": body.team, "department": body.department,
        "password_hash": hash_password(body.password) if body.password else None,
        "created_at": now_iso(), "active": True,
    }
    await db.users.insert_one(new)
    return {"id": new["id"], "email": new["email"]}


class UserUpdate(BaseModel):
    name: Optional[str] = None
    team: Optional[str] = None
    department: Optional[str] = None
    role: Optional[str] = None
    active: Optional[bool] = None
    password: Optional[str] = None


@router.patch("/v1/admin/users/{user_id}")
async def update_user(user_id: str, body: UserUpdate, user: dict = Depends(require_role("admin"))):
    update = {}
    for k, v in body.model_dump(exclude_none=True).items():
        if k == "password":
            update["password_hash"] = hash_password(v)
        else:
            update[k] = v
    if not update:
        raise HTTPException(400, "No fields to update")
    res = await db.users.update_one({"id": user_id}, {"$set": update})
    if res.matched_count == 0:
        raise HTTPException(404, "User not found")
    return {"ok": True}


@router.delete("/v1/admin/users/{user_id}")
async def delete_user(user_id: str, user: dict = Depends(require_role("admin"))):
    if user_id == user["id"]:
        raise HTTPException(400, "Cannot delete your own account")
    res = await db.users.delete_one({"id": user_id})
    await db.user_sessions.delete_many({"user_id": user_id})
    if res.deleted_count == 0:
        raise HTTPException(404, "User not found")
    return {"ok": True}


# --------------------------- NOTIFICATION CHANNELS & RULES ---------------------------
class ChannelIn(BaseModel):
    name: str
    type: str
    webhook_url: Optional[str] = None
    to: Optional[str] = None
    enabled: bool = True


@router.get("/v1/admin/notification-channels")
async def list_channels(user: dict = Depends(get_current_user)):
    items = await db.notification_channels.find({}, {"_id": 0}).to_list(100)
    for c in items:
        if c.get("webhook_url") and len(c["webhook_url"]) > 30:
            c["webhook_url_masked"] = c["webhook_url"][:32] + "•••" + c["webhook_url"][-6:]
        c.pop("webhook_url", None)
    return {"items": items}


@router.post("/v1/admin/notification-channels")
async def create_channel(body: ChannelIn, user: dict = Depends(require_role("admin"))):
    from notifier import CHANNELS
    if body.type not in CHANNELS:
        raise HTTPException(400, f"type must be one of {CHANNELS}")
    if body.type == "email" and not body.to:
        raise HTTPException(400, "to (recipient email) is required for email channels")
    if body.type in ("discord", "slack", "teams", "webhook") and not body.webhook_url:
        raise HTTPException(400, "webhook_url is required for this channel type")
    doc = {**body.model_dump(), "id": str(uuid.uuid4()), "created_at": now_iso()}
    await db.notification_channels.insert_one(doc)
    return {"id": doc["id"]}


@router.delete("/v1/admin/notification-channels/{channel_id}")
async def delete_channel(channel_id: str, user: dict = Depends(require_role("admin"))):
    await db.notification_channels.delete_one({"id": channel_id})
    return {"ok": True}


@router.post("/v1/admin/notification-channels/{channel_id}/test")
async def test_channel(channel_id: str, user: dict = Depends(require_role("admin"))):
    from notifier import deliver
    channel = await db.notification_channels.find_one({"id": channel_id}, {"_id": 0})
    if not channel:
        raise HTTPException(404, "Channel not found")
    ctx = {
        "severity": "Critical", "title": "Test notification — Log4Shell RCE",
        "cve": "CVE-2021-44228", "asset": "web-prod-01", "owner_team": "Platform Eng",
        "risk_score": 96, "due_at": "2026-03-01",
        "url": "https://remediationhub.preview.emergentagent.com/findings/demo",
    }
    rec = await deliver(channel, "new_assignment", ctx, db)
    return {"delivered": rec["delivered"], "status_code": rec["status_code"], "response": rec["response"]}


class RuleIn(BaseModel):
    name: str
    trigger: str
    channel_ids: list[str]
    severity_in: Optional[list[str]] = None
    owner_team: Optional[str] = None
    template_id: Optional[str] = None
    frequency: str = "immediate"
    active: bool = True


@router.get("/v1/admin/notification-rules")
async def list_rules_notif(user: dict = Depends(get_current_user)):
    items = await db.notification_rules.find({}, {"_id": 0}).to_list(200)
    return {"items": items}


@router.post("/v1/admin/notification-rules")
async def create_rule_notif(body: RuleIn, user: dict = Depends(require_role("admin"))):
    from notifier import TRIGGERS
    if body.trigger not in TRIGGERS:
        raise HTTPException(400, f"trigger must be one of {TRIGGERS}")
    doc = {**body.model_dump(), "id": str(uuid.uuid4()), "created_at": now_iso()}
    await db.notification_rules.insert_one(doc)
    return {"id": doc["id"]}


@router.delete("/v1/admin/notification-rules/{rule_id}")
async def delete_rule_notif(rule_id: str, user: dict = Depends(require_role("admin"))):
    await db.notification_rules.delete_one({"id": rule_id})
    return {"ok": True}


@router.get("/v1/admin/notifications-outbox")
async def list_outbox(user: dict = Depends(get_current_user)):
    items = await db.notifications_outbox.find({}, {"_id": 0}).sort("created_at", -1).limit(200).to_list(200)
    return {"items": items}


@router.get("/v1/admin/notification-meta")
async def notification_meta(user: dict = Depends(get_current_user)):
    from notifier import TRIGGERS, CHANNELS, TEMPLATES
    return {"triggers": TRIGGERS, "channels": CHANNELS, "templates": list(TEMPLATES.keys())}


# --------------------------- ASSIGNMENT RULES ---------------------------
class AssignmentRule(BaseModel):
    id: Optional[str] = None
    name: str
    priority: int = 100
    field: str
    operator: str = "equals"
    value: str
    assign_team: str
    active: bool = True


@router.get("/v1/admin/assignment-rules")
async def list_rules(user: dict = Depends(get_current_user)):
    items = await db.assignment_rules.find({}, {"_id": 0}).sort("priority", 1).to_list(200)
    return {"items": items}


@router.post("/v1/admin/assignment-rules")
async def create_rule(body: AssignmentRule, user: dict = Depends(require_role("admin"))):
    rule = body.model_dump()
    rule["id"] = str(uuid.uuid4())
    rule["created_at"] = now_iso()
    await db.assignment_rules.insert_one(rule)
    return _clean(rule)


@router.patch("/v1/admin/assignment-rules/{rule_id}")
async def update_rule(rule_id: str, body: AssignmentRule, user: dict = Depends(require_role("admin"))):
    update = {k: v for k, v in body.model_dump().items() if k != "id" and v is not None}
    res = await db.assignment_rules.update_one({"id": rule_id}, {"$set": update})
    if res.matched_count == 0:
        raise HTTPException(404, "Rule not found")
    return {"ok": True}


@router.delete("/v1/admin/assignment-rules/{rule_id}")
async def delete_rule(rule_id: str, user: dict = Depends(require_role("admin"))):
    await db.assignment_rules.delete_one({"id": rule_id})
    return {"ok": True}


def _rule_matches(rule: dict, asset: dict) -> bool:
    f = rule["field"]
    val = rule["value"].lower()
    asset_val = asset.get(f) or asset.get("tags") if f == "tags" else asset.get(f)
    if f == "tags":
        tags = [str(t).lower() for t in (asset.get("tags") or [])]
        return val in tags if rule["operator"] == "equals" else any(val in t for t in tags)
    av = str(asset_val or "").lower()
    return av == val if rule["operator"] == "equals" else val in av


@router.post("/v1/admin/assignment-rules/apply")
async def apply_rules(user: dict = Depends(require_role("admin"))):
    rules = await db.assignment_rules.find({"active": True}, {"_id": 0}).sort("priority", 1).to_list(500)
    assets = await db.assets.find({}, {"_id": 0}).to_list(5000)
    updated_assets = 0
    updated_findings = 0
    for asset in assets:
        matched_rule = next((r for r in rules if _rule_matches(r, asset)), None)
        if matched_rule:
            new_team = matched_rule["assign_team"]
            rationale = f"Matched rule '{matched_rule['name']}': {matched_rule['field']} {matched_rule['operator']} '{matched_rule['value']}'"
            confidence = 0.95
        else:
            new_team = asset.get("owner_team", "Unassigned")
            rationale = "No assignment rule matched — preserved existing owner"
            confidence = 0.3
        await db.assets.update_one({"id": asset["id"]}, {"$set": {
            "owner_team": new_team, "ownership_rationale": rationale, "ownership_confidence": confidence,
        }})
        updated_assets += 1
        r = await db.findings.update_many(
            {"asset_id": asset["id"], "status": {"$nin": ["Fixed validated", "Closed administratively"]}},
            {"$set": {"owner_team": new_team, "ownership_confidence": confidence, "ownership_rationale": rationale}},
        )
        updated_findings += r.modified_count
    return {"updated_assets": updated_assets, "updated_findings": updated_findings, "rules_evaluated": len(rules)}


@router.get("/v1/ownership-mappings")
async def ownership_mappings(user: dict = Depends(get_current_user), q: Optional[str] = None):
    flt = {}
    if q:
        flt["$or"] = [{"hostname": {"$regex": q, "$options": "i"}}, {"owner_team": {"$regex": q, "$options": "i"}}]
    items = await db.assets.find(flt, {"_id": 0, "id": 1, "hostname": 1, "owner_team": 1,
                                       "ownership_confidence": 1, "ownership_rationale": 1, "tags": 1,
                                       "environment": 1, "platform": 1, "criticality": 1, "exposure": 1}).to_list(1000)
    return {"items": items}


@router.get("/v1/admin/sla-policies")
async def get_sla_policies(user: dict = Depends(get_current_user)):
    from scoring import SLA_DAYS
    return {"policies": SLA_DAYS}


class SLAUpdate(BaseModel):
    policies: dict  # {severity: {criticality: days}}


@router.put("/v1/admin/sla-policies")
async def update_sla_policies(body: SLAUpdate, user: dict = Depends(require_role("admin"))):
    from scoring import SLA_DAYS
    # Validate structure and coerce ints
    severities = {"Critical", "High", "Medium", "Low", "Info"}
    criticalities = {"crown_jewel", "critical", "high", "medium", "low"}
    cleaned: dict = {}
    for sev, rows in (body.policies or {}).items():
        if sev not in severities or not isinstance(rows, dict):
            raise HTTPException(400, f"Invalid severity '{sev}'")
        cleaned[sev] = {}
        for crit, days in rows.items():
            if crit not in criticalities:
                raise HTTPException(400, f"Invalid criticality '{crit}'")
            try:
                cleaned[sev][crit] = max(1, min(3650, int(days)))
            except (TypeError, ValueError):
                raise HTTPException(400, f"days must be int for {sev}/{crit}")
    # Persist
    await db.sla_policies.update_one(
        {"id": "default"},
        {"$set": {"id": "default", "policies": cleaned, "updated_at": now_iso(), "updated_by": user["email"]}},
        upsert=True,
    )
    # Hot-reload in-memory copy
    SLA_DAYS.update(cleaned)
    return {"policies": SLA_DAYS}


@router.get("/v1/admin/api-keys")
async def list_api_keys(user: dict = Depends(require_role("admin"))):
    items = await db.api_keys.find({}, {"_id": 0}).to_list(100)
    return {"items": items}


# --------------------------- NIGHTLY RESCORE ---------------------------
@router.post("/v1/admin/nightly-rescore/run")
async def trigger_nightly(user: dict = Depends(require_role("admin"))):
    from nightly import run_nightly_rescore
    return await run_nightly_rescore(db)


@router.get("/v1/admin/nightly-rescore/runs")
async def list_rescore_runs(user: dict = Depends(require_role("admin"))):
    items = await db.rescoring_runs.find({}, {"_id": 0}).sort("ran_at", -1).limit(50).to_list(50)
    return {"items": items}


# --------------------------- QUALYS LIVE SYNC ---------------------------
@router.post("/v1/admin/qualys/sync/run")
async def trigger_qualys_sync(user: dict = Depends(require_role("admin"))):
    """One-shot Qualys VMDR sync (admin only). Returns the run record."""
    from qualys_sync import run_qualys_sync
    try:
        return await run_qualys_sync(db)
    except RuntimeError as e:
        raise HTTPException(400, str(e))


@router.get("/v1/admin/qualys/sync/runs")
async def list_qualys_runs(user: dict = Depends(require_role("admin"))):
    items = await db.qualys_sync_runs.find({}, {"_id": 0}).sort("ran_at", -1).limit(50).to_list(50)
    return {"items": items}


# --------------------------- DATA WIPE (one-shot demo cleanup) ---------------------------
@router.post("/v1/admin/wipe-demo-data")
async def wipe_demo(user: dict = Depends(require_role("admin"))):
    """Delete every operational data collection (findings, assets, products, tickets, etc.).
    Keeps users, integrations config, notification channels, assignment rules, API keys."""
    from seed import wipe_demo_data
    return {"deleted": await wipe_demo_data(db)}
