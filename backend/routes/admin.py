"""Admin routes: users, notifications (channels + rules + outbox + meta),
assignment-rules, ownership-mappings, sla-policies, api-keys, nightly-rescore."""
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr, field_validator

from db import db
from rbac import require_module, all_roles
from auth_utils import hash_password, get_current_user, require_role
from routes.common import now_iso, _clean

router = APIRouter()


# --------------------------- USERS ---------------------------
@router.get("/v1/admin/users")
async def list_users(user: dict = Depends(require_role("admin")), _rbac: dict = Depends(require_module("/admin/users"))):
    items = await db.users.find({}, {"_id": 0, "password_hash": 0}).to_list(100)
    return {"items": items}


class UserCreate(BaseModel):
    email: EmailStr
    name: str
    role: str = "analyst"
    # `teams` is the canonical multi-team membership list now (a user can belong to
    # more than one team, e.g. covering two product areas). `team` (singular) is kept
    # as a derived/legacy field -- set automatically to teams[0] -- because a lot of
    # existing code (Teams admin member list, incident-response assignee picker,
    # dashboards) still reads the singular field, and migrating every one of those
    # read sites in lockstep isn't necessary: they just see "a" team, which is fine
    # for display purposes. Anything that GATES data visibility (findings, assets)
    # uses the full `teams` list, not the derived singular one.
    teams: List[str] = []
    team: Optional[str] = None  # legacy/derived -- ignored on input if `teams` given
    department: Optional[str] = None
    password: Optional[str] = None
    must_change_password: bool = True  # forces the change-password flow on first login


@router.post("/v1/admin/users")
async def create_user(body: UserCreate, user: dict = Depends(require_role("admin"))):
    existing = await db.users.find_one({"email": body.email.lower()})
    if existing:
        raise HTTPException(409, "Email already exists")
    if body.role not in await all_roles(db):
        raise HTTPException(400, "Invalid role")
    teams = list(dict.fromkeys(t for t in (body.teams or []) if t))  # de-dupe, keep order
    if not teams and body.team:
        teams = [body.team]
    new = {
        "id": str(uuid.uuid4()), "email": body.email.lower(), "name": body.name,
        "role": body.role, "teams": teams, "team": teams[0] if teams else None,
        "department": body.department,
        "password_hash": hash_password(body.password) if body.password else None,
        # A temp password only needs to be changed if the admin actually set one --
        # an account with no password yet (SSO-only, or set up some other way) has
        # nothing to force a change away FROM.
        "must_change_password": bool(body.password) and body.must_change_password,
        "created_at": now_iso(), "active": True,
    }
    await db.users.insert_one(new)
    return {"id": new["id"], "email": new["email"]}


class UserUpdate(BaseModel):
    name: Optional[str] = None
    email: Optional[EmailStr] = None
    teams: Optional[List[str]] = None
    team: Optional[str] = None
    department: Optional[str] = None
    role: Optional[str] = None
    active: Optional[bool] = None
    password: Optional[str] = None
    must_change_password: Optional[bool] = None


@router.patch("/v1/admin/users/{user_id}")
async def update_user(user_id: str, body: UserUpdate, user: dict = Depends(require_role("admin"))):
    existing = await db.users.find_one({"id": user_id}, {"_id": 0})
    if not existing:
        raise HTTPException(404, "User not found")

    update = {}
    for k, v in body.model_dump(exclude_none=True).items():
        if k == "role":
            if v not in await all_roles(db):
                raise HTTPException(400, "Invalid role")
            update["role"] = v
        elif k == "password":
            update["password_hash"] = hash_password(v)
            # An admin-set/reset password is a new temp password by convention --
            # force the change-password flow again, unless the request explicitly
            # says otherwise via must_change_password in the same call.
            if "must_change_password" not in body.model_fields_set:
                update["must_change_password"] = True
        elif k == "email":
            new_email = v.lower()
            if new_email != existing["email"]:
                dupe = await db.users.find_one({"email": new_email, "id": {"$ne": user_id}})
                if dupe:
                    raise HTTPException(409, "Email already in use by another user")
                update["email"] = new_email
        elif k == "teams":
            teams = list(dict.fromkeys(t for t in (v or []) if t))
            update["teams"] = teams
            update["team"] = teams[0] if teams else None
        else:
            update[k] = v
    if not update:
        raise HTTPException(400, "No fields to update")
    res = await db.users.update_one({"id": user_id}, {"$set": update})
    if res.matched_count == 0:
        raise HTTPException(404, "User not found")

    # Keep any 'specific person' approval-route steps pointing at this user's old
    # address in sync, so renaming an approver's email doesn't silently break routing.
    if "email" in update and existing["email"] != update["email"]:
        async for route in db.approval_routes.find({"chain.approver_email": existing["email"]}):
            changed = False
            for step in route.get("chain", []):
                if step.get("approver_email") == existing["email"]:
                    step["approver_email"] = update["email"]
                    changed = True
            if changed:
                await db.approval_routes.update_one({"tier": route["tier"]}, {"$set": {"chain": route["chain"]}})
    return {"ok": True}


@router.delete("/v1/admin/users/{user_id}")
async def delete_user(user_id: str, user: dict = Depends(require_role("admin"))):
    if user_id == user["id"]:
        raise HTTPException(400, "Cannot delete your own account")
    res = await db.users.delete_one({"id": user_id})
    await db.user_sessions.delete_many({"user_id": user_id})
    await db.active_sessions.update_many({"user_id": user_id, "revoked": {"$ne": True}},
        {"$set": {"revoked": True, "revoked_at": now_iso(), "revoked_reason": "user_deleted"}})
    if res.deleted_count == 0:
        raise HTTPException(404, "User not found")
    return {"ok": True}


@router.get("/v1/admin/users/{user_id}/sessions")
async def list_user_sessions(user_id: str, user: dict = Depends(require_role("admin"))):
    """Admin view of another user's active sessions -- for investigating a suspected
    compromise (see the login_audit / UEBA work) without waiting on the user
    themselves to notice and revoke it from their own end."""
    items = await db.active_sessions.find(
        {"user_id": user_id, "revoked": {"$ne": True}}, {"_id": 0, "jti": 0},
    ).sort("created_at", -1).to_list(200)
    return {"items": items}


@router.post("/v1/admin/users/{user_id}/sessions/revoke-all")
async def revoke_all_user_sessions(user_id: str, user: dict = Depends(require_role("admin"))):
    res = await db.active_sessions.update_many(
        {"user_id": user_id, "revoked": {"$ne": True}},
        {"$set": {"revoked": True, "revoked_at": now_iso(), "revoked_reason": f"admin_revoked_by:{user['email']}"}},
    )
    return {"ok": True, "revoked_count": res.modified_count}


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
    if body.type == "sms" and not body.to:
        raise HTTPException(400, "to (recipient phone/cell number) is required for sms channels")
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
        "url": "{APP_BASE_URL}/findings/demo (example)",
    }
    rec = await deliver(channel, "new_assignment", ctx, db)
    return {"delivered": rec["delivered"], "simulated": rec.get("simulated", False),
            "status_code": rec["status_code"], "response": rec["response"]}


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
async def list_rules_notif(user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/admin/notifications"))):
    items = await db.notification_rules.find({}, {"_id": 0}).to_list(200)
    for r in items:
        if r.get("frequency", "immediate") != "immediate":
            r["queued_count"] = await db.notification_queue.count_documents({"rule_id": r["id"]})
    return {"items": items}


@router.post("/v1/admin/notification-rules/{rule_id}/send-digest-now")
async def send_digest_now(rule_id: str, user: dict = Depends(require_role("admin"))):
    rule = await db.notification_rules.find_one({"id": rule_id}, {"_id": 0})
    if not rule:
        raise HTTPException(404, "Rule not found")
    if rule.get("frequency", "immediate") == "immediate":
        raise HTTPException(400, "This rule is immediate -- nothing is queued for it")
    await db.notification_rules.update_one({"id": rule_id}, {"$set": {"last_digest_sent_at": None}})
    from notifier import run_digest_dispatch
    result = await run_digest_dispatch(db)
    return result


@router.post("/v1/admin/notification-rules")
async def create_rule_notif(body: RuleIn, user: dict = Depends(require_role("admin"))):
    from notifier import TRIGGERS
    if body.trigger not in TRIGGERS:
        raise HTTPException(400, f"trigger must be one of {TRIGGERS}")
    if body.frequency not in ("immediate", "hourly", "daily", "weekly"):
        raise HTTPException(400, "frequency must be one of: immediate, hourly, daily, weekly")
    doc = {**body.model_dump(), "id": str(uuid.uuid4()), "created_at": now_iso(), "last_digest_sent_at": None}
    await db.notification_rules.insert_one(doc)
    return {"id": doc["id"]}


@router.patch("/v1/admin/notification-rules/{rule_id}")
async def update_rule_notif(rule_id: str, body: RuleIn, user: dict = Depends(require_role("admin"))):
    from notifier import TRIGGERS
    if body.trigger not in TRIGGERS:
        raise HTTPException(400, f"trigger must be one of {TRIGGERS}")
    if body.frequency not in ("immediate", "hourly", "daily", "weekly"):
        raise HTTPException(400, "frequency must be one of: immediate, hourly, daily, weekly")
    existing = await db.notification_rules.find_one({"id": rule_id}, {"_id": 0})
    if not existing:
        raise HTTPException(404, "Rule not found")
    update = body.model_dump()
    if update.get("frequency") != existing.get("frequency"):
        # Cadence changed -- reset the digest window so it doesn't immediately fire (or
        # wait a stale amount of time) using the old cadence's clock.
        update["last_digest_sent_at"] = None
    await db.notification_rules.update_one({"id": rule_id}, {"$set": update})
    return {**existing, **update}


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

    @field_validator("value")
    @classmethod
    def _dedupe_value(cls, v: str) -> str:
        """Defense in depth alongside the frontend's MultiValueInput dedupe check --
        collapses case/whitespace-insensitive duplicates in the comma-separated value
        list so a rule created or edited directly via the API (not through the chip
        UI) can't end up with the same value listed twice either."""
        seen = set()
        out = []
        for part in (v or "").split(","):
            part = part.strip()
            if not part:
                continue
            key = part.lower()
            if key in seen:
                continue
            seen.add(key)
            out.append(part)
        return ",".join(out)


@router.get("/v1/admin/assignment-rules/settings")
async def get_assignment_settings(user: dict = Depends(get_current_user)):
    doc = await db.settings.find_one({"id": "assignment_rules"}, {"_id": 0})
    return {"default_team": (doc or {}).get("default_team")}


class AssignmentSettingsBody(BaseModel):
    default_team: Optional[str] = None


@router.put("/v1/admin/assignment-rules/settings")
async def set_assignment_settings(body: AssignmentSettingsBody, user: dict = Depends(require_role("admin"))):
    await db.settings.update_one({"id": "assignment_rules"},
        {"$set": {"id": "assignment_rules", "default_team": body.default_team}}, upsert=True)
    return {"default_team": body.default_team}


# Fields with a small, known set of valid values -- offered as a dropdown of exactly
# those options rather than a free-text field, since typos here (e.g. "crown-jewel" vs
# "crown_jewel") mean the rule silently never matches anything.
# --------------------------- CUSTOMIZABLE PAGE LAYOUTS ---------------------------
# Lets admins reorder the "tile" sections on certain pages (e.g. FindingDetail's
# sidebar) without a code change/redeploy. Unknown page keys just get an empty
# default -- the frontend falls back to its own hardcoded order in that case.
DEFAULT_LAYOUTS = {
    # Must stay in sync with DEFAULT_SIDEBAR_ORDER in frontend/src/pages/FindingDetail.jsx --
    # this is the backend's copy of the same default, served to anyone who hasn't saved a
    # custom order yet. (Missed updating this the first time "playbook"/"mitigations" were
    # added as sidebar sections, which silently dropped them from the page entirely --
    # get_ui_layout's "append missing keys" safety net only helps once this list itself
    # actually lists them.)
    "finding_detail_sidebar": [
        "status", "exception", "comments", "playbook", "mitigations", "risk_score",
        "identifiers", "scoring", "exploits", "asset", "sla", "source", "tickets", "references",
    ],
}


@router.get("/v1/admin/ui-layout/{page}")
async def get_ui_layout(page: str, user: dict = Depends(get_current_user)):
    doc = await db.ui_layout_prefs.find_one({"page": page}, {"_id": 0})
    default = DEFAULT_LAYOUTS.get(page, [])
    order = (doc or {}).get("order") or list(default)
    # If new sections were added to the code after a custom order was saved, append
    # them at the end instead of letting them silently disappear from the page.
    order = order + [k for k in default if k not in order]
    return {"order": order, "default": default, "customized": bool(doc)}


class UiLayoutBody(BaseModel):
    order: List[str]


@router.put("/v1/admin/ui-layout/{page}")
async def set_ui_layout(page: str, body: UiLayoutBody, user: dict = Depends(require_role("admin"))):
    await db.ui_layout_prefs.update_one(
        {"page": page},
        {"$set": {"page": page, "order": body.order, "updated_at": now_iso(), "updated_by": user["email"]}},
        upsert=True,
    )
    return {"ok": True}


@router.delete("/v1/admin/ui-layout/{page}")
async def reset_ui_layout(page: str, user: dict = Depends(require_role("admin"))):
    await db.ui_layout_prefs.delete_one({"page": page})
    return {"ok": True, "default": DEFAULT_LAYOUTS.get(page, [])}


ENUM_FIELD_VALUES = {
    "environment": ["production", "staging", "development", "unknown"],
    "platform": ["aws", "azure", "gcp", "on_prem", "unknown"],
    "criticality": ["crown_jewel", "critical", "high", "medium", "low"],
    "exposure": ["internet", "external", "internal", "unknown"],
}


@router.get("/v1/admin/assignment-rules/field-values")
async def assignment_rule_field_values(field: str, user: dict = Depends(get_current_user)):
    """Values to populate the rule builder's Value dropdown for the selected field --
    a fixed enum for known-shape fields, or the actual distinct values already present
    on your assets for open-ended ones (tags, department, hostname, operating_system).
    cve isn't included -- there's no fixed list to offer, and it's better typed by hand
    or copy-pasted from a finding."""
    if field in ENUM_FIELD_VALUES:
        return {"values": ENUM_FIELD_VALUES[field]}
    if field == "tags":
        tags = await db.assets.distinct("tags")
        return {"values": sorted(t for t in tags if t)}
    if field in ("department", "hostname", "operating_system"):
        vals = await db.assets.distinct(field)
        return {"values": sorted(v for v in vals if v)}
    return {"values": []}


@router.get("/v1/admin/assignment-rules")
async def list_rules(user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/admin/assignment-rules"))):
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


def _rule_values(rule: dict) -> list:
    """A rule's 'value' is a single comma-separated string on the wire (backward
    compatible with rules created before multi-value support existed) -- split it
    into the list of candidate values it should match against, any-of."""
    raw = rule.get("value") or ""
    return [v.strip().lower() for v in raw.split(",") if v.strip()]


def _rule_matches(rule: dict, asset: dict) -> bool:
    f = rule["field"]
    vals = _rule_values(rule)
    if not vals:
        return False
    if f == "tags":
        tags = [str(t).lower() for t in (asset.get("tags") or [])]
        if rule["operator"] == "equals":
            return any(v in tags for v in vals)
        return any(v in t for v in vals for t in tags)
    if f == "cve":
        return False  # CVE rules don't match by asset — handled in apply_rules per-finding
    av = str(asset.get(f) or "").lower()
    if rule["operator"] == "equals":
        return av in vals
    return any(v in av for v in vals)


def _rule_matches_finding(rule: dict, finding: dict) -> bool:
    """Match assignment rule against a finding's CVE/title fields."""
    f = rule["field"]
    vals = _rule_values(rule)
    if not vals:
        return False
    if f == "cve":
        fv = str(finding.get("cve") or "").lower()
    elif f == "title":
        fv = str(finding.get("title") or "").lower()
    elif f == "cwe":
        fv = str(finding.get("cwe") or "").lower()
    else:
        return False
    if rule["operator"] == "equals":
        return fv in vals
    return any(v in fv for v in vals)


@router.post("/v1/admin/assignment-rules/apply")
async def apply_rules(user: dict = Depends(require_role("admin"))):
    rules = await db.assignment_rules.find({"active": True}, {"_id": 0}).sort("priority", 1).to_list(500)
    asset_rules = [r for r in rules if r["field"] not in ("cve", "title", "cwe")]
    finding_rules = [r for r in rules if r["field"] in ("cve", "title", "cwe")]
    assets = await db.assets.find({}, {"_id": 0}).to_list(50000)
    settings_doc = await db.settings.find_one({"id": "assignment_rules"}, {"_id": 0})
    default_team = (settings_doc or {}).get("default_team")
    updated_assets = 0
    updated_findings = 0
    defaulted = 0
    still_unassigned = 0
    for asset in assets:
        matched_rule = next((r for r in asset_rules if _rule_matches(r, asset)), None)
        if matched_rule:
            new_team = matched_rule["assign_team"]
            rationale = f"Matched rule '{matched_rule['name']}': {matched_rule['field']} {matched_rule['operator']} '{matched_rule['value']}'"
            confidence = 0.95
        else:
            existing = asset.get("owner_team")
            has_real_owner = existing and existing != "Unassigned"
            if has_real_owner:
                new_team = existing
                rationale = "No assignment rule matched — preserved existing owner"
                confidence = 0.3
            elif default_team:
                new_team = default_team
                rationale = f"No assignment rule matched — fell back to default team '{default_team}'"
                confidence = 0.5
                defaulted += 1
            else:
                new_team = existing or "Unassigned"
                rationale = "No assignment rule matched and no default team is configured"
                confidence = 0.3
                still_unassigned += 1
        await db.assets.update_one({"id": asset["id"]}, {"$set": {
            "owner_team": new_team, "ownership_rationale": rationale, "ownership_confidence": confidence,
        }})
        updated_assets += 1
        r = await db.findings.update_many(
            {"asset_id": asset["id"], "status": {"$nin": ["Fixed validated", "Closed administratively"]}},
            {"$set": {"owner_team": new_team, "ownership_confidence": confidence, "ownership_rationale": rationale}},
        )
        updated_findings += r.modified_count
    # CVE / title / CWE rules — re-route the matched findings
    if finding_rules:
        async for fdoc in db.findings.find({"status": {"$nin": ["Fixed validated", "Closed administratively"]}},
                                            {"_id": 0, "id": 1, "cve": 1, "title": 1, "cwe": 1}):
            matched = next((r for r in finding_rules if _rule_matches_finding(r, fdoc)), None)
            if matched:
                await db.findings.update_one({"id": fdoc["id"]}, {"$set": {
                    "owner_team": matched["assign_team"],
                    "ownership_confidence": 0.95,
                    "ownership_rationale": f"Matched CVE/title rule '{matched['name']}'",
                }})
                updated_findings += 1
    return {"updated_assets": updated_assets, "updated_findings": updated_findings, "rules_evaluated": len(rules),
            "defaulted_to_fallback": defaulted, "still_unassigned": still_unassigned}


STALE_OWNERSHIP_DAYS = 90


@router.get("/v1/ownership-mappings")
async def ownership_mappings(user: dict = Depends(get_current_user), q: Optional[str] = None,
                              stale_only: bool = False, low_confidence_only: bool = False,
                              _rbac: dict = Depends(require_module("/admin/ownership"))):
    flt = {}
    if q:
        flt["$or"] = [{"hostname": {"$regex": q, "$options": "i"}}, {"owner_team": {"$regex": q, "$options": "i"}}]
    items = await db.assets.find(flt, {"_id": 0, "id": 1, "hostname": 1, "owner_team": 1,
                                       "ownership_confidence": 1, "ownership_rationale": 1, "tags": 1,
                                       "ownership_confirmed_at": 1,
                                       "environment": 1, "platform": 1, "criticality": 1, "exposure": 1}).to_list(1000)
    cutoff = (datetime.now(timezone.utc) - timedelta(days=STALE_OWNERSHIP_DAYS)).isoformat()
    for a in items:
        confirmed = a.get("ownership_confirmed_at")
        a["stale"] = (not confirmed) or (confirmed < cutoff)
    if stale_only:
        items = [a for a in items if a["stale"]]
    if low_confidence_only:
        items = [a for a in items if (a.get("ownership_confidence") or 0) < 0.7]
    return {"items": items, "stale_threshold_days": STALE_OWNERSHIP_DAYS}


class ReassignOwnerBody(BaseModel):
    owner_team: str


@router.post("/v1/assets/{asset_id}/reassign-owner")
async def reassign_owner(asset_id: str, body: ReassignOwnerBody, user: dict = Depends(require_role("admin", "manager")),
                          _rbac: dict = Depends(require_module("/admin/ownership", level="edit"))):
    """Directly set an asset's owner team from the Ownership Mappings page, instead of
    only being able to Confirm whatever a rule already inferred. Counts as a
    confirmation too -- resets confidence/staleness the same way confirm-ownership does."""
    asset = await db.assets.find_one({"id": asset_id}, {"_id": 0})
    if not asset:
        raise HTTPException(404, "Asset not found")
    if not body.owner_team.strip():
        raise HTTPException(400, "owner_team is required")
    now = now_iso()
    update = {
        "owner_team": body.owner_team.strip(), "ownership_confidence": 1.0, "ownership_confirmed_at": now,
        "ownership_rationale": f"Manually assigned to {body.owner_team.strip()} by {user['email']}",
    }
    await db.assets.update_one({"id": asset_id}, {"$set": update})
    await db.findings.update_many(
        {"asset_id": asset_id, "status": {"$nin": ["Fixed validated", "Closed administratively"]}},
        {"$set": {"owner_team": update["owner_team"], "ownership_confidence": 1.0, "ownership_confirmed_at": now}},
    )
    await db.activity_log.insert_one({
        "id": str(uuid.uuid4()), "entity_type": "asset", "entity_id": asset_id,
        "action": "owner_reassigned", "actor": user["email"], "timestamp": now,
        "details": f"Owner team manually set to {update['owner_team']}",
    })
    return {**asset, **update}


@router.post("/v1/assets/{asset_id}/confirm-ownership")
async def confirm_ownership(asset_id: str, user: dict = Depends(require_role("admin", "manager")),
                             _rbac: dict = Depends(require_module("/admin/ownership", level="edit"))):
    """A human looked at this asset's owner team and confirmed it's correct -- resets the
    staleness clock even if the team assignment itself doesn't change."""
    asset = await db.assets.find_one({"id": asset_id}, {"_id": 0})
    if not asset:
        raise HTTPException(404, "Asset not found")
    now = now_iso()
    update = {"ownership_confidence": 1.0, "ownership_confirmed_at": now,
              "ownership_rationale": f"Manually confirmed by {user['email']}"}
    await db.assets.update_one({"id": asset_id}, {"$set": update})
    await db.findings.update_many(
        {"asset_id": asset_id, "status": {"$nin": ["Fixed validated", "Closed administratively"]}},
        {"$set": {"ownership_confidence": 1.0, "ownership_confirmed_at": now}},
    )
    return {**asset, **update}


@router.get("/v1/admin/sla-policies")
async def get_sla_policies(user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/admin/sla-policies"))):
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


class ApiKeyCreateBody(BaseModel):
    name: str = "Ingestion Key"


@router.get("/v1/admin/api-keys")
async def list_api_keys(user: dict = Depends(require_role("admin"))):
    items = await db.api_keys.find({}, {"_id": 0}).to_list(100)
    # Flag any key still carrying the old hardcoded/publicly-known demo value from an
    # earlier seed version, so the UI can nudge you to rotate it.
    for k in items:
        k["is_known_demo_value"] = k.get("key") == "vulnops_ingest_demo_key_2026"
    return {"items": items}


@router.post("/v1/admin/api-keys")
async def create_api_key(body: ApiKeyCreateBody, user: dict = Depends(require_role("admin"))):
    import secrets
    doc = {
        "id": str(uuid.uuid4()), "key": f"vulnops_{secrets.token_urlsafe(32)}",
        "name": body.name, "active": True, "created_at": now_iso(), "last_used_at": None,
    }
    await db.api_keys.insert_one(doc)
    return _clean(doc)


@router.post("/v1/admin/api-keys/{key_id}/regenerate")
async def regenerate_api_key(key_id: str, user: dict = Depends(require_role("admin"))):
    import secrets
    existing = await db.api_keys.find_one({"id": key_id}, {"_id": 0})
    if not existing:
        raise HTTPException(404, "API key not found")
    new_key = f"vulnops_{secrets.token_urlsafe(32)}"
    await db.api_keys.update_one({"id": key_id}, {"$set": {"key": new_key, "rotated_at": now_iso()}})
    return {**existing, "key": new_key}


@router.put("/v1/admin/api-keys/{key_id}")
async def toggle_api_key(key_id: str, active: bool, user: dict = Depends(require_role("admin"))):
    await db.api_keys.update_one({"id": key_id}, {"$set": {"active": active}})
    return {"ok": True}


@router.delete("/v1/admin/api-keys/{key_id}")
async def delete_api_key(key_id: str, user: dict = Depends(require_role("admin"))):
    await db.api_keys.delete_one({"id": key_id})
    return {"ok": True}


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
@router.get("/v1/admin/qualys/scope")
async def qualys_scope(user: dict = Depends(require_role("admin"))):
    """Return the API user's effective Qualys scope (role + visible host count)
    so the UI can warn when permissions are too narrow."""
    import httpx
    import re
    import xml.etree.ElementTree as ET
    integration = await db.integrations.find_one({"name": "Qualys VMDR"}, {"_id": 0})
    cfg = (integration or {}).get("config") or {}
    if not (cfg.get("endpoint") and cfg.get("username") and cfg.get("api_key")):
        return {"configured": False}
    try:
        async with httpx.AsyncClient(timeout=30, auth=(cfg["username"], cfg["api_key"])) as c:
            # Visible hosts
            r1 = await c.post(f"{cfg['endpoint'].rstrip('/')}/api/2.0/fo/asset/host/",
                              params={"action": "list", "truncation_limit": 1},
                              headers={"X-Requested-With": "VulnOps"})
            root = ET.fromstring(r1.content)
            total_el = root.find(".//{*}TOTAL") or root.find(".//TOTAL")
            host_count = int(total_el.text) if total_el is not None and total_el.text else None
            if host_count is None:
                # Fallback — count returned hosts on a wider pull
                r1b = await c.post(f"{cfg['endpoint'].rstrip('/')}/api/2.0/fo/asset/host/",
                                   params={"action": "list", "truncation_limit": 5000},
                                   headers={"X-Requested-With": "VulnOps"})
                host_count = len(list(ET.fromstring(r1b.content).iter("HOST")))

            # Role via msp/user_list
            role = None
            try:
                r2 = await c.post(f"{cfg['endpoint'].rstrip('/')}/msp/user_list.php",
                                  headers={"X-Requested-With": "VulnOps"})
                m = re.search(rf"<USER_LOGIN>{re.escape(cfg['username'])}</USER_LOGIN>(.*?)</USER>", r2.text, re.DOTALL)
                if m:
                    role_m = re.search(r"<USER_ROLE>([^<]+)</USER_ROLE>", m.group(1))
                    role = role_m.group(1) if role_m else None
            except Exception:
                pass
        return {
            "configured": True,
            "username": cfg["username"],
            "endpoint": cfg["endpoint"],
            "role": role,
            "host_count": host_count,
            "is_narrow": (role in ("Reader", "Scanner")) or (host_count is not None and host_count < 100),
        }
    except Exception as e:
        return {"configured": True, "error": str(e)}


@router.post("/v1/admin/qualys/sync/run")
async def trigger_qualys_sync(user: dict = Depends(require_role("admin"))):
    """Kick off a Qualys VMDR sync in the background and return immediately.
    The browser polls GET /v1/admin/qualys/sync/runs for completion."""
    from qualys_sync import run_qualys_sync
    import asyncio
    import uuid as _uuid
    existing = await db.qualys_sync_runs.find_one({"status": "running"}, {"_id": 0})
    if existing:
        return {"id": existing["id"], "status": "running", "message": "Sync already in progress"}

    job_id = str(_uuid.uuid4())
    await db.qualys_sync_runs.insert_one({
        "id": job_id, "status": "running", "ran_at": now_iso(),
        "summary": {"detections": 0, "created": 0, "updated": 0, "deduped": 0, "failed": 0},
        "errors": [],
    })

    async def _runner():
        try:
            result = await run_qualys_sync(db)
            # `run_qualys_sync` writes its own record; remove the placeholder
            await db.qualys_sync_runs.delete_one({"id": job_id})
            return result
        except Exception as e:
            await db.qualys_sync_runs.update_one(
                {"id": job_id},
                {"$set": {"status": "failed", "errors": [{"stage": "runner", "error": str(e)}]}},
            )

    asyncio.create_task(_runner())
    return {"id": job_id, "status": "running", "message": "Sync started — poll /v1/admin/qualys/sync/runs"}


@router.get("/v1/admin/qualys/sync/runs")
async def list_qualys_runs(user: dict = Depends(require_role("admin"))):
    items = await db.qualys_sync_runs.find({}, {"_id": 0}).sort("ran_at", -1).limit(50).to_list(50)
    return {"items": items}


@router.post("/v1/admin/tenable/sync/run")
async def trigger_tenable_sync(user: dict = Depends(require_role("admin"))):
    """Kick off a Tenable Nessus sync in the background and return immediately.
    The browser polls GET /v1/admin/tenable/sync/runs for completion. Mirrors
    /v1/admin/qualys/sync/run's async-job-with-placeholder-row pattern exactly."""
    from tenable_sync import run_tenable_sync
    import asyncio
    import uuid as _uuid
    existing = await db.tenable_sync_runs.find_one({"status": "running"}, {"_id": 0})
    if existing:
        return {"id": existing["id"], "status": "running", "message": "Sync already in progress"}

    job_id = str(_uuid.uuid4())
    await db.tenable_sync_runs.insert_one({
        "id": job_id, "status": "running", "ran_at": now_iso(),
        "summary": {"scans_found": 0, "created": 0, "updated": 0, "deduped": 0, "failed": 0},
        "errors": [],
    })

    async def _runner():
        try:
            result = await run_tenable_sync(db)
            # run_tenable_sync writes its own record; remove the placeholder
            await db.tenable_sync_runs.delete_one({"id": job_id})
            return result
        except Exception as e:
            await db.tenable_sync_runs.update_one(
                {"id": job_id},
                {"$set": {"status": "failed", "errors": [{"stage": "runner", "error": str(e)}]}},
            )

    asyncio.create_task(_runner())
    return {"id": job_id, "status": "running", "message": "Sync started — poll /v1/admin/tenable/sync/runs"}


@router.get("/v1/admin/tenable/sync/runs")
async def list_tenable_runs(user: dict = Depends(require_role("admin"))):
    items = await db.tenable_sync_runs.find({}, {"_id": 0}).sort("ran_at", -1).limit(50).to_list(50)
    return {"items": items}


@router.post("/v1/admin/qualys/sync/tags")
async def qualys_sync_tags(user: dict = Depends(require_role("admin"))):
    """Lightweight: re-pull only the Qualys asset-tag memberships and stamp `tags`
    on each asset + propagate to open findings. Use this when the full sync was
    fine but tag changes need to be reflected without re-importing detections."""
    from qualys_sync import _sync_qualys_asset_tags
    integration = await db.integrations.find_one({"name": "Qualys VMDR"}, {"_id": 0})
    if not integration:
        raise HTTPException(404, "Qualys VMDR integration not found")
    cfg = integration.get("config") or {}
    if not (cfg.get("endpoint") and cfg.get("username") and cfg.get("api_key")):
        raise HTTPException(400, "Qualys integration missing endpoint/username/api_key")
    return await _sync_qualys_asset_tags(cfg["endpoint"], cfg["username"], cfg["api_key"], db)


# --------------------------- ENRICHERS (KEV, EPSS) ---------------------------
@router.post("/v1/admin/enrich/kev")
async def trigger_kev(user: dict = Depends(require_role("admin"))):
    from enrichers import sync_kev
    return await sync_kev(db)


@router.post("/v1/admin/enrich/epss")
async def trigger_epss(user: dict = Depends(require_role("admin"))):
    from enrichers import sync_epss
    return await sync_epss(db)


@router.post("/v1/admin/enrich/exploitdb")
async def trigger_exploitdb(user: dict = Depends(require_role("admin"))):
    from enrichers import sync_exploitdb
    return await sync_exploitdb(db)


@router.post("/v1/admin/enrich/security-news")
async def trigger_security_news(user: dict = Depends(require_role("admin"))):
    from security_news import sync_security_news
    return await sync_security_news(db)


@router.get("/v1/admin/security-news/status")
async def security_news_status(user: dict = Depends(require_role("admin"))):
    total = await db.security_news_articles.count_documents({})
    latest = await db.security_news_articles.find_one({}, {"_id": 0, "synced_at": 1}, sort=[("synced_at", -1)])
    return {"articles_cached": total, "last_synced_at": (latest or {}).get("synced_at")}


@router.post("/v1/admin/enrich/hash-intel-backlog")
async def trigger_hash_intel_backlog(user: dict = Depends(require_role("admin"))):
    from hash_intel import auto_check_hash_backlog
    return await auto_check_hash_backlog(db)


@router.get("/v1/admin/hash-intel/status")
async def hash_intel_status(user: dict = Depends(require_role("admin"))):
    total_checked = await db.hash_intel_checks.count_documents({})
    malicious = await db.hash_intel_checks.count_documents({"status": "malicious"})
    latest = await db.hash_intel_checks.find_one({}, {"_id": 0, "checked_at": 1}, sort=[("checked_at", -1)])
    return {"hashes_checked": total_checked, "malicious_hits": malicious,
            "last_checked_at": (latest or {}).get("checked_at")}


@router.get("/v1/admin/exploitdb/status")
async def exploitdb_status(user: dict = Depends(require_role("admin"))):
    catalog_size = await db.exploitdb_catalog.count_documents({})
    with_exploits = await db.findings.count_documents({"exploit_references": {"$exists": True, "$ne": []}})
    latest = await db.exploitdb_catalog.find_one({}, {"_id": 0, "synced_at": 1}, sort=[("synced_at", -1)])
    return {"catalog_cves": catalog_size, "findings_with_exploits": with_exploits,
            "last_synced_at": (latest or {}).get("synced_at")}


@router.get("/v1/admin/threat-intel/status")
async def threat_intel_status(user: dict = Depends(require_role("admin"))):
    """Rolls up KEV / EPSS / Exploit-DB feed health in one place -- these are always-on
    enrichers (no per-integration config, no credentials) that previously had zero
    visibility in the UI: they only ran silently every 12h via threat_intel_loop, or
    when an admin happened to know the /v1/admin/enrich/* endpoints existed."""
    heartbeat = await db.loop_heartbeats.find_one({"name": "threat_intel_loop"}, {"_id": 0})
    detail = (heartbeat or {}).get("detail") or {}
    kev_count = await db.findings.count_documents({"kev_flag": True})
    epss_count = await db.findings.count_documents({"epss_score": {"$gt": 0}})
    exploitdb_catalog = await db.exploitdb_catalog.count_documents({})
    exploitdb_findings = await db.findings.count_documents({"exploit_references": {"$exists": True, "$ne": []}})
    return {
        "last_run_at": (heartbeat or {}).get("last_run_at"),
        "last_run_status": (heartbeat or {}).get("status"),
        "kev": {"findings_flagged": kev_count, "catalog_size": (detail.get("kev") or {}).get("catalog_size"),
                "last_result": detail.get("kev"), "error": detail.get("kev_error")},
        "epss": {"findings_scored": epss_count, "last_result": detail.get("epss"), "error": detail.get("epss_error")},
        "exploitdb": {"catalog_cves": exploitdb_catalog, "findings_with_exploits": exploitdb_findings,
                       "last_result": detail.get("exploitdb"), "error": detail.get("exploitdb_error")},
    }


# --------------------------- CISA WEB SCAN UPLOAD ---------------------------
from fastapi import UploadFile, File, Form


@router.post("/v1/admin/web-scans/upload")
async def upload_web_scans(
    file: UploadFile = File(...),
    label: str = Form("CISA Web Scan"),
    user: dict = Depends(require_role("admin")),
):
    """Upload a CISA Web Scan XLSX. Returns counts (created/updated/web_apps)."""
    from cisa_scans import import_cisa_scans_xlsx
    from routes.common import record_engagement, now_iso
    if not file.filename or not file.filename.lower().endswith(".xlsx"):
        raise HTTPException(400, "File must be .xlsx")
    content = await file.read()
    started = now_iso()
    try:
        result = await import_cisa_scans_xlsx(db, content, source_label=label)
        await record_engagement(
            db, name=label or file.filename, scanner="CISA Web Scan", scan_type="manual_upload",
            scan_method="file_upload", status="completed",
            assets_scanned=result.get("web_apps", 0), findings_created=result.get("created", 0),
            findings_updated=result.get("updated", 0), started_at=started,
        )
        return result
    except Exception as e:
        await record_engagement(db, name=label or file.filename, scanner="CISA Web Scan",
                                 scan_type="manual_upload", scan_method="file_upload", status="failed",
                                 started_at=started, error=str(e))
        raise HTTPException(400, f"Failed to parse XLSX: {e}")


# --------------------------- NMAP SCAN UPLOAD ---------------------------
@router.post("/v1/admin/nmap/upload")
async def upload_nmap_scan(
    file: UploadFile = File(...),
    vantage: str = Form("internal"),
    label: str = Form(""),
    user: dict = Depends(require_role("admin")),
):
    """Upload an `nmap -oX` XML file. vantage='external' means the scan was run from
    outside your network (so open ports found = real internet reachability); vantage=
    'internal' means it was run from inside (used for port/service enrichment only,
    no exposure-verification claims)."""
    from nmap_scan import import_nmap_xml
    from routes.common import record_engagement, now_iso
    if not file.filename or not file.filename.lower().endswith(".xml"):
        raise HTTPException(400, "File must be .xml (nmap -oX output)")
    content = await file.read()
    started = now_iso()
    try:
        result = await import_nmap_xml(db, content, vantage=vantage, source_label=label or None)
        await record_engagement(
            db, name=label or file.filename, scanner="Nmap", scan_type="manual_upload",
            scan_method="file_upload", status="completed",
            assets_scanned=result.get("hosts_parsed", 0), findings_created=result.get("findings_created", 0),
            findings_updated=result.get("assets_touched", 0), started_at=started,
        )
        return result
    except ValueError as e:
        await record_engagement(db, name=label or file.filename, scanner="Nmap", scan_type="manual_upload",
                                 scan_method="file_upload", status="failed", started_at=started, error=str(e))
        raise HTTPException(400, str(e))
    except Exception as e:
        await record_engagement(db, name=label or file.filename, scanner="Nmap", scan_type="manual_upload",
                                 scan_method="file_upload", status="failed", started_at=started, error=str(e))
        raise HTTPException(400, f"Failed to parse Nmap XML: {e}")


# --------------------------- OWNERSHIP RULES PREVIEW ---------------------------
@router.post("/v1/admin/assignment-rules/preview")
async def preview_rules(user: dict = Depends(get_current_user)):
    """Show what apply_rules would do WITHOUT modifying anything."""
    rules = await db.assignment_rules.find({"active": True}, {"_id": 0}).sort("priority", 1).to_list(500)
    assets = await db.assets.find({}, {"_id": 0}).to_list(5000)
    settings_doc = await db.settings.find_one({"id": "assignment_rules"}, {"_id": 0})
    default_team = (settings_doc or {}).get("default_team")
    preview: dict = {}  # rule_name → {team, count, sample_hosts}
    no_match_count = 0
    for asset in assets:
        matched = next((r for r in rules if _rule_matches(r, asset)), None)
        if matched:
            key = f"{matched['name']} → {matched['assign_team']}"
            entry = preview.setdefault(key, {"rule_name": matched["name"], "team": matched["assign_team"],
                                              "field": matched["field"], "value": matched["value"],
                                              "count": 0, "sample_hosts": []})
            entry["count"] += 1
            if len(entry["sample_hosts"]) < 5:
                entry["sample_hosts"].append(asset.get("hostname"))
        else:
            no_match_count += 1
    return {"groups": list(preview.values()), "no_match_assets": no_match_count, "total_assets": len(assets),
            "default_team": default_team,
            "will_still_be_unassigned": 0 if default_team else no_match_count}


# --------------------------- BULK ASSIGN OWNER TEAM (FINDINGS) ---------------------------
# NOTE: a duplicate of this endpoint used to live here (dead code -- findings.py's
# version registers first in server.py and was the one actually serving requests).
# Removed; see routes/findings.py:bulk_owner for the live implementation, which is
# role-gated to admin/manager and writes an activity_log entry, unlike this old copy.


@router.post("/v1/admin/wipe-demo-data")
async def wipe_demo(user: dict = Depends(require_role("admin"))):
    """Delete every operational data collection (findings, assets, products, tickets, etc.).
    Keeps users, integrations config, notification channels, assignment rules, API keys."""
    from seed import wipe_demo_data
    return {"deleted": await wipe_demo_data(db)}



# --------------------------- TEAMS ---------------------------
class TeamIn(BaseModel):
    name: str
    color: Optional[str] = "#3b82f6"
    description: Optional[str] = None
    members: Optional[list[str]] = None  # user ids


@router.get("/v1/admin/teams")
async def list_teams(user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/admin/teams"))):
    """List teams. Includes user count + member emails for convenience."""
    teams = await db.teams.find({}, {"_id": 0}).sort("name", 1).to_list(500)
    # Hydrate members → user summaries
    all_user_ids = list({m for t in teams for m in (t.get("members") or [])})
    users = {u["id"]: u for u in await db.users.find(
        {"id": {"$in": all_user_ids}}, {"_id": 0, "id": 1, "email": 1, "name": 1, "role": 1}
    ).to_list(len(all_user_ids))} if all_user_ids else {}
    for t in teams:
        t["member_count"] = len(t.get("members") or [])
        t["member_users"] = [users[uid] for uid in (t.get("members") or []) if uid in users]
    # Also include implicit teams that exist on users/assets/findings but not in
    # the formal teams collection yet — gives admins a way to see/adopt them.
    implicit = set()
    for src in (await db.users.distinct("team"),
                await db.assets.distinct("owner_team"),
                await db.findings.distinct("owner_team")):
        implicit.update([s for s in src if s])
    known = {t["name"] for t in teams}
    for name in sorted(implicit):
        if name and name != "Unassigned" and name not in known:
            teams.append({"id": None, "name": name, "color": "#64748b",
                          "implicit": True, "member_count": 0, "member_users": []})
    return {"items": teams}


@router.post("/v1/admin/teams")
async def create_team(body: TeamIn, user: dict = Depends(require_role("admin", "manager")),
                      _rbac: dict = Depends(require_module("/admin/teams", level="edit"))):
    name = body.name.strip()
    if not name:
        raise HTTPException(400, "Name required")
    if await db.teams.find_one({"name": name}):
        raise HTTPException(409, "Team already exists")
    doc = {
        "id": str(uuid.uuid4()), "name": name,
        "color": body.color or "#3b82f6",
        "description": body.description, "members": body.members or [],
        "created_at": now_iso(), "created_by": user.get("email"),
    }
    await db.teams.insert_one(doc)
    # Sync both the legacy singular `team` field and the canonical `teams` array
    # for assigned members -- a user can belong to more than one team, so this adds
    # to their teams list ($addToSet, not an overwrite) rather than replacing it.
    if body.members:
        await db.users.update_many({"id": {"$in": body.members}},
                                    {"$set": {"team": name}, "$addToSet": {"teams": name}})
    return _clean(doc)


@router.patch("/v1/admin/teams/{team_id}")
async def update_team(team_id: str, body: TeamIn, user: dict = Depends(require_role("admin", "manager")),
                      _rbac: dict = Depends(require_module("/admin/teams", level="edit"))):
    cur = await db.teams.find_one({"id": team_id}, {"_id": 0})
    if not cur:
        raise HTTPException(404, "Team not found")
    update = {k: v for k, v in body.model_dump(exclude_none=True).items()}
    if "name" in update and update["name"] != cur["name"]:
        # Rename → propagate to users + assets + findings
        old, new = cur["name"], update["name"]
        await db.users.update_many({"team": old}, {"$set": {"team": new}})
        await db.assets.update_many({"owner_team": old}, {"$set": {"owner_team": new}})
        await db.findings.update_many({"owner_team": old}, {"$set": {"owner_team": new}})
        # Also rename this team's entry inside every affected user's `teams` array.
        # Done as a per-user read/replace rather than a single array-filter update
        # so this works the same against mongomock in tests as it does against real
        # MongoDB (array-filter operator support varies across drivers/versions).
        async for u in db.users.find({"teams": old}, {"_id": 0, "id": 1, "teams": 1}):
            new_teams = [new if t == old else t for t in (u.get("teams") or [])]
            await db.users.update_one({"id": u["id"]}, {"$set": {"teams": new_teams}})
    if "members" in update:
        old_members = set(cur.get("members") or [])
        new_members = set(update["members"])
        # Clear team on removed users (only if their team still matches this team's old name)
        removed = old_members - new_members
        team_name_for_removal = update.get("name", cur["name"])
        if removed:
            await db.users.update_many({"id": {"$in": list(removed)}, "team": cur["name"]}, {"$set": {"team": None}})
            await db.users.update_many({"id": {"$in": list(removed)}}, {"$pull": {"teams": team_name_for_removal}})
        added = new_members - old_members
        if added:
            await db.users.update_many({"id": {"$in": list(added)}}, {"$set": {"team": team_name_for_removal},
                                                                        "$addToSet": {"teams": team_name_for_removal}})
    await db.teams.update_one({"id": team_id}, {"$set": update})
    return {"ok": True}


@router.delete("/v1/admin/teams/{team_id}")
async def delete_team(team_id: str, user: dict = Depends(require_role("admin"))):
    t = await db.teams.find_one({"id": team_id}, {"_id": 0})
    if not t:
        raise HTTPException(404, "Team not found")
    # Detach users — keep findings/assets but mark owner_team as 'Unassigned'
    await db.users.update_many({"team": t["name"]}, {"$set": {"team": None}})
    await db.users.update_many({"teams": t["name"]}, {"$pull": {"teams": t["name"]}})
    await db.teams.delete_one({"id": team_id})
    return {"ok": True}


# --------------------------- IMPLICIT TEAMS (rename / clear) ---------------------------
# "Implicit" teams (see list_teams above) are just a distinct owner_team/team string
# that shows up on users/assets/findings without ever having a real teams collection
# document -- e.g. legacy data, or a value a connector wrote in before Teams existed
# as a formal concept. There's no team_id to PATCH/DELETE against, so renaming or
# clearing one previously required editing every asset/finding by hand. This does the
# same bulk find/replace update_team already does for a real team's rename, just keyed
# by name instead of id, and lets an implicit team be either renamed to something else
# (optionally promoting it to a real team at the same time) or cleared to "Unassigned".
class ImplicitTeamRenameIn(BaseModel):
    old_name: str
    new_name: Optional[str] = None  # blank/omitted => clear to "Unassigned"
    create_team: Optional[bool] = False  # also create a formal Team doc for new_name


@router.post("/v1/admin/teams/implicit/rename")
async def rename_implicit_team(body: ImplicitTeamRenameIn, user: dict = Depends(require_role("admin", "manager")),
                               _rbac: dict = Depends(require_module("/admin/teams", level="edit"))):
    old = (body.old_name or "").strip()
    if not old:
        raise HTTPException(400, "old_name is required")
    if await db.teams.find_one({"name": old}):
        raise HTTPException(400, f"'{old}' is a formally-defined team — use its own Edit/Delete actions instead.")
    new = (body.new_name or "").strip() or "Unassigned"
    if new != "Unassigned" and await db.teams.find_one({"name": new}):
        raise HTTPException(409, f"A formal team named '{new}' already exists — rename to that exact name to merge into it, or pick a different name.")

    user_new = None if new == "Unassigned" else new
    u_res = await db.users.update_many({"team": old}, {"$set": {"team": user_new}})
    a_res = await db.assets.update_many({"owner_team": old}, {"$set": {"owner_team": new}})
    f_res = await db.findings.update_many({"owner_team": old}, {"$set": {"owner_team": new}})
    async for u in db.users.find({"teams": old}, {"_id": 0, "id": 1, "teams": 1}):
        if new == "Unassigned":
            new_teams = [t for t in (u.get("teams") or []) if t != old]
        else:
            new_teams = [new if t == old else t for t in (u.get("teams") or [])]
        await db.users.update_one({"id": u["id"]}, {"$set": {"teams": new_teams}})

    if new != "Unassigned" and body.create_team:
        await db.teams.insert_one({
            "id": str(uuid.uuid4()), "name": new, "color": "#64748b",
            "description": f"Promoted from implicit team '{old}'.", "members": [],
            "created_at": now_iso(), "created_by": user.get("email"),
        })

    return {"ok": True, "new_name": new, "users_updated": u_res.modified_count,
            "assets_updated": a_res.modified_count, "findings_updated": f_res.modified_count}


# --------------------------- INTEGRATION CONFIG PATCH ---------------------------
class IntegrationConfigPatch(BaseModel):
    config: dict


@router.patch("/v1/admin/integrations/{integration_id}/config")
async def patch_integration_config(integration_id: str, body: IntegrationConfigPatch,
                                   user: dict = Depends(require_role("admin"))):
    """Shallow-merge config into the integration. Used by the Integrations UI to
    safely store secrets without overwriting other config keys."""
    cur = await db.integrations.find_one({"id": integration_id}, {"_id": 0})
    if not cur:
        raise HTTPException(404, "Integration not found")
    merged = {**(cur.get("config") or {}), **(body.config or {})}
    await db.integrations.update_one({"id": integration_id}, {"$set": {"config": merged}})
    return {"ok": True}
