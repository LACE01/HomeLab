"""Automation — a condition-based rules engine for findings, evaluated on a schedule
(nightly, alongside rescoring/exception-expiry) plus on-demand via "Run now". Each rule
is: a trigger label (for the UI's mental model — what kind of moment this rule is meant
to react to), a set of AND-ed conditions matched against a finding's fields, and a list
of actions applied to every match.

Idempotency: each finding tracks which rule IDs have already fired on it
(`automation_applied: [rule_id, ...]`), so re-running a rule (nightly or manually) only
acts on findings it hasn't already touched -- otherwise every sweep would re-tag,
re-notify, and re-assign the same findings forever.
"""
import uuid
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from db import db
from auth_utils import get_current_user, require_role
from routes.common import now_iso, _clean, finding_ctx

router = APIRouter()

OPEN_STATES = ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]

TRIGGER_LABELS = [
    {"id": "new_finding", "label": "New finding ingested"},
    {"id": "kev_flagged", "label": "Finding flagged as KEV"},
    {"id": "severity_critical", "label": "Severity is Critical"},
    {"id": "overdue", "label": "Finding goes overdue"},
    {"id": "reopened", "label": "Finding reopened"},
    {"id": "scheduled_sweep", "label": "Scheduled sweep (any match)"},
]

CONDITION_FIELDS = [
    {"field": "severity", "label": "Severity", "type": "enum", "values": ["Critical", "High", "Medium", "Low", "Info"]},
    {"field": "status", "label": "Status", "type": "enum", "values": OPEN_STATES},
    {"field": "kev_flag", "label": "KEV (exploited)", "type": "bool"},
    {"field": "internet_facing", "label": "Internet-facing", "type": "bool"},
    {"field": "owner_team", "label": "Owner team", "type": "text"},
    {"field": "product_name", "label": "Product", "type": "text"},
    {"field": "asset_environment", "label": "Environment", "type": "text"},
    {"field": "asset_criticality", "label": "Asset criticality", "type": "enum", "values": ["crown_jewel", "critical", "high", "medium", "low"]},
    {"field": "cwe", "label": "CWE", "type": "text"},
    {"field": "cve", "label": "CVE", "type": "text"},
    {"field": "min_risk_score", "label": "Risk score ≥", "type": "number"},
    {"field": "min_epss", "label": "EPSS ≥", "type": "number"},
    {"field": "assigned_to", "label": "Currently unassigned", "type": "unassigned"},
]

ACTION_TYPES = [
    {"type": "assign_team", "label": "Assign to team", "params": ["team"]},
    {"type": "add_tag", "label": "Add tag", "params": ["tag"]},
    {"type": "set_status", "label": "Set status", "params": ["status"]},
    {"type": "notify", "label": "Send notification", "params": ["channel_id"]},
    {"type": "log_note", "label": "Add activity log note", "params": ["note"]},
]


class RuleBody(BaseModel):
    name: str
    description: Optional[str] = ""
    trigger: str = "scheduled_sweep"
    enabled: bool = True
    conditions: dict = {}   # {severity: "Critical", kev_flag: true, min_risk_score: 70, ...}
    actions: List[dict] = []  # [{"type": "assign_team", "team": "AppSec"}, ...]


def _build_query(conditions: dict) -> dict:
    q: dict = {"status": {"$in": OPEN_STATES}}
    if conditions.get("severity"):
        q["severity"] = conditions["severity"]
    if conditions.get("status"):
        q["status"] = conditions["status"]
    if conditions.get("kev_flag") is not None:
        q["kev_flag"] = bool(conditions["kev_flag"])
    if conditions.get("internet_facing") is not None:
        q["internet_facing"] = bool(conditions["internet_facing"])
    if conditions.get("owner_team"):
        q["owner_team"] = conditions["owner_team"]
    if conditions.get("product_name"):
        q["product_name"] = conditions["product_name"]
    if conditions.get("asset_environment"):
        q["asset_environment"] = conditions["asset_environment"]
    if conditions.get("asset_criticality"):
        q["asset_criticality"] = conditions["asset_criticality"]
    if conditions.get("cwe"):
        q["cwe"] = conditions["cwe"]
    if conditions.get("cve"):
        q["cve"] = conditions["cve"]
    if conditions.get("min_risk_score") is not None:
        q["risk_score"] = {"$gte": conditions["min_risk_score"]}
    if conditions.get("min_epss") is not None:
        q["epss_score"] = {"$gte": conditions["min_epss"]}
    if conditions.get("assigned_to") == "unassigned":
        q["owner_team"] = None
    return q


async def _apply_actions(rule: dict, finding: dict) -> list:
    applied = []
    for action in rule.get("actions", []):
        atype = action.get("type")
        try:
            if atype == "assign_team" and action.get("team"):
                await db.findings.update_one({"id": finding["id"]}, {"$set": {
                    "owner_team": action["team"], "ownership_confidence": 1.0}})
                applied.append(f"assigned to {action['team']}")
            elif atype == "add_tag" and action.get("tag"):
                await db.findings.update_one({"id": finding["id"]}, {"$addToSet": {"tags": action["tag"]}})
                applied.append(f"tagged '{action['tag']}'")
            elif atype == "set_status" and action.get("status"):
                await db.findings.update_one({"id": finding["id"]}, {"$set": {
                    "status": action["status"], "last_changed_at": now_iso()}})
                applied.append(f"status -> {action['status']}")
            elif atype == "notify" and action.get("channel_id"):
                from notifier import deliver
                channel = await db.notification_channels.find_one({"id": action["channel_id"]}, {"_id": 0})
                if channel:
                    await deliver(channel, "new_assignment", finding_ctx(finding), db)
                    applied.append(f"notified via {channel.get('name', action['channel_id'])}")
            elif atype == "log_note" and action.get("note"):
                await db.activity_log.insert_one({
                    "id": str(uuid.uuid4()), "finding_id": finding["id"], "actor": "automation",
                    "action": "automation_note", "detail": action["note"], "created_at": now_iso(),
                })
                applied.append("note logged")
        except Exception as e:
            applied.append(f"{atype} failed: {e}")
    return applied


async def run_rule(rule: dict, dry_run: bool = False) -> dict:
    query = _build_query(rule.get("conditions") or {})
    query["automation_applied"] = {"$ne": rule["id"]}
    findings = await db.findings.find(query, {"_id": 0}).limit(500).to_list(500)

    if dry_run:
        return {"matched": len(findings), "sample": [
            {"id": f["id"], "title": f.get("title"), "severity": f.get("severity"),
             "asset": f.get("asset_hostname")} for f in findings[:10]]}

    touched = 0
    for f in findings:
        applied = await _apply_actions(rule, f)
        await db.findings.update_one({"id": f["id"]}, {"$addToSet": {"automation_applied": rule["id"]}})
        await db.automation_runs.insert_one({
            "id": str(uuid.uuid4()), "rule_id": rule["id"], "rule_name": rule["name"],
            "finding_id": f["id"], "finding_title": f.get("title"),
            "actions_applied": applied, "ran_at": now_iso(),
        })
        touched += 1
    if touched:
        await db.automation_rules.update_one({"id": rule["id"]}, {"$set": {
            "last_run_at": now_iso()}, "$inc": {"run_count": touched}})
    return {"matched": touched}


async def run_all_automation_rules(db) -> dict:
    """Called from the nightly loop -- sweep every enabled rule against current findings."""
    rules = await db.automation_rules.find({"enabled": True}, {"_id": 0}).to_list(200)
    total = 0
    for rule in rules:
        try:
            r = await run_rule(rule)
            total += r.get("matched", 0)
        except Exception:
            pass
    return {"rules_run": len(rules), "findings_touched": total}


@router.get("/v1/automation/meta")
async def automation_meta(user: dict = Depends(get_current_user)):
    channels = await db.notification_channels.find({}, {"_id": 0, "id": 1, "name": 1}).to_list(50)
    return {"triggers": TRIGGER_LABELS, "condition_fields": CONDITION_FIELDS,
            "action_types": ACTION_TYPES, "channels": channels}


@router.get("/v1/automation/rules")
async def list_rules(user: dict = Depends(get_current_user)):
    items = await db.automation_rules.find({}, {"_id": 0}).sort("created_at", -1).to_list(200)
    return {"items": items}


@router.post("/v1/automation/rules")
async def create_rule(body: RuleBody, user: dict = Depends(require_role("admin", "manager"))):
    doc = {"id": str(uuid.uuid4()), **body.model_dump(), "run_count": 0, "last_run_at": None,
           "created_at": now_iso(), "created_by": user["email"]}
    await db.automation_rules.insert_one(doc)
    return _clean(doc)


@router.put("/v1/automation/rules/{rule_id}")
async def update_rule(rule_id: str, body: RuleBody, user: dict = Depends(require_role("admin", "manager"))):
    existing = await db.automation_rules.find_one({"id": rule_id}, {"_id": 0})
    if not existing:
        raise HTTPException(404, "Rule not found")
    update = body.model_dump()
    update["updated_at"] = now_iso()
    await db.automation_rules.update_one({"id": rule_id}, {"$set": update})
    return {**existing, **update}


@router.delete("/v1/automation/rules/{rule_id}")
async def delete_rule(rule_id: str, user: dict = Depends(require_role("admin", "manager"))):
    await db.automation_rules.delete_one({"id": rule_id})
    return {"ok": True}


@router.post("/v1/automation/rules/{rule_id}/preview")
async def preview_rule(rule_id: str, user: dict = Depends(get_current_user)):
    rule = await db.automation_rules.find_one({"id": rule_id}, {"_id": 0})
    if not rule:
        raise HTTPException(404, "Rule not found")
    return await run_rule(rule, dry_run=True)


@router.post("/v1/automation/rules/{rule_id}/run")
async def run_rule_now(rule_id: str, user: dict = Depends(require_role("admin", "manager"))):
    rule = await db.automation_rules.find_one({"id": rule_id}, {"_id": 0})
    if not rule:
        raise HTTPException(404, "Rule not found")
    return await run_rule(rule, dry_run=False)


@router.get("/v1/automation/runs")
async def list_runs(user: dict = Depends(get_current_user), rule_id: Optional[str] = None, limit: int = 100):
    flt = {"rule_id": rule_id} if rule_id else {}
    items = await db.automation_runs.find(flt, {"_id": 0}).sort("ran_at", -1).limit(min(limit, 500)).to_list(500)
    return {"items": items}
