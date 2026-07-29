"""Attack Surface Telemetry API (items 37 + 38). See attack_telemetry.py for
the pipeline and the guardrails."""
import uuid
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from db import db
from rbac import require_module
from routes.common import now_iso
import attack_telemetry as at

router = APIRouter()

MODULE_KEY = "/attack-telemetry"


class IngestBody(BaseModel):
    minutes: int = 60
    limit: int = 2000


class AllowlistBody(BaseModel):
    value: str                       # IP or CIDR
    reason: str = ""
    label: str = ""


class ObservationUpdateBody(BaseModel):
    status: Optional[str] = None     # new | investigating | confirmed | dismissed
    note: Optional[str] = None


class RuleUpdateBody(BaseModel):
    status: Optional[str] = None     # draft | approved | rejected | applied
    action: Optional[str] = None     # block | challenge | js_challenge | log
    expression: Optional[str] = None


class IndicatorReviewBody(BaseModel):
    review_status: str               # confirmed | false_positive
    note: str = ""


@router.get("/v1/attack-telemetry/status")
async def telemetry_status(user: dict = Depends(require_module(MODULE_KEY))):
    """Configuration + retention posture. Surfaces the Free/Pro reality: short
    upstream retention, so our own store is the system of record."""
    integration = await db.integrations.find_one({"name": "Cloudflare"}, {"_id": 0})
    cfg = (integration or {}).get("config") or {}
    configured = bool(cfg.get("api_key") and cfg.get("zone_id"))
    retention = None
    if configured:
        try:
            retention = await at.discover_retention(db)
        except Exception as e:
            retention = {"error": str(e)}
    cursors = await db.attack_telemetry_cursors.find({}, {"_id": 0}).to_list(10)
    return {
        "configured": configured,
        "retention": retention,
        "cursors": cursors,
        "observations": await db.attack_observations.count_documents({}),
        "observations_confirmed": await db.attack_observations.count_documents({"status": "confirmed"}),
        "draft_rules": await db.attack_waf_rules.count_documents({"status": "draft"}),
        "auto_indicators": await db.ioc_watchlist.count_documents({"source": "auto/cf-exploit"}),
        "allowlist_entries": await db.attack_ip_allowlist.count_documents({}),
        "local_retention_days": at.DEFAULT_RETENTION_DAYS,
    }


@router.post("/v1/attack-telemetry/ingest")
async def ingest_now(body: IngestBody,
                      user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    try:
        return await at.ingest_cloudflare(db, minutes=body.minutes, limit=body.limit)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(502, f"Cloudflare ingest failed: {e}")


@router.get("/v1/attack-telemetry/observations")
async def list_observations(
    status: Optional[str] = None, attack_type: Optional[str] = None,
    min_score: Optional[int] = None, reached_origin: Optional[bool] = None,
    host: Optional[str] = None, source_ip: Optional[str] = None,
    limit: int = 200, user: dict = Depends(require_module(MODULE_KEY)),
):
    flt: dict = {}
    if status:
        flt["status"] = status
    if attack_type:
        flt["attack_types"] = attack_type
    if min_score is not None:
        flt["business_risk_score"] = {"$gte": min_score}
    if host:
        flt["host"] = {"$regex": host, "$options": "i"}
    if source_ip:
        flt["source_ip"] = source_ip
    if reached_origin is True:
        # "did anything actually reach origin" -- the successful-vs-blocked view
        flt["cf_action"] = {"$nin": ["block", "drop", "challenge", "managed_challenge", "jschallenge"]}
        flt["last_origin_status"] = {"$ne": None}
    elif reached_origin is False:
        flt["cf_action"] = {"$in": ["block", "drop", "challenge", "managed_challenge", "jschallenge"]}
    items = await db.attack_observations.find(flt, {"_id": 0}).sort(
        "business_risk_score", -1).to_list(min(limit, 1000))
    return {"items": items, "total": len(items)}


@router.get("/v1/attack-telemetry/summary")
async def telemetry_summary(user: dict = Depends(require_module(MODULE_KEY))):
    """Dashboard rollup: by attack type, blocked vs reached-origin, top sources,
    top targets, and how many attacks line up with a real open vulnerability."""
    obs = await db.attack_observations.find({}, {"_id": 0}).to_list(5000)
    by_type, by_country, by_source, by_target = {}, {}, {}, {}
    blocked = reached = 0
    with_vuln = 0
    for o in obs:
        for t in (o.get("attack_types") or [o.get("attack_type")]):
            if t:
                by_type[t] = by_type.get(t, 0) + o.get("hit_count", 1)
        if o.get("country"):
            by_country[o["country"]] = by_country.get(o["country"], 0) + o.get("hit_count", 1)
        if o.get("source_ip"):
            by_source[o["source_ip"]] = by_source.get(o["source_ip"], 0) + o.get("hit_count", 1)
        if o.get("host"):
            by_target[o["host"]] = by_target.get(o["host"], 0) + o.get("hit_count", 1)
        action = (o.get("cf_action") or "").lower()
        if action in ("block", "drop", "challenge", "managed_challenge", "jschallenge"):
            blocked += o.get("hit_count", 1)
        elif o.get("last_origin_status") is not None:
            reached += o.get("hit_count", 1)
        if o.get("has_matching_vulnerability"):
            with_vuln += 1

    def top(d, n=10):
        return sorted(({"key": k, "count": v} for k, v in d.items()), key=lambda x: -x["count"])[:n]

    return {
        "observations": len(obs),
        "total_hits": sum(o.get("hit_count", 1) for o in obs),
        "by_attack_type": top(by_type, 15),
        "by_country": top(by_country),
        "top_sources": top(by_source),
        "top_targets": top(by_target),
        "blocked_hits": blocked,
        "reached_origin_hits": reached,
        "attacks_matching_open_vulnerability": with_vuln,
        "high_risk": len([o for o in obs if (o.get("business_risk_score") or 0) >= 70]),
        "generated_at": now_iso(),
    }


@router.get("/v1/attack-telemetry/observations/{observation_id}")
async def get_observation(observation_id: str, user: dict = Depends(require_module(MODULE_KEY))):
    o = await db.attack_observations.find_one({"id": observation_id}, {"_id": 0})
    if not o:
        raise HTTPException(404, "Observation not found")
    if o.get("matching_finding_ids"):
        o["matching_findings"] = await db.findings.find(
            {"id": {"$in": o["matching_finding_ids"]}},
            {"_id": 0, "id": 1, "title": 1, "severity": 1, "cwe": 1, "status": 1}).to_list(20)
    return o


@router.patch("/v1/attack-telemetry/observations/{observation_id}")
async def update_observation(observation_id: str, body: ObservationUpdateBody,
                              user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    o = await db.attack_observations.find_one({"id": observation_id}, {"_id": 0})
    if not o:
        raise HTTPException(404, "Observation not found")
    changes = {}
    if body.status:
        if body.status not in ("new", "investigating", "confirmed", "dismissed"):
            raise HTTPException(400, "status must be new/investigating/confirmed/dismissed")
        changes["status"] = body.status
    if body.note is not None:
        changes["analyst_note"] = body.note
    if changes:
        changes["updated_at"] = now_iso()
        changes["updated_by"] = user.get("email")
        await db.attack_observations.update_one({"id": observation_id}, {"$set": changes})
    return await db.attack_observations.find_one({"id": observation_id}, {"_id": 0})


@router.get("/v1/assets/{asset_id}/attacks")
async def asset_attacks(asset_id: str, user: dict = Depends(require_module(MODULE_KEY))):
    """Item 38(B) -- the "attempted exploits / blocks" view on the targeted
    public server's own asset record."""
    items = await db.attack_observations.find(
        {"asset_id": asset_id}, {"_id": 0}).sort("business_risk_score", -1).to_list(500)
    blocked = sum(o.get("hit_count", 1) for o in items
                  if (o.get("cf_action") or "").lower() in
                  ("block", "drop", "challenge", "managed_challenge", "jschallenge"))
    total = sum(o.get("hit_count", 1) for o in items)
    return {
        "items": items, "total_observations": len(items), "total_hits": total,
        "blocked_hits": blocked, "reached_origin_hits": total - blocked,
        "matching_vulnerability_count": len([o for o in items if o.get("has_matching_vulnerability")]),
    }


# --------------------------- allowlist (item 38 guardrail) ---------------------------

@router.get("/v1/attack-telemetry/allowlist")
async def list_allowlist(user: dict = Depends(require_module(MODULE_KEY))):
    return {"items": await db.attack_ip_allowlist.find({}, {"_id": 0}).sort("value", 1).to_list(500)}


@router.post("/v1/attack-telemetry/allowlist")
async def add_allowlist(body: AllowlistBody,
                         user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    import ipaddress
    value = body.value.strip()
    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
    except ValueError:
        raise HTTPException(400, f"{value} is not a valid IP address or CIDR range")
    if await db.attack_ip_allowlist.find_one({"value": value}, {"_id": 0, "id": 1}):
        raise HTTPException(409, "Already allowlisted")
    doc = {"id": str(uuid.uuid4()), "value": value, "label": body.label,
           "reason": body.reason, "added_by": user.get("email"), "added_at": now_iso()}
    await db.attack_ip_allowlist.insert_one(dict(doc))
    return doc


@router.delete("/v1/attack-telemetry/allowlist/{entry_id}")
async def delete_allowlist(entry_id: str,
                            user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    r = await db.attack_ip_allowlist.delete_one({"id": entry_id})
    if r.deleted_count == 0:
        raise HTTPException(404, "Not found")
    return {"ok": True}


# --------------------------- drafted WAF rules ---------------------------

@router.get("/v1/attack-telemetry/waf-rules")
async def list_waf_rules(status: Optional[str] = None,
                          user: dict = Depends(require_module(MODULE_KEY))):
    flt = {"status": status} if status else {}
    return {"items": await db.attack_waf_rules.find(flt, {"_id": 0}).sort("created_at", -1).to_list(300)}


@router.patch("/v1/attack-telemetry/waf-rules/{rule_id}")
async def update_waf_rule(rule_id: str, body: RuleUpdateBody,
                           user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    rule = await db.attack_waf_rules.find_one({"id": rule_id}, {"_id": 0})
    if not rule:
        raise HTTPException(404, "Rule not found")
    changes = {}
    if body.status:
        if body.status not in ("draft", "approved", "rejected", "applied"):
            raise HTTPException(400, "status must be draft/approved/rejected/applied")
        # Deliberate: this endpoint records a HUMAN decision. Nothing in the
        # pipeline can move a rule to approved/applied on its own.
        changes["status"] = body.status
        changes["decided_by"] = user.get("email")
        changes["decided_at"] = now_iso()
    if body.action:
        if body.action not in ("block", "challenge", "js_challenge", "log"):
            raise HTTPException(400, "action must be block/challenge/js_challenge/log")
        changes["action"] = body.action
    if body.expression:
        changes["expression"] = body.expression
    if changes:
        changes["updated_at"] = now_iso()
        await db.attack_waf_rules.update_one({"id": rule_id}, {"$set": changes})
    return await db.attack_waf_rules.find_one({"id": rule_id}, {"_id": 0})


@router.get("/v1/attack-telemetry/waf-rules/export")
async def export_waf_rules(user: dict = Depends(require_module(MODULE_KEY))):
    """Reviewable export of approved rules -- Cloudflare expression syntax, ready
    to paste into a custom ruleset. Export rather than push, because pushing
    blocking rules from an automated classifier is how you take your own site
    offline."""
    rules = await db.attack_waf_rules.find({"status": "approved"}, {"_id": 0}).to_list(300)
    lines = ["# Nightwatch — approved WAF rules", f"# Generated {now_iso()}", ""]
    for r in rules:
        lines.append(f"# {r.get('description')}")
        lines.append(f"#   rationale: {r.get('rationale')}")
        lines.append(f"{r.get('expression')}  ->  {r.get('action')}")
        lines.append("")
    return {"count": len(rules), "text": "\n".join(lines), "rules": rules}


# --------------------------- auto-created indicator review (item 38) ---------------------------

@router.get("/v1/attack-telemetry/auto-indicators")
async def list_auto_indicators(user: dict = Depends(require_module(MODULE_KEY))):
    items = await db.ioc_watchlist.find(
        {"source": "auto/cf-exploit"}, {"_id": 0}).sort("added_at", -1).to_list(500)
    return {"items": items}


@router.post("/v1/attack-telemetry/auto-indicators/{value}/review")
async def review_auto_indicator(value: str, body: IndicatorReviewBody,
                                 user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    """Confidence-tagged auto-additions exist so false positives can be
    DOWNGRADED. Marking one a false positive removes it from the watchlist and
    allowlists it, so the same benign scanner doesn't get re-added tomorrow."""
    if body.review_status not in ("confirmed", "false_positive"):
        raise HTTPException(400, "review_status must be confirmed or false_positive")
    ioc = await db.ioc_watchlist.find_one({"value": value.lower(), "source": "auto/cf-exploit"}, {"_id": 0})
    if not ioc:
        raise HTTPException(404, "Auto-created indicator not found")
    if body.review_status == "confirmed":
        await db.ioc_watchlist.update_one({"value": value.lower()}, {"$set": {
            "review_status": "confirmed", "auto_created": False,
            "reviewed_by": user.get("email"), "reviewed_at": now_iso(),
            "review_note": body.note}})
        return {"ok": True, "result": "promoted to a reviewed indicator"}

    await db.ioc_watchlist.delete_one({"value": value.lower(), "source": "auto/cf-exploit"})
    if not await db.attack_ip_allowlist.find_one({"value": value}, {"_id": 0, "id": 1}):
        await db.attack_ip_allowlist.insert_one({
            "id": str(uuid.uuid4()), "value": value, "label": "false positive",
            "reason": body.note or "Reviewed as a false positive from attack telemetry",
            "added_by": user.get("email"), "added_at": now_iso()})
    return {"ok": True, "result": "removed and allowlisted so it isn't re-added"}
