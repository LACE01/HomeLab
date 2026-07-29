"""Security Reviews API -- Phase 1 (see security_reviews.py's module docstring
for scope and collection layout). Everything here refuses writes with 409 once a
review is Closed: the closed review IS the audit package, per spec."""
import uuid
from datetime import datetime, timezone
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from db import db
from rbac import require_module
from routes.common import now_iso, team_scope_filter
from security_reviews import (
    REVIEW_TYPES, DATA_CLASSIFICATIONS, REVIEW_STATUSES, STEP_STATUSES,
    DECISION_OUTCOMES, URGENCIES, IMPACT_DIMENSIONS,
    ensure_seeded, next_review_number, audit, review_is_closed, score_rating,
    latest_playbook_for_type, latest_questionnaire, instantiate_steps,
    upsert_reviewed_entity, prior_reviews_lookup,
)
from security_reviews_hooks import (
    AUTOFILL_HOOKS, auto_answer_questions, draft_finding_from_answer,
    draft_executive_summary, compile_vendor_questionnaire, suggest_risk,
    run_external_checks, clone_for_revalidation, ensure_phase2_seeded,
    REREVIEW_MONTHS,
)
import auth_utils
from auth_utils import get_current_user
from report_templates import (
    BLOCK_CATALOG, DEFAULT_KEY, active_template, default_layout, ensure_seeded as ensure_template_seeded,
    resolve_layout, validate_blocks,
)
from questionnaire_v3 import (
    CAPABILITY_FLAGS, NA_REASON_CODES, QUESTIONNAIRE_V3, default_capabilities,
    applicable_questions, score_questionnaire, confidence_note, ensure_v3_seeded,
    custom_questions_for,
)

router = APIRouter()

MODULE_KEY = "/security-reviews"


# --------------------------- bodies ---------------------------

class IntakeBody(BaseModel):
    title: str
    review_type: str
    requestor_name: str = ""
    requestor_department: str = ""
    business_justification: str = ""
    urgency: str = "Normal"
    target_decision_date: Optional[str] = None
    data_classifications: List[str] = []
    scope_statement: str = ""
    entity_name: Optional[str] = None       # vendor/product/system under review
    entity_domain: Optional[str] = None
    owner_team: Optional[str] = None


class ReviewUpdateBody(BaseModel):
    title: Optional[str] = None
    linked_asset_ids: Optional[List[str]] = None
    assignee: Optional[str] = None
    urgency: Optional[str] = None
    target_decision_date: Optional[str] = None
    data_classifications: Optional[List[str]] = None
    scope_statement: Optional[str] = None
    business_justification: Optional[str] = None
    entity_name: Optional[str] = None
    entity_domain: Optional[str] = None
    owner_team: Optional[str] = None


class StatusBody(BaseModel):
    status: str


class StepBody(BaseModel):
    status: Optional[str] = None
    na_reason: Optional[str] = None
    blocked_on: Optional[str] = None
    blocked_date: Optional[str] = None
    notes: Optional[str] = None
    evidence: Optional[List[dict]] = None   # [{name, mime, data_url}] -- same shape FindingDetail attachments use


class LinkAssetsBody(BaseModel):
    """Flexible in-scope asset linking: pick individually, or pull in a whole
    team's or tag's worth at once. All three can be combined in one call."""
    asset_ids: List[str] = []
    teams: List[str] = []
    tags: List[str] = []
    replace: bool = False        # False = add to what's already linked


class UnlinkAssetsBody(BaseModel):
    asset_ids: List[str]


class AttachmentBody(BaseModel):
    name: str
    mime: str = ""
    data_url: str                # base64 data URL, same shape step evidence uses
    description: str = ""
    category: str = "supporting"  # supporting | contract | certificate | questionnaire | screenshot


class ResponseBody(BaseModel):
    question_order: int
    answer: str                             # yes | no | partial | na
    na_reason_code: Optional[str] = None    # na_by_design | unknown | pending_vendor
    evidence_text: str = ""
    attachments: List[dict] = []


class CapabilityBody(BaseModel):
    capabilities: dict                      # {flag_key: bool}


class TemplateBody(BaseModel):
    """A report layout is a versioned record, not code. Saving always creates a
    NEW version so a report rendered last quarter can still be explained."""
    name: str
    blocks: List[dict]
    key: str = DEFAULT_KEY


class CustomQuestionBody(BaseModel):
    text: str
    domain: str = "Custom"
    risk_weight: int = 3
    vendor_facing: bool = False


class RiskScoreBody(BaseModel):
    inherent_likelihood: int
    inherent_impacts: dict                  # {confidentiality: 1-5, ...}
    suggested_band: Optional[str] = None    # echo of the suggestion the UI displayed (Phase 3)
    compensating_controls: str = ""
    residual_likelihood: Optional[int] = None
    residual_impacts: Optional[dict] = None
    not_adopting_likelihood: Optional[int] = None
    not_adopting_impacts: Optional[dict] = None
    override_justification: str = ""


class ReviewFindingBody(BaseModel):
    description: str
    severity: str = "Medium"
    category: str = "General"
    affected_component: str = ""
    cis_mapping: str = ""
    recommendation: str = ""
    owner: str = ""
    due_date: Optional[str] = None
    is_condition_of_approval: bool = False
    condition_deadline: Optional[str] = None


class ReviewFindingUpdateBody(BaseModel):
    description: Optional[str] = None
    severity: Optional[str] = None
    category: Optional[str] = None
    affected_component: Optional[str] = None
    cis_mapping: Optional[str] = None
    recommendation: Optional[str] = None
    owner: Optional[str] = None
    due_date: Optional[str] = None
    status: Optional[str] = None            # open | resolved
    is_condition_of_approval: Optional[bool] = None
    condition_met: Optional[str] = None     # met | not_met | pending
    condition_deadline: Optional[str] = None


class DecisionBody(BaseModel):
    outcome: str
    rationale: str = ""
    decision_maker: str = ""
    expiration_date: Optional[str] = None
    requestor_acknowledged: bool = False


class NoteBody(BaseModel):
    text: str                       # plain-text fallback (search/summary)
    html: Optional[str] = None      # rich-text body from the editor


# --------------------------- helpers ---------------------------

async def _get_review_or_404(review_id: str) -> dict:
    r = await db.security_reviews.find_one({"id": review_id}, {"_id": 0})
    if not r:
        raise HTTPException(404, "Review not found")
    return r


async def _reject_if_closed(review_id: str):
    if await review_is_closed(db, review_id):
        raise HTTPException(409, "This review is closed -- its evidence and responses are immutable. "
                                  "Reopen is intentionally not supported; open a new review instead.")


def _sla_seconds(review: dict) -> Optional[int]:
    """Elapsed working seconds since intake, minus paused time. None if closed."""
    try:
        created = datetime.fromisoformat(review["created_at"])
    except Exception:
        return None
    now = datetime.now(timezone.utc)
    paused_total = review.get("sla_paused_total_seconds") or 0
    if review.get("sla_paused_at"):
        try:
            paused_total += (now - datetime.fromisoformat(review["sla_paused_at"])).total_seconds()
        except Exception:
            pass
    return int((now - created).total_seconds() - paused_total)


# --------------------------- meta / list / intake ---------------------------

@router.get("/v1/security-reviews/meta")
async def reviews_meta(user: dict = Depends(require_module(MODULE_KEY))):
    await ensure_seeded(db)
    await ensure_phase2_seeded(db)
    await ensure_v3_seeded(db)
    return {
        "capability_flags": CAPABILITY_FLAGS, "na_reason_codes": NA_REASON_CODES,
        "review_types": REVIEW_TYPES, "data_classifications": DATA_CLASSIFICATIONS,
        "statuses": REVIEW_STATUSES, "step_statuses": STEP_STATUSES,
        "decision_outcomes": DECISION_OUTCOMES, "urgencies": URGENCIES,
        "impact_dimensions": IMPACT_DIMENSIONS,
    }


@router.get("/v1/security-reviews")
async def list_reviews(
    status: Optional[str] = None, review_type: Optional[str] = None,
    assignee: Optional[str] = None, risk: Optional[str] = None, q: Optional[str] = None,
    user: dict = Depends(require_module(MODULE_KEY)),
):
    flt: dict = {}
    flt.update(team_scope_filter(user))
    if status:
        flt["status"] = status
    if review_type:
        flt["review_type"] = review_type
    if assignee:
        flt["assignee"] = assignee
    if risk:
        flt["$or"] = [{"inherent_risk.band": risk}, {"residual_risk.band": risk}]
    if q:
        flt["$and"] = [{"$or": [
            {"title": {"$regex": q, "$options": "i"}},
            {"review_number": {"$regex": q, "$options": "i"}},
            {"entity_name": {"$regex": q, "$options": "i"}},
        ]}]
    items = await db.security_reviews.find(flt, {"_id": 0}).sort("created_at", -1).to_list(500)
    for r in items:
        r["sla_elapsed_seconds"] = None if r.get("status") == "Closed" else _sla_seconds(r)
    return {"items": items, "total": len(items)}


@router.post("/v1/security-reviews")
async def create_review(body: IntakeBody, user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    await ensure_seeded(db)
    await ensure_phase2_seeded(db)
    if body.review_type not in REVIEW_TYPES:
        raise HTTPException(400, f"review_type must be one of {REVIEW_TYPES}")
    if not body.title.strip():
        raise HTTPException(400, "title is required")
    bad = [c for c in body.data_classifications if c not in DATA_CLASSIFICATIONS]
    if bad:
        raise HTTPException(400, f"Unknown data classification(s): {bad}")

    playbook = await latest_playbook_for_type(db, body.review_type)
    # Item 28: new reviews use the adaptive capability-gated questionnaire.
    template = await db.review_questionnaires.find_one(
        {"key": QUESTIONNAIRE_V3["key"], "version": 3}, {"_id": 0})
    if not template:
        template = await latest_questionnaire(db)
    review = {
        "id": str(uuid.uuid4()), "review_number": await next_review_number(db),
        "title": body.title.strip(), "review_type": body.review_type, "status": "Requested",
        "capabilities": default_capabilities(playbook["key"] if playbook else None),
        "requestor_name": body.requestor_name, "requestor_department": body.requestor_department,
        "business_justification": body.business_justification, "urgency": body.urgency,
        "target_decision_date": body.target_decision_date,
        "data_classifications": body.data_classifications, "scope_statement": body.scope_statement,
        "entity_name": (body.entity_name or "").strip() or None,
        "entity_domain": (body.entity_domain or "").strip().lower() or None,
        "assignee": user.get("email"), "owner_team": body.owner_team or user.get("team"),
        "created_at": now_iso(), "updated_at": now_iso(),
        "playbook_version_id": playbook["id"] if playbook else None,
        "playbook_key": playbook["key"] if playbook else None,
        "playbook_version": playbook["version"] if playbook else None,
        "template_version_id": template["id"] if template else None,
        "template_key": template["key"] if template else None,
        "template_version": template["version"] if template else None,
        "sla_paused_at": None, "sla_paused_total_seconds": 0,
        "inherent_risk": None, "residual_risk": None, "risk_of_not_adopting": None,
        "compensating_controls": "", "analyst_override_justification": "",
        "decision": None,
    }
    await db.security_reviews.insert_one(review)
    if playbook:
        await instantiate_steps(db, review, playbook)
    if review["entity_name"]:
        entity = await upsert_reviewed_entity(db, name=review["entity_name"], domain=review["entity_domain"])
        await db.security_reviews.update_one({"id": review["id"]}, {"$set": {"entity_id": entity["id"]}})
        review["entity_id"] = entity["id"]
    await audit(db, review["id"], "created", user.get("email", "?"),
                f"Intake: {review['review_number']} — {review['title']} ({review['review_type']})")
    return {k: v for k, v in review.items() if k != "_id"}


@router.get("/v1/security-reviews/asset-picker")
async def asset_picker(q: Optional[str] = None, team: Optional[str] = None,
                        tag: Optional[str] = None, limit: int = 200,
                        user: dict = Depends(require_module(MODULE_KEY))):
    """Candidates for linking, plus the distinct teams and tags available so the
    UI can offer bulk-by-team / bulk-by-tag without a second round trip."""
    flt: dict = {}
    if q:
        flt["$or"] = [{"hostname": {"$regex": q, "$options": "i"}},
                      {"ip": {"$regex": q, "$options": "i"}}]
    if team:
        flt["owner_team"] = team
    if tag:
        flt["tags"] = tag
    items = await db.assets.find(
        flt, {"_id": 0, "id": 1, "hostname": 1, "ip": 1, "owner_team": 1,
              "criticality": 1, "tags": 1, "os": 1, "internet_facing": 1}).sort("hostname", 1).to_list(min(limit, 1000))
    teams = sorted({t for t in await db.assets.distinct("owner_team") if t})
    tags = sorted({t for t in await db.assets.distinct("tags") if t})
    return {"items": items, "total": len(items), "teams": teams, "tags": tags}


@router.get("/v1/report-templates/blocks")
async def report_template_blocks(user: dict = Depends(require_module(MODULE_KEY))):
    """Every block the renderers know how to draw, with its description, default
    title, configurable options, and whether it's internal-only."""
    return {"blocks": BLOCK_CATALOG, "default_layout": default_layout()}


@router.get("/v1/report-templates")
async def list_report_templates(user: dict = Depends(require_module(MODULE_KEY))):
    await ensure_template_seeded(db)
    items = await db.report_templates.find({}, {"_id": 0}).sort(
        [("key", 1), ("version", -1)]).to_list(200)
    return {"items": items, "active": await active_template(db)}


@router.post("/v1/report-templates")
async def save_report_template(body: TemplateBody,
                                user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    """Save as the next version. Existing reports keep rendering under whatever
    version they were produced with."""
    try:
        blocks = validate_blocks(body.blocks)
    except ValueError as e:
        raise HTTPException(400, str(e))
    latest = await db.report_templates.find(
        {"key": body.key}, {"_id": 0, "version": 1}).sort("version", -1).to_list(1)
    version = (latest[0]["version"] + 1) if latest else 1
    doc = {"id": str(uuid.uuid4()), "key": body.key, "name": body.name,
           "version": version, "is_default": body.key == DEFAULT_KEY, "blocks": blocks,
           "created_by": user.get("email"), "created_at": now_iso()}
    await db.report_templates.insert_one(dict(doc))
    return doc


@router.post("/v1/report-templates/reset")
async def reset_report_template(user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    """Save the stock layout as a new version -- an undo that doesn't destroy
    history."""
    latest = await db.report_templates.find(
        {"key": DEFAULT_KEY}, {"_id": 0, "version": 1}).sort("version", -1).to_list(1)
    version = (latest[0]["version"] + 1) if latest else 1
    doc = {"id": str(uuid.uuid4()), "key": DEFAULT_KEY,
           "name": "Security Review Report (reset to default)", "version": version,
           "is_default": True, "blocks": default_layout(),
           "created_by": user.get("email"), "created_at": now_iso()}
    await db.report_templates.insert_one(dict(doc))
    return doc


@router.get("/v1/security-reviews/assignable-users")
async def assignable_users(user: dict = Depends(require_module(MODULE_KEY))):
    """Users who can be assigned a review -- anyone with view access to this
    module (admins always qualify)."""
    from rbac import access_map_for_role
    users = await db.users.find({}, {"_id": 0, "id": 1, "email": 1, "name": 1, "role": 1}).to_list(500)
    out = []
    for u in users:
        if u.get("role") == "admin":
            out.append(u)
            continue
        try:
            granted = (await access_map_for_role(db, u.get("role"))).get(MODULE_KEY)
        except Exception:
            granted = None
        if granted:
            out.append(u)
    return {"items": sorted(out, key=lambda x: x.get("email") or "")}


@router.get("/v1/security-reviews/dashboard")
async def reviews_dashboard(user: dict = Depends(require_module(MODULE_KEY))):
    """Dashboard v1+v2 in one endpoint: workload (open by status/type/assignee,
    aging, blocked>14d, conditions due), plus program metrics (completed per
    quarter, avg time-to-decision excluding paused time, % approved with
    conditions, % conditions met on time, risk distribution, upcoming
    re-reviews and expiring certifications)."""
    from datetime import datetime as _dt, timezone as _tz, timedelta as _td
    reviews = await db.security_reviews.find({}, {"_id": 0}).to_list(2000)
    now = _dt.now(_tz.utc)
    now_iso_s = now.isoformat()

    open_reviews = [r for r in reviews if r.get("status") not in ("Closed",)]
    by_status, by_type, by_assignee = {}, {}, {}
    aging_over_30 = 0
    for r in open_reviews:
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1
        by_type[r["review_type"]] = by_type.get(r["review_type"], 0) + 1
        if r.get("assignee"):
            by_assignee[r["assignee"]] = by_assignee.get(r["assignee"], 0) + 1
        try:
            age = (now - _dt.fromisoformat(r["created_at"])).days
            if age > 30:
                aging_over_30 += 1
        except Exception:
            pass

    blocked_cutoff = (now - _td(days=14)).date().isoformat()
    blocked_steps = await db.security_review_steps.find(
        {"status": "Blocked", "blocked_date": {"$lte": blocked_cutoff}},
        {"_id": 0, "review_id": 1, "title": 1, "blocked_on": 1, "blocked_date": 1}).to_list(100)

    due_cutoff = (now + _td(days=30)).date().isoformat()
    conditions = await db.security_review_findings.find(
        {"is_condition_of_approval": True, "condition_met": {"$in": ["pending", "not_met"]}},
        {"_id": 0, "review_id": 1, "description": 1, "condition_deadline": 1, "condition_met": 1, "owner": 1}).to_list(200)
    conditions_due = [c for c in conditions if c.get("condition_deadline") and c["condition_deadline"] <= due_cutoff]
    conditions_overdue = [c for c in conditions if c.get("condition_deadline") and c["condition_deadline"] < now.date().isoformat()]

    # metrics v2
    decided = [r for r in reviews if r.get("decision")]
    per_quarter: dict = {}
    ttd_seconds = []
    approved_with_conditions = 0
    risk_distribution: dict = {}
    for r in decided:
        d = r["decision"]
        try:
            dd = _dt.fromisoformat(d["decision_date"])
            per_quarter_key = f"{dd.year}-Q{(dd.month - 1)//3 + 1}"
            per_quarter[per_quarter_key] = per_quarter.get(per_quarter_key, 0) + 1
            created = _dt.fromisoformat(r["created_at"])
            paused = r.get("sla_paused_total_seconds") or 0
            ttd_seconds.append(max(0, (dd - created).total_seconds() - paused))
        except Exception:
            pass
        if d.get("outcome") == "Approved with Conditions":
            approved_with_conditions += 1
        band = (r.get("residual_risk") or {}).get("band") or (r.get("inherent_risk") or {}).get("band")
        if band:
            risk_distribution[band] = risk_distribution.get(band, 0) + 1
    all_conditions = await db.security_review_findings.find(
        {"is_condition_of_approval": True}, {"_id": 0, "condition_met": 1, "condition_deadline": 1}).to_list(500)
    met_on_time = sum(1 for c in all_conditions if c.get("condition_met") == "met")
    pct_conditions_met = round(100 * met_on_time / len(all_conditions)) if all_conditions else None

    upcoming_cutoff = (now + _td(days=90)).date().isoformat()
    entities = await db.reviewed_entities.find({}, {"_id": 0}).to_list(500)
    upcoming_rereviews = [e for e in entities if e.get("next_review_date") and e["next_review_date"] <= upcoming_cutoff]
    cert_cutoff = (now + _td(days=60)).date().isoformat()
    expiring_certs = []
    for e in entities:
        for cert in e.get("certifications") or []:
            if cert.get("expires_at") and cert["expires_at"] <= cert_cutoff:
                expiring_certs.append({"entity": e["name"], **cert})

    return {
        "open_total": len(open_reviews), "by_status": by_status, "by_type": by_type,
        "by_assignee": by_assignee, "aging_over_30_days": aging_over_30,
        "blocked_over_14_days": blocked_steps,
        "conditions_due_30_days": conditions_due, "conditions_overdue": conditions_overdue,
        "completed_per_quarter": per_quarter,
        "avg_days_to_decision_excl_paused": round(sum(ttd_seconds) / len(ttd_seconds) / 86400, 1) if ttd_seconds else None,
        "pct_approved_with_conditions": round(100 * approved_with_conditions / len(decided)) if decided else None,
        "pct_conditions_met": pct_conditions_met,
        "risk_distribution": risk_distribution,
        "upcoming_rereviews": upcoming_rereviews, "expiring_certifications": expiring_certs,
        "generated_at": now_iso_s,
    }


@router.get("/v1/security-reviews/my-requests")
async def my_requests(user: dict = Depends(get_current_user)):
    """Requestor-facing view (Phase 3 intake portal): reviews this user requested,
    regardless of module permission -- requestors get status visibility on their
    own submissions only."""
    items = await db.security_reviews.find(
        {"requestor_email": user.get("email")},
        {"_id": 0, "id": 1, "review_number": 1, "title": 1, "status": 1, "review_type": 1,
         "created_at": 1, "decision": 1, "residual_risk": 1, "target_decision_date": 1}).sort("created_at", -1).to_list(100)
    return {"items": items}


@router.post("/v1/security-reviews/request")
async def submit_request(body: IntakeBody, user: dict = Depends(get_current_user)):
    """Requestor-facing intake (Phase 3): any authenticated user can submit a
    review request -- it lands as Requested/unassigned for the security team to
    pick up, and the requestor tracks it via /my-requests. Deliberately NOT
    gated on the /security-reviews module permission (that gates working
    reviews, not asking for one)."""
    await ensure_seeded(db)
    await ensure_phase2_seeded(db)
    if body.review_type not in REVIEW_TYPES:
        raise HTTPException(400, f"review_type must be one of {REVIEW_TYPES}")
    if not body.title.strip():
        raise HTTPException(400, "title is required")
    playbook = await latest_playbook_for_type(db, body.review_type)
    template = await latest_questionnaire(db)
    review = {
        "id": str(uuid.uuid4()), "review_number": await next_review_number(db),
        "title": body.title.strip(), "review_type": body.review_type, "status": "Requested",
        "requestor_name": body.requestor_name or user.get("name") or user.get("email"),
        "requestor_department": body.requestor_department,
        "requestor_email": user.get("email"),
        "business_justification": body.business_justification, "urgency": body.urgency,
        "target_decision_date": body.target_decision_date,
        "data_classifications": body.data_classifications, "scope_statement": body.scope_statement,
        "entity_name": (body.entity_name or "").strip() or None,
        "entity_domain": (body.entity_domain or "").strip().lower() or None,
        "assignee": None, "owner_team": body.owner_team,
        "created_at": now_iso(), "updated_at": now_iso(),
        "playbook_version_id": playbook["id"] if playbook else None,
        "playbook_key": playbook["key"] if playbook else None,
        "playbook_version": playbook["version"] if playbook else None,
        "template_version_id": template["id"] if template else None,
        "template_key": template["key"] if template else None,
        "template_version": template["version"] if template else None,
        "sla_paused_at": None, "sla_paused_total_seconds": 0,
        "inherent_risk": None, "residual_risk": None, "risk_of_not_adopting": None,
        "compensating_controls": "", "analyst_override_justification": "",
        "decision": None,
    }
    await db.security_reviews.insert_one(dict(review))
    if playbook:
        await instantiate_steps(db, review, playbook)
    if review["entity_name"]:
        entity = await upsert_reviewed_entity(db, name=review["entity_name"], domain=review["entity_domain"])
        await db.security_reviews.update_one({"id": review["id"]}, {"$set": {"entity_id": entity["id"]}})
    await audit(db, review["id"], "created", user.get("email", "?"),
                f"Requestor-submitted intake: {review['review_number']}")
    return {"id": review["id"], "review_number": review["review_number"], "status": "Requested"}


@router.get("/v1/security-reviews/{review_id}")
async def get_review(review_id: str, user: dict = Depends(require_module(MODULE_KEY))):
    r = await _get_review_or_404(review_id)
    steps = await db.security_review_steps.find({"review_id": review_id}, {"_id": 0}).sort("order", 1).to_list(100)
    responses = await db.security_review_responses.find({"review_id": review_id}, {"_id": 0}).to_list(200)
    findings = await db.security_review_findings.find({"review_id": review_id}, {"_id": 0}).sort("created_at", 1).to_list(200)
    template = None
    if r.get("template_version_id"):
        template = await db.review_questionnaires.find_one({"id": r["template_version_id"]}, {"_id": 0})
    if not template:
        template = await latest_questionnaire(db)
    r["sla_elapsed_seconds"] = None if r.get("status") == "Closed" else _sla_seconds(r)
    # Item 28: the adaptive view -- only the questions this thing's capability
    # profile actually makes applicable, plus any per-review custom questions,
    # plus the live confidence read.
    customs = await custom_questions_for(db, review_id)
    applicable = []
    scoring = None
    if (template or {}).get("engine") == "capability_gated":
        applicable = applicable_questions(template, r.get("capabilities") or {},
                                           r.get("data_classifications") or [])
        applicable = applicable + customs
        scoring = score_questionnaire(applicable, responses)
    return {"review": r, "steps": steps, "responses": responses, "findings": findings,
            "questionnaire": template, "applicable_questions": applicable,
            "custom_questions": customs, "questionnaire_scoring": scoring}


@router.patch("/v1/security-reviews/{review_id}")
async def update_review(review_id: str, body: ReviewUpdateBody,
                         user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    await _get_review_or_404(review_id)
    await _reject_if_closed(review_id)
    changes = {k: v for k, v in body.dict().items() if v is not None}
    if not changes:
        return {"ok": True, "updated": 0}
    if "data_classifications" in changes:
        bad = [c for c in changes["data_classifications"] if c not in DATA_CLASSIFICATIONS]
        if bad:
            raise HTTPException(400, f"Unknown data classification(s): {bad}")
    if changes.get("entity_domain"):
        changes["entity_domain"] = changes["entity_domain"].strip().lower()
    changes["updated_at"] = now_iso()
    await db.security_reviews.update_one({"id": review_id}, {"$set": changes})
    await audit(db, review_id, "updated", user.get("email", "?"),
                f"Fields changed: {', '.join(k for k in changes if k != 'updated_at')}")
    return {"ok": True, "updated": len(changes) - 1}


@router.post("/v1/security-reviews/{review_id}/status")
async def set_status(review_id: str, body: StatusBody,
                      user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    r = await _get_review_or_404(review_id)
    if body.status not in REVIEW_STATUSES:
        raise HTTPException(400, f"status must be one of {REVIEW_STATUSES}")
    if r.get("status") == "Closed":
        raise HTTPException(409, "Closed reviews cannot change status -- open a new review instead.")
    changes: dict = {"status": body.status, "updated_at": now_iso()}
    # SLA clock: auto-pause while Pending Info, auto-resume when leaving it.
    if body.status == "Pending Info" and not r.get("sla_paused_at"):
        changes["sla_paused_at"] = now_iso()
    elif r.get("status") == "Pending Info" and body.status != "Pending Info" and r.get("sla_paused_at"):
        try:
            paused = (datetime.now(timezone.utc) - datetime.fromisoformat(r["sla_paused_at"])).total_seconds()
        except Exception:
            paused = 0
        changes["sla_paused_total_seconds"] = (r.get("sla_paused_total_seconds") or 0) + int(paused)
        changes["sla_paused_at"] = None
    if body.status == "Closed":
        changes["closed_at"] = now_iso()
        # Closing stamps the entity catalog: current rating + this review as the last.
        if r.get("entity_id"):
            band = (r.get("residual_risk") or {}).get("band")
            months = REREVIEW_MONTHS.get(band)
            next_review = None
            if months:
                from datetime import datetime as _dt, timezone as _tz, timedelta as _td
                next_review = (_dt.now(_tz.utc) + _td(days=months * 30)).date().isoformat()
            await db.reviewed_entities.update_one({"id": r["entity_id"]}, {"$set": {
                "current_rating": band,
                "last_review_id": review_id,
                "next_review_date": next_review,
            }})
    await db.security_reviews.update_one({"id": review_id}, {"$set": changes})
    await audit(db, review_id, "status_changed", user.get("email", "?"),
                f"{r.get('status')} → {body.status}")
    return {"ok": True, "status": body.status}


# --------------------------- playbook steps ---------------------------

@router.patch("/v1/security-reviews/{review_id}/steps/{step_id}")
async def update_step(review_id: str, step_id: str, body: StepBody,
                       user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    await _get_review_or_404(review_id)
    await _reject_if_closed(review_id)
    step = await db.security_review_steps.find_one({"id": step_id, "review_id": review_id}, {"_id": 0})
    if not step:
        raise HTTPException(404, "Step not found")
    changes: dict = {}
    if body.status is not None:
        if body.status not in STEP_STATUSES:
            raise HTTPException(400, f"status must be one of {STEP_STATUSES}")
        if body.status == "N/A" and not (body.na_reason or step.get("na_reason")):
            raise HTTPException(400, "Marking a step N/A requires a reason")
        changes["status"] = body.status
        if body.status == "Done":
            changes["completed_by"] = user.get("email")
            changes["completed_at"] = now_iso()
        if body.status == "Blocked":
            changes["blocked_on"] = body.blocked_on or step.get("blocked_on")
            changes["blocked_date"] = body.blocked_date or now_iso()[:10]
    for field in ("na_reason", "blocked_on", "blocked_date", "notes"):
        val = getattr(body, field)
        if val is not None:
            changes[field] = val
    if body.evidence is not None:
        changes["evidence"] = (step.get("evidence") or []) + body.evidence
        await audit(db, review_id, "evidence_uploaded", user.get("email", "?"),
                    f"Step {step['order']} ({step['title']}): {len(body.evidence)} file(s)")
    if not changes:
        return {"ok": True}
    await db.security_review_steps.update_one({"id": step_id}, {"$set": changes})
    if body.status is not None:
        detail = f"Step {step['order']} ({step['title']}): {step.get('status')} → {body.status}"
        if body.status == "N/A":
            detail += f" — reason: {body.na_reason or step.get('na_reason')}"
        await audit(db, review_id, "step_status", user.get("email", "?"), detail)
    updated = await db.security_review_steps.find_one({"id": step_id}, {"_id": 0})
    return updated


# --------------------------- questionnaire ---------------------------

@router.put("/v1/security-reviews/{review_id}/responses")
async def save_response(review_id: str, body: ResponseBody,
                         user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    await _get_review_or_404(review_id)
    await _reject_if_closed(review_id)
    if body.answer not in ("yes", "no", "partial", "na"):
        raise HTTPException(400, "answer must be yes/no/partial/na")
    if body.answer == "na":
        # Item 28: a bare N/A conflated "doesn't apply" with "we don't know",
        # which are opposite signals. v3 requires which one it is.
        if not body.na_reason_code:
            raise HTTPException(400, f"N/A requires a reason code: {sorted(NA_REASON_CODES)}")
        if body.na_reason_code not in NA_REASON_CODES:
            raise HTTPException(400, f"na_reason_code must be one of {sorted(NA_REASON_CODES)}")
    existing = await db.security_review_responses.find_one(
        {"review_id": review_id, "question_order": body.question_order}, {"_id": 0})
    was_auto = bool(existing and existing.get("auto_answered"))
    doc = {
        "review_id": review_id, "question_order": body.question_order, "answer": body.answer,
        "evidence_text": body.evidence_text, "attachments": body.attachments,
        "na_reason_code": body.na_reason_code if body.answer == "na" else None,
        # An analyst changing an auto-answered value is an OVERRIDE -- recorded, per spec.
        "auto_answered": False, "source_tag": "Analyst",
        "analyst_overridden": was_auto and existing.get("answer") != body.answer,
        "answered_by": user.get("email"), "answered_at": now_iso(),
    }
    if existing:
        await db.security_review_responses.update_one(
            {"review_id": review_id, "question_order": body.question_order}, {"$set": doc})
    else:
        doc["id"] = str(uuid.uuid4())
        await db.security_review_responses.insert_one(dict(doc))
    if doc["analyst_overridden"]:
        await audit(db, review_id, "auto_answer_overridden", user.get("email", "?"),
                    f"Q{body.question_order}: {existing.get('answer')} → {body.answer}")

    # Phase 2: No/Partial on a heavily-weighted question pre-drafts a finding
    # (status='draft') the analyst edits/accepts/deletes -- once per question.
    review_doc = await db.security_reviews.find_one({"id": review_id}, {"_id": 0})
    template = None
    if review_doc and review_doc.get("template_version_id"):
        template = await db.review_questionnaires.find_one({"id": review_doc["template_version_id"]}, {"_id": 0})
    if template:
        q = next((qq for qq in template.get("questions", []) if qq["order"] == body.question_order), None)
        if q:
            already = await db.security_review_findings.find_one(
                {"review_id": review_id, "from_question_order": body.question_order}, {"_id": 0, "id": 1})
            draft = None if already else draft_finding_from_answer(review_id, q, body.answer)
            if draft:
                await db.security_review_findings.insert_one(dict(draft))
    return {k: v for k, v in doc.items() if k != "_id"}


# --------------------------- risk scoring ---------------------------

@router.put("/v1/security-reviews/{review_id}/capabilities")
async def set_capabilities(review_id: str, body: CapabilityBody,
                            user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    """Item 28 Section 0 -- the Capability Profile. These ten flags decide which
    questionnaire modules apply, so changing them reshapes the questionnaire.
    Pre-seeded from the playbook type at intake; always analyst-overridable."""
    await _get_review_or_404(review_id)
    await _reject_if_closed(review_id)
    valid = {f["key"] for f in CAPABILITY_FLAGS}
    bad = [k for k in body.capabilities if k not in valid]
    if bad:
        raise HTTPException(400, f"Unknown capability flag(s): {bad}")
    caps = {k: bool(v) for k, v in body.capabilities.items()}
    await db.security_reviews.update_one({"id": review_id}, {"$set": {
        "capabilities": caps, "updated_at": now_iso()}})
    await audit(db, review_id, "capabilities_set", user.get("email", "?"),
                ", ".join(sorted(k for k, v in caps.items() if v)) or "none")
    r = await _get_review_or_404(review_id)
    template = await db.review_questionnaires.find_one({"id": r.get("template_version_id")}, {"_id": 0})
    if not template or template.get("engine") != "capability_gated":
        template = await db.review_questionnaires.find_one(
            {"key": QUESTIONNAIRE_V3["key"], "version": 3}, {"_id": 0})
    applicable = applicable_questions(template or {}, caps, r.get("data_classifications") or [])
    return {"capabilities": caps, "applicable_count": len(applicable),
            "applicable_questions": applicable}


@router.get("/v1/security-reviews/{review_id}/questionnaire-scoring")
async def questionnaire_scoring(review_id: str, user: dict = Depends(require_module(MODULE_KEY))):
    """Score + confidence over APPLICABLE questions only (item 28)."""
    r = await _get_review_or_404(review_id)
    template = await db.review_questionnaires.find_one({"id": r.get("template_version_id")}, {"_id": 0})
    if not template or template.get("engine") != "capability_gated":
        template = await db.review_questionnaires.find_one(
            {"key": QUESTIONNAIRE_V3["key"], "version": 3}, {"_id": 0})
    responses = await db.security_review_responses.find({"review_id": review_id}, {"_id": 0}).to_list(300)
    applicable = applicable_questions(template or {}, r.get("capabilities") or {},
                                       r.get("data_classifications") or [])
    applicable += await custom_questions_for(db, review_id)
    score = score_questionnaire(applicable, responses)
    band = (r.get("residual_risk") or {}).get("band") or (r.get("inherent_risk") or {}).get("band")
    return {**score, "summary": confidence_note(score, band)}


@router.get("/v1/security-reviews/{review_id}/custom-questions")
async def list_custom_questions(review_id: str, user: dict = Depends(require_module(MODULE_KEY))):
    await _get_review_or_404(review_id)
    return {"items": await custom_questions_for(db, review_id)}


@router.post("/v1/security-reviews/{review_id}/custom-questions")
async def add_custom_question(review_id: str, body: CustomQuestionBody,
                               user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    """Per-review custom questions (item 28). Numbered from 1000 up so they can
    never collide with template question orders."""
    await _get_review_or_404(review_id)
    await _reject_if_closed(review_id)
    if not body.text.strip():
        raise HTTPException(400, "text is required")
    existing = await db.security_review_custom_questions.count_documents({"review_id": review_id})
    doc = {
        "id": str(uuid.uuid4()), "review_id": review_id, "order": 1000 + existing,
        "domain": body.domain or "Custom", "text": body.text.strip(),
        "cis_mapping": "", "risk_weight": max(0, min(5, body.risk_weight)),
        "vendor_facing": body.vendor_facing, "requires_capability": None,
        "conditional_on": None, "custom": True,
        "created_by": user.get("email"), "created_at": now_iso(),
    }
    await db.security_review_custom_questions.insert_one(dict(doc))
    return doc


@router.delete("/v1/security-reviews/{review_id}/custom-questions/{question_id}")
async def delete_custom_question(review_id: str, question_id: str,
                                  user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    await _reject_if_closed(review_id)
    result = await db.security_review_custom_questions.delete_one(
        {"id": question_id, "review_id": review_id})
    if result.deleted_count == 0:
        raise HTTPException(404, "Custom question not found")
    return {"ok": True}


@router.post("/v1/security-reviews/{review_id}/custom-questions/{question_id}/promote")
async def promote_custom_question(review_id: str, question_id: str,
                                   user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    """Promote a per-review question into the template as a NEW version (item 28)
    -- the mechanism by which the methodology learns from real reviews without
    anyone editing code."""
    q = await db.security_review_custom_questions.find_one(
        {"id": question_id, "review_id": review_id}, {"_id": 0})
    if not q:
        raise HTTPException(404, "Custom question not found")
    latest = await db.review_questionnaires.find(
        {"key": QUESTIONNAIRE_V3["key"]}, {"_id": 0}).sort("version", -1).to_list(1)
    if not latest:
        raise HTTPException(400, "Adaptive template not seeded yet")
    base = latest[0]
    questions = [dict(x) for x in base.get("questions", [])]
    max_order = max([x.get("order", 0) for x in questions if x.get("order", 0) < 99] or [0])
    questions.append({
        "order": max_order + 1, "domain": q.get("domain") or "Custom",
        "requires_capability": q.get("requires_capability"),
        "text": q["text"], "cis_mapping": q.get("cis_mapping") or "",
        "risk_weight": q.get("risk_weight", 3), "vendor_facing": q.get("vendor_facing", False),
        "conditional_on": None,
    })
    questions.sort(key=lambda x: x.get("order", 0))
    doc = {"id": str(uuid.uuid4()), "key": base["key"], "name": base["name"],
           "version": base["version"] + 1, "engine": "capability_gated",
           "capability_flags": base.get("capability_flags"),
           "na_reason_codes": base.get("na_reason_codes"),
           "questions": questions, "created_by": user.get("email"), "created_at": now_iso()}
    await db.review_questionnaires.insert_one(dict(doc))
    await db.security_review_custom_questions.update_one(
        {"id": question_id}, {"$set": {"promoted_to_version": doc["version"]}})
    await audit(db, review_id, "question_promoted", user.get("email", "?"),
                f"\"{q['text'][:80]}\" → template v{doc['version']}")
    return {"ok": True, "version": doc["version"], "question_count": len(questions)}


@router.get("/v1/security-reviews/{review_id}/assets")
async def list_review_assets(review_id: str, user: dict = Depends(require_module(MODULE_KEY))):
    """In-scope assets for this review, with their open-finding counts -- the
    same list the asset_inventory_check / open_findings_pull hooks read."""
    r = await _get_review_or_404(review_id)
    ids = r.get("linked_asset_ids") or []
    if not ids:
        return {"items": [], "total": 0}
    assets = await db.assets.find({"id": {"$in": ids}}, {"_id": 0}).to_list(2000)
    OPEN = ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]
    for a in assets:
        a["open_findings"] = await db.findings.count_documents(
            {"asset_id": a["id"], "status": {"$in": OPEN}})
        a["critical_high_findings"] = await db.findings.count_documents(
            {"asset_id": a["id"], "status": {"$in": OPEN}, "severity": {"$in": ["Critical", "High"]}})
    assets.sort(key=lambda a: -a.get("critical_high_findings", 0))
    return {"items": assets, "total": len(assets)}


@router.post("/v1/security-reviews/{review_id}/assets")
async def link_assets(review_id: str, body: LinkAssetsBody,
                       user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    """Link in-scope assets individually, by team, by tag, or any combination.
    Bulk selectors resolve to concrete asset ids at link time -- a review's scope
    is a fixed list of assets, not a live query, so it stays reproducible when
    someone re-tags a host six months later."""
    await _get_review_or_404(review_id)
    await _reject_if_closed(review_id)
    resolved: set = set(body.asset_ids or [])
    matched_by = {"explicit": len(body.asset_ids or []), "teams": {}, "tags": {}}
    for team in body.teams or []:
        ids = [a["id"] for a in await db.assets.find({"owner_team": team}, {"_id": 0, "id": 1}).to_list(5000)]
        matched_by["teams"][team] = len(ids)
        resolved.update(ids)
    for tag in body.tags or []:
        ids = [a["id"] for a in await db.assets.find({"tags": tag}, {"_id": 0, "id": 1}).to_list(5000)]
        matched_by["tags"][tag] = len(ids)
        resolved.update(ids)
    if not resolved:
        raise HTTPException(400, "Nothing matched -- provide asset_ids, teams, or tags that exist")

    r = await _get_review_or_404(review_id)
    current = set() if body.replace else set(r.get("linked_asset_ids") or [])
    added = resolved - current
    final = sorted(current | resolved)
    await db.security_reviews.update_one({"id": review_id}, {"$set": {
        "linked_asset_ids": final, "updated_at": now_iso()}})
    detail = f"{len(added)} asset(s) added"
    if body.teams:
        detail += f" (teams: {', '.join(body.teams)})"
    if body.tags:
        detail += f" (tags: {', '.join(body.tags)})"
    await audit(db, review_id, "assets_linked", user.get("email", "?"), detail)
    return {"ok": True, "linked_total": len(final), "added": len(added), "matched_by": matched_by}


@router.post("/v1/security-reviews/{review_id}/assets/unlink")
async def unlink_assets(review_id: str, body: UnlinkAssetsBody,
                         user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    r = await _get_review_or_404(review_id)
    await _reject_if_closed(review_id)
    # POST rather than DELETE: a DELETE carrying a request body is inconsistently
    # supported across HTTP clients and proxies, and this needs a list of ids.
    remaining = [a for a in (r.get("linked_asset_ids") or []) if a not in set(body.asset_ids)]
    await db.security_reviews.update_one({"id": review_id}, {"$set": {
        "linked_asset_ids": remaining, "updated_at": now_iso()}})
    await audit(db, review_id, "assets_unlinked", user.get("email", "?"),
                f"{len(body.asset_ids)} asset(s) removed")
    return {"ok": True, "linked_total": len(remaining)}


@router.get("/v1/security-reviews/{review_id}/attachments")
async def list_attachments(review_id: str, user: dict = Depends(require_module(MODULE_KEY))):
    """Review-level supporting documents. Step evidence stays attached to its
    step; this is for everything that belongs to the review as a whole --
    contracts, SOC 2 reports, vendor questionnaire responses, screenshots."""
    await _get_review_or_404(review_id)
    items = await db.security_review_attachments.find(
        {"review_id": review_id}, {"_id": 0}).sort("uploaded_at", -1).to_list(200)
    return {"items": items}


@router.post("/v1/security-reviews/{review_id}/attachments")
async def add_attachment(review_id: str, body: AttachmentBody,
                          user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    await _get_review_or_404(review_id)
    await _reject_if_closed(review_id)
    if not body.data_url.startswith("data:"):
        raise HTTPException(400, "data_url must be a base64 data URL")
    # Rough size guard -- base64 inflates ~33%; keep a single doc under ~10MB.
    if len(body.data_url) > 14_000_000:
        raise HTTPException(413, "Attachment is too large (10MB limit per file)")
    doc = {"id": str(uuid.uuid4()), "review_id": review_id, "name": body.name,
           "mime": body.mime, "data_url": body.data_url, "description": body.description,
           "category": body.category, "size_bytes": int(len(body.data_url) * 0.75),
           "uploaded_by": user.get("email"), "uploaded_at": now_iso()}
    await db.security_review_attachments.insert_one(dict(doc))
    await audit(db, review_id, "attachment_added", user.get("email", "?"),
                f"{body.name} ({body.category})")
    return {k: v for k, v in doc.items() if k != "data_url"}


@router.delete("/v1/security-reviews/{review_id}/attachments/{attachment_id}")
async def delete_attachment(review_id: str, attachment_id: str,
                             user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    await _reject_if_closed(review_id)
    result = await db.security_review_attachments.delete_one(
        {"id": attachment_id, "review_id": review_id})
    if result.deleted_count == 0:
        raise HTTPException(404, "Attachment not found")
    await audit(db, review_id, "attachment_deleted", user.get("email", "?"), attachment_id)
    return {"ok": True}


@router.put("/v1/security-reviews/{review_id}/risk-score")
async def set_risk_score(review_id: str, body: RiskScoreBody,
                          user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    await _get_review_or_404(review_id)
    await _reject_if_closed(review_id)
    inherent = score_rating(body.inherent_likelihood, body.inherent_impacts)
    if not inherent["band"]:
        raise HTTPException(400, "Inherent risk needs a likelihood (1-5) and at least one impact dimension scored")
    # Phase 3: overriding the displayed suggested rating requires a justification.
    # Never auto-finalized -- the analyst's score always wins, it just has to say why.
    if body.suggested_band and body.suggested_band != inherent["band"] and not body.override_justification.strip():
        raise HTTPException(400, f"Your inherent rating ({inherent['band']}) differs from the suggested rating "
                                  f"({body.suggested_band}) -- an override justification is required.")
    residual = None
    if body.residual_likelihood and body.residual_impacts:
        residual = score_rating(body.residual_likelihood, body.residual_impacts)
    not_adopting = None
    if body.not_adopting_likelihood and body.not_adopting_impacts:
        not_adopting = score_rating(body.not_adopting_likelihood, body.not_adopting_impacts)
    await db.security_reviews.update_one({"id": review_id}, {"$set": {
        "inherent_risk": inherent, "residual_risk": residual, "risk_of_not_adopting": not_adopting,
        "compensating_controls": body.compensating_controls,
        "analyst_override_justification": body.override_justification,
        "updated_at": now_iso(),
    }})
    await audit(db, review_id, "risk_scored", user.get("email", "?"),
                f"Inherent {inherent['band']}" + (f", residual {residual['band']}" if residual else "") +
                (f", not-adopting {not_adopting['band']}" if not_adopting else ""))
    return {"inherent_risk": inherent, "residual_risk": residual, "risk_of_not_adopting": not_adopting}


# --------------------------- findings / conditions ---------------------------

@router.post("/v1/security-reviews/{review_id}/findings")
async def create_review_finding(review_id: str, body: ReviewFindingBody,
                                 user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    await _get_review_or_404(review_id)
    await _reject_if_closed(review_id)
    if body.severity not in ("Critical", "High", "Medium", "Low"):
        raise HTTPException(400, "severity must be Critical/High/Medium/Low")
    doc = {
        "id": str(uuid.uuid4()), "review_id": review_id, "description": body.description,
        "severity": body.severity, "category": body.category, "affected_component": body.affected_component,
        "cis_mapping": body.cis_mapping, "recommendation": body.recommendation, "owner": body.owner,
        "due_date": body.due_date, "status": "open",
        "is_condition_of_approval": body.is_condition_of_approval,
        "condition_met": ("pending" if body.is_condition_of_approval else None),
        "condition_deadline": body.condition_deadline,
        "promoted_to_risk_register_id": None,
        "created_by": user.get("email"), "created_at": now_iso(),
    }
    await db.security_review_findings.insert_one(dict(doc))
    await audit(db, review_id, "finding_created", user.get("email", "?"),
                f"[{body.severity}] {body.description[:120]}" +
                (" (condition of approval)" if body.is_condition_of_approval else ""))
    return doc


@router.patch("/v1/security-reviews/{review_id}/findings/{finding_id}")
async def update_review_finding(review_id: str, finding_id: str, body: ReviewFindingUpdateBody,
                                 user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    await _get_review_or_404(review_id)
    await _reject_if_closed(review_id)
    f = await db.security_review_findings.find_one({"id": finding_id, "review_id": review_id}, {"_id": 0})
    if not f:
        raise HTTPException(404, "Finding not found")
    changes = {k: v for k, v in body.dict().items() if v is not None}
    if not changes:
        return f
    if "condition_met" in changes and changes["condition_met"] not in ("met", "not_met", "pending"):
        raise HTTPException(400, "condition_met must be met/not_met/pending")
    await db.security_review_findings.update_one({"id": finding_id}, {"$set": changes})
    await audit(db, review_id, "finding_updated", user.get("email", "?"),
                f"{f['description'][:80]}: {', '.join(changes.keys())}")
    return await db.security_review_findings.find_one({"id": finding_id}, {"_id": 0})


@router.delete("/v1/security-reviews/{review_id}/findings/{finding_id}")
async def delete_review_finding(review_id: str, finding_id: str,
                                 user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    await _get_review_or_404(review_id)
    await _reject_if_closed(review_id)
    result = await db.security_review_findings.delete_one({"id": finding_id, "review_id": review_id})
    if result.deleted_count == 0:
        raise HTTPException(404, "Finding not found")
    await audit(db, review_id, "finding_deleted", user.get("email", "?"), finding_id)
    return {"ok": True}


@router.post("/v1/security-reviews/{review_id}/findings/{finding_id}/promote")
async def promote_finding_to_risk_register(review_id: str, finding_id: str,
                                            user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    """One-click promotion into the (already-built) Risk Register: creates a
    linked db.risks entry and records the linkage both ways. The spec queued this
    for Phase 3 'when the register exists' -- it exists, so it's wired now."""
    r = await _get_review_or_404(review_id)
    f = await db.security_review_findings.find_one({"id": finding_id, "review_id": review_id}, {"_id": 0})
    if not f:
        raise HTTPException(404, "Finding not found")
    if f.get("promoted_to_risk_register_id"):
        raise HTTPException(409, "Already promoted to the Risk Register")
    sev_to_impact = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2}
    impact = sev_to_impact.get(f.get("severity"), 3)
    risk = {
        "id": str(uuid.uuid4()),
        "title": f"[{r['review_number']}] {f['description'][:140]}",
        "description": (f"Promoted from Security Review {r['review_number']} ({r['title']}).\n\n"
                        f"Finding: {f['description']}\n\nRecommendation: {f.get('recommendation') or '—'}"),
        "category": "Third-party" if r.get("entity_name") else "Technical",
        "likelihood": 3, "impact": impact,
        "inherent_score": 3 * impact,
        "treatment_strategy": "Mitigate", "treatment_plan": f.get("recommendation") or "",
        "residual_likelihood": None, "residual_impact": None,
        "owner": f.get("owner") or r.get("assignee"), "status": "Open",
        "review_cadence": "Quarterly",
        "linked_finding_ids": [], "linked_asset_ids": [], "linked_exception_ids": [],
        "linked_albert_alert_ids": [], "linked_ir_case_ids": [],
        "external_reference": r.get("entity_name"),
        "tags": ["security-review", r["review_number"]],
        "source_review_id": review_id, "source_review_finding_id": finding_id,
        "created_by": user.get("email"), "created_at": now_iso(), "updated_at": now_iso(),
        "last_reviewed_at": None,
    }
    await db.risks.insert_one(dict(risk))
    await db.security_review_findings.update_one({"id": finding_id},
                                                  {"$set": {"promoted_to_risk_register_id": risk["id"]}})
    await audit(db, review_id, "finding_promoted", user.get("email", "?"),
                f"→ Risk Register {risk['id']}: {f['description'][:80]}")
    return {"ok": True, "risk_id": risk["id"]}


# --------------------------- decision ---------------------------

@router.put("/v1/security-reviews/{review_id}/decision")
async def set_decision(review_id: str, body: DecisionBody,
                        user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    await _get_review_or_404(review_id)
    await _reject_if_closed(review_id)
    if body.outcome not in DECISION_OUTCOMES:
        raise HTTPException(400, f"outcome must be one of {DECISION_OUTCOMES}")
    decision = {
        "outcome": body.outcome, "rationale": body.rationale,
        "decision_maker": body.decision_maker or user.get("email"),
        "decision_date": now_iso(), "expiration_date": body.expiration_date,
        "requestor_acknowledged": body.requestor_acknowledged,
        "requestor_acknowledged_date": now_iso() if body.requestor_acknowledged else None,
    }
    await db.security_reviews.update_one({"id": review_id}, {"$set": {
        "decision": decision, "status": "Decision Issued", "updated_at": now_iso(),
    }})
    await audit(db, review_id, "decision_recorded", user.get("email", "?"),
                f"{body.outcome} by {decision['decision_maker']}")
    return decision


# --------------------------- notes / audit / prior lookup / report ---------------------------

@router.get("/v1/security-reviews/{review_id}/notes")
async def list_notes(review_id: str, user: dict = Depends(require_module(MODULE_KEY))):
    await _get_review_or_404(review_id)
    items = await db.security_review_notes.find({"review_id": review_id}, {"_id": 0}).sort("at", -1).to_list(500)
    return {"items": items}


@router.post("/v1/security-reviews/{review_id}/notes")
async def add_note(review_id: str, body: NoteBody,
                    user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    await _get_review_or_404(review_id)
    await _reject_if_closed(review_id)
    # Item 21: the Notes tab was double-submitting (Enter + click, or a repeated
    # keypress) and creating two identical rows. The frontend now guards with an
    # in-flight ref, and this is the server-side backstop: an identical note from
    # the same author within 5 seconds is treated as the same submission and
    # returns the existing row instead of inserting a duplicate.
    from datetime import datetime as _dt, timezone as _tz, timedelta as _td
    cutoff = (_dt.now(_tz.utc) - _td(seconds=5)).isoformat()
    dup = await db.security_review_notes.find_one(
        {"review_id": review_id, "author": user.get("email"), "text": body.text,
         "at": {"$gte": cutoff}}, {"_id": 0})
    if dup:
        return dup
    doc = {"id": str(uuid.uuid4()), "review_id": review_id, "text": body.text,
           "html": body.html, "author": user.get("email"), "at": now_iso()}
    await db.security_review_notes.insert_one(dict(doc))
    return doc


@router.get("/v1/security-reviews/{review_id}/audit")
async def review_audit_log(review_id: str, user: dict = Depends(require_module(MODULE_KEY))):
    await _get_review_or_404(review_id)
    items = await db.security_review_audit.find({"review_id": review_id}, {"_id": 0}).sort("at", -1).to_list(1000)
    return {"items": items}


@router.get("/v1/security-reviews/{review_id}/export.docx")
async def export_review_docx(review_id: str, user: dict = Depends(require_module(MODULE_KEY))):
    """Item 39 -- editable Word export alongside the existing print/PDF path.
    Uses a dedicated style-mapped generator (security_review_docx.py) rather
    than an HTML conversion, so the result stays editable and imports cleanly
    into Google Docs."""
    from fastapi.responses import Response
    from security_review_docx import build_review_docx
    data = await report_data(review_id, user)
    blob = build_review_docx(data)
    review_number = (data["review"].get("review_number") or "security-review")
    return Response(
        content=blob,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": f'attachment; filename="{review_number}-report.docx"'},
    )


@router.get("/v1/security-reviews/{review_id}/prior-reviews")
async def review_prior_lookup(review_id: str, user: dict = Depends(require_module(MODULE_KEY))):
    """Phase 1's one auto-fill hook -- the "What we already know" panel."""
    r = await _get_review_or_404(review_id)
    return await prior_reviews_lookup(db, entity_name=r.get("entity_name"),
                                       domain=r.get("entity_domain"), exclude_review_id=review_id)


@router.get("/v1/security-reviews/{review_id}/report-data")
async def report_data(review_id: str, user: dict = Depends(require_module(MODULE_KEY))):
    """Everything the print-styled report view needs in one call: the review
    (risk badges, decision, classifications), findings sorted worst-first,
    questionnaire + responses for the technical appendix, and version stamps."""
    r = await _get_review_or_404(review_id)
    findings = await db.security_review_findings.find({"review_id": review_id}, {"_id": 0}).to_list(200)
    sev_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    findings.sort(key=lambda f: sev_rank.get(f.get("severity"), 4))
    responses = await db.security_review_responses.find({"review_id": review_id}, {"_id": 0}).to_list(200)
    template = None
    if r.get("template_version_id"):
        template = await db.review_questionnaires.find_one({"id": r["template_version_id"]}, {"_id": 0})
    steps = await db.security_review_steps.find({"review_id": review_id}, {"_id": 0}).sort("order", 1).to_list(100)
    interviews = await db.security_review_interviews.find({"review_id": review_id}, {"_id": 0}).to_list(100)
    # Phase 2: pre-drafted plain-English executive summary -- the analyst's saved
    # edit wins; otherwise generate boilerplate from severity/category/ratings.
    summary = r.get("executive_summary") or draft_executive_summary(r, findings)
    return {
        "review": r, "findings": findings, "responses": responses,
        "questionnaire": template, "steps": steps, "interviews": interviews,
        "executive_summary": summary,
        # Item 23: the 5x5 matrix points, so the report can draw the same grid the
        # Risk Scoring tab shows instead of the reader having to open the app.
        "matrix_points": _matrix_points(r),
        # Item 27: the compensating controls documented during scoring are the
        # whole reason residual < inherent -- they belong next to the verdict.
        "compensating_controls": r.get("compensating_controls") or "",
        "recommendation": r.get("recommendation"),
        # Everything else that belongs in a complete report: the work that was
        # done (notes), what was in scope (assets), what we verified externally,
        # and the supporting paperwork.
        "notes": await db.security_review_notes.find(
            {"review_id": review_id}, {"_id": 0}).sort("at", 1).to_list(500),
        "external_checks": r.get("external_checks"),
        "attachments": await db.security_review_attachments.find(
            {"review_id": review_id}, {"_id": 0, "data_url": 0}).sort("uploaded_at", 1).to_list(200),
        "linked_assets": await _linked_asset_summary(db, r),
        "questionnaire_scoring": await _report_questionnaire_scoring(db, r),
        "audit_trail": await db.security_review_audit.find(
            {"review_id": review_id}, {"_id": 0}).sort("at", -1).to_list(200),
        # The layout is configuration: the print view, the shared copy and the
        # Word export all render from this same resolved block list.
        "layout": resolve_layout(await active_template(db), shared=False),
        "template": {k: v for k, v in (await active_template(db)).items() if k != "blocks"},
        "generated_at": now_iso(),
    }


# --------------------------- reviewed entities catalog ---------------------------

@router.get("/v1/reviewed-entities")
async def list_reviewed_entities(q: Optional[str] = None,
                                  user: dict = Depends(require_module(MODULE_KEY))):
    flt: dict = {}
    if q:
        flt["name"] = {"$regex": q, "$options": "i"}
    items = await db.reviewed_entities.find(flt, {"_id": 0}).sort("name", 1).to_list(500)
    return {"items": items}


# =========================================================================
# Phase 2/3 endpoints
# =========================================================================

class VendorQTrackBody(BaseModel):
    sent: Optional[bool] = None
    received: Optional[bool] = None


class InterviewBody(BaseModel):
    who: str
    role: str = ""
    when: Optional[str] = None
    summary: str = ""


class ShareLinkBody(BaseModel):
    expires_days: int = 30


class ComparisonBody(BaseModel):
    review_ids: List[str]


class ExecSummaryBody(BaseModel):
    text: str


class RecommendationBody(BaseModel):
    """Item 24 -- the ANALYST's proposed path, deliberately separate from the
    Decision (what leadership actually decided). Both render in the report."""
    what_was_reviewed: str = ""
    why: str = ""
    recommendation: str = ""          # e.g. "Approve with conditions"
    rationale: str = ""


class AcknowledgeBody(BaseModel):
    acknowledged: bool = True


class ReassignBody(BaseModel):
    assignee: str


class ShareGrantBody(BaseModel):
    """Item 26 -- access-controlled sharing. Either an external email (recipient
    must enter a one-time verification code sent to that address) or an existing
    platform user (must be logged in as them). Anyone-with-the-link is gone."""
    email: Optional[str] = None
    platform_user_email: Optional[str] = None
    expires_days: int = 30


class ShareVerifyBody(BaseModel):
    code: str




class PlaybookVersionBody(BaseModel):
    key: str
    name: str
    review_types: List[str] = []
    steps: List[dict]


class QuestionnaireVersionBody(BaseModel):
    key: str
    name: str
    questions: List[dict]


class EntityUpdateBody(BaseModel):
    domain: Optional[str] = None
    next_review_date: Optional[str] = None
    certifications: Optional[List[dict]] = None   # [{name, expires_at}]


@router.get("/v1/security-reviews/{review_id}/autofill/{hook}")
async def run_autofill_hook(review_id: str, hook: str, user: dict = Depends(require_module(MODULE_KEY))):
    """Phase 2 auto-fill hooks: asset_inventory_check / open_findings_pull /
    osint_compromise_pull / governance_crosswalk. Read-only except
    asset_inventory_check's shadow-deployment draft finding."""
    r = await _get_review_or_404(review_id)
    fn = AUTOFILL_HOOKS.get(hook)
    if not fn:
        raise HTTPException(404, f"Unknown auto-fill hook: {hook} (have: {sorted(AUTOFILL_HOOKS)})")
    return await fn(db, r)


@router.post("/v1/security-reviews/{review_id}/auto-answer")
async def auto_answer(review_id: str, user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    r = await _get_review_or_404(review_id)
    await _reject_if_closed(review_id)
    template = None
    if r.get("template_version_id"):
        template = await db.review_questionnaires.find_one({"id": r["template_version_id"]}, {"_id": 0})
    if not template:
        template = await latest_questionnaire(db)
    answered = await auto_answer_questions(db, r, template or {})
    if answered:
        await audit(db, review_id, "auto_answered", user.get("email", "?"),
                    f"{len(answered)} question(s) auto-answered from platform data")
    return {"answered": answered}


@router.get("/v1/security-reviews/{review_id}/vendor-questionnaire")
async def vendor_questionnaire(review_id: str, user: dict = Depends(require_module(MODULE_KEY))):
    r = await _get_review_or_404(review_id)
    template = None
    if r.get("template_version_id"):
        template = await db.review_questionnaires.find_one({"id": r["template_version_id"]}, {"_id": 0})
    if not template:
        template = await latest_questionnaire(db)
    responses = await db.security_review_responses.find({"review_id": review_id}, {"_id": 0}).to_list(200)
    compiled = compile_vendor_questionnaire(r, template or {}, responses)
    compiled["sent_at"] = r.get("vendor_q_sent_at")
    compiled["received_at"] = r.get("vendor_q_received_at")
    return compiled


@router.post("/v1/security-reviews/{review_id}/vendor-questionnaire/track")
async def vendor_questionnaire_track(review_id: str, body: VendorQTrackBody,
                                      user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    """Sent/received tracking. Sending auto-pauses the SLA clock (awaiting the
    vendor is out of our hands); receipt resumes it -- same clock the Pending
    Info status uses, so pauses never double-count."""
    r = await _get_review_or_404(review_id)
    await _reject_if_closed(review_id)
    changes: dict = {}
    if body.sent:
        changes["vendor_q_sent_at"] = now_iso()
        if not r.get("sla_paused_at"):
            changes["sla_paused_at"] = now_iso()
        await audit(db, review_id, "vendor_questionnaire_sent", user.get("email", "?"), "")
    if body.received:
        changes["vendor_q_received_at"] = now_iso()
        if r.get("sla_paused_at"):
            from datetime import datetime as _dt, timezone as _tz
            try:
                paused = (_dt.now(_tz.utc) - _dt.fromisoformat(r["sla_paused_at"])).total_seconds()
            except Exception:
                paused = 0
            changes["sla_paused_total_seconds"] = (r.get("sla_paused_total_seconds") or 0) + int(paused)
            changes["sla_paused_at"] = None
        await audit(db, review_id, "vendor_questionnaire_received", user.get("email", "?"), "")
    if changes:
        await db.security_reviews.update_one({"id": review_id}, {"$set": changes})
    return {"ok": True, **{k: v for k, v in changes.items()}}


@router.get("/v1/security-reviews/{review_id}/interviews")
async def list_interviews(review_id: str, user: dict = Depends(require_module(MODULE_KEY))):
    await _get_review_or_404(review_id)
    items = await db.security_review_interviews.find({"review_id": review_id}, {"_id": 0}).sort("when", -1).to_list(100)
    return {"items": items}


@router.post("/v1/security-reviews/{review_id}/interviews")
async def add_interview(review_id: str, body: InterviewBody,
                         user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    await _get_review_or_404(review_id)
    await _reject_if_closed(review_id)
    doc = {"id": str(uuid.uuid4()), "review_id": review_id, "who": body.who, "role": body.role,
           "when": body.when or now_iso()[:10], "summary": body.summary,
           "captured_by": user.get("email"), "captured_at": now_iso()}
    await db.security_review_interviews.insert_one(dict(doc))
    await audit(db, review_id, "interview_captured", user.get("email", "?"), f"{body.who} ({body.role})")
    return doc


@router.put("/v1/security-reviews/{review_id}/executive-summary")
async def set_exec_summary(review_id: str, body: ExecSummaryBody,
                            user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    await _get_review_or_404(review_id)
    await _reject_if_closed(review_id)
    await db.security_reviews.update_one({"id": review_id}, {"$set": {
        "executive_summary": body.text, "updated_at": now_iso()}})
    return {"ok": True}


@router.post("/v1/security-reviews/{review_id}/share")
async def create_share_grant(review_id: str, body: ShareGrantBody,
                              user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    """Item 26 -- ACCESS-CONTROLLED sharing, replacing the previous
    anyone-with-the-link token. Two mutually-exclusive modes:

      email=...                a one-time 6-digit verification code is emailed to
                               that address; the recipient must enter it to open
                               the report. The link alone is useless.
      platform_user_email=...  grants an existing platform user access; they must
                               be logged in as that user to view it.

    Either way the grant is scoped to a named recipient, expires, and every view
    is recorded on the grant (who/when/how many)."""
    await _get_review_or_404(review_id)
    if bool(body.email) == bool(body.platform_user_email):
        raise HTTPException(400, "Provide exactly one of email (external, code-verified) "
                                  "or platform_user_email (existing platform user)")
    from datetime import datetime as _dt, timezone as _tz, timedelta as _td
    import secrets
    token = secrets.token_urlsafe(24)
    expires = (_dt.now(_tz.utc) + _td(days=max(1, min(body.expires_days, 365)))).isoformat()

    grant = {
        "id": str(uuid.uuid4()), "token": token, "review_id": review_id,
        "mode": "email_code" if body.email else "platform_user",
        "recipient": (body.email or body.platform_user_email or "").strip().lower(),
        "code": None, "verified": False, "view_count": 0, "last_viewed_at": None,
        "revoked": False,
        "created_by": user.get("email"), "created_at": now_iso(), "expires_at": expires,
    }
    emailed = False
    if body.email:
        code = f"{secrets.randbelow(1000000):06d}"
        grant["code"] = code
        review = await _get_review_or_404(review_id)
        try:
            from notifier import send_email_with_attachment
            await send_email_with_attachment(
                grant["recipient"],
                f"Security Review {review.get('review_number')} — access code",
                f"You've been given access to the security review report for "
                f"\"{review.get('title')}\".\n\n"
                f"Your one-time access code is: {code}\n\n"
                f"This code and link expire on {expires[:10]}.",
                [],
            )
            emailed = True
        except Exception:
            # SMTP not configured / unreachable -- the grant is still valid, the
            # sharer just has to hand the code over another way. Never silently
            # fall back to an unauthenticated link.
            emailed = False
    if body.platform_user_email:
        target = await db.users.find_one({"email": grant["recipient"]}, {"_id": 0, "id": 1})
        if not target:
            raise HTTPException(404, f"No platform user with email {grant['recipient']}")

    await db.security_review_share_grants.insert_one(dict(grant))
    await audit(db, review_id, "share_granted", user.get("email", "?"),
                f"{grant['mode']} → {grant['recipient']}, expires {expires[:10]}")
    return {"token": token, "mode": grant["mode"], "recipient": grant["recipient"],
            "expires_at": expires, "url": f"/shared-report/{token}",
            "code_emailed": emailed,
            "code": None if emailed else grant["code"]}


@router.get("/v1/security-reviews/{review_id}/shares")
async def list_share_grants(review_id: str, user: dict = Depends(require_module(MODULE_KEY))):
    await _get_review_or_404(review_id)
    items = await db.security_review_share_grants.find(
        {"review_id": review_id}, {"_id": 0, "code": 0, "token": 0}).sort("created_at", -1).to_list(100)
    return {"items": items}


@router.delete("/v1/security-reviews/{review_id}/shares/{grant_id}")
async def revoke_share_grant(review_id: str, grant_id: str,
                              user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    result = await db.security_review_share_grants.update_one(
        {"id": grant_id, "review_id": review_id}, {"$set": {"revoked": True}})
    if result.matched_count == 0:
        raise HTTPException(404, "Share grant not found")
    await audit(db, review_id, "share_revoked", user.get("email", "?"), grant_id)
    return {"ok": True}


async def _resolve_grant(token: str) -> dict:
    grant = await db.security_review_share_grants.find_one({"token": token}, {"_id": 0})
    if not grant or grant.get("revoked") or grant["expires_at"] < now_iso():
        raise HTTPException(404, "This report link is invalid, revoked, or has expired.")
    return grant


async def _linked_asset_summary(db, r: dict) -> list:
    ids = r.get("linked_asset_ids") or []
    if not ids:
        return []
    OPEN = ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]
    assets = await db.assets.find(
        {"id": {"$in": ids}},
        {"_id": 0, "id": 1, "hostname": 1, "ip": 1, "owner_team": 1, "criticality": 1,
         "tags": 1, "internet_facing": 1}).to_list(2000)
    for a in assets:
        a["open_findings"] = await db.findings.count_documents(
            {"asset_id": a["id"], "status": {"$in": OPEN}})
        a["critical_high_findings"] = await db.findings.count_documents(
            {"asset_id": a["id"], "status": {"$in": OPEN}, "severity": {"$in": ["Critical", "High"]}})
    assets.sort(key=lambda a: -a.get("critical_high_findings", 0))
    return assets


async def _report_questionnaire_scoring(db, r: dict) -> Optional[dict]:
    """Confidence read for the report, so a rating never appears more precise
    than the evidence behind it."""
    template = await db.review_questionnaires.find_one({"id": r.get("template_version_id")}, {"_id": 0})
    if not template or template.get("engine") != "capability_gated":
        return None
    responses = await db.security_review_responses.find(
        {"review_id": r["id"]}, {"_id": 0}).to_list(300)
    applicable = applicable_questions(template, r.get("capabilities") or {},
                                       r.get("data_classifications") or [])
    applicable += await custom_questions_for(db, r["id"])
    score = score_questionnaire(applicable, responses)
    band = (r.get("residual_risk") or {}).get("band") or (r.get("inherent_risk") or {}).get("band")
    return {**score, "summary": confidence_note(score, band)}


def _matrix_points(r: dict) -> list:
    """The inherent/residual/not-adopting positions for the report's 5x5 grid."""
    out = []
    for key, label in (("inherent_risk", "Inherent"), ("residual_risk", "Residual"),
                        ("risk_of_not_adopting", "Not adopting")):
        rating = r.get(key)
        if rating and rating.get("likelihood") and rating.get("max_impact"):
            out.append({"label": label, "likelihood": rating["likelihood"],
                        "impact": rating["max_impact"], "band": rating.get("band")})
    return out


async def _build_shared_payload(review_id: str) -> dict:
    r = await db.security_reviews.find_one({"id": review_id}, {"_id": 0})
    if not r:
        raise HTTPException(404, "Review not found")
    findings = await db.security_review_findings.find(
        {"review_id": review_id, "status": {"$ne": "draft"}}, {"_id": 0}).to_list(200)
    sev_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    findings.sort(key=lambda f: sev_rank.get(f.get("severity"), 4))
    responses = await db.security_review_responses.find({"review_id": review_id}, {"_id": 0}).to_list(300)
    template = None
    if r.get("template_version_id"):
        template = await db.review_questionnaires.find_one({"id": r["template_version_id"]}, {"_id": 0})
    interviews = await db.security_review_interviews.find({"review_id": review_id}, {"_id": 0}).to_list(100)
    summary = r.get("executive_summary") or draft_executive_summary(r, findings)
    return {"review": r, "findings": findings, "responses": responses, "questionnaire": template,
            "interviews": interviews, "executive_summary": summary,
            "matrix_points": _matrix_points(r),
            "compensating_controls": r.get("compensating_controls") or "",
            "recommendation": r.get("recommendation"),
            "external_checks": r.get("external_checks"),
            "linked_assets": await _linked_asset_summary(db, r),
            "attachments": await db.security_review_attachments.find(
                {"review_id": review_id}, {"_id": 0, "data_url": 0}).sort("uploaded_at", 1).to_list(200),
            "questionnaire_scoring": await _report_questionnaire_scoring(db, r),
            # Internal working notes are deliberately EXCLUDED from shared
            # reports -- that promise is part of what makes analysts write
            # candidly in them.
            "notes": [],
            "audit_trail": [],
            # shared=True drops internal-only blocks centrally, so no template
            # edit can leak working notes or the audit trail to a vendor
            "layout": resolve_layout(await active_template(db), shared=True),
            "generated_at": now_iso(), "shared": True}


@router.get("/v1/shared/security-review/{token}/meta")
async def shared_report_meta(token: str):
    """PUBLIC: what kind of verification this link needs, WITHOUT leaking any
    report content. The viewer page calls this first to know which gate to show."""
    grant = await _resolve_grant(token)
    return {"mode": grant["mode"], "recipient_hint": _mask_email(grant["recipient"]),
            "requires_code": grant["mode"] == "email_code" and not grant.get("verified")}


def _mask_email(email: str) -> str:
    if "@" not in email:
        return "***"
    local, domain = email.split("@", 1)
    return f"{local[:2]}{'*' * max(1, len(local) - 2)}@{domain}"


@router.post("/v1/shared/security-review/{token}/verify")
async def shared_report_verify(token: str, body: ShareVerifyBody):
    """PUBLIC: exchange the emailed one-time code for report access. Wrong codes
    are counted and the grant locks after 5 failures."""
    grant = await _resolve_grant(token)
    if grant["mode"] != "email_code":
        raise HTTPException(400, "This link doesn't use a verification code")
    if (grant.get("failed_attempts") or 0) >= 5:
        raise HTTPException(429, "Too many incorrect codes -- ask the sender for a new link.")
    if body.code.strip() != grant.get("code"):
        await db.security_review_share_grants.update_one(
            {"id": grant["id"]}, {"$inc": {"failed_attempts": 1}})
        raise HTTPException(403, "Incorrect code")
    await db.security_review_share_grants.update_one(
        {"id": grant["id"]}, {"$set": {"verified": True, "verified_at": now_iso()},
                               "$unset": {"failed_attempts": ""}})
    payload = await _build_shared_payload(grant["review_id"])
    await db.security_review_share_grants.update_one(
        {"id": grant["id"]}, {"$inc": {"view_count": 1}, "$set": {"last_viewed_at": now_iso()}})
    await audit(db, grant["review_id"], "shared_report_viewed", grant["recipient"], "code verified")
    return payload


@router.get("/v1/shared/security-review/{token}")
async def shared_report(token: str, user: Optional[dict] = Depends(auth_utils.get_current_user_optional)):
    """Resolves a share grant to report data. Access requires EITHER a prior
    successful code verification (external recipients) OR being logged in as the
    granted platform user. There is no anonymous path."""
    grant = await _resolve_grant(token)
    if grant["mode"] == "platform_user":
        if not user or (user.get("email") or "").lower() != grant["recipient"]:
            raise HTTPException(403, "This report was shared with a specific platform user. "
                                      "Sign in as that user to view it.")
    else:
        if not grant.get("verified"):
            raise HTTPException(401, "Enter the access code that was emailed to you.")
    payload = await _build_shared_payload(grant["review_id"])
    await db.security_review_share_grants.update_one(
        {"id": grant["id"]}, {"$inc": {"view_count": 1}, "$set": {"last_viewed_at": now_iso()}})
    return payload


@router.put("/v1/security-reviews/{review_id}/recommendation")
async def set_recommendation(review_id: str, body: RecommendationBody,
                              user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    """Item 24 -- the analyst's Executive Summary / Recommendation, kept separate
    from the Decision. Recommendation = what the reviewer proposes; Decision =
    what leadership actually chose. The report renders both, side by side, so a
    decision that diverges from the recommendation is visible rather than
    quietly overwritten."""
    await _get_review_or_404(review_id)
    await _reject_if_closed(review_id)
    rec = {
        "what_was_reviewed": body.what_was_reviewed, "why": body.why,
        "recommendation": body.recommendation, "rationale": body.rationale,
        "authored_by": user.get("email"), "authored_at": now_iso(),
    }
    await db.security_reviews.update_one({"id": review_id}, {"$set": {
        "recommendation": rec, "updated_at": now_iso()}})
    await audit(db, review_id, "recommendation_set", user.get("email", "?"),
                body.recommendation[:120])
    return rec


@router.post("/v1/security-reviews/{review_id}/reassign")
async def reassign_reviewer(review_id: str, body: ReassignBody,
                             user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    """Item 25 -- reassign the reviewer. Its own audited action rather than a
    silent field edit, since 'who owns this review' is exactly the kind of thing
    an auditor asks about later."""
    r = await _get_review_or_404(review_id)
    await _reject_if_closed(review_id)
    new_assignee = (body.assignee or "").strip().lower()
    if not new_assignee:
        raise HTTPException(400, "assignee is required")
    target = await db.users.find_one({"email": new_assignee}, {"_id": 0, "id": 1, "name": 1})
    if not target:
        raise HTTPException(404, f"No platform user with email {new_assignee}")
    await db.security_reviews.update_one({"id": review_id}, {"$set": {
        "assignee": new_assignee, "updated_at": now_iso()}})
    await audit(db, review_id, "reviewer_reassigned", user.get("email", "?"),
                f"{r.get('assignee') or 'unassigned'} → {new_assignee}")
    return {"ok": True, "assignee": new_assignee}


@router.get("/v1/security-reviews/{review_id}/suggested-risk")
async def suggested_risk(review_id: str, user: dict = Depends(require_module(MODULE_KEY))):
    r = await _get_review_or_404(review_id)
    template = None
    if r.get("template_version_id"):
        template = await db.review_questionnaires.find_one({"id": r["template_version_id"]}, {"_id": 0})
    if not template:
        template = await latest_questionnaire(db)
    responses = await db.security_review_responses.find({"review_id": review_id}, {"_id": 0}).to_list(200)
    return await suggest_risk(db, r, template or {}, responses)


@router.post("/v1/security-reviews/{review_id}/comparison")
async def set_comparison(review_id: str, body: ComparisonBody,
                          user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    """Comparison mode: link this review with sibling reviews of alternative
    candidates evaluated for the same need."""
    await _get_review_or_404(review_id)
    group = sorted(set([review_id] + body.review_ids))
    for rid in group:
        other = await db.security_reviews.find_one({"id": rid}, {"_id": 0, "id": 1})
        if not other:
            raise HTTPException(404, f"Review {rid} not found")
    group_id = str(uuid.uuid4())
    for rid in group:
        await db.security_reviews.update_one({"id": rid}, {"$set": {"comparison_group": group_id}})
    await audit(db, review_id, "comparison_linked", user.get("email", "?"), f"{len(group)} reviews in group")
    return {"comparison_group": group_id, "review_ids": group}


@router.get("/v1/security-reviews/{review_id}/comparison-data")
async def comparison_data(review_id: str, user: dict = Depends(require_module(MODULE_KEY))):
    """Side-by-side data for every review in this review's comparison group:
    ratings, decisions, and per-question answers in columns."""
    r = await _get_review_or_404(review_id)
    if not r.get("comparison_group"):
        return {"reviews": [], "questions": []}
    group = await db.security_reviews.find({"comparison_group": r["comparison_group"]}, {"_id": 0}).to_list(10)
    cols = []
    template = None
    for g in group:
        responses = await db.security_review_responses.find({"review_id": g["id"]}, {"_id": 0}).to_list(200)
        if not template and g.get("template_version_id"):
            template = await db.review_questionnaires.find_one({"id": g["template_version_id"]}, {"_id": 0})
        cols.append({
            "id": g["id"], "review_number": g.get("review_number"), "title": g.get("title"),
            "entity_name": g.get("entity_name"),
            "inherent": (g.get("inherent_risk") or {}).get("band"),
            "residual": (g.get("residual_risk") or {}).get("band"),
            "decision": (g.get("decision") or {}).get("outcome"),
            "answers": {resp["question_order"]: resp["answer"] for resp in responses},
        })
    return {"reviews": cols, "questions": (template or {}).get("questions", [])}


@router.post("/v1/security-reviews/{review_id}/revalidate")
async def revalidate(review_id: str, user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    r = await _get_review_or_404(review_id)
    new = await clone_for_revalidation(db, r, user.get("email", "?"))
    return {"id": new["id"], "review_number": new["review_number"]}


@router.post("/v1/security-reviews/{review_id}/external-checks")
async def external_checks(review_id: str, panel: Optional[str] = None,
                           user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    """Item 30 -- two panels keyed off the reviewed entity: company posture
    (registration, breach reputation, certifications, viability) and technical
    posture (TLS/headers, CVEs, SPF/DKIM/DMARC, Shodan, CT logs, DNS/WHOIS,
    typosquats). Pass ?panel=company or ?panel=technical to run one."""
    r = await _get_review_or_404(review_id)
    await _reject_if_closed(review_id)
    if panel not in (None, "company", "technical"):
        raise HTTPException(400, "panel must be 'company' or 'technical' (omit for both)")
    from external_checks import run_external_checks as run_two_panel_checks
    # r is the freshly-read review, so previously-stored panels come along and a
    # single-panel run merges instead of replacing.
    result = await run_two_panel_checks(db, r, panel=panel)
    ran = []
    for key in ("company_posture", "technical_posture"):
        for c in (result.get(key) or {}).get("results", []):
            ran.append(f"{c['check']}={c['status']}")
    await audit(db, review_id, "external_checks_run", user.get("email", "?"), ", ".join(ran))
    return result


@router.patch("/v1/security-reviews/{review_id}/entity")
async def update_review_entity(review_id: str, body: dict,
                                user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    """Item 30 prerequisite -- the entity needs a domain and a legal company name
    before the two posture panels can do much. This edits them in place from the
    review workspace instead of sending the analyst off to another page."""
    r = await _get_review_or_404(review_id)
    await _reject_if_closed(review_id)
    allowed = {"legal_name", "domain", "jurisdiction", "certifications"}
    changes = {k: v for k, v in (body or {}).items() if k in allowed and v is not None}
    if not changes:
        raise HTTPException(400, f"Provide at least one of {sorted(allowed)}")
    if "domain" in changes:
        changes["domain"] = str(changes["domain"]).strip().lower()
        await db.security_reviews.update_one({"id": review_id},
                                              {"$set": {"entity_domain": changes["domain"]}})
    entity_id = r.get("entity_id")
    if not entity_id:
        entity = await upsert_reviewed_entity(db, name=r.get("entity_name") or r.get("title"),
                                               domain=changes.get("domain"))
        entity_id = entity["id"]
        await db.security_reviews.update_one({"id": review_id}, {"$set": {"entity_id": entity_id}})
    await db.reviewed_entities.update_one({"id": entity_id}, {"$set": changes})
    await audit(db, review_id, "entity_updated", user.get("email", "?"), ", ".join(sorted(changes)))
    return await db.reviewed_entities.find_one({"id": entity_id}, {"_id": 0})


@router.post("/v1/security-reviews/{review_id}/acknowledge")
async def acknowledge_decision(review_id: str, body: AcknowledgeBody,
                                user: dict = Depends(get_current_user)):
    """Requestor acknowledgment of a decision/conditions -- callable by the
    requestor themselves (matched by email), not just module holders."""
    r = await _get_review_or_404(review_id)
    if not r.get("decision"):
        raise HTTPException(400, "No decision to acknowledge yet")
    if r.get("requestor_email") and r["requestor_email"] != user.get("email") and user.get("role") != "admin":
        raise HTTPException(403, "Only the requestor (or an admin) can acknowledge this decision")
    await db.security_reviews.update_one({"id": review_id}, {"$set": {
        "decision.requestor_acknowledged": body.acknowledged,
        "decision.requestor_acknowledged_date": now_iso() if body.acknowledged else None,
    }})
    await audit(db, review_id, "decision_acknowledged", user.get("email", "?"), "")
    return {"ok": True}


# --------------------------- playbook / template admin (Phase 3) ---------------------------

@router.get("/v1/review-playbooks")
async def list_playbooks(user: dict = Depends(require_module(MODULE_KEY))):
    await ensure_seeded(db)
    await ensure_phase2_seeded(db)
    items = await db.review_playbooks.find({}, {"_id": 0}).sort([("key", 1), ("version", -1)]).to_list(100)
    return {"items": items}


@router.post("/v1/review-playbooks")
async def create_playbook_version(body: PlaybookVersionBody,
                                   user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    """Methodology evolves as NEW VERSIONS, never edits -- existing reviews keep
    the version they pinned."""
    if not body.steps:
        raise HTTPException(400, "steps must not be empty")
    for i, s in enumerate(body.steps, start=1):
        if not s.get("title") or not s.get("guidance"):
            raise HTTPException(400, f"step {i} needs title + guidance")
        s["order"] = i
        s.setdefault("step_type", "task")
        s.setdefault("autofill_hook", None)
        s.setdefault("conditional_on", None)
        s.setdefault("allows_na", True)
        s.setdefault("expected_output", "")
    latest = await db.review_playbooks.find({"key": body.key}, {"_id": 0, "version": 1}).sort("version", -1).to_list(1)
    version = (latest[0]["version"] + 1) if latest else 1
    doc = {"id": str(uuid.uuid4()), "key": body.key, "name": body.name, "version": version,
           "review_types": body.review_types, "steps": body.steps,
           "created_by": user.get("email"), "created_at": now_iso()}
    await db.review_playbooks.insert_one(dict(doc))
    return doc


@router.get("/v1/review-questionnaires")
async def list_questionnaires(user: dict = Depends(require_module(MODULE_KEY))):
    await ensure_seeded(db)
    await ensure_phase2_seeded(db)
    items = await db.review_questionnaires.find({}, {"_id": 0}).sort([("key", 1), ("version", -1)]).to_list(100)
    return {"items": items}


@router.post("/v1/review-questionnaires")
async def create_questionnaire_version(body: QuestionnaireVersionBody,
                                        user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    if not body.questions:
        raise HTTPException(400, "questions must not be empty")
    for i, q in enumerate(body.questions, start=1):
        if not q.get("text"):
            raise HTTPException(400, f"question {i} needs text")
        q["order"] = i
        q.setdefault("domain", "General")
        q.setdefault("cis_mapping", "")
        q.setdefault("risk_weight", 3)
        q.setdefault("vendor_facing", False)
        q.setdefault("conditional_on", None)
    latest = await db.review_questionnaires.find({"key": body.key}, {"_id": 0, "version": 1}).sort("version", -1).to_list(1)
    version = (latest[0]["version"] + 1) if latest else 1
    doc = {"id": str(uuid.uuid4()), "key": body.key, "name": body.name, "version": version,
           "questions": body.questions, "created_by": user.get("email"), "created_at": now_iso()}
    await db.review_questionnaires.insert_one(dict(doc))
    return doc


@router.patch("/v1/reviewed-entities/{entity_id}")
async def update_reviewed_entity(entity_id: str, body: EntityUpdateBody,
                                  user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    e = await db.reviewed_entities.find_one({"id": entity_id}, {"_id": 0})
    if not e:
        raise HTTPException(404, "Entity not found")
    changes = {k: v for k, v in body.dict().items() if v is not None}
    if changes:
        await db.reviewed_entities.update_one({"id": entity_id}, {"$set": changes})
    return await db.reviewed_entities.find_one({"id": entity_id}, {"_id": 0})
