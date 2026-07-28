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
from auth_utils import get_current_user

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


class ResponseBody(BaseModel):
    question_order: int
    answer: str                             # yes | no | partial | na
    evidence_text: str = ""
    attachments: List[dict] = []


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
    text: str


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
    return {
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
    template = await latest_questionnaire(db)
    review = {
        "id": str(uuid.uuid4()), "review_number": await next_review_number(db),
        "title": body.title.strip(), "review_type": body.review_type, "status": "Requested",
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
    return {"review": r, "steps": steps, "responses": responses, "findings": findings,
            "questionnaire": template}


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
    existing = await db.security_review_responses.find_one(
        {"review_id": review_id, "question_order": body.question_order}, {"_id": 0})
    was_auto = bool(existing and existing.get("auto_answered"))
    doc = {
        "review_id": review_id, "question_order": body.question_order, "answer": body.answer,
        "evidence_text": body.evidence_text, "attachments": body.attachments,
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
    doc = {"id": str(uuid.uuid4()), "review_id": review_id, "text": body.text,
           "author": user.get("email"), "at": now_iso()}
    await db.security_review_notes.insert_one(dict(doc))
    return doc


@router.get("/v1/security-reviews/{review_id}/audit")
async def review_audit_log(review_id: str, user: dict = Depends(require_module(MODULE_KEY))):
    await _get_review_or_404(review_id)
    items = await db.security_review_audit.find({"review_id": review_id}, {"_id": 0}).sort("at", -1).to_list(1000)
    return {"items": items}


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


class AcknowledgeBody(BaseModel):
    acknowledged: bool = True


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


@router.post("/v1/security-reviews/{review_id}/share-link")
async def create_share_link(review_id: str, body: ShareLinkBody,
                             user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    """Read-only tokenized report link with expiration -- stakeholders view the
    report without an app account. The token grants access to the REPORT only
    (never working notes)."""
    await _get_review_or_404(review_id)
    from datetime import datetime as _dt, timezone as _tz, timedelta as _td
    import secrets
    token = secrets.token_urlsafe(24)
    expires = (_dt.now(_tz.utc) + _td(days=max(1, min(body.expires_days, 365)))).isoformat()
    await db.security_review_share_tokens.insert_one({
        "id": str(uuid.uuid4()), "token": token, "review_id": review_id,
        "created_by": user.get("email"), "created_at": now_iso(), "expires_at": expires,
    })
    await audit(db, review_id, "share_link_created", user.get("email", "?"), f"expires {expires[:10]}")
    return {"token": token, "expires_at": expires, "url": f"/shared-report/{token}"}


@router.get("/v1/shared/security-review/{token}")
async def shared_report(token: str):
    """PUBLIC (no auth): resolves a share token to report data. Working notes are
    structurally excluded -- this reuses report-data's shape minus anything
    internal."""
    doc = await db.security_review_share_tokens.find_one({"token": token}, {"_id": 0})
    if not doc or doc["expires_at"] < now_iso():
        raise HTTPException(404, "This report link is invalid or has expired.")
    r = await db.security_reviews.find_one({"id": doc["review_id"]}, {"_id": 0})
    if not r:
        raise HTTPException(404, "Review not found")
    findings = await db.security_review_findings.find(
        {"review_id": r["id"], "status": {"$ne": "draft"}}, {"_id": 0}).to_list(200)
    sev_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    findings.sort(key=lambda f: sev_rank.get(f.get("severity"), 4))
    responses = await db.security_review_responses.find({"review_id": r["id"]}, {"_id": 0}).to_list(200)
    template = None
    if r.get("template_version_id"):
        template = await db.review_questionnaires.find_one({"id": r["template_version_id"]}, {"_id": 0})
    interviews = await db.security_review_interviews.find({"review_id": r["id"]}, {"_id": 0}).to_list(100)
    summary = r.get("executive_summary") or draft_executive_summary(r, findings)
    return {"review": r, "findings": findings, "responses": responses, "questionnaire": template,
            "interviews": interviews, "executive_summary": summary, "generated_at": now_iso(),
            "shared": True}


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
async def external_checks(review_id: str, user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    r = await _get_review_or_404(review_id)
    await _reject_if_closed(review_id)
    result = await run_external_checks(db, r)
    await audit(db, review_id, "external_checks_run", user.get("email", "?"),
                ", ".join(f"{c['check']}={c['status']}" for c in result["results"]))
    return result


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
