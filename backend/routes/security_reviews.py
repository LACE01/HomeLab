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
            await db.reviewed_entities.update_one({"id": r["entity_id"]}, {"$set": {
                "current_rating": (r.get("residual_risk") or {}).get("band"),
                "last_review_id": review_id,
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
    doc = {
        "review_id": review_id, "question_order": body.question_order, "answer": body.answer,
        "evidence_text": body.evidence_text, "attachments": body.attachments,
        "auto_answered": False, "source_tag": "Analyst", "analyst_overridden": False,
        "answered_by": user.get("email"), "answered_at": now_iso(),
    }
    if existing:
        await db.security_review_responses.update_one(
            {"review_id": review_id, "question_order": body.question_order}, {"$set": doc})
    else:
        doc["id"] = str(uuid.uuid4())
        await db.security_review_responses.insert_one(dict(doc))
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
    return {
        "review": r, "findings": findings, "responses": responses,
        "questionnaire": template, "steps": steps,
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
