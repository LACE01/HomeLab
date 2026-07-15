"""Risk Register -- full GRC-style register: manual risk entries scored on a 5x5
likelihood x impact matrix, with a treatment plan, owner, review cadence, and
optional links to findings/assets/exceptions. This is deliberately a separate
thing from a "finding": a finding is a specific technical vulnerability on a
specific asset, a risk entry here is the broader, often non-technical business
risk an auditor expects to see in a register (e.g. "single point of failure in
vendor X", "unpatched legacy app can't be upgraded until Q3 budget"), which may
reference one or more findings as supporting evidence but isn't one itself.
"""
import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from db import db
from rbac import require_module
from routes.common import now_iso, _clean

router = APIRouter()

CATEGORIES = ["Technical", "Operational", "Compliance", "Third-Party", "Strategic", "Financial", "Reputational"]
STRATEGIES = ["Mitigate", "Accept", "Transfer", "Avoid"]
STATUSES = ["Open", "In Treatment", "Monitoring", "Accepted", "Closed"]
CADENCES = {"Monthly": 30, "Quarterly": 90, "Semi-Annual": 180, "Annual": 365}


def _score(likelihood: int, impact: int) -> int:
    return max(1, min(5, likelihood or 1)) * max(1, min(5, impact or 1))


def _band(score: int) -> str:
    if score >= 15:
        return "Critical"
    if score >= 10:
        return "High"
    if score >= 5:
        return "Medium"
    return "Low"


def _next_review(cadence: str, from_dt: Optional[datetime] = None) -> Optional[str]:
    days = CADENCES.get(cadence)
    if not days:
        return None
    base = from_dt or datetime.now(timezone.utc)
    return (base + timedelta(days=days)).isoformat()


async def _log_risk_event(risk_id: str, action: str, actor: str, details: str) -> None:
    await db.activity_log.insert_one({
        "id": str(uuid.uuid4()), "entity_type": "risk", "entity_id": risk_id,
        "action": f"risk_{action}", "actor": actor, "timestamp": now_iso(), "details": details,
    })


class RiskBody(BaseModel):
    title: str
    description: str = ""
    category: str = "Technical"
    likelihood: int = 3
    impact: int = 3
    treatment_strategy: str = "Mitigate"
    treatment_plan: str = ""
    residual_likelihood: Optional[int] = None
    residual_impact: Optional[int] = None
    owner: Optional[str] = None
    status: str = "Open"
    review_cadence: str = "Quarterly"
    linked_finding_ids: List[str] = []
    linked_asset_ids: List[str] = []
    linked_exception_ids: List[str] = []
    tags: List[str] = []


class RiskUpdateBody(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    likelihood: Optional[int] = None
    impact: Optional[int] = None
    treatment_strategy: Optional[str] = None
    treatment_plan: Optional[str] = None
    residual_likelihood: Optional[int] = None
    residual_impact: Optional[int] = None
    owner: Optional[str] = None
    status: Optional[str] = None
    review_cadence: Optional[str] = None
    linked_finding_ids: Optional[List[str]] = None
    linked_asset_ids: Optional[List[str]] = None
    linked_exception_ids: Optional[List[str]] = None
    tags: Optional[List[str]] = None


class CommentBody(BaseModel):
    text: str
    attachments: Optional[List[dict]] = None


@router.get("/v1/risk-register/meta")
async def risk_register_meta(user: dict = Depends(require_module("/risk-register"))):
    return {"categories": CATEGORIES, "strategies": STRATEGIES, "statuses": STATUSES, "cadences": list(CADENCES.keys())}


@router.get("/v1/risk-register")
async def list_risks(
    status: Optional[str] = None, category: Optional[str] = None, owner: Optional[str] = None,
    band: Optional[str] = None, q: Optional[str] = None,
    user: dict = Depends(require_module("/risk-register")),
):
    flt = {}
    if status:
        flt["status"] = status
    if category:
        flt["category"] = category
    if owner:
        flt["owner"] = owner
    if q:
        flt["$or"] = [{"title": {"$regex": q, "$options": "i"}}, {"description": {"$regex": q, "$options": "i"}}]
    docs = await db.risks.find(flt, {"_id": 0}).sort("inherent_score", -1).to_list(2000)
    if band:
        docs = [d for d in docs if _band(d.get("inherent_score", 1)) == band]
    return docs


@router.get("/v1/risk-register/matrix")
async def risk_matrix(user: dict = Depends(require_module("/risk-register"))):
    """5x5 cell counts (inherent, i.e. pre-treatment) for the heatmap, plus the
    same breakdown for residual scores so "did treatment actually move the
    needle" is visible at a glance."""
    docs = await db.risks.find({}, {"_id": 0, "likelihood": 1, "impact": 1, "residual_likelihood": 1, "residual_impact": 1, "status": 1}).to_list(2000)
    inherent_cells = {}
    residual_cells = {}
    for d in docs:
        if d.get("status") == "Closed":
            continue
        li, im = max(1, min(5, d.get("likelihood") or 1)), max(1, min(5, d.get("impact") or 1))
        inherent_cells[f"{li}-{im}"] = inherent_cells.get(f"{li}-{im}", 0) + 1
        rli, rim = d.get("residual_likelihood"), d.get("residual_impact")
        if rli and rim:
            rli, rim = max(1, min(5, rli)), max(1, min(5, rim))
            residual_cells[f"{rli}-{rim}"] = residual_cells.get(f"{rli}-{rim}", 0) + 1
    band_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for d in docs:
        if d.get("status") == "Closed":
            continue
        band_counts[_band(_score(d.get("likelihood", 1), d.get("impact", 1)))] += 1
    overdue = sum(1 for d in docs if d.get("status") not in ("Closed",) and d.get("next_review_date") and d["next_review_date"] < now_iso())
    return {
        "inherent_cells": inherent_cells, "residual_cells": residual_cells,
        "band_counts": band_counts, "total_open": sum(1 for d in docs if d.get("status") != "Closed"),
        "overdue_reviews": overdue,
    }


@router.post("/v1/risk-register")
async def create_risk(body: RiskBody, user: dict = Depends(require_module("/risk-register", level="edit"))):
    if body.category not in CATEGORIES:
        raise HTTPException(400, f"category must be one of {CATEGORIES}")
    if body.treatment_strategy not in STRATEGIES:
        raise HTTPException(400, f"treatment_strategy must be one of {STRATEGIES}")
    if body.status not in STATUSES:
        raise HTTPException(400, f"status must be one of {STATUSES}")
    if body.review_cadence not in CADENCES:
        raise HTTPException(400, f"review_cadence must be one of {list(CADENCES.keys())}")

    ts = now_iso()
    doc = body.dict()
    doc["id"] = str(uuid.uuid4())
    doc["inherent_score"] = _score(body.likelihood, body.impact)
    doc["inherent_band"] = _band(doc["inherent_score"])
    if body.residual_likelihood and body.residual_impact:
        doc["residual_score"] = _score(body.residual_likelihood, body.residual_impact)
        doc["residual_band"] = _band(doc["residual_score"])
    else:
        doc["residual_score"] = None
        doc["residual_band"] = None
    doc["created_at"] = ts
    doc["created_by"] = user["email"]
    doc["updated_at"] = ts
    doc["last_reviewed_at"] = None
    doc["last_reviewed_by"] = None
    doc["next_review_date"] = _next_review(body.review_cadence)

    await db.risks.insert_one(doc)
    await _log_risk_event(doc["id"], "created", user["email"], f"Risk created: {body.title} (inherent {doc['inherent_band']}, score {doc['inherent_score']})")
    return _clean(doc)


@router.get("/v1/risk-register/{risk_id}")
async def get_risk(risk_id: str, user: dict = Depends(require_module("/risk-register"))):
    doc = await db.risks.find_one({"id": risk_id}, {"_id": 0})
    if not doc:
        raise HTTPException(404, "Risk not found")
    return doc


@router.patch("/v1/risk-register/{risk_id}")
async def update_risk(risk_id: str, body: RiskUpdateBody, user: dict = Depends(require_module("/risk-register", level="edit"))):
    doc = await db.risks.find_one({"id": risk_id}, {"_id": 0})
    if not doc:
        raise HTTPException(404, "Risk not found")

    updates = {k: v for k, v in body.dict().items() if v is not None}
    if "category" in updates and updates["category"] not in CATEGORIES:
        raise HTTPException(400, f"category must be one of {CATEGORIES}")
    if "treatment_strategy" in updates and updates["treatment_strategy"] not in STRATEGIES:
        raise HTTPException(400, f"treatment_strategy must be one of {STRATEGIES}")
    if "status" in updates and updates["status"] not in STATUSES:
        raise HTTPException(400, f"status must be one of {STATUSES}")
    if "review_cadence" in updates and updates["review_cadence"] not in CADENCES:
        raise HTTPException(400, f"review_cadence must be one of {list(CADENCES.keys())}")

    merged = {**doc, **updates}
    updates["inherent_score"] = _score(merged.get("likelihood", 1), merged.get("impact", 1))
    updates["inherent_band"] = _band(updates["inherent_score"])
    rli, rim = merged.get("residual_likelihood"), merged.get("residual_impact")
    if rli and rim:
        updates["residual_score"] = _score(rli, rim)
        updates["residual_band"] = _band(updates["residual_score"])

    if "review_cadence" in updates and updates["review_cadence"] != doc.get("review_cadence"):
        updates["next_review_date"] = _next_review(updates["review_cadence"])

    updates["updated_at"] = now_iso()
    await db.risks.update_one({"id": risk_id}, {"$set": updates})

    changed = ", ".join(f"{k}" for k in updates if k not in ("updated_at", "inherent_score", "inherent_band", "residual_score", "residual_band"))
    await _log_risk_event(risk_id, "updated", user["email"], f"Updated: {changed}" if changed else "Updated")

    if updates.get("status") and updates["status"] != doc.get("status"):
        await _log_risk_event(risk_id, "status_changed", user["email"], f"Status: {doc.get('status')} -> {updates['status']}")

    return _clean({**doc, **updates})


@router.delete("/v1/risk-register/{risk_id}")
async def delete_risk(risk_id: str, user: dict = Depends(require_module("/risk-register", level="edit"))):
    doc = await db.risks.find_one({"id": risk_id}, {"_id": 0})
    if not doc:
        raise HTTPException(404, "Risk not found")
    await db.risks.delete_one({"id": risk_id})
    await _log_risk_event(risk_id, "deleted", user["email"], f"Risk deleted: {doc.get('title')}")
    return {"ok": True}


@router.post("/v1/risk-register/{risk_id}/review")
async def mark_reviewed(risk_id: str, user: dict = Depends(require_module("/risk-register", level="edit"))):
    doc = await db.risks.find_one({"id": risk_id}, {"_id": 0})
    if not doc:
        raise HTTPException(404, "Risk not found")
    ts = now_iso()
    next_review = _next_review(doc.get("review_cadence", "Quarterly"))
    await db.risks.update_one({"id": risk_id}, {"$set": {
        "last_reviewed_at": ts, "last_reviewed_by": user["email"], "next_review_date": next_review, "updated_at": ts,
    }})
    await _log_risk_event(risk_id, "reviewed", user["email"], f"Reviewed -- next review {next_review[:10] if next_review else 'n/a'}")
    return {"ok": True, "last_reviewed_at": ts, "next_review_date": next_review}


@router.get("/v1/risk-register/{risk_id}/comments")
async def list_risk_comments(risk_id: str, user: dict = Depends(require_module("/risk-register"))):
    docs = await db.comments.find({"risk_id": risk_id}, {"_id": 0}).sort("created_at", 1).to_list(500)
    return docs


@router.post("/v1/risk-register/{risk_id}/comments")
async def add_risk_comment(risk_id: str, body: CommentBody, user: dict = Depends(require_module("/risk-register", level="edit"))):
    doc = await db.risks.find_one({"id": risk_id}, {"_id": 0})
    if not doc:
        raise HTTPException(404, "Risk not found")
    c = {"id": str(uuid.uuid4()), "risk_id": risk_id, "author": user["email"],
         "text": body.text, "attachments": body.attachments or [], "created_at": now_iso()}
    await db.comments.insert_one(c)
    await _log_risk_event(risk_id, "note_added", user["email"], f"Note added: {body.text[:140]}")
    return _clean(c)


@router.get("/v1/risk-register/{risk_id}/timeline")
async def risk_timeline(risk_id: str, user: dict = Depends(require_module("/risk-register"))):
    docs = await db.activity_log.find({"entity_type": "risk", "entity_id": risk_id}, {"_id": 0}).sort("timestamp", 1).to_list(500)
    return docs
