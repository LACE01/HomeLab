"""Threat Modeling API -- see threat_modeling.py for concepts/data model."""
import uuid
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from db import db
from rbac import require_module
from routes.common import now_iso
from threat_modeling import (
    STRIDE, ELEMENT_TYPES, STRIDE_BY_ELEMENT, STRIDE_EXAMPLES,
    risk_band, dread_score, dread_to_5x5, new_threat_doc, bootstrap_model_from_assets,
)

router = APIRouter()

MODULE_KEY = "/threat-modeling"


class ModelBody(BaseModel):
    name: str
    description: str = ""


class BootstrapBody(BaseModel):
    name: str
    owner_team: Optional[str] = None


class DiagramBody(BaseModel):
    elements: List[dict]
    flows: List[dict]


class ThreatBody(BaseModel):
    element_id: Optional[str] = None
    stride: str
    title: str
    description: str = ""
    parent_threat_id: Optional[str] = None
    likelihood: int = 3
    impact: int = 3


class ThreatUpdateBody(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    stride: Optional[str] = None
    element_id: Optional[str] = None
    parent_threat_id: Optional[str] = None
    dread: Optional[dict] = None
    likelihood: Optional[int] = None
    impact: Optional[int] = None
    status: Optional[str] = None          # open | mitigated | accepted
    linked_finding_ids: Optional[List[str]] = None


class MitigationBody(BaseModel):
    description: str
    owner: str = ""
    status: str = "planned"               # planned | in_progress | done


class MitigationUpdateBody(BaseModel):
    description: Optional[str] = None
    owner: Optional[str] = None
    status: Optional[str] = None


async def _get_model_or_404(model_id: str) -> dict:
    m = await db.threat_models.find_one({"id": model_id}, {"_id": 0})
    if not m:
        raise HTTPException(404, "Threat model not found")
    return m


@router.get("/v1/threat-models/meta")
async def tm_meta(user: dict = Depends(require_module(MODULE_KEY))):
    return {"stride": STRIDE, "element_types": ELEMENT_TYPES,
            "stride_by_element": STRIDE_BY_ELEMENT, "stride_examples": STRIDE_EXAMPLES}


@router.get("/v1/threat-models")
async def list_models(user: dict = Depends(require_module(MODULE_KEY))):
    items = await db.threat_models.find({}, {"_id": 0}).sort("updated_at", -1).to_list(200)
    for m in items:
        m["threat_count"] = await db.threat_model_threats.count_documents({"model_id": m["id"]})
        m["open_threat_count"] = await db.threat_model_threats.count_documents({"model_id": m["id"], "status": "open"})
    return {"items": items}


@router.post("/v1/threat-models")
async def create_model(body: ModelBody, user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    if not body.name.strip():
        raise HTTPException(400, "name is required")
    doc = {"id": str(uuid.uuid4()), "name": body.name.strip(), "description": body.description,
           "elements": [], "flows": [],
           "created_by": user.get("email"), "created_at": now_iso(), "updated_at": now_iso()}
    await db.threat_models.insert_one(dict(doc))
    return doc


@router.post("/v1/threat-models/bootstrap")
async def bootstrap_model(body: BootstrapBody, user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    if not body.name.strip():
        raise HTTPException(400, "name is required")
    return await bootstrap_model_from_assets(db, name=body.name.strip(),
                                              owner_team=body.owner_team,
                                              created_by=user.get("email", ""))


@router.get("/v1/threat-models/{model_id}")
async def get_model(model_id: str, user: dict = Depends(require_module(MODULE_KEY))):
    m = await _get_model_or_404(model_id)
    threats = await db.threat_model_threats.find({"model_id": model_id}, {"_id": 0}).sort("created_at", 1).to_list(500)
    return {"model": m, "threats": threats}


@router.patch("/v1/threat-models/{model_id}")
async def update_model(model_id: str, body: ModelBody, user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    await _get_model_or_404(model_id)
    await db.threat_models.update_one({"id": model_id}, {"$set": {
        "name": body.name, "description": body.description, "updated_at": now_iso()}})
    return {"ok": True}


@router.delete("/v1/threat-models/{model_id}")
async def delete_model(model_id: str, user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    await _get_model_or_404(model_id)
    await db.threat_models.delete_one({"id": model_id})
    await db.threat_model_threats.delete_many({"model_id": model_id})
    return {"ok": True}


@router.put("/v1/threat-models/{model_id}/diagram")
async def save_diagram(model_id: str, body: DiagramBody,
                        user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    """Atomic save of the whole DFD from the canvas. Elements referenced by
    existing threats can't silently vanish -- deleting one detaches its threats
    to element_id=None (kept, flagged unplaced) rather than orphan-deleting."""
    await _get_model_or_404(model_id)
    for e in body.elements:
        if e.get("type") not in ELEMENT_TYPES:
            raise HTTPException(400, f"element type must be one of {ELEMENT_TYPES}")
        if not e.get("id"):
            e["id"] = str(uuid.uuid4())
    el_ids = {e["id"] for e in body.elements}
    for f in body.flows:
        if not f.get("id"):
            f["id"] = str(uuid.uuid4())
        if f.get("from_id") not in el_ids or f.get("to_id") not in el_ids:
            raise HTTPException(400, "flow endpoints must reference existing elements")
    await db.threat_models.update_one({"id": model_id}, {"$set": {
        "elements": body.elements, "flows": body.flows, "updated_at": now_iso()}})
    await db.threat_model_threats.update_many(
        {"model_id": model_id, "element_id": {"$nin": list(el_ids) + [None]}},
        {"$set": {"element_id": None}})
    return {"ok": True, "elements": len(body.elements), "flows": len(body.flows)}


@router.get("/v1/threat-models/{model_id}/stride-suggestions/{element_id}")
async def stride_suggestions(model_id: str, element_id: str,
                              user: dict = Depends(require_module(MODULE_KEY))):
    """Applicable STRIDE categories for this element's type, each with a
    name-instantiated example, plus which categories already have threats --
    the per-element STRIDE checklist."""
    m = await _get_model_or_404(model_id)
    el = next((e for e in m.get("elements", []) if e["id"] == element_id), None)
    if not el:
        raise HTTPException(404, "Element not found")
    applicable = STRIDE_BY_ELEMENT.get(el["type"], [])
    existing = await db.threat_model_threats.find(
        {"model_id": model_id, "element_id": element_id}, {"_id": 0, "stride": 1}).to_list(100)
    covered = {t["stride"] for t in existing}
    return {
        "element": el,
        "suggestions": [{
            "stride": s,
            "example": STRIDE_EXAMPLES[s].format(name=el["name"]),
            "covered": s in covered,
        } for s in applicable],
    }


@router.post("/v1/threat-models/{model_id}/threats")
async def create_threat(model_id: str, body: ThreatBody,
                         user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    m = await _get_model_or_404(model_id)
    if body.stride not in STRIDE:
        raise HTTPException(400, f"stride must be one of {STRIDE}")
    if body.element_id and not any(e["id"] == body.element_id for e in m.get("elements", [])):
        raise HTTPException(404, "Element not found on this model")
    if body.parent_threat_id:
        parent = await db.threat_model_threats.find_one(
            {"id": body.parent_threat_id, "model_id": model_id}, {"_id": 0, "id": 1})
        if not parent:
            raise HTTPException(404, "Parent threat not found")
    doc = new_threat_doc(model_id, element_id=body.element_id, stride=body.stride,
                          title=body.title, description=body.description,
                          parent_threat_id=body.parent_threat_id,
                          likelihood=body.likelihood, impact=body.impact,
                          created_by=user.get("email", ""))
    await db.threat_model_threats.insert_one(dict(doc))
    return doc


@router.patch("/v1/threat-models/{model_id}/threats/{threat_id}")
async def update_threat(model_id: str, threat_id: str, body: ThreatUpdateBody,
                         user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    t = await db.threat_model_threats.find_one({"id": threat_id, "model_id": model_id}, {"_id": 0})
    if not t:
        raise HTTPException(404, "Threat not found")
    changes = {k: v for k, v in body.dict().items() if v is not None}
    if "stride" in changes and changes["stride"] not in STRIDE:
        raise HTTPException(400, f"stride must be one of {STRIDE}")
    if "status" in changes and changes["status"] not in ("open", "mitigated", "accepted"):
        raise HTTPException(400, "status must be open/mitigated/accepted")
    if "dread" in changes:
        merged = {**(t.get("dread") or {}), **changes["dread"]}
        changes["dread"] = merged
        changes["dread_score"] = dread_score(merged)
        changes["dread_suggestion"] = dread_to_5x5(merged)
    lik = changes.get("likelihood", t.get("likelihood"))
    imp = changes.get("impact", t.get("impact"))
    changes["band"] = risk_band(lik, imp)
    changes["updated_at"] = now_iso()
    await db.threat_model_threats.update_one({"id": threat_id}, {"$set": changes})
    return await db.threat_model_threats.find_one({"id": threat_id}, {"_id": 0})


@router.delete("/v1/threat-models/{model_id}/threats/{threat_id}")
async def delete_threat(model_id: str, threat_id: str,
                         user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    result = await db.threat_model_threats.delete_one({"id": threat_id, "model_id": model_id})
    if result.deleted_count == 0:
        raise HTTPException(404, "Threat not found")
    # attack-tree children of a deleted node become roots rather than orphans
    await db.threat_model_threats.update_many(
        {"model_id": model_id, "parent_threat_id": threat_id},
        {"$set": {"parent_threat_id": None}})
    return {"ok": True}


@router.post("/v1/threat-models/{model_id}/threats/{threat_id}/mitigations")
async def add_mitigation(model_id: str, threat_id: str, body: MitigationBody,
                          user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    t = await db.threat_model_threats.find_one({"id": threat_id, "model_id": model_id}, {"_id": 0})
    if not t:
        raise HTTPException(404, "Threat not found")
    if body.status not in ("planned", "in_progress", "done"):
        raise HTTPException(400, "status must be planned/in_progress/done")
    mit = {"id": str(uuid.uuid4()), "description": body.description, "owner": body.owner,
           "status": body.status, "added_by": user.get("email"), "added_at": now_iso()}
    await db.threat_model_threats.update_one({"id": threat_id}, {
        "$push": {"mitigations": mit}, "$set": {"updated_at": now_iso()}})
    return mit


@router.patch("/v1/threat-models/{model_id}/threats/{threat_id}/mitigations/{mitigation_id}")
async def update_mitigation(model_id: str, threat_id: str, mitigation_id: str,
                             body: MitigationUpdateBody,
                             user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    t = await db.threat_model_threats.find_one({"id": threat_id, "model_id": model_id}, {"_id": 0})
    if not t:
        raise HTTPException(404, "Threat not found")
    mits = t.get("mitigations") or []
    target = next((m for m in mits if m["id"] == mitigation_id), None)
    if not target:
        raise HTTPException(404, "Mitigation not found")
    for k in ("description", "owner", "status"):
        v = getattr(body, k)
        if v is not None:
            if k == "status" and v not in ("planned", "in_progress", "done"):
                raise HTTPException(400, "status must be planned/in_progress/done")
            target[k] = v
    changes: dict = {"mitigations": mits, "updated_at": now_iso()}
    # every mitigation done -> the threat is mitigated (analyst can still flip back)
    if mits and all(m["status"] == "done" for m in mits) and t.get("status") == "open":
        changes["status"] = "mitigated"
    await db.threat_model_threats.update_one({"id": threat_id}, {"$set": changes})
    return await db.threat_model_threats.find_one({"id": threat_id}, {"_id": 0})


@router.get("/v1/threat-models/{model_id}/matrix")
async def threat_matrix(model_id: str, user: dict = Depends(require_module(MODULE_KEY))):
    """5x5 Impact x Likelihood grid: open-threat counts per cell + band totals."""
    await _get_model_or_404(model_id)
    threats = await db.threat_model_threats.find(
        {"model_id": model_id}, {"_id": 0, "likelihood": 1, "impact": 1, "band": 1, "status": 1}).to_list(500)
    cells: dict = {}
    bands: dict = {}
    for t in threats:
        if t.get("status") != "open":
            continue
        key = f"{t.get('likelihood', 3)}x{t.get('impact', 3)}"
        cells[key] = cells.get(key, 0) + 1
        bands[t.get("band", "Medium")] = bands.get(t.get("band", "Medium"), 0) + 1
    return {"cells": cells, "band_totals": bands,
            "total_open": sum(cells.values()), "total": len(threats)}
