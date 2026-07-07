"""Incident Response routes -- admin config (plan phases/roles/classification/
wizard questions/tool catalog), the helpdesk triage wizard, and IR cases (the
collaborative ticket: timeline, phase checklist, evidence, closure report).
See backend/incident_response.py for the domain logic/defaults this wires up."""
import uuid
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from db import db
from rbac import require_module
from auth_utils import get_current_user, require_role
from routes.common import now_iso, _clean
import incident_response as ir

router = APIRouter()


# --------------------------------------------------------------------------------
# Admin config: plan phases, roles, classification, wizard config, tool catalog.
# Each is a singleton doc, lazily seeded with defaults on first read so a fresh
# deployment has a working starting point without a separate migration step.
# --------------------------------------------------------------------------------
async def _get_or_seed(collection_name: str, seed_fn) -> dict:
    coll = db[collection_name]
    doc = await coll.find_one({}, {"_id": 0})
    if not doc:
        doc = seed_fn()
        await coll.update_one({}, {"$set": doc}, upsert=True)
    return doc


@router.get("/v1/admin/ir/plan")
async def get_ir_plan(user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/admin/ir-setup"))):
    doc = await _get_or_seed("ir_plan_config", lambda: {"phases": ir._default_phases(), "updated_at": now_iso()})
    return doc


class PhaseBody(BaseModel):
    id: Optional[str] = None
    name: str
    responsible_party: Optional[str] = ""
    tasks: List[str] = []
    objectives: List[str] = []
    things_needed: List[str] = []
    parallel_fast_path: Optional[bool] = False


class PlanBody(BaseModel):
    phases: List[PhaseBody]


@router.put("/v1/admin/ir/plan")
async def set_ir_plan(body: PlanBody, user: dict = Depends(require_role("admin", "manager")),
                       _rbac: dict = Depends(require_module("/admin/ir-setup", level="edit"))):
    phases = []
    for i, p in enumerate(body.phases):
        d = p.model_dump()
        d["id"] = d.get("id") or str(uuid.uuid4())
        d["order"] = i
        phases.append(d)
    doc = {"phases": phases, "updated_at": now_iso()}
    await db.ir_plan_config.update_one({}, {"$set": doc}, upsert=True)
    await db.activity_log.insert_one({
        "id": str(uuid.uuid4()), "entity_type": "ir_plan_config", "entity_id": "global",
        "action": "ir_plan_updated", "actor": user["email"], "timestamp": now_iso(),
        "details": f"{len(phases)} phase(s) configured",
    })
    return doc


@router.get("/v1/admin/ir/roles")
async def get_ir_roles(user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/admin/ir-setup"))):
    return await _get_or_seed("ir_roles_config", ir._default_roles_config)


class RoleBody(BaseModel):
    id: Optional[str] = None
    name: str
    kind: str = "optional"  # standing | mandatory | optional
    description: Optional[str] = ""
    contacts: List[dict] = []  # [{name, phone, email}]


class RolesBody(BaseModel):
    roles: List[RoleBody]


@router.put("/v1/admin/ir/roles")
async def set_ir_roles(body: RolesBody, user: dict = Depends(require_role("admin", "manager")),
                        _rbac: dict = Depends(require_module("/admin/ir-setup", level="edit"))):
    roles = []
    for r in body.roles:
        d = r.model_dump()
        d["id"] = d.get("id") or str(uuid.uuid4())
        roles.append(d)
    doc = {"roles": roles, "updated_at": now_iso()}
    await db.ir_roles_config.update_one({}, {"$set": doc}, upsert=True)
    return doc


@router.get("/v1/admin/ir/classification")
async def get_ir_classification(user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/admin/ir-setup"))):
    return await _get_or_seed("ir_classification_config", ir._default_classification_config)


class ClassificationLevelBody(BaseModel):
    level: str
    criteria: str = ""
    response: str = ""


class ClassificationBody(BaseModel):
    levels: List[ClassificationLevelBody]


@router.put("/v1/admin/ir/classification")
async def set_ir_classification(body: ClassificationBody, user: dict = Depends(require_role("admin", "manager")),
                                 _rbac: dict = Depends(require_module("/admin/ir-setup", level="edit"))):
    doc = {"levels": [l.model_dump() for l in body.levels], "updated_at": now_iso()}
    await db.ir_classification_config.update_one({}, {"$set": doc}, upsert=True)
    return doc


@router.get("/v1/admin/ir/wizard-config")
async def get_ir_wizard_config(user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/admin/ir-setup"))):
    return await _get_or_seed("ir_wizard_config", ir._default_wizard_config)


class WizardOptionBody(BaseModel):
    id: Optional[str] = None
    label: str
    weights: Dict[str, float] = {}
    severity_points: Optional[float] = 0
    immediate_containment: Optional[bool] = False


class WizardQuestionBody(BaseModel):
    id: Optional[str] = None
    text: str
    help_text: Optional[str] = ""
    options: List[WizardOptionBody]


class WizardConfigBody(BaseModel):
    categories: List[dict]
    questions: List[WizardQuestionBody]
    action_plans: Dict[str, Any]


@router.put("/v1/admin/ir/wizard-config")
async def set_ir_wizard_config(body: WizardConfigBody, user: dict = Depends(require_role("admin", "manager")),
                                _rbac: dict = Depends(require_module("/admin/ir-setup", level="edit"))):
    questions = []
    for q in body.questions:
        qd = q.model_dump()
        qd["id"] = qd.get("id") or str(uuid.uuid4())
        for opt in qd["options"]:
            opt["id"] = opt.get("id") or str(uuid.uuid4())
        questions.append(qd)
    doc = {"categories": body.categories, "questions": questions, "action_plans": body.action_plans, "updated_at": now_iso()}
    await db.ir_wizard_config.update_one({}, {"$set": doc}, upsert=True)
    return doc


async def _ensure_tool_catalog_seeded():
    if await db.ir_tools.count_documents({}) == 0:
        now = now_iso()
        docs = [{"id": str(uuid.uuid4()), **t, "created_at": now} for t in ir.DEFAULT_TOOL_CATALOG]
        if docs:
            await db.ir_tools.insert_many(docs)


@router.get("/v1/admin/ir/tools")
async def list_ir_tools(user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/admin/ir-setup"))):
    await _ensure_tool_catalog_seeded()
    items = await db.ir_tools.find({}, {"_id": 0}).sort("name", 1).to_list(500)
    return {"items": items}


class ToolBody(BaseModel):
    name: str
    description: Optional[str] = ""
    location: Optional[str] = ""  # URL, path, or "ask IT" style instructions
    applicable_categories: List[str] = []


@router.post("/v1/admin/ir/tools")
async def create_ir_tool(body: ToolBody, user: dict = Depends(require_role("admin", "manager")),
                          _rbac: dict = Depends(require_module("/admin/ir-setup", level="edit"))):
    doc = {"id": str(uuid.uuid4()), **body.model_dump(), "created_at": now_iso()}
    await db.ir_tools.insert_one(doc)
    return _clean(doc)


@router.put("/v1/admin/ir/tools/{tool_id}")
async def update_ir_tool(tool_id: str, body: ToolBody, user: dict = Depends(require_role("admin", "manager")),
                          _rbac: dict = Depends(require_module("/admin/ir-setup", level="edit"))):
    existing = await db.ir_tools.find_one({"id": tool_id}, {"_id": 0})
    if not existing:
        raise HTTPException(404, "Tool not found")
    update = body.model_dump()
    await db.ir_tools.update_one({"id": tool_id}, {"$set": update})
    return {**existing, **update}


@router.delete("/v1/admin/ir/tools/{tool_id}")
async def delete_ir_tool(tool_id: str, user: dict = Depends(require_role("admin", "manager")),
                          _rbac: dict = Depends(require_module("/admin/ir-setup", level="edit"))):
    await db.ir_tools.delete_one({"id": tool_id})
    return {"ok": True}


# --------------------------------------------------------------------------------
# Wizard (helpdesk-facing) -- open to any authenticated user, not admin-gated,
# since the whole point is letting someone with no cyber background use it.
# --------------------------------------------------------------------------------
@router.get("/v1/ir/wizard")
async def get_wizard(user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/ir/wizard"))):
    cfg = await _get_or_seed("ir_wizard_config", ir._default_wizard_config)
    await _ensure_tool_catalog_seeded()
    return cfg


class WizardAnswer(BaseModel):
    question_id: str
    option_id: str


class WizardSubmitBody(BaseModel):
    title: Optional[str] = None
    reporter_contact: Optional[str] = None
    answers: List[WizardAnswer]


async def _next_case_number() -> str:
    from datetime import datetime, timezone
    year = datetime.now(timezone.utc).year
    count = await db.ir_cases.count_documents({"case_number": {"$regex": f"^IR-{year}-"}})
    return f"IR-{year}-{count + 1:04d}"


async def _create_case_from_wizard(user: dict, body: WizardSubmitBody, result: dict, wizard_cfg: dict) -> dict:
    plan = await _get_or_seed("ir_plan_config", lambda: {"phases": ir._default_phases(), "updated_at": now_iso()})
    phases = plan["phases"]
    phase_progress = [
        {"phase_id": p["id"], "phase_name": p["name"], "order": p["order"], "tasks_done": [], "completed_at": None,
         # Snapshot the phase's actual content at case-open time -- a case's checklist
         # shouldn't silently change shape if an admin edits the plan template while
         # this case is still open. Without this snapshot, the frontend has nothing
         # to render checkboxes for (this was the "can't click Done" bug).
         "tasks": p.get("tasks") or [], "objectives": p.get("objectives") or [],
         "responsible_party": p.get("responsible_party") or "", "things_needed": p.get("things_needed") or []}
        for p in phases
    ]
    action_plan = wizard_cfg.get("action_plans", {}).get(result["top_category"], {})
    tools = await db.ir_tools.find({"applicable_categories": result["top_category"]}, {"_id": 0}).to_list(50)

    category_label = next((c["label"] for c in wizard_cfg["categories"] if c["id"] == result["top_category"]), result["top_category"])
    title = body.title or f"{category_label} — reported via triage wizard"
    case = {
        "id": str(uuid.uuid4()), "case_number": await _next_case_number(), "title": title,
        "status": "open", "classification": result["classification"],
        "outcome_category": result["top_category"], "confidence_pct": result["confidence_pct"],
        "immediate_containment": result["immediate_containment"],
        "opened_at": now_iso(), "closed_at": None,
        "created_by": user["email"], "reporter_contact": body.reporter_contact,
        "initial_intake": "\n".join(f"Q: {a['question']}\nA: {a['answer']}" for a in result["answered"]),
        "recommended_actions": action_plan.get("immediate_actions", []),
        "recommended_tools": [{"id": t["id"], "name": t["name"]} for t in tools],
        "assigned_roles": {}, "sheets_webhook_url": None,
        "root_cause": None, "follow_up_actions": [], "updated_at": now_iso(),
    }
    await db.ir_cases.insert_one(case)
    await db.ir_case_phase_progress.insert_many([{**pp, "case_id": case["id"]} for pp in phase_progress]) if phase_progress else None

    open_event = {
        "id": str(uuid.uuid4()), "case_id": case["id"], "type": "case_opened",
        "text": f"Case opened via triage wizard. Likely outcome: {category_label} ({result['confidence_pct']}% confidence). Classification: {result['classification']}.",
        "author": user["email"], "attachments": [], "created_at": now_iso(),
    }
    await db.ir_case_events.insert_one(dict(open_event))
    await ir.push_case_event_to_sheet(db, case, open_event)

    from notifier import dispatch
    await dispatch("ir_case_opened", {
        "severity": ir.CLASSIFICATION_TO_SEVERITY.get(result["classification"], "Medium"),
        "title": title, "case_number": case["case_number"], "classification": result["classification"],
        "category": category_label, "confidence_pct": result["confidence_pct"],
        "url": f"/ir/cases/{case['id']}",
    }, db)

    return _clean(case)


@router.post("/v1/ir/wizard/submit")
async def submit_wizard(body: WizardSubmitBody, user: dict = Depends(get_current_user),
                         _rbac: dict = Depends(require_module("/ir/wizard"))):
    wizard_cfg = await _get_or_seed("ir_wizard_config", ir._default_wizard_config)
    await _ensure_tool_catalog_seeded()
    result = ir.score_wizard(wizard_cfg, [a.model_dump() for a in body.answers])
    category_label = next((c["label"] for c in wizard_cfg["categories"] if c["id"] == result["top_category"]), result["top_category"])
    action_plan = wizard_cfg.get("action_plans", {}).get(result["top_category"], {})
    tools = await db.ir_tools.find({"applicable_categories": result["top_category"]}, {"_id": 0}).to_list(50)

    case = await _create_case_from_wizard(user, body, result, wizard_cfg)

    return {
        "result": {**result, "category_label": category_label},
        "action_plan": action_plan, "recommended_tools": tools,
        "case": case,
    }


# --------------------------------------------------------------------------------
# IR Cases -- the collaborative ticket.
# --------------------------------------------------------------------------------
@router.get("/v1/ir/cases")
async def list_cases(status: Optional[str] = None, classification: Optional[str] = None,
                      user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/ir/cases"))):
    flt = {}
    if status:
        flt["status"] = status
    if classification:
        flt["classification"] = classification
    items = await db.ir_cases.find(flt, {"_id": 0}).sort("opened_at", -1).to_list(500)
    return {"items": items}


class ManualCaseBody(BaseModel):
    title: str
    classification: str = "Moderate"
    initial_intake: Optional[str] = ""
    reporter_contact: Optional[str] = None


@router.post("/v1/ir/cases")
async def create_case_manually(body: ManualCaseBody, user: dict = Depends(get_current_user),
                                _rbac: dict = Depends(require_module("/ir/cases", level="edit"))):
    if body.classification not in ir.CLASSIFICATION_LEVELS:
        raise HTTPException(400, f"classification must be one of {ir.CLASSIFICATION_LEVELS}")
    plan = await _get_or_seed("ir_plan_config", lambda: {"phases": ir._default_phases(), "updated_at": now_iso()})
    phase_progress = [
        {"phase_id": p["id"], "phase_name": p["name"], "order": p["order"], "tasks_done": [], "completed_at": None, "case_id": None,
         "tasks": p.get("tasks") or [], "objectives": p.get("objectives") or [],
         "responsible_party": p.get("responsible_party") or "", "things_needed": p.get("things_needed") or []}
        for p in plan["phases"]
    ]
    case = {
        "id": str(uuid.uuid4()), "case_number": await _next_case_number(), "title": body.title,
        "status": "open", "classification": body.classification, "outcome_category": None, "confidence_pct": None,
        "immediate_containment": False, "opened_at": now_iso(), "closed_at": None,
        "created_by": user["email"], "reporter_contact": body.reporter_contact,
        "initial_intake": body.initial_intake or "", "recommended_actions": [], "recommended_tools": [],
        "assigned_roles": {}, "sheets_webhook_url": None, "root_cause": None, "follow_up_actions": [], "updated_at": now_iso(),
    }
    await db.ir_cases.insert_one(case)
    for pp in phase_progress:
        pp["case_id"] = case["id"]
    if phase_progress:
        await db.ir_case_phase_progress.insert_many(phase_progress)
    event = {"id": str(uuid.uuid4()), "case_id": case["id"], "type": "case_opened",
             "text": "Case opened manually.", "author": user["email"], "attachments": [], "created_at": now_iso()}
    await db.ir_case_events.insert_one(dict(event))
    await ir.push_case_event_to_sheet(db, case, event)
    from notifier import dispatch
    await dispatch("ir_case_opened", {
        "severity": ir.CLASSIFICATION_TO_SEVERITY.get(body.classification, "Medium"),
        "title": body.title, "case_number": case["case_number"], "classification": body.classification,
        "category": "Manually opened", "confidence_pct": "n/a", "url": f"/ir/cases/{case['id']}",
    }, db)
    return _clean(case)


async def _get_case_or_404(case_id: str) -> dict:
    case = await db.ir_cases.find_one({"id": case_id}, {"_id": 0})
    if not case:
        raise HTTPException(404, "IR case not found")
    return case


@router.get("/v1/ir/cases/{case_id}")
async def get_case(case_id: str, user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/ir/cases"))):
    case = await _get_case_or_404(case_id)
    phase_progress = await db.ir_case_phase_progress.find({"case_id": case_id}, {"_id": 0}).sort("order", 1).to_list(100)
    # Self-heal: cases opened before the phase-snapshot fix have no "tasks" field on
    # their phase_progress docs at all (the original bug -- nothing to check off).
    # Backfill from the current plan config by phase_id, best-effort, and persist it
    # so this only needs to happen once per old case.
    if any("tasks" not in pp for pp in phase_progress):
        plan = await _get_or_seed("ir_plan_config", lambda: {"phases": ir._default_phases(), "updated_at": now_iso()})
        phases_by_id = {p["id"]: p for p in plan["phases"]}
        for pp in phase_progress:
            if "tasks" not in pp:
                src = phases_by_id.get(pp["phase_id"], {})
                fill = {"tasks": src.get("tasks") or [], "objectives": src.get("objectives") or [],
                        "responsible_party": src.get("responsible_party") or "", "things_needed": src.get("things_needed") or []}
                pp.update(fill)
                await db.ir_case_phase_progress.update_one({"case_id": case_id, "phase_id": pp["phase_id"]}, {"$set": fill})
    events = await db.ir_case_events.find({"case_id": case_id}, {"_id": 0}).sort("created_at", -1).to_list(500)
    evidence = await db.ir_case_evidence.find({"case_id": case_id}, {"_id": 0}).sort("item_no", 1).to_list(200)
    roles_cfg = await _get_or_seed("ir_roles_config", ir._default_roles_config)
    return {"case": case, "phase_progress": phase_progress, "events": events, "evidence": evidence, "roles": roles_cfg["roles"]}


class CaseUpdateBody(BaseModel):
    title: Optional[str] = None
    classification: Optional[str] = None
    reporter_contact: Optional[str] = None
    sheets_webhook_url: Optional[str] = None
    root_cause: Optional[str] = None
    follow_up_actions: Optional[List[str]] = None


@router.patch("/v1/ir/cases/{case_id}")
async def update_case(case_id: str, body: CaseUpdateBody, user: dict = Depends(get_current_user),
                       _rbac: dict = Depends(require_module("/ir/cases", level="edit"))):
    case = await _get_case_or_404(case_id)
    update = {k: v for k, v in body.model_dump().items() if v is not None}
    if update.get("classification") and update["classification"] not in ir.CLASSIFICATION_LEVELS:
        raise HTTPException(400, f"classification must be one of {ir.CLASSIFICATION_LEVELS}")
    if not update:
        return case
    update["updated_at"] = now_iso()
    await db.ir_cases.update_one({"id": case_id}, {"$set": update})
    changed = ", ".join(f"{k}={v}" for k, v in update.items() if k != "updated_at")
    event = {"id": str(uuid.uuid4()), "case_id": case_id, "type": "case_updated",
              "text": f"Case updated: {changed}", "author": user["email"], "attachments": [], "created_at": now_iso()}
    await db.ir_case_events.insert_one(dict(event))
    await ir.push_case_event_to_sheet(db, {**case, **update}, event)
    return {**case, **update}


class RolesAssignBody(BaseModel):
    assigned_roles: Dict[str, dict]  # role_id -> {name, contact}


@router.put("/v1/ir/cases/{case_id}/roles")
async def assign_case_roles(case_id: str, body: RolesAssignBody, user: dict = Depends(get_current_user),
                             _rbac: dict = Depends(require_module("/ir/cases", level="edit"))):
    case = await _get_case_or_404(case_id)
    await db.ir_cases.update_one({"id": case_id}, {"$set": {"assigned_roles": body.assigned_roles, "updated_at": now_iso()}})
    event = {"id": str(uuid.uuid4()), "case_id": case_id, "type": "roles_assigned",
              "text": "Roles updated: " + ", ".join(f"{v.get('name','?')}" for v in body.assigned_roles.values()),
              "author": user["email"], "attachments": [], "created_at": now_iso()}
    await db.ir_case_events.insert_one(dict(event))
    await ir.push_case_event_to_sheet(db, case, event)
    return {"ok": True}


class EventBody(BaseModel):
    type: str = "note"  # note | screenshot | status_change | evidence_added | other
    text: str
    attachments: Optional[List[dict]] = None  # [{name, mime, data_url}] -- small images only, same rule as findings/exceptions


@router.post("/v1/ir/cases/{case_id}/events")
async def add_case_event(case_id: str, body: EventBody, user: dict = Depends(get_current_user),
                          _rbac: dict = Depends(require_module("/ir/cases", level="edit"))):
    case = await _get_case_or_404(case_id)
    atts = body.attachments or []
    for a in atts:
        if isinstance(a.get("data_url"), str) and len(a["data_url"]) > 1_400_000:
            raise HTTPException(413, f"Attachment '{a.get('name','?')}' exceeds 1 MB limit")
        if a.get("mime") and not a["mime"].startswith(("image/", "application/pdf")):
            raise HTTPException(400, f"Only image and PDF attachments allowed (got {a['mime']})")
    event = {"id": str(uuid.uuid4()), "case_id": case_id, "type": body.type, "text": body.text,
              "author": user["email"], "attachments": atts, "created_at": now_iso()}
    await db.ir_case_events.insert_one(dict(event))
    await db.ir_cases.update_one({"id": case_id}, {"$set": {"updated_at": now_iso()}})
    await ir.push_case_event_to_sheet(db, case, event)
    return _clean(event)


class TaskToggleBody(BaseModel):
    task_index: int
    done: bool


@router.put("/v1/ir/cases/{case_id}/phases/{phase_id}/tasks")
async def toggle_phase_task(case_id: str, phase_id: str, body: TaskToggleBody, user: dict = Depends(get_current_user),
                             _rbac: dict = Depends(require_module("/ir/cases", level="edit"))):
    case = await _get_case_or_404(case_id)
    pp = await db.ir_case_phase_progress.find_one({"case_id": case_id, "phase_id": phase_id}, {"_id": 0})
    if not pp:
        raise HTTPException(404, "Phase not found on this case")
    # Use the snapshot taken at case-open time, not the live (possibly since-edited)
    # plan config -- this case's checklist is whatever it was when the case opened.
    tasks = pp.get("tasks") or []
    n_tasks = len(tasks)
    tasks_done = set(pp.get("tasks_done") or [])
    if body.done:
        tasks_done.add(body.task_index)
    else:
        tasks_done.discard(body.task_index)
    update = {"tasks_done": sorted(tasks_done)}
    if n_tasks and len(tasks_done) >= n_tasks:
        update["completed_at"] = pp.get("completed_at") or now_iso()
    elif len(tasks_done) < n_tasks:
        update["completed_at"] = None
    await db.ir_case_phase_progress.update_one({"case_id": case_id, "phase_id": phase_id}, {"$set": update})
    task_label = tasks[body.task_index] if body.task_index < n_tasks else f"task {body.task_index}"
    event = {"id": str(uuid.uuid4()), "case_id": case_id, "type": "task_checked" if body.done else "task_unchecked",
              "text": f"[{pp.get('phase_name')}] {'Checked' if body.done else 'Unchecked'}: {task_label}",
              "author": user["email"], "attachments": [], "created_at": now_iso()}
    await db.ir_case_events.insert_one(dict(event))
    await ir.push_case_event_to_sheet(db, case, event)
    return {**pp, **update}


class EvidenceBody(BaseModel):
    description: str
    collected_by: Optional[str] = None
    location: Optional[str] = None


@router.post("/v1/ir/cases/{case_id}/evidence")
async def add_evidence(case_id: str, body: EvidenceBody, user: dict = Depends(get_current_user),
                        _rbac: dict = Depends(require_module("/ir/cases", level="edit"))):
    case = await _get_case_or_404(case_id)
    count = await db.ir_case_evidence.count_documents({"case_id": case_id})
    item = {
        "id": str(uuid.uuid4()), "case_id": case_id, "item_no": count + 1, "description": body.description,
        "collected_by": body.collected_by or user["email"], "collected_at": now_iso(), "location": body.location or "",
        "chain_of_custody": [{"by": user["email"], "at": now_iso(), "note": "Item logged"}],
    }
    await db.ir_case_evidence.insert_one(dict(item))
    event = {"id": str(uuid.uuid4()), "case_id": case_id, "type": "evidence_added",
              "text": f"Evidence item #{item['item_no']} logged: {body.description}",
              "author": user["email"], "attachments": [], "created_at": now_iso()}
    await db.ir_case_events.insert_one(dict(event))
    await ir.push_case_event_to_sheet(db, case, event)
    return _clean(item)


@router.get("/v1/ir/cases/{case_id}/evidence")
async def list_evidence(case_id: str, user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/ir/cases"))):
    items = await db.ir_case_evidence.find({"case_id": case_id}, {"_id": 0}).sort("item_no", 1).to_list(200)
    return {"items": items}


@router.get("/v1/ir/cases/{case_id}/report")
async def get_case_report(case_id: str, user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/ir/cases"))):
    report = await db.ir_case_reports.find_one({"case_id": case_id}, {"_id": 0})
    if not report:
        raise HTTPException(404, "No report generated yet for this case -- close the case to generate one")
    return report


@router.post("/v1/ir/cases/{case_id}/close")
async def close_case(case_id: str, user: dict = Depends(get_current_user),
                      _rbac: dict = Depends(require_module("/ir/cases", level="edit"))):
    case = await _get_case_or_404(case_id)
    if case["status"] == "closed":
        raise HTTPException(400, "Case is already closed")
    closed_at = now_iso()
    await db.ir_cases.update_one({"id": case_id}, {"$set": {"status": "closed", "closed_at": closed_at, "updated_at": closed_at}})
    phase_progress = await db.ir_case_phase_progress.find({"case_id": case_id}, {"_id": 0}).sort("order", 1).to_list(100)
    events = await db.ir_case_events.find({"case_id": case_id}, {"_id": 0}).to_list(1000)
    evidence = await db.ir_case_evidence.find({"case_id": case_id}, {"_id": 0}).sort("item_no", 1).to_list(200)
    report = ir.build_closure_report({**case, "status": "closed", "closed_at": closed_at}, phase_progress, events, evidence)
    report_doc = {"id": str(uuid.uuid4()), "case_id": case_id, "status": "draft",
                  "generated_by": user["email"], "approved_by": None, "approved_at": None, **report}
    await db.ir_case_reports.update_one({"case_id": case_id}, {"$set": report_doc}, upsert=True)
    event = {"id": str(uuid.uuid4()), "case_id": case_id, "type": "case_closed",
              "text": "Case closed. Closure report generated as a draft for IR lead review.",
              "author": user["email"], "attachments": [], "created_at": closed_at}
    await db.ir_case_events.insert_one(dict(event))
    await ir.push_case_event_to_sheet(db, case, event)
    return _clean(report_doc)


class ReportEditBody(BaseModel):
    summary: Optional[str] = None
    root_cause: Optional[str] = None
    follow_up_actions: Optional[List[str]] = None
    timeline_text: Optional[str] = None


@router.put("/v1/ir/cases/{case_id}/report")
async def edit_case_report(case_id: str, body: ReportEditBody, user: dict = Depends(get_current_user),
                            _rbac: dict = Depends(require_module("/ir/cases", level="edit"))):
    report = await db.ir_case_reports.find_one({"case_id": case_id}, {"_id": 0})
    if not report:
        raise HTTPException(404, "No report generated yet for this case")
    if report.get("status") == "approved":
        raise HTTPException(400, "Report is already approved and locked")
    update = {k: v for k, v in body.model_dump().items() if v is not None}
    update["generated_at"] = now_iso()
    await db.ir_case_reports.update_one({"case_id": case_id}, {"$set": update})
    if update.get("root_cause") is not None or update.get("follow_up_actions") is not None:
        case_update = {}
        if "root_cause" in update:
            case_update["root_cause"] = update["root_cause"]
        if "follow_up_actions" in update:
            case_update["follow_up_actions"] = update["follow_up_actions"]
        await db.ir_cases.update_one({"id": case_id}, {"$set": case_update})
    return {**report, **update}


@router.post("/v1/ir/cases/{case_id}/report/approve")
async def approve_case_report(case_id: str, user: dict = Depends(require_role("admin", "manager")),
                               _rbac: dict = Depends(require_module("/ir/cases", level="edit"))):
    report = await db.ir_case_reports.find_one({"case_id": case_id}, {"_id": 0})
    if not report:
        raise HTTPException(404, "No report generated yet for this case")
    update = {"status": "approved", "approved_by": user["email"], "approved_at": now_iso()}
    await db.ir_case_reports.update_one({"case_id": case_id}, {"$set": update})
    await db.activity_log.insert_one({
        "id": str(uuid.uuid4()), "entity_type": "ir_case", "entity_id": case_id,
        "action": "ir_report_approved", "actor": user["email"], "timestamp": now_iso(),
        "details": f"Closure report approved for {report.get('case_number')}",
    })
    return {**report, **update}
