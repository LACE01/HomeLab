"""Incident Response routes -- admin config (plan phases/roles/classification/
wizard questions/tool catalog), the helpdesk triage wizard, and IR cases (the
collaborative ticket: timeline, phase checklist, evidence, closure report).
See backend/incident_response.py for the domain logic/defaults this wires up."""
import uuid
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import StreamingResponse, FileResponse
from pydantic import BaseModel

from db import db
from rbac import require_module
from auth_utils import get_current_user, require_role
from routes.common import now_iso, _clean
import incident_response as ir
from risk_export import build_ir_case_export_docx

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
    tasks: List[str] = []  # checklist shown to whoever is assigned this role on a case
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
    linked_integration: Optional[str] = None  # name of an existing Integrations connector (e.g. "Qualys VMDR"), if this tool IS one
    vendor: Optional[str] = None  # free-text vendor/product name for tools not modeled as an Integrations connector (e.g. "Palo Alto", "on-prem Domain Controllers")


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
    report = await db.ir_case_reports.find_one({"case_id": case_id}, {"_id": 0})
    progress = ir.compute_case_progress(case, phase_progress, roles_cfg["roles"], report)
    return {"case": case, "phase_progress": phase_progress, "events": events, "evidence": evidence,
            "roles": roles_cfg["roles"], "progress": progress}


class CaseUpdateBody(BaseModel):
    title: Optional[str] = None
    classification: Optional[str] = None
    reporter_contact: Optional[str] = None
    sheets_webhook_url: Optional[str] = None
    root_cause: Optional[str] = None


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


class RoleTaskToggleBody(BaseModel):
    task_index: int
    done: bool


@router.put("/v1/ir/cases/{case_id}/roles/{role_id}/tasks")
async def toggle_role_task(case_id: str, role_id: str, body: RoleTaskToggleBody, user: dict = Depends(get_current_user),
                            _rbac: dict = Depends(require_module("/ir/cases", level="edit"))):
    """Lets whoever is assigned a role (or any case editor) check off that role's
    task checklist -- tracked per-case since the same role config can be reused
    across many cases with independent progress each time."""
    case = await _get_case_or_404(case_id)
    assigned_roles = dict(case.get("assigned_roles") or {})
    assignment = dict(assigned_roles.get(role_id) or {})
    tasks_done = set(assignment.get("tasks_done") or [])
    if body.done:
        tasks_done.add(body.task_index)
    else:
        tasks_done.discard(body.task_index)
    assignment["tasks_done"] = sorted(tasks_done)
    assigned_roles[role_id] = assignment
    await db.ir_cases.update_one({"id": case_id}, {"$set": {"assigned_roles": assigned_roles, "updated_at": now_iso()}})
    roles_cfg = await _get_or_seed("ir_roles_config", ir._default_roles_config)
    role = next((r for r in roles_cfg["roles"] if r["id"] == role_id), None)
    task_label = (role.get("tasks") or [])[body.task_index] if role and body.task_index < len(role.get("tasks") or []) else f"task {body.task_index}"
    event = {"id": str(uuid.uuid4()), "case_id": case_id, "type": "task_checked" if body.done else "task_unchecked",
              "text": f"[{role.get('name') if role else 'role'}] {'Checked' if body.done else 'Unchecked'}: {task_label}",
              "author": user["email"], "attachments": [], "created_at": now_iso()}
    await db.ir_case_events.insert_one(dict(event))
    await ir.push_case_event_to_sheet(db, case, event)
    return {"assigned_roles": assigned_roles}


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
    if "root_cause" in update:
        await db.ir_cases.update_one({"id": case_id}, {"$set": {"root_cause": update["root_cause"]}})
    return {**report, **update}


# --------------------------------------------------------------------------------
# Follow-up actions -- tracked as individual {id, text, done} items on the case
# itself (not frozen into the report), so they stay actionable even after the
# closure report is approved. A case with pending follow-ups isn't "truly done"
# even once its report is approved -- the frontend surfaces that distinction
# rather than this API inventing a third case status.
# --------------------------------------------------------------------------------
class FollowUpCreateBody(BaseModel):
    text: str


@router.post("/v1/ir/cases/{case_id}/follow-ups")
async def add_follow_up(case_id: str, body: FollowUpCreateBody, user: dict = Depends(get_current_user),
                         _rbac: dict = Depends(require_module("/ir/cases", level="edit"))):
    case = await _get_case_or_404(case_id)
    item = {"id": str(uuid.uuid4()), "text": body.text, "done": False}
    items = (case.get("follow_up_actions") or []) + [item]
    await db.ir_cases.update_one({"id": case_id}, {"$set": {"follow_up_actions": items, "updated_at": now_iso()}})
    await db.ir_case_events.insert_one({
        "id": str(uuid.uuid4()), "case_id": case_id, "type": "case_updated",
        "text": f"Follow-up action added: {body.text}", "author": user["email"], "attachments": [], "created_at": now_iso(),
    })
    return item


class FollowUpUpdateBody(BaseModel):
    text: Optional[str] = None
    done: Optional[bool] = None


@router.put("/v1/ir/cases/{case_id}/follow-ups/{item_id}")
async def update_follow_up(case_id: str, item_id: str, body: FollowUpUpdateBody, user: dict = Depends(get_current_user),
                            _rbac: dict = Depends(require_module("/ir/cases", level="edit"))):
    case = await _get_case_or_404(case_id)
    items = case.get("follow_up_actions") or []
    idx = next((i for i, it in enumerate(items) if it.get("id") == item_id), None)
    if idx is None:
        raise HTTPException(404, "Follow-up action not found")
    if body.text is not None:
        items[idx]["text"] = body.text
    if body.done is not None:
        items[idx]["done"] = body.done
    await db.ir_cases.update_one({"id": case_id}, {"$set": {"follow_up_actions": items, "updated_at": now_iso()}})
    if body.done is not None:
        await db.ir_case_events.insert_one({
            "id": str(uuid.uuid4()), "case_id": case_id, "type": "case_updated",
            "text": f"Follow-up action {'completed' if body.done else 'reopened'}: {items[idx]['text']}",
            "author": user["email"], "attachments": [], "created_at": now_iso(),
        })
    return items[idx]


@router.delete("/v1/ir/cases/{case_id}/follow-ups/{item_id}")
async def delete_follow_up(case_id: str, item_id: str, user: dict = Depends(get_current_user),
                            _rbac: dict = Depends(require_module("/ir/cases", level="edit"))):
    case = await _get_case_or_404(case_id)
    items = [it for it in (case.get("follow_up_actions") or []) if it.get("id") != item_id]
    await db.ir_cases.update_one({"id": case_id}, {"$set": {"follow_up_actions": items, "updated_at": now_iso()}})
    return {"ok": True}


@router.post("/v1/ir/cases/{case_id}/report/approve")
async def approve_case_report(case_id: str, user: dict = Depends(get_current_user),
                               _rbac: dict = Depends(require_module("/ir/case-approval", level="edit"))):
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


# --------------------------------------------------------------------------------
# Reporting obligations -- admin-managed library (mirrors the tool catalog's CRUD
# shape) plus per-case attachment/notify/complete.
# --------------------------------------------------------------------------------
async def _ensure_obligations_seeded():
    if await db.ir_reporting_obligations.count_documents({}) == 0:
        docs = ir._default_reporting_obligations()
        if docs:
            await db.ir_reporting_obligations.insert_many(docs)


class ObligationContactBody(BaseModel):
    name: str
    team: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    portal_url: Optional[str] = None
    notes: Optional[str] = None


class ObligationBody(BaseModel):
    name: str
    trigger_description: Optional[str] = ""
    reporting_target: Optional[str] = ""
    timeline_hours: Optional[float] = None
    timeline_text: Optional[str] = ""
    contacts: List[ObligationContactBody] = []
    auto_notify: Optional[bool] = False
    notify_webhook_url: Optional[str] = None
    active: Optional[bool] = True


@router.get("/v1/admin/ir/obligations")
async def list_obligations(user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/admin/ir-setup"))):
    await _ensure_obligations_seeded()
    items = await db.ir_reporting_obligations.find({}, {"_id": 0}).sort("name", 1).to_list(200)
    return {"items": items}


@router.post("/v1/admin/ir/obligations")
async def create_obligation(body: ObligationBody, user: dict = Depends(require_role("admin", "manager")),
                             _rbac: dict = Depends(require_module("/admin/ir-setup", level="edit"))):
    doc = {"id": str(uuid.uuid4()), **body.model_dump(), "created_at": now_iso()}
    await db.ir_reporting_obligations.insert_one(dict(doc))
    return _clean(doc)


@router.put("/v1/admin/ir/obligations/{obligation_id}")
async def update_obligation(obligation_id: str, body: ObligationBody, user: dict = Depends(require_role("admin", "manager")),
                             _rbac: dict = Depends(require_module("/admin/ir-setup", level="edit"))):
    existing = await db.ir_reporting_obligations.find_one({"id": obligation_id}, {"_id": 0})
    if not existing:
        raise HTTPException(404, "Obligation not found")
    update = body.model_dump()
    await db.ir_reporting_obligations.update_one({"id": obligation_id}, {"$set": update})
    return {**existing, **update}


@router.delete("/v1/admin/ir/obligations/{obligation_id}")
async def delete_obligation(obligation_id: str, user: dict = Depends(require_role("admin", "manager")),
                             _rbac: dict = Depends(require_module("/admin/ir-setup", level="edit"))):
    await db.ir_reporting_obligations.delete_one({"id": obligation_id})
    return {"ok": True}


def _compute_due_at(case: dict, timeline_hours: Optional[float]) -> Optional[str]:
    if timeline_hours is None:
        return None
    from datetime import datetime, timedelta, timezone
    try:
        opened = datetime.fromisoformat((case.get("opened_at") or "").replace("Z", "+00:00"))
    except ValueError:
        return None
    return (opened + timedelta(hours=timeline_hours)).isoformat()


@router.get("/v1/ir/cases/{case_id}/obligations")
async def list_case_obligations(case_id: str, user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/ir/cases"))):
    items = await db.ir_case_obligations.find({"case_id": case_id}, {"_id": 0}).sort("due_at", 1).to_list(200)
    return {"items": items}


class ObligationAttachBody(BaseModel):
    obligation_id: str


@router.post("/v1/ir/cases/{case_id}/obligations")
async def attach_obligation(case_id: str, body: ObligationAttachBody, user: dict = Depends(get_current_user),
                             _rbac: dict = Depends(require_module("/ir/cases", level="edit"))):
    case = await _get_case_or_404(case_id)
    obligation = await db.ir_reporting_obligations.find_one({"id": body.obligation_id}, {"_id": 0})
    if not obligation:
        raise HTTPException(404, "Obligation not found in the library")
    instance = {
        "id": str(uuid.uuid4()), "case_id": case_id, "obligation_id": obligation["id"],
        "name": obligation["name"], "trigger_description": obligation.get("trigger_description", ""),
        "reporting_target": obligation.get("reporting_target", ""), "timeline_text": obligation.get("timeline_text", ""),
        "contacts": obligation.get("contacts", []), "notify_webhook_url": obligation.get("notify_webhook_url"),
        "due_at": _compute_due_at(case, obligation.get("timeline_hours")),
        "status": "pending", "notified_at": None, "done_at": None,
        "attached_by": user["email"], "attached_at": now_iso(),
    }
    await db.ir_case_obligations.insert_one(dict(instance))
    event_text = f"Reporting obligation attached: {obligation['name']} ({obligation.get('reporting_target','')})"
    if instance["due_at"]:
        event_text += f" — due {instance['due_at'][:19]}"
    await db.ir_case_events.insert_one({
        "id": str(uuid.uuid4()), "case_id": case_id, "type": "obligation_attached", "text": event_text,
        "author": user["email"], "attachments": [], "created_at": now_iso(),
    })
    if obligation.get("auto_notify"):
        result = await ir.send_obligation_notification(db, case, instance)
        notified_at = now_iso()
        await db.ir_case_obligations.update_one({"id": instance["id"]}, {"$set": {"status": "notified", "notified_at": notified_at}})
        instance["status"], instance["notified_at"] = "notified", notified_at
        await db.ir_case_events.insert_one({
            "id": str(uuid.uuid4()), "case_id": case_id, "type": "obligation_notified",
            "text": f"Auto-notified for '{obligation['name']}': sent to {len(result['sent'])}, failed {len(result['failed'])}",
            "author": "system", "attachments": [], "created_at": notified_at,
        })
    return _clean(instance)


@router.post("/v1/ir/cases/{case_id}/obligations/{instance_id}/notify")
async def notify_obligation(case_id: str, instance_id: str, user: dict = Depends(get_current_user),
                             _rbac: dict = Depends(require_module("/ir/cases", level="edit"))):
    case = await _get_case_or_404(case_id)
    instance = await db.ir_case_obligations.find_one({"id": instance_id, "case_id": case_id}, {"_id": 0})
    if not instance:
        raise HTTPException(404, "Obligation not attached to this case")
    result = await ir.send_obligation_notification(db, case, instance)
    notified_at = now_iso()
    await db.ir_case_obligations.update_one({"id": instance_id}, {"$set": {"status": "notified", "notified_at": notified_at}})
    await db.ir_case_events.insert_one({
        "id": str(uuid.uuid4()), "case_id": case_id, "type": "obligation_notified",
        "text": f"Notified for '{instance['name']}' by {user['email']}: sent to {len(result['sent'])}, failed {len(result['failed'])}",
        "author": user["email"], "attachments": [], "created_at": notified_at,
    })
    return {"status": "notified", "notified_at": notified_at, **result}


class ObligationInstanceUpdateBody(BaseModel):
    status: Optional[str] = None  # pending | notified | done
    notes: Optional[str] = None


@router.put("/v1/ir/cases/{case_id}/obligations/{instance_id}")
async def update_case_obligation(case_id: str, instance_id: str, body: ObligationInstanceUpdateBody, user: dict = Depends(get_current_user),
                                  _rbac: dict = Depends(require_module("/ir/cases", level="edit"))):
    instance = await db.ir_case_obligations.find_one({"id": instance_id, "case_id": case_id}, {"_id": 0})
    if not instance:
        raise HTTPException(404, "Obligation not attached to this case")
    update = {}
    if body.status:
        if body.status not in ("pending", "notified", "done"):
            raise HTTPException(400, "status must be pending, notified, or done")
        update["status"] = body.status
        if body.status == "done":
            update["done_at"] = now_iso()
    if body.notes is not None:
        update["notes"] = body.notes
    if update:
        await db.ir_case_obligations.update_one({"id": instance_id}, {"$set": update})
        if update.get("status") == "done":
            await db.ir_case_events.insert_one({
                "id": str(uuid.uuid4()), "case_id": case_id, "type": "obligation_done",
                "text": f"Reporting obligation completed: {instance['name']}",
                "author": user["email"], "attachments": [], "created_at": now_iso(),
            })
    return {**instance, **update}


@router.delete("/v1/ir/cases/{case_id}/obligations/{instance_id}")
async def remove_case_obligation(case_id: str, instance_id: str, user: dict = Depends(get_current_user),
                                  _rbac: dict = Depends(require_module("/ir/cases", level="edit"))):
    await db.ir_case_obligations.delete_one({"id": instance_id, "case_id": case_id})
    return {"ok": True}


@router.get("/v1/ir/cases/{case_id}/export.docx")
async def export_case_docx(case_id: str, user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/ir/cases"))):
    case = await _get_case_or_404(case_id)
    phase_progress = await db.ir_case_phase_progress.find({"case_id": case_id}, {"_id": 0}).sort("order", 1).to_list(100)
    events = await db.ir_case_events.find({"case_id": case_id}, {"_id": 0}).to_list(1000)
    evidence = await db.ir_case_evidence.find({"case_id": case_id}, {"_id": 0}).sort("item_no", 1).to_list(200)
    obligations = await db.ir_case_obligations.find({"case_id": case_id}, {"_id": 0}).to_list(200)
    report = await db.ir_case_reports.find_one({"case_id": case_id}, {"_id": 0})
    artifacts = await db.ir_case_artifacts.find({"case_id": case_id}, {"_id": 0}).sort("uploaded_at", 1).to_list(500)
    related_entities = await db.ir_case_entities.find({"case_id": case_id}, {"_id": 0}).to_list(500)
    buf = ir.build_case_docx(case, phase_progress, events, evidence, obligations, report,
                              artifacts=artifacts, related_entities=related_entities)
    filename = f"{case.get('case_number','ir-case')}.docx"
    return StreamingResponse(
        buf, media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/v1/ir/cases/{case_id}/risk-export.docx")
async def export_case_risk_docx(case_id: str, user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/ir/cases"))):
    """Separate from export.docx above (the case's own timeline/evidence/report) --
    this pulls in whatever's been tracked in the Risk Register for this case, same
    shape as the Albert-alert-anchored export in routes.albert."""
    from routes.risk_register import gather_linked_bundle
    case = await _get_case_or_404(case_id)
    risks = await db.risks.find({"linked_ir_case_ids": case_id}, {"_id": 0}).to_list(200)
    bundles = [await gather_linked_bundle(db, r) for r in risks]
    buf = build_ir_case_export_docx(case, bundles)
    filename = f"{case.get('case_number','ir-case')}-risk-report.docx"
    return StreamingResponse(
        buf, media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/v1/ir/users-lite")
async def list_users_lite(user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/ir/cases"))):
    """Lightweight user picker for role assignment -- name/email/role only, and not
    admin-gated like /v1/admin/users, since any responder with case-edit access
    needs to be able to assign roles to teammates, not just admins."""
    items = await db.users.find({"active": {"$ne": False}}, {"_id": 0, "id": 1, "name": 1, "email": 1, "role": 1, "team": 1}).sort("name", 1).to_list(500)
    return {"items": items}


@router.get("/v1/ir/obligations-lite")
async def list_obligations_lite(user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/ir/cases"))):
    """Read-only library listing for the case-attachment picker -- any responder
    with case-edit access needs to attach a reporting obligation to a live incident,
    which shouldn't be blocked behind the admin-only IR Setup module (attaching a
    72-hour CISA reporting clock isn't something that should wait on an admin)."""
    await _ensure_obligations_seeded()
    items = await db.ir_reporting_obligations.find({"active": {"$ne": False}}, {"_id": 0}).sort("name", 1).to_list(200)
    return {"items": items}


@router.post("/v1/ir/cases/{case_id}/reopen")
async def reopen_case(case_id: str, user: dict = Depends(get_current_user),
                       _rbac: dict = Depends(require_module("/ir/cases", level="edit"))):
    case = await _get_case_or_404(case_id)
    if case["status"] != "closed":
        raise HTTPException(400, "Case is not closed")
    await db.ir_cases.update_one({"id": case_id}, {"$set": {"status": "open", "closed_at": None, "updated_at": now_iso()}})
    event = {"id": str(uuid.uuid4()), "case_id": case_id, "type": "case_reopened",
              "text": f"Case reopened by {user['email']}.", "author": user["email"], "attachments": [], "created_at": now_iso()}
    await db.ir_case_events.insert_one(dict(event))
    await ir.push_case_event_to_sheet(db, case, event)
    return {"ok": True, "status": "open"}


# --------------------------------------------------------------------------------
# Case artifacts -- general file attachments (any type: .txt, .csv, .xlsx, .docx,
# .pdf, exports from other tools...), optionally grouped into a named "folder" when
# several files belong together (e.g. a batch of logs from one host).
# --------------------------------------------------------------------------------
@router.get("/v1/ir/cases/{case_id}/artifacts")
async def list_case_artifacts(case_id: str, user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/ir/cases"))):
    items = await db.ir_case_artifacts.find({"case_id": case_id}, {"_id": 0}).sort("uploaded_at", -1).to_list(500)
    return {"items": items}


@router.post("/v1/ir/cases/{case_id}/artifacts")
async def upload_case_artifacts(case_id: str, files: List[UploadFile] = File(...), folder: Optional[str] = Form(None),
                                 user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/ir/cases", level="edit"))):
    case = await _get_case_or_404(case_id)
    case_dir = ir.ARTIFACTS_DIR / case_id
    case_dir.mkdir(parents=True, exist_ok=True)
    saved = []
    for f in files:
        content = await f.read()
        if len(content) > ir.MAX_ARTIFACT_BYTES:
            raise HTTPException(413, f"'{f.filename}' exceeds the 25MB per-file limit")
        stored_name = f"{uuid.uuid4().hex}_{f.filename}"
        (case_dir / stored_name).write_bytes(content)
        doc = {
            "id": str(uuid.uuid4()), "case_id": case_id, "filename": f.filename, "stored_name": stored_name,
            "mime": f.content_type or "application/octet-stream", "size": len(content), "folder": folder,
            "uploaded_by": user["email"], "uploaded_at": now_iso(),
        }
        await db.ir_case_artifacts.insert_one(dict(doc))
        saved.append(_clean(doc))
    names = ", ".join(a["filename"] for a in saved)
    folder_suffix = f' to folder "{folder}"' if folder else ""
    event = {"id": str(uuid.uuid4()), "case_id": case_id, "type": "evidence_added",
              "text": f"Artifact(s) uploaded{folder_suffix}: {names}",
              "author": user["email"], "attachments": [], "created_at": now_iso()}
    await db.ir_case_events.insert_one(dict(event))
    await ir.push_case_event_to_sheet(db, case, event)
    return {"items": saved}


@router.get("/v1/ir/cases/{case_id}/artifacts/{artifact_id}/download")
async def download_case_artifact(case_id: str, artifact_id: str, user: dict = Depends(get_current_user),
                                  _rbac: dict = Depends(require_module("/ir/cases"))):
    artifact = await db.ir_case_artifacts.find_one({"id": artifact_id, "case_id": case_id}, {"_id": 0})
    if not artifact:
        raise HTTPException(404, "Artifact not found")
    try:
        path = ir.artifact_disk_path(case_id, artifact["stored_name"])
    except ValueError:
        raise HTTPException(400, "Invalid artifact")
    if not path.exists():
        raise HTTPException(404, "Artifact file is missing on disk")
    return FileResponse(path, media_type=artifact.get("mime") or "application/octet-stream", filename=artifact["filename"])


@router.delete("/v1/ir/cases/{case_id}/artifacts/{artifact_id}")
async def delete_case_artifact(case_id: str, artifact_id: str, user: dict = Depends(get_current_user),
                                _rbac: dict = Depends(require_module("/ir/cases", level="edit"))):
    artifact = await db.ir_case_artifacts.find_one({"id": artifact_id, "case_id": case_id}, {"_id": 0})
    if artifact:
        try:
            path = ir.artifact_disk_path(case_id, artifact["stored_name"])
            path.unlink(missing_ok=True)
        except ValueError:
            pass
    await db.ir_case_artifacts.delete_one({"id": artifact_id, "case_id": case_id})
    return {"ok": True}


# --------------------------------------------------------------------------------
# Related assets/entities -- what this incident could have affected: internal
# assets (servers/websites) pulled from the asset inventory, users, or external
# parties (vendors/supply-chain partners) that aren't in inventory at all.
# --------------------------------------------------------------------------------
RELATED_ENTITY_TYPES = {"asset", "user", "server", "website", "external_vendor", "other"}


class RelatedEntityBody(BaseModel):
    type: str
    name: str
    asset_id: Optional[str] = None
    notes: Optional[str] = None


@router.get("/v1/ir/cases/{case_id}/entities")
async def list_case_entities(case_id: str, user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/ir/cases"))):
    items = await db.ir_case_entities.find({"case_id": case_id}, {"_id": 0}).to_list(500)
    return {"items": items}


@router.post("/v1/ir/cases/{case_id}/entities")
async def add_case_entity(case_id: str, body: RelatedEntityBody, user: dict = Depends(get_current_user),
                           _rbac: dict = Depends(require_module("/ir/cases", level="edit"))):
    if body.type not in RELATED_ENTITY_TYPES:
        raise HTTPException(400, f"type must be one of {sorted(RELATED_ENTITY_TYPES)}")
    case = await _get_case_or_404(case_id)
    doc = {"id": str(uuid.uuid4()), "case_id": case_id, "type": body.type, "name": body.name,
           "asset_id": body.asset_id, "notes": body.notes or "", "added_by": user["email"], "added_at": now_iso()}
    await db.ir_case_entities.insert_one(dict(doc))
    event = {"id": str(uuid.uuid4()), "case_id": case_id, "type": "entity_linked",
              "text": f"Linked {body.type.replace('_',' ')}: {body.name}",
              "author": user["email"], "attachments": [], "created_at": now_iso()}
    await db.ir_case_events.insert_one(dict(event))
    await ir.push_case_event_to_sheet(db, case, event)
    return _clean(doc)


@router.delete("/v1/ir/cases/{case_id}/entities/{entity_id}")
async def remove_case_entity(case_id: str, entity_id: str, user: dict = Depends(get_current_user),
                              _rbac: dict = Depends(require_module("/ir/cases", level="edit"))):
    await db.ir_case_entities.delete_one({"id": entity_id, "case_id": case_id})
    return {"ok": True}


@router.get("/v1/ir/assets-lite")
async def list_assets_lite(user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/ir/cases"))):
    """Lightweight asset picker source for linking related assets to a case."""
    items = await db.assets.find({}, {"_id": 0, "id": 1, "hostname": 1, "ip_address": 1, "criticality": 1}).to_list(1000)
    return {"items": items}
