"""Routes for the recon-ng OSINT module runner -- see backend/reconng.py for the
execution/parsing engine and its up-front caveats about module-version drift."""
import asyncio
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from db import db
from rbac import require_module
from auth_utils import get_current_user, require_role
from routes.common import now_iso, _clean

router = APIRouter()


# Non-recon-ng "source" lookups -- each needs its own connector configured under
# Integrations rather than a recon-ng API key. GreyNoise's endpoint doesn't strictly
# require a key (there's a tiny unauthenticated allowance) but the connector is meant
# to be configured, so it's still gated on having one, same as the others.
SOURCE_INTEGRATION = {
    "opencti": "OpenCTI",
    "greynoise": "GreyNoise",
    "otx": "AlienVault OTX",
    "abusech": "abuse.ch (ThreatFox)",
    "virustotal": "VirusTotal",
    "hibp_breach": "HaveIBeenPwned",
    "hibp_paste": "HaveIBeenPwned",
}


@router.get("/v1/recon/modules")
async def list_modules(user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/admin/recon-osint"))):
    from reconng import MODULE_CATALOG, ALL_REQUIRED_KEYS, TARGET_TYPES
    integration = await db.integrations.find_one({"name": "recon-ng"}, {"_id": 0})
    cfg = (integration or {}).get("config") or {}

    source_ready: dict = {}
    for source, name in SOURCE_INTEGRATION.items():
        src_integration = await db.integrations.find_one({"name": name}, {"_id": 0})
        src_cfg = (src_integration or {}).get("config") or {}
        source_ready[source] = bool(src_cfg.get("endpoint") and src_cfg.get("api_key"))

    items = []
    for m in MODULE_CATALOG:
        source = m.get("source")
        if source:
            ready = source_ready.get(source, False)
            missing = [] if ready else [f"{SOURCE_INTEGRATION.get(source, source)} connection (Integrations → {SOURCE_INTEGRATION.get(source, source)})"]
        else:
            missing = [k for k in m["requires_keys"] if not cfg.get(k)]
            ready = not missing
        items.append({**m, "ready": ready, "missing_keys": missing})
    return {"items": items, "configured_keys": [k for k in ALL_REQUIRED_KEYS if cfg.get(k)], "target_types": TARGET_TYPES}


class ReconConfigBody(BaseModel):
    hibp_api_key: Optional[str] = None


@router.put("/v1/admin/recon-config")
async def update_recon_config(body: ReconConfigBody, user: dict = Depends(require_role("admin"))):
    integration = await db.integrations.find_one({"name": "recon-ng"})
    update = body.model_dump(exclude_none=True)
    if not integration:
        await db.integrations.insert_one({
            "id": str(uuid.uuid4()), "name": "recon-ng", "type": "osint",
            "config": update, "status": "healthy" if update else "not_configured",
            "last_changed_at": now_iso(),
        })
    else:
        cfg = integration.get("config") or {}
        cfg.update(update)
        await db.integrations.update_one({"id": integration["id"]}, {"$set": {
            "config": cfg, "status": "healthy" if cfg else "not_configured", "last_changed_at": now_iso(),
        }})
    return {"ok": True}


@router.get("/v1/admin/recon-config")
async def get_recon_config(user: dict = Depends(require_role("admin"))):
    integration = await db.integrations.find_one({"name": "recon-ng"}, {"_id": 0})
    cfg = (integration or {}).get("config") or {}
    return {"hibp_api_key_set": bool(cfg.get("hibp_api_key"))}


class RunBody(BaseModel):
    module_id: Optional[str] = None       # back-compat: a single module
    module_ids: Optional[List[str]] = None  # preferred: one or more modules run in one batch
    target: str

    def all_ids(self) -> List[str]:
        ids = list(dict.fromkeys(self.module_ids or []))  # de-dupe, keep order
        if self.module_id and self.module_id not in ids:
            ids.insert(0, self.module_id)
        return ids


async def _execute_run(run_id: str):
    """Runs every module in run['module_ids'] against run['target'], one at a time
    (recon-cli isn't safe to run concurrently against the same disposable workspace
    naming scheme), and records a per-module result so a batch of e.g. HackerTarget +
    WHOIS + OpenCTI in one submission shows what each one individually found/failed."""
    from reconng import run_module
    run = await db.recon_runs.find_one({"id": run_id}, {"_id": 0})
    if not run:
        return
    results = []
    any_ok = False
    for module_id in run.get("module_ids", []):
        try:
            result = await run_module(db, module_id, run["target"])
            results.append({"module_id": module_id, "status": "success", "result": result, "error": None})
            any_ok = True
        except Exception as e:
            results.append({"module_id": module_id, "status": "failed", "result": None, "error": str(e)})
        # Persist incrementally so the UI can poll and show partial progress on a
        # multi-module batch instead of waiting for the whole thing to finish.
        await db.recon_runs.update_one({"id": run_id}, {"$set": {"results": results}})
    final_status = "success" if any_ok and all(r["status"] == "success" for r in results) else                    "partial" if any_ok else "failed"
    await db.recon_runs.update_one({"id": run_id}, {"$set": {
        "status": final_status, "finished_at": now_iso(), "results": results,
    }})


@router.post("/v1/recon/run")
async def start_run(body: RunBody, user: dict = Depends(require_role("admin", "manager")),
                     _rbac: dict = Depends(require_module("/admin/recon-osint", level="edit"))):
    from reconng import MODULE_BY_ID, validate_target
    module_ids = body.all_ids()
    if not module_ids:
        raise HTTPException(400, "Select at least one module")
    unknown = [m for m in module_ids if m not in MODULE_BY_ID]
    if unknown:
        raise HTTPException(404, f"Unknown module(s): {', '.join(unknown)}")
    try:
        target = validate_target(body.target)
    except ValueError as e:
        raise HTTPException(400, str(e))
    already_running = await db.recon_runs.count_documents({"status": "running"})
    if already_running:
        raise HTTPException(409, "Another recon-ng run is already in progress -- wait for it to finish")
    run_id = str(uuid.uuid4())
    doc = {
        "id": run_id, "module_ids": module_ids,
        "module_labels": [MODULE_BY_ID[m]["label"] for m in module_ids],
        "target": target,
        "status": "running", "started_at": now_iso(), "finished_at": None, "results": [], "error": None,
        "triggered_by": user["email"], "scheduled": False,
    }
    await db.recon_runs.insert_one(doc)
    # Enqueued to the worker. recon-ng spawns module subprocesses; running them in
    # the API process contributed to the OOM crash. See job_handlers._recon.
    from jobqueue import enqueue
    import job_handlers  # noqa: F401
    await enqueue(db, "recon_run", {"run_id": run_id},
                  requested_by=user.get("email") or user.get("id"))
    return {"id": run_id, "status": "queued"}


@router.get("/v1/recon/preflight")
async def recon_preflight(user: dict = Depends(get_current_user),
                          _rbac: dict = Depends(require_module("/admin/recon-osint"))):
    """Whether recon-ng is actually installed and which modules are present.

    Turns the long-standing 'first run is a smoke test' caveat into an
    observable status: the page can show 'recon-ng ready, 8/9 modules installed'
    or 'recon-cli not found' instead of failing a run with a confusing error.
    """
    from reconng import preflight
    return await preflight()


@router.get("/v1/recon/runs")
async def list_runs(user: dict = Depends(get_current_user)):
    items = await db.recon_runs.find({}, {"_id": 0}).sort("started_at", -1).to_list(200)
    return {"items": items}


@router.get("/v1/recon/runs/{run_id}")
async def get_run(run_id: str, user: dict = Depends(get_current_user)):
    run = await db.recon_runs.find_one({"id": run_id}, {"_id": 0})
    if not run:
        raise HTTPException(404, "Run not found")
    return run


@router.get("/v1/recon/osint-findings")
async def list_osint_findings(user: dict = Depends(get_current_user)):
    items = await db.osint_findings.find({}, {"_id": 0}).sort("found_at", -1).to_list(500)
    return {"items": items}


class AckBody(BaseModel):
    acknowledged: bool = True


@router.patch("/v1/recon/osint-findings/{finding_id}")
async def ack_osint_finding(finding_id: str, body: AckBody, user: dict = Depends(get_current_user)):
    res = await db.osint_findings.update_one({"id": finding_id}, {"$set": {"acknowledged": body.acknowledged}})
    if res.matched_count == 0:
        raise HTTPException(404, "Not found")
    return {"ok": True}


# --------------------------- SCHEDULES ---------------------------
class ScheduleBody(BaseModel):
    module_id: str
    target: str
    interval_hours: int = 24
    enabled: bool = True


@router.get("/v1/admin/recon-schedules")
async def list_schedules(user: dict = Depends(get_current_user)):
    items = await db.recon_schedules.find({}, {"_id": 0}).sort("created_at", -1).to_list(200)
    return {"items": items}


@router.post("/v1/admin/recon-schedules")
async def create_schedule(body: ScheduleBody, user: dict = Depends(require_role("admin"))):
    from reconng import MODULE_BY_ID, validate_target
    if body.module_id not in MODULE_BY_ID:
        raise HTTPException(404, f"Unknown module '{body.module_id}'")
    try:
        target = validate_target(body.target)
    except ValueError as e:
        raise HTTPException(400, str(e))
    if body.interval_hours < 1 or body.interval_hours > 24 * 30:
        raise HTTPException(400, "interval_hours must be between 1 and 720")
    doc = {
        "id": str(uuid.uuid4()), "module_id": body.module_id, "target": target,
        "interval_hours": body.interval_hours, "enabled": body.enabled,
        "last_run_at": None, "created_at": now_iso(), "created_by": user["email"],
    }
    await db.recon_schedules.insert_one(doc)
    return _clean(doc)


@router.put("/v1/admin/recon-schedules/{schedule_id}")
async def update_schedule(schedule_id: str, body: ScheduleBody, user: dict = Depends(require_role("admin"))):
    existing = await db.recon_schedules.find_one({"id": schedule_id}, {"_id": 0})
    if not existing:
        raise HTTPException(404, "Schedule not found")
    await db.recon_schedules.update_one({"id": schedule_id}, {"$set": {
        "module_id": body.module_id, "target": body.target,
        "interval_hours": body.interval_hours, "enabled": body.enabled, "updated_at": now_iso(),
    }})
    return {"ok": True}


@router.delete("/v1/admin/recon-schedules/{schedule_id}")
async def delete_schedule(schedule_id: str, user: dict = Depends(require_role("admin"))):
    await db.recon_schedules.delete_one({"id": schedule_id})
    return {"ok": True}


async def run_due_scheduled_recon(db) -> dict:
    already_running = await db.recon_runs.count_documents({"status": "running"})
    if already_running:
        return {"skipped": "a run is already in progress"}
    now = datetime.now(timezone.utc)
    schedules = await db.recon_schedules.find({"enabled": True}, {"_id": 0}).to_list(200)
    for sched in schedules:
        last = sched.get("last_run_at")
        due = True
        if last:
            try:
                last_dt = datetime.fromisoformat(last.replace("Z", "+00:00"))
                due = (now - last_dt).total_seconds() >= sched["interval_hours"] * 3600
            except Exception:
                due = True
        if due:
            run_id = str(uuid.uuid4())
            from reconng import MODULE_BY_ID
            mod = MODULE_BY_ID.get(sched["module_id"])
            if not mod:
                continue
            await db.recon_runs.insert_one({
                "id": run_id, "module_ids": [sched["module_id"]], "module_labels": [mod["label"]],
                "target": sched["target"],
                "status": "running", "started_at": now_iso(), "finished_at": None, "results": [], "error": None,
                "triggered_by": "schedule", "scheduled": True,
            })
            await db.recon_schedules.update_one({"id": sched["id"]}, {"$set": {"last_run_at": now_iso()}})
            await _execute_run(run_id)
            return {"ran": run_id, "module": sched["module_id"], "target": sched["target"]}
    return {"ran": None}


async def recon_scheduled_loop(db, interval_minutes: int = 30):
    import logging
    from heartbeat import record_heartbeat
    logger = logging.getLogger("vulnops")
    await asyncio.sleep(60)
    while True:
        ok, detail = True, {}
        try:
            result = await run_due_scheduled_recon(db)
            if result.get("ran"):
                logger.info(f"recon-ng scheduler: ran module '{result.get('module')}' against '{result.get('target')}'")
            detail = result
        except Exception as e:
            logger.exception(f"recon-ng scheduler error: {e}")
            ok, detail["error"] = False, str(e)
        await record_heartbeat(db, "recon_scheduled_loop", "ok" if ok else "error", detail)
        await asyncio.sleep(interval_minutes * 60)
