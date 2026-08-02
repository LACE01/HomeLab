"""Scheduled / on-demand active Nikto web-application scans -- same shape as
routes/nmap.py: the container runs the scanner itself against targets you
configure, gated by an explicit authorization checkbox on every config, since
this makes the container originate real HTTP traffic against the target.
"""
import asyncio
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from db import db
from rbac import require_module
from auth_utils import get_current_user, require_role
from routes.common import now_iso, _clean

router = APIRouter()


class WebScanConfigBody(BaseModel):
    name: str
    target_url: str                    # e.g. https://app.example.com
    schedule_hours: int = 0            # 0 = manual only ("Run now" button)
    enabled: bool = True
    authorized: bool = False           # must be true to create/update
    tuning: Optional[str] = None       # Nikto -Tuning spec, e.g. "1259bcx" -- blank = default (all checks)
    timeout_sec: int = 600


def _validate(body: WebScanConfigBody) -> None:
    if not body.authorized:
        raise HTTPException(400, "You must confirm you're authorized to scan this target")
    if body.schedule_hours < 0 or body.schedule_hours > 24 * 30:
        raise HTTPException(400, "schedule_hours must be between 0 (manual only) and 720 (30 days)")
    if body.timeout_sec < 30 or body.timeout_sec > 7200:
        raise HTTPException(400, "timeout_sec must be between 30 and 7200 (2 hours) -- full Nikto scans against large sites legitimately run long")
    from nikto_scan import validate_target_url
    try:
        validate_target_url(body.target_url)
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.get("/v1/admin/nikto/configs")
async def list_scan_configs(user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/admin/nikto-scans"))):
    items = await db.nikto_scan_configs.find({}, {"_id": 0}).sort("created_at", -1).to_list(200)
    return {"items": items}


@router.post("/v1/admin/nikto/configs")
async def create_scan_config(body: WebScanConfigBody, user: dict = Depends(require_role("admin"))):
    _validate(body)
    doc = {
        "id": str(uuid.uuid4()), **body.model_dump(), "status": "idle",
        "last_run_at": None, "last_result": None,
        "created_at": now_iso(), "created_by": user["email"],
    }
    await db.nikto_scan_configs.insert_one(doc)
    return _clean(doc)


@router.put("/v1/admin/nikto/configs/{config_id}")
async def update_scan_config(config_id: str, body: WebScanConfigBody, user: dict = Depends(require_role("admin"))):
    _validate(body)
    existing = await db.nikto_scan_configs.find_one({"id": config_id}, {"_id": 0})
    if not existing:
        raise HTTPException(404, "Scan config not found")
    update = body.model_dump()
    update["updated_at"] = now_iso()
    await db.nikto_scan_configs.update_one({"id": config_id}, {"$set": update})
    return {**existing, **update}


@router.delete("/v1/admin/nikto/configs/{config_id}")
async def delete_scan_config(config_id: str, user: dict = Depends(require_role("admin"))):
    await db.nikto_scan_configs.delete_one({"id": config_id})
    return {"ok": True}


async def _execute_scan(config_id: str):
    from nikto_scan import run_nikto_scan, parse_nikto_json, import_nikto_results
    from routes.common import record_engagement
    cfg = await db.nikto_scan_configs.find_one({"id": config_id}, {"_id": 0})
    if not cfg:
        return
    started = now_iso()
    try:
        raw = await run_nikto_scan(cfg["target_url"], timeout_sec=cfg.get("timeout_sec", 600), tuning=cfg.get("tuning"))
        parsed = parse_nikto_json(raw)
        result = await import_nikto_results(db, cfg["target_url"], parsed, source_label=f"Scheduled: {cfg['name']}")
        await db.nikto_scan_configs.update_one({"id": config_id}, {"$set": {
            "status": "idle", "last_run_at": now_iso(), "last_result": {**result, "ok": True},
        }})
        await record_engagement(
            db, name=cfg["name"], scanner="Nikto", scan_type="web_app_scan",
            scan_method="active_scan", status="completed",
            assets_scanned=1, findings_created=result.get("findings_created", 0),
            findings_updated=0, started_at=started,
        )
    except Exception as e:
        await db.nikto_scan_configs.update_one({"id": config_id}, {"$set": {
            "status": "idle", "last_run_at": now_iso(), "last_result": {"ok": False, "error": str(e)},
        }})
        await record_engagement(
            db, name=cfg["name"], scanner="Nikto", scan_type="web_app_scan",
            scan_method="active_scan", status="failed", started_at=started, error=str(e),
        )


@router.post("/v1/admin/nikto/configs/{config_id}/run-now")
async def run_scan_now(config_id: str, user: dict = Depends(require_role("admin"))):
    cfg = await db.nikto_scan_configs.find_one({"id": config_id}, {"_id": 0})
    if not cfg:
        raise HTTPException(404, "Scan config not found")
    if cfg.get("status") == "running":
        return {"status": "running", "message": "This scan is already in progress"}
    await db.nikto_scan_configs.update_one({"id": config_id}, {"$set": {"status": "running"}})
    # Enqueued, not create_task'd. Running a scanner inside the API process means
    # it competes with request handling for one event loop, and a wedged scan
    # takes the whole product down -- which is exactly what happened. A queued job
    # also survives a deploy: the worker picks it up again instead of the scan
    # silently never finishing. See jobqueue.py.
    from jobqueue import enqueue
    import job_handlers  # noqa: F401 -- registers the handler so the kind validates
    job = await enqueue(db, "nikto_scan", {"config_id": config_id},
                         requested_by=user.get("email") or user.get("id"))
    return {"status": "queued", "job_id": job["id"], "deduped": job.get("deduped", False),
            "message": ("This scan was already queued." if job.get("deduped")
                         else "Scan queued -- poll GET /v1/jobs/{} for progress".format(job["id"]))}


async def run_due_scheduled_scans(db) -> dict:
    """Called from a periodic loop. Runs one scan at a time, same reasoning as Nmap's
    scheduler -- avoid piling up concurrent scanner subprocesses."""
    already_running = await db.nikto_scan_configs.count_documents({"status": "running"})
    if already_running:
        return {"skipped": "a scan is already running"}

    now = datetime.now(timezone.utc)
    configs = await db.nikto_scan_configs.find(
        {"enabled": True, "schedule_hours": {"$gt": 0}}, {"_id": 0}
    ).to_list(200)
    for cfg in configs:
        last = cfg.get("last_run_at")
        due = True
        if last:
            try:
                last_dt = datetime.fromisoformat(last.replace("Z", "+00:00"))
                due = (now - last_dt).total_seconds() >= cfg["schedule_hours"] * 3600
            except Exception:
                due = True
        if due:
            await db.nikto_scan_configs.update_one({"id": cfg["id"]}, {"$set": {"status": "running"}})
            await _execute_scan(cfg["id"])
            return {"ran": cfg["id"], "name": cfg["name"]}
    return {"ran": None}


async def nikto_scan_loop(db, interval_minutes: int = 15):
    import logging
    from heartbeat import record_heartbeat
    logger = logging.getLogger("vulnops")
    await asyncio.sleep(45)  # stagger past the Nmap loop's own 30s startup delay
    while True:
        ok, detail = True, {}
        try:
            result = await run_due_scheduled_scans(db)
            if result.get("ran"):
                logger.info(f"Nikto scheduler: ran scan '{result.get('name')}'")
            detail = result
        except Exception as e:
            logger.exception(f"Nikto scheduler error: {e}")
            ok, detail["error"] = False, str(e)
        await record_heartbeat(db, "nikto_scan_loop", "ok" if ok else "error", detail)
        await asyncio.sleep(interval_minutes * 60)
