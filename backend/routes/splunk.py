"""Splunk connector config -- CRUD for saved searches to poll on a schedule (or
run on demand), same shape as routes/nikto.py's scan configs. See
splunk_sync.py for the actual HTTP call + event-emission logic.
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


class SplunkConfigBody(BaseModel):
    name: str
    endpoint: str                      # e.g. https://splunk.example.com:8089
    token: Optional[str] = None        # Splunk HEC/auth token (Bearer) -- blank on update keeps existing
    search: str                        # SPL query, e.g. "search index=security sourcetype=alert"
    schedule_minutes: int = 0          # 0 = manual only ("Run now" button)
    enabled: bool = True
    verify_ssl: bool = True
    timeout_sec: int = 60


def _validate(body: SplunkConfigBody) -> None:
    if not body.endpoint.strip():
        raise HTTPException(400, "Endpoint is required")
    if body.schedule_minutes < 0 or body.schedule_minutes > 24 * 60:
        raise HTTPException(400, "schedule_minutes must be between 0 (manual only) and 1440 (24h)")
    if body.timeout_sec < 5 or body.timeout_sec > 300:
        raise HTTPException(400, "timeout_sec must be between 5 and 300")
    from splunk_sync import validate_search
    try:
        validate_search(body.search)
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.get("/v1/admin/splunk/configs")
async def list_configs(user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/admin/splunk"))):
    items = await db.splunk_configs.find({}, {"_id": 0, "token": 0}).sort("created_at", -1).to_list(200)
    return {"items": items}


@router.post("/v1/admin/splunk/configs")
async def create_config(body: SplunkConfigBody, user: dict = Depends(require_role("admin"))):
    _validate(body)
    if not body.token:
        raise HTTPException(400, "An auth token is required to create a new Splunk connection")
    doc = {
        "id": str(uuid.uuid4()), **body.model_dump(), "status": "idle",
        "last_run_at": None, "last_result": None,
        "created_at": now_iso(), "created_by": user["email"],
    }
    await db.splunk_configs.insert_one(doc)
    return _clean({**doc, "token": None})


@router.put("/v1/admin/splunk/configs/{config_id}")
async def update_config(config_id: str, body: SplunkConfigBody, user: dict = Depends(require_role("admin"))):
    _validate(body)
    existing = await db.splunk_configs.find_one({"id": config_id}, {"_id": 0})
    if not existing:
        raise HTTPException(404, "Splunk connection not found")
    update = body.model_dump()
    if not update.get("token"):
        update["token"] = existing.get("token")  # blank on edit == keep existing token
    update["updated_at"] = now_iso()
    await db.splunk_configs.update_one({"id": config_id}, {"$set": update})
    return {**_clean({**existing, **update}), "token": None}


@router.delete("/v1/admin/splunk/configs/{config_id}")
async def delete_config(config_id: str, user: dict = Depends(require_role("admin"))):
    await db.splunk_configs.delete_one({"id": config_id})
    return {"ok": True}


async def _execute_sync(config_id: str):
    from splunk_sync import run_splunk_sync
    cfg = await db.splunk_configs.find_one({"id": config_id}, {"_id": 0})
    if not cfg:
        return
    try:
        result = await run_splunk_sync(
            db, endpoint=cfg["endpoint"], token=cfg["token"], search=cfg["search"],
            verify_ssl=cfg.get("verify_ssl", True), timeout_sec=cfg.get("timeout_sec", 60),
        )
        await db.splunk_configs.update_one({"id": config_id}, {"$set": {
            "status": "idle", "last_run_at": now_iso(), "last_result": {**result, "ok": True},
        }})
    except Exception as e:
        await db.splunk_configs.update_one({"id": config_id}, {"$set": {
            "status": "idle", "last_run_at": now_iso(), "last_result": {"ok": False, "error": str(e)},
        }})


@router.post("/v1/admin/splunk/configs/{config_id}/run-now")
async def run_now(config_id: str, user: dict = Depends(require_role("admin"))):
    cfg = await db.splunk_configs.find_one({"id": config_id}, {"_id": 0})
    if not cfg:
        raise HTTPException(404, "Splunk connection not found")
    if cfg.get("status") == "running":
        return {"status": "running", "message": "This search is already running"}
    await db.splunk_configs.update_one({"id": config_id}, {"$set": {"status": "running"}})
    asyncio.create_task(_execute_sync(config_id))
    return {"status": "running", "message": "Sync started"}


async def run_due_scheduled_syncs(db) -> dict:
    already_running = await db.splunk_configs.count_documents({"status": "running"})
    if already_running:
        return {"skipped": "a sync is already running"}
    now = datetime.now(timezone.utc)
    configs = await db.splunk_configs.find(
        {"enabled": True, "schedule_minutes": {"$gt": 0}}, {"_id": 0}
    ).to_list(200)
    for cfg in configs:
        last = cfg.get("last_run_at")
        due = True
        if last:
            try:
                last_dt = datetime.fromisoformat(last.replace("Z", "+00:00"))
                due = (now - last_dt).total_seconds() >= cfg["schedule_minutes"] * 60
            except Exception:
                due = True
        if due:
            await db.splunk_configs.update_one({"id": cfg["id"]}, {"$set": {"status": "running"}})
            await _execute_sync(cfg["id"])
            return {"ran": cfg["name"]}
    return {"ran": None}


async def splunk_sync_loop(db, interval_minutes: int = 5):
    import logging
    from heartbeat import record_heartbeat
    logger = logging.getLogger("vulnops")
    await asyncio.sleep(60)  # stagger past the other scan loops' own startup delays
    while True:
        ok, detail = True, {}
        try:
            result = await run_due_scheduled_syncs(db)
            if result.get("ran"):
                logger.info(f"Splunk scheduler: ran sync '{result.get('ran')}'")
            detail = result
        except Exception as e:
            logger.exception(f"Splunk scheduler error: {e}")
            ok, detail["error"] = False, str(e)
        await record_heartbeat(db, "splunk_sync_loop", "ok" if ok else "error", detail)
        await asyncio.sleep(interval_minutes * 60)
