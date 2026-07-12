"""Wazuh connector config -- CRUD for indexer connections to poll on a schedule
(or run on demand), same shape as routes/splunk.py. See wazuh_sync.py for the
actual HTTP call + event-emission logic and the time-windowing cursor."""
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


class WazuhConfigBody(BaseModel):
    name: str
    endpoint: str                          # e.g. https://wazuh-indexer.example.com:9200
    username: str
    password: Optional[str] = None         # blank on update keeps existing
    index_pattern: str = "wazuh-alerts-*"
    min_level: int = 7                     # only pull alerts at/above this rule.level
    schedule_minutes: int = 0              # 0 = manual only
    enabled: bool = True
    verify_ssl: bool = True
    timeout_sec: int = 60


def _validate(body: WazuhConfigBody) -> None:
    if not body.endpoint.strip():
        raise HTTPException(400, "Endpoint is required")
    if not body.username.strip():
        raise HTTPException(400, "Username is required")
    if body.min_level < 0 or body.min_level > 15:
        raise HTTPException(400, "min_level must be between 0 and 15 (Wazuh's own rule.level scale)")
    if body.schedule_minutes < 0 or body.schedule_minutes > 24 * 60:
        raise HTTPException(400, "schedule_minutes must be between 0 (manual only) and 1440 (24h)")
    if body.timeout_sec < 5 or body.timeout_sec > 300:
        raise HTTPException(400, "timeout_sec must be between 5 and 300")


@router.get("/v1/admin/wazuh/configs")
async def list_configs(user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/admin/wazuh"))):
    items = await db.wazuh_configs.find({}, {"_id": 0, "password": 0}).sort("created_at", -1).to_list(200)
    return {"items": items}


@router.post("/v1/admin/wazuh/configs")
async def create_config(body: WazuhConfigBody, user: dict = Depends(require_role("admin"))):
    _validate(body)
    if not body.password:
        raise HTTPException(400, "A password is required to create a new Wazuh connection")
    doc = {
        "id": str(uuid.uuid4()), **body.model_dump(), "status": "idle",
        "last_run_at": None, "last_result": None, "last_synced_at": None,
        "created_at": now_iso(), "created_by": user["email"],
    }
    await db.wazuh_configs.insert_one(doc)
    return _clean({**doc, "password": None})


@router.put("/v1/admin/wazuh/configs/{config_id}")
async def update_config(config_id: str, body: WazuhConfigBody, user: dict = Depends(require_role("admin"))):
    _validate(body)
    existing = await db.wazuh_configs.find_one({"id": config_id}, {"_id": 0})
    if not existing:
        raise HTTPException(404, "Wazuh connection not found")
    update = body.model_dump()
    if not update.get("password"):
        update["password"] = existing.get("password")  # blank on edit == keep existing
    update["updated_at"] = now_iso()
    await db.wazuh_configs.update_one({"id": config_id}, {"$set": update})
    return {**_clean({**existing, **update}), "password": None}


@router.delete("/v1/admin/wazuh/configs/{config_id}")
async def delete_config(config_id: str, user: dict = Depends(require_role("admin"))):
    await db.wazuh_configs.delete_one({"id": config_id})
    return {"ok": True}


async def _execute_sync(config_id: str):
    from wazuh_sync import run_wazuh_sync
    cfg = await db.wazuh_configs.find_one({"id": config_id}, {"_id": 0})
    if not cfg:
        return
    try:
        result = await run_wazuh_sync(
            db, endpoint=cfg["endpoint"], username=cfg["username"], password=cfg["password"],
            index_pattern=cfg.get("index_pattern", "wazuh-alerts-*"), min_level=cfg.get("min_level", 7),
            verify_ssl=cfg.get("verify_ssl", True), timeout_sec=cfg.get("timeout_sec", 60),
            last_synced_at=cfg.get("last_synced_at"),
        )
        await db.wazuh_configs.update_one({"id": config_id}, {"$set": {
            "status": "idle", "last_run_at": now_iso(),
            "last_synced_at": result.get("last_synced_at") or cfg.get("last_synced_at"),
            "last_result": {k: v for k, v in result.items() if k != "last_synced_at"},
        }})
    except Exception as e:
        await db.wazuh_configs.update_one({"id": config_id}, {"$set": {
            "status": "idle", "last_run_at": now_iso(), "last_result": {"ok": False, "error": str(e)},
        }})


@router.post("/v1/admin/wazuh/configs/{config_id}/run-now")
async def run_now(config_id: str, user: dict = Depends(require_role("admin"))):
    cfg = await db.wazuh_configs.find_one({"id": config_id}, {"_id": 0})
    if not cfg:
        raise HTTPException(404, "Wazuh connection not found")
    if cfg.get("status") == "running":
        return {"status": "running", "message": "This sync is already running"}
    await db.wazuh_configs.update_one({"id": config_id}, {"$set": {"status": "running"}})
    asyncio.create_task(_execute_sync(config_id))
    return {"status": "running", "message": "Sync started"}


async def run_due_scheduled_syncs(db) -> dict:
    already_running = await db.wazuh_configs.count_documents({"status": "running"})
    if already_running:
        return {"skipped": "a sync is already running"}
    now = datetime.now(timezone.utc)
    configs = await db.wazuh_configs.find(
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
            await db.wazuh_configs.update_one({"id": cfg["id"]}, {"$set": {"status": "running"}})
            await _execute_sync(cfg["id"])
            return {"ran": cfg["name"]}
    return {"ran": None}


async def wazuh_sync_loop(db, interval_minutes: int = 5):
    import logging
    from heartbeat import record_heartbeat
    logger = logging.getLogger("vulnops")
    await asyncio.sleep(75)  # stagger past the other scan/sync loops' own startup delays
    while True:
        ok, detail = True, {}
        try:
            result = await run_due_scheduled_syncs(db)
            if result.get("ran"):
                logger.info(f"Wazuh scheduler: ran sync '{result.get('ran')}'")
            detail = result
        except Exception as e:
            logger.exception(f"Wazuh scheduler error: {e}")
            ok, detail["error"] = False, str(e)
        await record_heartbeat(db, "wazuh_sync_loop", "ok" if ok else "error", detail)
        await asyncio.sleep(interval_minutes * 60)
