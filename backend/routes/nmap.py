"""Scheduled / on-demand active Nmap scans -- the container runs nmap itself against
targets you configure, instead of you uploading XML by hand. Kept in its own router
(separate from the passive XML-upload endpoint in routes/admin.py) since it's a
meaningfully different trust boundary: this one makes the container originate network
traffic, gated by an explicit authorization checkbox on every config.
"""
import asyncio
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from db import db
from auth_utils import get_current_user, require_role
from routes.common import now_iso, _clean

router = APIRouter()

SCAN_TYPES = ["quick", "standard", "thorough"]


class ScanConfigBody(BaseModel):
    name: str
    targets: str                       # comma/whitespace-separated IPs, CIDRs, hostnames
    scan_type: str = "standard"        # quick | standard | thorough
    vantage: str = "internal"          # scans launched from this container are internal
                                        # to your own network by construction -- "external"
                                        # only makes honest sense if this host itself sits
                                        # outside the network you're scanning.
    schedule_hours: int = 0            # 0 = manual only ("Run now" button)
    enabled: bool = True
    authorized: bool = False           # must be true to create/update -- your explicit
                                        # confirmation that you're allowed to scan these targets


def _validate(body: ScanConfigBody):
    if not body.authorized:
        raise HTTPException(400, "You must confirm you're authorized to scan these targets")
    if body.scan_type not in SCAN_TYPES:
        raise HTTPException(400, f"scan_type must be one of {SCAN_TYPES}")
    if body.vantage not in ("internal", "external"):
        raise HTTPException(400, "vantage must be 'internal' or 'external'")
    if body.schedule_hours < 0 or body.schedule_hours > 24 * 30:
        raise HTTPException(400, "schedule_hours must be between 0 (manual only) and 720 (30 days)")
    from nmap_scan import validate_targets
    try:
        validate_targets(body.targets)
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.get("/v1/admin/nmap/configs")
async def list_scan_configs(user: dict = Depends(get_current_user)):
    items = await db.nmap_scan_configs.find({}, {"_id": 0}).sort("created_at", -1).to_list(200)
    return {"items": items, "scan_types": SCAN_TYPES}


@router.post("/v1/admin/nmap/configs")
async def create_scan_config(body: ScanConfigBody, user: dict = Depends(require_role("admin"))):
    _validate(body)
    doc = {
        "id": str(uuid.uuid4()), **body.model_dump(), "status": "idle",
        "last_run_at": None, "last_result": None,
        "created_at": now_iso(), "created_by": user["email"],
    }
    await db.nmap_scan_configs.insert_one(doc)
    return _clean(doc)


@router.put("/v1/admin/nmap/configs/{config_id}")
async def update_scan_config(config_id: str, body: ScanConfigBody, user: dict = Depends(require_role("admin"))):
    _validate(body)
    existing = await db.nmap_scan_configs.find_one({"id": config_id}, {"_id": 0})
    if not existing:
        raise HTTPException(404, "Scan config not found")
    update = body.model_dump()
    update["updated_at"] = now_iso()
    await db.nmap_scan_configs.update_one({"id": config_id}, {"$set": update})
    return {**existing, **update}


@router.delete("/v1/admin/nmap/configs/{config_id}")
async def delete_scan_config(config_id: str, user: dict = Depends(require_role("admin"))):
    await db.nmap_scan_configs.delete_one({"id": config_id})
    return {"ok": True}


async def _execute_scan(config_id: str):
    """Runs in the background; updates the config doc with status/result as it goes."""
    from nmap_scan import run_active_scan, import_nmap_xml
    cfg = await db.nmap_scan_configs.find_one({"id": config_id}, {"_id": 0})
    if not cfg:
        return
    timeout = {"quick": 300, "standard": 900, "thorough": 2700}.get(cfg["scan_type"], 900)
    try:
        xml_bytes = await run_active_scan(cfg["targets"], cfg["scan_type"], timeout_sec=timeout)
        result = await import_nmap_xml(db, xml_bytes, vantage=cfg["vantage"], source_label=f"Scheduled: {cfg['name']}")
        await db.nmap_scan_configs.update_one({"id": config_id}, {"$set": {
            "status": "idle", "last_run_at": now_iso(), "last_result": {**result, "ok": True},
        }})
    except Exception as e:
        await db.nmap_scan_configs.update_one({"id": config_id}, {"$set": {
            "status": "idle", "last_run_at": now_iso(), "last_result": {"ok": False, "error": str(e)},
        }})


@router.post("/v1/admin/nmap/configs/{config_id}/run-now")
async def run_scan_now(config_id: str, user: dict = Depends(require_role("admin"))):
    cfg = await db.nmap_scan_configs.find_one({"id": config_id}, {"_id": 0})
    if not cfg:
        raise HTTPException(404, "Scan config not found")
    if cfg.get("status") == "running":
        return {"status": "running", "message": "This scan is already in progress"}
    await db.nmap_scan_configs.update_one({"id": config_id}, {"$set": {"status": "running"}})
    asyncio.create_task(_execute_scan(config_id))
    return {"status": "running", "message": "Scan started -- poll GET /v1/admin/nmap/configs for status"}


async def run_due_scheduled_scans(db) -> dict:
    """Called from a periodic loop. Runs one scan at a time (no concurrent nmap
    processes) to avoid hammering the network or the container's resources."""
    already_running = await db.nmap_scan_configs.count_documents({"status": "running"})
    if already_running:
        return {"skipped": "a scan is already running"}

    now = datetime.now(timezone.utc)
    configs = await db.nmap_scan_configs.find(
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
            await db.nmap_scan_configs.update_one({"id": cfg["id"]}, {"$set": {"status": "running"}})
            await _execute_scan(cfg["id"])  # awaited directly -- this loop only runs one at a time anyway
            return {"ran": cfg["id"], "name": cfg["name"]}
    return {"ran": None}


async def nmap_scan_loop(db, interval_minutes: int = 15):
    """Background poll -- checks every `interval_minutes` for scan configs that are
    due to run and, if the scanner is free, runs the next one due. One at a time by
    design (see run_due_scheduled_scans), so a big fleet of configs drains gradually
    rather than launching a pile of concurrent nmap processes."""
    import logging
    logger = logging.getLogger("vulnops")
    await asyncio.sleep(30)  # let other startup tasks settle first
    while True:
        try:
            result = await run_due_scheduled_scans(db)
            if result.get("ran"):
                logger.info(f"Nmap scheduler: ran scan '{result.get('name')}'")
        except Exception as e:
            logger.exception(f"Nmap scheduler error: {e}")
        await asyncio.sleep(interval_minutes * 60)
