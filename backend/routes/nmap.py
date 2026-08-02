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
from rbac import require_module
from auth_utils import get_current_user, require_role
from routes.common import now_iso, _clean

router = APIRouter()

SCAN_TYPES = ["quick", "standard", "thorough"]


MODES = ["preset", "builder", "raw"]
PORT_MODES = ["top100", "top1000", "all", "custom"]
SCAN_TECHNIQUES = ["syn", "connect", "udp"]


class ScanConfigBody(BaseModel):
    name: str
    targets: str                       # comma/whitespace-separated IPs, CIDRs, hostnames --
                                        # ignored in "raw" mode, where targets come from the command itself
    mode: str = "preset"               # preset | builder | raw
    scan_type: str = "standard"        # quick | standard | thorough -- used when mode == "preset"
    vantage: str = "internal"          # scans launched from this container are internal
                                        # to your own network by construction -- "external"
                                        # only makes honest sense if this host itself sits
                                        # outside the network you're scanning.
    schedule_hours: int = 0            # 0 = manual only ("Run now" button)
    enabled: bool = True
    authorized: bool = False           # must be true to create/update -- your explicit
                                        # confirmation that you're allowed to scan these targets

    # --- "builder" mode: GUI toggle options ---
    port_mode: str = "top1000"         # top100 | top1000 | all | custom
    custom_ports: Optional[str] = None
    timing: int = 4                    # -T0 (paranoid) .. -T5 (insane)
    detect_service: bool = True        # -sV
    detect_os: bool = True             # -O
    scripts: list = []                 # subset of default/safe/discovery/version/vuln
    scan_technique: str = "syn"        # syn (-sS) | connect (-sT) | udp (-sU)
    skip_host_discovery: bool = True   # -Pn -- on by default; see nmap_scan.py comment

    # --- "raw" mode: paste a command line ---
    custom_command: Optional[str] = None


def _validate(body: ScanConfigBody) -> dict:
    """Returns extra fields to merge into the stored doc (parsed args, resolved
    command preview, and -- for raw mode -- the targets extracted from the command)."""
    if not body.authorized:
        raise HTTPException(400, "You must confirm you're authorized to scan these targets")
    if body.vantage not in ("internal", "external"):
        raise HTTPException(400, "vantage must be 'internal' or 'external'")
    if body.schedule_hours < 0 or body.schedule_hours > 24 * 30:
        raise HTTPException(400, "schedule_hours must be between 0 (manual only) and 720 (30 days)")
    if body.mode not in MODES:
        raise HTTPException(400, f"mode must be one of {MODES}")

    from nmap_scan import validate_targets, build_scan_args, parse_nmap_command, resolved_command_preview

    if body.mode == "preset":
        if body.scan_type not in SCAN_TYPES:
            raise HTTPException(400, f"scan_type must be one of {SCAN_TYPES}")
        try:
            validate_targets(body.targets)
        except ValueError as e:
            raise HTTPException(400, str(e))
        return {"custom_args": None, "resolved_command": None}

    if body.mode == "builder":
        if body.port_mode not in PORT_MODES:
            raise HTTPException(400, f"port_mode must be one of {PORT_MODES}")
        if body.scan_technique not in SCAN_TECHNIQUES:
            raise HTTPException(400, f"scan_technique must be one of {SCAN_TECHNIQUES}")
        try:
            validate_targets(body.targets)
            args = build_scan_args(
                port_mode=body.port_mode, custom_ports=body.custom_ports, timing=body.timing,
                detect_service=body.detect_service, detect_os=body.detect_os,
                scripts=body.scripts, scan_technique=body.scan_technique,
                skip_host_discovery=body.skip_host_discovery,
            )
        except ValueError as e:
            raise HTTPException(400, str(e))
        return {"custom_args": args, "resolved_command": resolved_command_preview(args, body.targets)}

    # mode == "raw"
    if not body.custom_command or not body.custom_command.strip():
        raise HTTPException(400, "Paste an nmap command when mode is 'raw'")
    try:
        parsed = parse_nmap_command(body.custom_command)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {
        "custom_args": parsed["args"], "targets": parsed["targets"],
        "resolved_command": resolved_command_preview(parsed["args"], parsed["targets"]),
    }


@router.get("/v1/admin/nmap/configs")
async def list_scan_configs(user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/admin/nmap-scans"))):
    items = await db.nmap_scan_configs.find({}, {"_id": 0}).sort("created_at", -1).to_list(200)
    return {"items": items, "scan_types": SCAN_TYPES, "port_modes": PORT_MODES,
            "scan_techniques": SCAN_TECHNIQUES, "script_categories": ["default", "safe", "discovery", "version", "vuln"]}


@router.post("/v1/admin/nmap/configs/preview")
async def preview_scan_config(body: ScanConfigBody, user: dict = Depends(require_role("admin"))):
    """Dry-run validation -- returns the resolved nmap command without saving anything,
    so the UI can show 'this is exactly what will run' before you hit Save."""
    extra = _validate(body)
    if extra.get("resolved_command"):
        resolved = extra["resolved_command"]
    else:
        from nmap_scan import SCAN_PRESETS, resolved_command_preview
        resolved = resolved_command_preview(SCAN_PRESETS.get(body.scan_type, SCAN_PRESETS["standard"]), body.targets)
    return {"resolved_command": resolved, "targets": extra.get("targets", body.targets)}


@router.post("/v1/admin/nmap/configs")
async def create_scan_config(body: ScanConfigBody, user: dict = Depends(require_role("admin"))):
    extra = _validate(body)
    doc = {
        "id": str(uuid.uuid4()), **body.model_dump(), **extra, "status": "idle",
        "last_run_at": None, "last_result": None,
        "created_at": now_iso(), "created_by": user["email"],
    }
    await db.nmap_scan_configs.insert_one(doc)
    return _clean(doc)


@router.put("/v1/admin/nmap/configs/{config_id}")
async def update_scan_config(config_id: str, body: ScanConfigBody, user: dict = Depends(require_role("admin"))):
    extra = _validate(body)
    existing = await db.nmap_scan_configs.find_one({"id": config_id}, {"_id": 0})
    if not existing:
        raise HTTPException(404, "Scan config not found")
    update = {**body.model_dump(), **extra}
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
    from routes.common import record_engagement
    cfg = await db.nmap_scan_configs.find_one({"id": config_id}, {"_id": 0})
    if not cfg:
        return
    if cfg.get("mode") in ("builder", "raw"):
        timeout = 1800  # custom scans (all-ports / slow timing / scripts) get more headroom
    else:
        timeout = {"quick": 300, "standard": 900, "thorough": 2700}.get(cfg.get("scan_type"), 900)
    started = now_iso()
    try:
        xml_bytes = await run_active_scan(
            cfg["targets"], cfg.get("scan_type", "standard"), timeout_sec=timeout,
            custom_args=cfg.get("custom_args"),
        )
        result = await import_nmap_xml(db, xml_bytes, vantage=cfg["vantage"], source_label=f"Scheduled: {cfg['name']}")
        await db.nmap_scan_configs.update_one({"id": config_id}, {"$set": {
            "status": "idle", "last_run_at": now_iso(), "last_result": {**result, "ok": True},
        }})
        await record_engagement(
            db, name=cfg["name"], scanner="Nmap", scan_type=cfg.get("scan_type", cfg.get("mode", "custom")),
            scan_method="active_scan", status="completed",
            assets_scanned=result.get("hosts_parsed", 0), findings_created=result.get("findings_created", 0),
            findings_updated=result.get("assets_touched", 0), started_at=started,
        )
    except Exception as e:
        await db.nmap_scan_configs.update_one({"id": config_id}, {"$set": {
            "status": "idle", "last_run_at": now_iso(), "last_result": {"ok": False, "error": str(e)},
        }})
        await record_engagement(
            db, name=cfg["name"], scanner="Nmap", scan_type=cfg.get("scan_type", cfg.get("mode", "custom")),
            scan_method="active_scan", status="failed", started_at=started, error=str(e),
        )


@router.post("/v1/admin/nmap/configs/{config_id}/run-now")
async def run_scan_now(config_id: str, user: dict = Depends(require_role("admin"))):
    cfg = await db.nmap_scan_configs.find_one({"id": config_id}, {"_id": 0})
    if not cfg:
        raise HTTPException(404, "Scan config not found")
    if cfg.get("status") == "running":
        return {"status": "running", "message": "This scan is already in progress"}
    await db.nmap_scan_configs.update_one({"id": config_id}, {"$set": {"status": "running"}})
    # Enqueued, not create_task'd. Running a scanner inside the API process means
    # it competes with request handling for one event loop, and a wedged scan
    # takes the whole product down -- which is exactly what happened. A queued job
    # also survives a deploy: the worker picks it up again instead of the scan
    # silently never finishing. See jobqueue.py.
    from jobqueue import enqueue
    import job_handlers  # noqa: F401 -- registers the handler so the kind validates
    job = await enqueue(db, "nmap_scan", {"config_id": config_id},
                         requested_by=user.get("email") or user.get("id"))
    return {"status": "queued", "job_id": job["id"], "deduped": job.get("deduped", False),
            "message": ("This scan was already queued." if job.get("deduped")
                         else "Scan queued -- poll GET /v1/jobs/{} for progress".format(job["id"]))}


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
    from heartbeat import record_heartbeat
    logger = logging.getLogger("vulnops")
    await asyncio.sleep(30)  # let other startup tasks settle first
    while True:
        ok, detail = True, {}
        try:
            result = await run_due_scheduled_scans(db)
            if result.get("ran"):
                logger.info(f"Nmap scheduler: ran scan '{result.get('name')}'")
            detail = result
        except Exception as e:
            logger.exception(f"Nmap scheduler error: {e}")
            ok, detail["error"] = False, str(e)
        await record_heartbeat(db, "nmap_scan_loop", "ok" if ok else "error", detail)
        await asyncio.sleep(interval_minutes * 60)
