"""VulnOps — Vulnerability Operations Platform backend.

Thin wiring layer:
  - Creates FastAPI app + master /api APIRouter
  - Includes per-domain APIRouter modules from /app/backend/routes/
  - Mounts CORS middleware and startup hook (index creation, seeding, nightly loop)

All business-logic endpoints live under routes/.
"""
import os
import logging
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env")

from fastapi import FastAPI, APIRouter
from starlette.middleware.cors import CORSMiddleware

from db import db
from seed import seed_all

from routes.auth import router as auth_router
from routes.findings import router as findings_router
from routes.inventory import router as inventory_router
from routes.workflows import router as workflows_router
from routes.integrations import router as integrations_router
from routes.dashboards import router as dashboards_router
from routes.reports_routes import router as reports_router
from routes.admin import router as admin_router
from routes.preferences import router as preferences_router
from routes.playbooks import router as playbooks_router
from routes.automation import router as automation_router
from routes.nmap import router as nmap_router
from routes.nikto import router as nikto_router
from routes.reconng import router as reconng_router
from routes.criticality import router as criticality_router
from routes.charts import router as charts_router
from routes.rbac import router as rbac_router
from routes.scan_schedule import router as scan_schedule_router
from routes.certs import router as certs_router
from routes.sbom import router as sbom_router
from routes.easm import router as easm_router
from routes.compliance import router as compliance_router
from routes.chatops import router as chatops_router
from routes.health import router as health_router
from routes.backups import router as backups_router
from routes.audit import router as audit_router
from routes.yara import router as yara_router

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vulnops")


app = FastAPI(title="VulnOps API", version="1.0.0")
api = APIRouter(prefix="/api")


# Register each domain router (order does not matter — APIRouter merges routes safely).
api.include_router(auth_router)
api.include_router(findings_router)
api.include_router(inventory_router)
api.include_router(workflows_router)
api.include_router(integrations_router)
api.include_router(dashboards_router)
api.include_router(reports_router)
api.include_router(admin_router)
api.include_router(preferences_router)
api.include_router(playbooks_router)
api.include_router(automation_router)
api.include_router(nmap_router)
api.include_router(nikto_router)
api.include_router(reconng_router)
api.include_router(criticality_router)
api.include_router(charts_router)
api.include_router(certs_router)
api.include_router(sbom_router)
api.include_router(easm_router)
api.include_router(compliance_router)
api.include_router(chatops_router)
api.include_router(health_router)
api.include_router(backups_router)
api.include_router(audit_router)
api.include_router(yara_router)
api.include_router(rbac_router)
api.include_router(scan_schedule_router)


@api.get("/")
async def root():
    return {"name": "VulnOps API", "version": "1.0.0", "status": "ok"}


# Mount the master /api router onto the app.
app.include_router(api)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def on_startup():
    await db.users.create_index("email", unique=True)
    await db.findings.create_index("canonical_key")
    await db.findings.create_index("asset_id")
    await db.findings.create_index("status")
    await db.findings.create_index("severity")
    await db.observations.create_index("finding_id")
    await db.api_keys.create_index("key", unique=True)
    # Hot-load SLA policy overrides if user has saved any
    try:
        from scoring import load_sla_overrides
        await load_sla_overrides(db)
    except Exception as e:
        logger.exception(f"SLA override load failed: {e}")
    try:
        await seed_all(db)
        logger.info("Seed completed.")
    except Exception as e:
        logger.exception(f"Seed failed: {e}")
    # Backfill score_snapshots on first boot so Manager/Executive trend charts
    # aren't blank before the first nightly run completes.
    try:
        from nightly import backfill_score_snapshots
        n = await backfill_score_snapshots(db)
        if n:
            logger.info(f"Backfilled {n} score snapshot(s).")
    except Exception as e:
        logger.exception(f"Score snapshot backfill failed: {e}")

    # Nightly rescore loop (24h)
    import asyncio as _a
    from nightly import nightly_loop, threat_intel_loop, digest_dispatch_loop
    from qualys_sync import qualys_poll_loop
    from routes.nmap import nmap_scan_loop
    from routes.nikto import nikto_scan_loop
    from routes.reconng import recon_scheduled_loop
    from cert_monitor import cert_monitor_loop
    from easm import easm_scan_loop
    from backup import backup_loop
    from routes.automation import automation_scheduler_loop
    _a.create_task(nightly_loop(db, interval_hours=24))
    # KEV / EPSS / active-attacks sync loop (12h) — was previously manual-trigger only
    _a.create_task(threat_intel_loop(db, interval_hours=12))
    _a.create_task(digest_dispatch_loop(db, interval_hours=1))
    # Qualys live sync loop (60min) — skips when integration is not configured
    _a.create_task(qualys_poll_loop(db, interval_minutes=60))
    # Scheduled Nmap scan loop (15min poll) — runs at most one config's scan at a time
    _a.create_task(nmap_scan_loop(db, interval_minutes=15))
    # Scheduled Nikto web-app scan loop (15min poll) — runs at most one scan at a time
    _a.create_task(nikto_scan_loop(db, interval_minutes=15))
    # Scheduled recon-ng OSINT module loop (30min poll) — runs at most one module at a time
    _a.create_task(recon_scheduled_loop(db, interval_minutes=30))
    # TLS cert expiry loop (once/day -- certs don't change often)
    _a.create_task(cert_monitor_loop(db, interval_hours=24))
    # EASM passive subdomain discovery loop (once/day)
    _a.create_task(easm_scan_loop(db, interval_hours=24))
    # Scheduled DB backup loop -- no-ops unless BACKUP_SCHEDULE_ENABLED=true (see backup.py)
    _a.create_task(backup_loop(db, interval_hours=24))
    # Automation rules with a daily/weekly/monthly schedule -- separate from the nightly
    # sweep so they can fire at a specific configured time (15min poll resolution)
    _a.create_task(automation_scheduler_loop(db, interval_minutes=15))
