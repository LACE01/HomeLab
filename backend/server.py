"""Nightwatch — Security Operations Platform backend.

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
from routes.corroboration import router as corroboration_router
from routes.jobs import router as jobs_router
from routes.platform_health import router as platform_health_router
from routes.wstg import router as wstg_router
from routes.world_monitor import router as world_monitor_router
from routes.geo_forecast import router as geo_forecast_router
from routes.active_validation import router as active_validation_router
from routes.identity import router as identity_router
from routes.inventory import router as inventory_router
from routes.workflows import router as workflows_router
from routes.integrations import router as integrations_router
from routes.dashboards import router as dashboards_router
from routes.reports_routes import router as reports_router
from routes.scheduled_reports import router as scheduled_reports_router
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
from routes.security_events import router as security_events_router
from routes.splunk import router as splunk_router
from routes.wazuh import router as wazuh_router
from routes.threat_intel import router as threat_intel_router
from routes.ticketing import router as ticketing_router
from routes.certs import router as certs_router
from routes.domain_email_security import router as domain_email_security_router
from routes.eol_tracking import router as eol_tracking_router
from routes.container_scan import router as container_scan_router
from routes.secrets_scan import router as secrets_scan_router
from routes.sbom import router as sbom_router
from routes.easm import router as easm_router
from routes.compliance import router as compliance_router
from routes.chatops import router as chatops_router
from routes.health import router as health_router
from routes.backups import router as backups_router
from routes.retention import router as retention_router
from routes.audit import router as audit_router
from routes.yara import router as yara_router
from routes.incident_response import router as incident_response_router
from routes.albert import router as albert_router
from routes.risk_register import router as risk_register_router
from routes.security_reviews import router as security_reviews_router
from routes.threat_modeling import router as threat_modeling_router
from routes.cti import router as cti_router
from routes.attack_telemetry import router as attack_telemetry_router
from routes.attack_paths import router as attack_paths_router
from routes.vendors import router as vendors_router
from routes.directory import router as directory_router
from routes.settings import router as settings_router

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vulnops")


app = FastAPI(title="Nightwatch API", version="1.0.0")
api = APIRouter(prefix="/api")


# Register each domain router (order does not matter — APIRouter merges routes safely).
api.include_router(auth_router)
# These two go FIRST, deliberately. FastAPI matches routes in registration order,
# and both of the big routers below register catch-alls that would swallow the
# literal paths registered here:
#   inventory  "/v1/assets/{asset_id}"   would eat "/v1/assets/duplicates"
#   findings   "/v1/findings/{finding_id}" would eat "/v1/findings/corroboration/summary"
# and then try to look the literal segment up as an id. This codebase has hit that
# shadowing bug repeatedly; registering the literal routes ahead of the catch-alls
# is what prevents it.
api.include_router(identity_router)
api.include_router(corroboration_router)
api.include_router(jobs_router)
api.include_router(platform_health_router)
api.include_router(wstg_router)
api.include_router(world_monitor_router)
api.include_router(geo_forecast_router)
api.include_router(active_validation_router)
api.include_router(findings_router)
api.include_router(inventory_router)
api.include_router(workflows_router)
api.include_router(integrations_router)
api.include_router(dashboards_router)
api.include_router(reports_router)
api.include_router(scheduled_reports_router)
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
api.include_router(domain_email_security_router)
api.include_router(eol_tracking_router)
api.include_router(container_scan_router)
api.include_router(secrets_scan_router)
api.include_router(sbom_router)
api.include_router(easm_router)
api.include_router(compliance_router)
api.include_router(chatops_router)
api.include_router(health_router)
api.include_router(backups_router)
api.include_router(retention_router)
api.include_router(audit_router)
api.include_router(yara_router)
api.include_router(albert_router)
api.include_router(risk_register_router)
api.include_router(security_reviews_router)
api.include_router(threat_modeling_router)
api.include_router(cti_router)
api.include_router(attack_telemetry_router)
api.include_router(attack_paths_router)
api.include_router(rbac_router)
api.include_router(scan_schedule_router)
api.include_router(security_events_router)
api.include_router(splunk_router)
api.include_router(wazuh_router)
api.include_router(threat_intel_router)
api.include_router(ticketing_router)
api.include_router(incident_response_router)
api.include_router(vendors_router)
api.include_router(directory_router)
api.include_router(settings_router)


@api.get("/")
async def root():
    return {"name": "Nightwatch API", "version": "1.0.0", "status": "ok"}


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
    await db.active_sessions.create_index("jti", unique=True)
    await db.active_sessions.create_index("user_id")
    await db.login_audit.create_index([("email", 1), ("timestamp", -1)])
    await db.login_audit.create_index([("ip", 1), ("timestamp", -1)])
    await db.security_events.create_index([("dedupe_key", 1), ("status", 1)])
    await db.security_events.create_index([("entity_id", 1), ("status", 1)])
    await db.security_events.create_index([("status", 1), ("last_seen_at", -1)])
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
    # Same idea for patch-completion events -- backfill once at boot so already-
    # resolved patch groups show up on the "patches applied" chart overlay
    # immediately instead of waiting for the next nightly sweep (up to 24h away).
    try:
        from nightly import sweep_patch_completions
        n = await sweep_patch_completions(db)
        if n.get("patches_recorded"):
            logger.info(f"Backfilled {n['patches_recorded']} patch-completion event(s).")
    except Exception as e:
        logger.exception(f"Patch completion backfill failed: {e}")

    # Nightly rescore loop (24h)
    import asyncio as _a
    from nightly import nightly_loop, threat_intel_loop, digest_dispatch_loop
    from qualys_sync import qualys_poll_loop
    from tenable_sync import tenable_poll_loop
    from aws_cspm import aws_cspm_poll_loop
    from routes.nmap import nmap_scan_loop
    from routes.nikto import nikto_scan_loop
    from routes.reconng import recon_scheduled_loop
    from cert_monitor import cert_monitor_loop
    from domain_email_security import domain_email_monitor_loop
    from eol_tracking import eol_monitor_loop
    from container_scan import container_scan_loop
    from secrets_scan import secrets_scan_loop
    from easm import easm_scan_loop
    from backup import backup_loop
    from routes.automation import automation_scheduler_loop
    from routes.splunk import splunk_sync_loop
    from routes.wazuh import wazuh_sync_loop
    from routes.threat_intel import threat_intel_watchlist_sync_loop
    # Watchdog first: it logs a warning whenever the event loop stalls. Without it
    # a blocking call in any of the loops below is invisible from the server side --
    # the log just goes quiet, which reads like "no traffic" rather than "the
    # process stopped answering everything", and that ambiguity is expensive.
    from correlation_loop import correlation_loop
    from posture_loop import posture_snapshot_loop
    from selfcheck_loop import self_check_loop
    from blocking_io import loop_lag_monitor
    _a.create_task(loop_lag_monitor())
    _a.create_task(correlation_loop(db, interval_hours=6))
    _a.create_task(posture_snapshot_loop(db, interval_hours=24))
    _a.create_task(self_check_loop(db, interval_hours=1))
    _a.create_task(nightly_loop(db, interval_hours=24))
    # KEV / EPSS / active-attacks sync loop (12h) — was previously manual-trigger only
    _a.create_task(threat_intel_loop(db, interval_hours=12))
    _a.create_task(digest_dispatch_loop(db, interval_hours=1))
    # Qualys live sync loop (60min) — skips when integration is not configured
    _a.create_task(qualys_poll_loop(db, interval_minutes=60))
    # Tenable Nessus live sync loop (60min) — skips when integration is not configured
    _a.create_task(tenable_poll_loop(db, interval_minutes=60))
    # AWS CSPM scan loop (24h) — skips when integration is not configured
    _a.create_task(aws_cspm_poll_loop(db, interval_hours=24))
    # Scheduled Nmap scan loop (15min poll) — runs at most one config's scan at a time
    _a.create_task(nmap_scan_loop(db, interval_minutes=15))
    # Scheduled Nikto web-app scan loop (15min poll) — runs at most one scan at a time
    _a.create_task(nikto_scan_loop(db, interval_minutes=15))
    # Scheduled recon-ng OSINT module loop (30min poll) — runs at most one module at a time
    _a.create_task(recon_scheduled_loop(db, interval_minutes=30))
    # TLS cert expiry loop (once/day -- certs don't change often)
    _a.create_task(cert_monitor_loop(db, interval_hours=24))
    # Email authentication (SPF/DKIM/DMARC) monitoring loop (once/day -- DNS
    # records like these change rarely)
    _a.create_task(domain_email_monitor_loop(db, interval_hours=24))
    # End-of-life software/OS tracking loop (once/day -- EOL dates don't change often)
    _a.create_task(eol_monitor_loop(db, interval_hours=24))
    # Container image vulnerability scan loop (once/day)
    _a.create_task(container_scan_loop(db, interval_hours=24))
    # Secrets/credential leak scan loop (once/day)
    _a.create_task(secrets_scan_loop(db, interval_hours=24))
    # EASM passive subdomain discovery loop (once/day)
    _a.create_task(easm_scan_loop(db, interval_hours=24))
    # Scheduled DB backup loop -- no-ops unless BACKUP_SCHEDULE_ENABLED=true (see backup.py)
    _a.create_task(backup_loop(db, interval_hours=24))
    # Automation rules with a daily/weekly/monthly schedule -- separate from the nightly
    # sweep so they can fire at a specific configured time (15min poll resolution)
    _a.create_task(automation_scheduler_loop(db, interval_minutes=15))
    # Splunk scheduled saved-search polling loop (5min poll resolution) -- runs at
    # most one configured search at a time, same reasoning as the other scanner loops
    _a.create_task(splunk_sync_loop(db, interval_minutes=5))
    # Wazuh scheduled indexer polling loop (5min poll resolution)
    _a.create_task(wazuh_sync_loop(db, interval_minutes=5))
    # Threat intel watchlist: bulk-pulls ThreatFox's recent IOC feed on a schedule
    # (in addition to manual add/import) -- no-ops quietly if abuse.ch isn't configured
    _a.create_task(threat_intel_watchlist_sync_loop(db, interval_hours=12))
    from cti import cti_loop
    _a.create_task(cti_loop(db, interval_hours=12))
    from attack_telemetry import attack_telemetry_loop
    _a.create_task(attack_telemetry_loop(db))
    # Data retention/archival: purges old records from enabled policies once a day,
    # archiving to a compressed JSON file first (see retention.py)
    from retention import retention_loop
    _a.create_task(retention_loop(db, interval_hours=24))
