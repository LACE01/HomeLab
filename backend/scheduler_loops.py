"""Periodic background scheduler loops, extracted so they can run in EITHER the API
process or the worker process (or both), chosen by the RUN_SCHEDULERS env var.

Why: these loops (Qualys/Nmap/CTI/EASM/backup/... polling) do heavy, occasionally
blocking work. Running them inside the API process means a slow scan competes with
request handling -- the exact "background work degrades logins" class of problems.
Default is to run them in the worker container (process isolation); set
RUN_SCHEDULERS=api to keep the historical behavior, or =both (not recommended --
duplicates every scheduled job).

start_scheduler_loops() must be called from within a running asyncio loop (both the
API lifespan startup and worker main() qualify). It deliberately does NOT start the
loop-lag watchdog -- each process starts its own so it monitors its own event loop.
"""
import asyncio
import logging

logger = logging.getLogger("vulnops.schedulers")


def start_scheduler_loops(db) -> int:
    """Launch every periodic loop as a background task. Returns the count started."""
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
    from correlation_loop import correlation_loop
    from posture_loop import posture_snapshot_loop
    from selfcheck_loop import self_check_loop
    from cti import cti_loop
    from attack_telemetry import attack_telemetry_loop
    from retention import retention_loop
    from saved_search_alerts import saved_search_alert_loop
    from routes.integrations import integration_health_loop

    tasks = [
        correlation_loop(db, interval_hours=6),
        posture_snapshot_loop(db, interval_hours=24),
        self_check_loop(db, interval_hours=1),
        nightly_loop(db, interval_hours=24),
        threat_intel_loop(db, interval_hours=12),
        digest_dispatch_loop(db, interval_hours=1),
        qualys_poll_loop(db, interval_minutes=60),
        tenable_poll_loop(db, interval_minutes=60),
        aws_cspm_poll_loop(db, interval_hours=24),
        nmap_scan_loop(db, interval_minutes=15),
        nikto_scan_loop(db, interval_minutes=15),
        recon_scheduled_loop(db, interval_minutes=30),
        cert_monitor_loop(db, interval_hours=24),
        domain_email_monitor_loop(db, interval_hours=24),
        eol_monitor_loop(db, interval_hours=24),
        container_scan_loop(db, interval_hours=24),
        secrets_scan_loop(db, interval_hours=24),
        easm_scan_loop(db, interval_hours=24),
        backup_loop(db, interval_hours=24),
        automation_scheduler_loop(db, interval_minutes=15),
        splunk_sync_loop(db, interval_minutes=5),
        wazuh_sync_loop(db, interval_minutes=5),
        threat_intel_watchlist_sync_loop(db, interval_hours=12),
        cti_loop(db, interval_hours=12),
        attack_telemetry_loop(db),
        retention_loop(db, interval_hours=24),
        saved_search_alert_loop(db, interval_minutes=60),
        integration_health_loop(db, interval_hours=6),
    ]
    for coro in tasks:
        asyncio.create_task(coro)
    logger.info("Started %d periodic scheduler loop(s)", len(tasks))
    return len(tasks)
