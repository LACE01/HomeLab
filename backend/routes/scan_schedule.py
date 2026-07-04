"""Unified scan schedule -- one view over the three separate scheduled-scan sources
(Nmap host scans, Nikto web-app scans, recon-ng OSINT modules) instead of checking
three separate "Schedules" tabs to know what's going to run and when. Read-only: the
actual schedule is still created/edited on each tool's own page (Nmap Scan Uploads,
Web App Scans, Recon & OSINT) -- this just answers "what's coming up, across all of
them, and is anything overdue" in one place.

Every source already tracks the same shape of information (enabled, an interval, and
last_run_at) so "next run" is computed the same way for all three: last_run_at +
interval if it's run before, otherwise "due now" (never run yet).
"""
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends

from db import db
from auth_utils import get_current_user
from rbac import require_module

router = APIRouter()


def _next_run(last_run_at: str, interval_hours: int) -> tuple:
    """Returns (next_run_iso_or_None, overdue_bool). next_run is None when the
    scan has never run yet -- it's due now, not scheduled for some computable instant."""
    if not last_run_at:
        return None, True
    try:
        last_dt = datetime.fromisoformat(last_run_at.replace("Z", "+00:00"))
    except Exception:
        return None, True
    next_dt = last_dt + timedelta(hours=interval_hours)
    now = datetime.now(timezone.utc)
    return next_dt.isoformat(), next_dt <= now


def _bucket(next_run_iso: str, overdue: bool) -> str:
    if overdue:
        return "overdue"
    now = datetime.now(timezone.utc)
    next_dt = datetime.fromisoformat(next_run_iso.replace("Z", "+00:00"))
    if next_dt.date() == now.date():
        return "today"
    if next_dt <= now + timedelta(days=7):
        return "this_week"
    return "later"


@router.get("/v1/admin/scan-schedule")
async def scan_schedule(user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/admin/scan-schedule"))):
    items = []

    async for cfg in db.nmap_scan_configs.find({"schedule_hours": {"$gt": 0}}, {"_id": 0}):
        next_run, overdue = _next_run(cfg.get("last_run_at"), cfg["schedule_hours"])
        items.append({
            "id": cfg["id"], "source": "nmap", "source_label": "Nmap", "name": cfg["name"],
            "target_summary": cfg.get("targets") or cfg.get("resolved_command", "")[:60],
            "interval_hours": cfg["schedule_hours"], "enabled": cfg.get("enabled", True),
            "last_run_at": cfg.get("last_run_at"), "next_run_at": next_run, "overdue": overdue,
            "manage_url": "/admin/nmap-scans",
        })

    async for cfg in db.nikto_scan_configs.find({"schedule_hours": {"$gt": 0}}, {"_id": 0}):
        next_run, overdue = _next_run(cfg.get("last_run_at"), cfg["schedule_hours"])
        items.append({
            "id": cfg["id"], "source": "nikto", "source_label": "Nikto", "name": cfg.get("name") or cfg.get("target_url"),
            "target_summary": cfg.get("target_url"),
            "interval_hours": cfg["schedule_hours"], "enabled": cfg.get("enabled", True),
            "last_run_at": cfg.get("last_run_at"), "next_run_at": next_run, "overdue": overdue,
            "manage_url": "/admin/nikto-scans",
        })

    async for sched in db.recon_schedules.find({}, {"_id": 0}):
        next_run, overdue = _next_run(sched.get("last_run_at"), sched["interval_hours"])
        items.append({
            "id": sched["id"], "source": "recon-ng", "source_label": "Recon & OSINT",
            "name": sched.get("module_id"), "target_summary": sched.get("target"),
            "interval_hours": sched["interval_hours"], "enabled": sched.get("enabled", True),
            "last_run_at": sched.get("last_run_at"), "next_run_at": next_run, "overdue": overdue,
            "manage_url": "/admin/recon-osint",
        })

    for it in items:
        it["bucket"] = _bucket(it["next_run_at"], it["overdue"]) if it["enabled"] else "disabled"

    # Soonest-first within each bucket; disabled schedules sink to the bottom since
    # they're not actually going to run.
    order = {"overdue": 0, "today": 1, "this_week": 2, "later": 3, "disabled": 4}
    items.sort(key=lambda it: (order[it["bucket"]], it["next_run_at"] or ""))

    counts = {b: sum(1 for it in items if it["bucket"] == b) for b in ("overdue", "today", "this_week", "later", "disabled")}
    return {"items": items, "counts": counts, "total": len(items)}
