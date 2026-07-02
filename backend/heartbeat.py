"""Shared heartbeat tracking for background loops -- every loop records one entry per
pass so the Ops Health page can show, for each of them, whether it's actually running
and when it last succeeded/failed. Deliberately dead simple (one upserted doc per
loop name) rather than a time-series history, since "is it alive and when did it last
run" is what actually matters operationally; per-iteration logs already go to stdout
for anything deeper.
"""
from datetime import datetime, timezone

# Static registry of every loop that should appear on the health page even before its
# first heartbeat lands (so a loop that's crashed on startup shows as "never ran"
# instead of just not existing).
KNOWN_LOOPS = {
    "nightly_loop": {"label": "Nightly Rescore + Snapshot", "expected_interval_hours": 24},
    "threat_intel_loop": {"label": "Threat Intel (KEV/EPSS/Exploit-DB)", "expected_interval_hours": 12},
    "digest_dispatch_loop": {"label": "Notification Digest Dispatch", "expected_interval_hours": 1},
    "qualys_poll_loop": {"label": "Qualys Live Sync", "expected_interval_hours": 1},
    "nmap_scan_loop": {"label": "Nmap Scheduled Scans", "expected_interval_hours": 0.25},
    "cert_monitor_loop": {"label": "TLS Certificate Monitor", "expected_interval_hours": 24},
    "easm_scan_loop": {"label": "EASM Subdomain Discovery", "expected_interval_hours": 24},
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def record_heartbeat(db, name: str, status: str = "ok", detail: dict | None = None) -> None:
    await db.loop_heartbeats.update_one(
        {"name": name},
        {"$set": {"name": name, "status": status, "detail": detail, "last_run_at": _now_iso()},
         "$inc": {"run_count": 1, **({"error_count": 1} if status == "error" else {})}},
        upsert=True,
    )


async def get_health_summary(db) -> dict:
    heartbeats = {h["name"]: h for h in await db.loop_heartbeats.find({}, {"_id": 0}).to_list(100)}
    now = datetime.now(timezone.utc)
    loops = []
    for name, meta in KNOWN_LOOPS.items():
        hb = heartbeats.get(name)
        if not hb:
            loops.append({"name": name, "label": meta["label"], "status": "never_run",
                          "last_run_at": None, "run_count": 0, "error_count": 0, "detail": None, "stale": True})
            continue
        last_run = hb.get("last_run_at")
        stale = True
        if last_run:
            try:
                last_dt = datetime.fromisoformat(last_run.replace("Z", "+00:00"))
                # Stale if it's missed more than 2x its expected interval -- gives
                # slack for slow individual sub-steps without false-alarming.
                stale = (now - last_dt).total_seconds() > meta["expected_interval_hours"] * 3600 * 2 + 300
            except Exception:
                stale = True
        loops.append({
            "name": name, "label": meta["label"], "status": "stale" if stale else hb.get("status", "ok"),
            "last_run_at": last_run, "run_count": hb.get("run_count", 0),
            "error_count": hb.get("error_count", 0), "detail": hb.get("detail"), "stale": stale,
        })

    healthy = len([l for l in loops if l["status"] == "ok"])
    return {
        "loops": loops, "healthy_count": healthy, "total_count": len(loops),
        "generated_at": _now_iso(),
    }
