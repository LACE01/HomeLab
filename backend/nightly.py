"""Nightly re-scoring job — refreshes EPSS from FIRST.org for all open CVEs,
recomputes KRI/urgency, and auto-dispatches notifications on tier escalation.
Also computes and stores the daily org-wide score snapshot used by the
Manager/Executive dashboards (score_snapshots collection)."""
import asyncio
import logging
import statistics
from datetime import datetime, timezone, timedelta

import httpx

logger = logging.getLogger("vulnops.nightly")

OPEN_STATES = ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]
RESOLVED_STATES = ["Fixed validated", "Closed administratively"]


async def _fetch_epss_batch(cves: list[str]) -> dict:
    """Query FIRST.org EPSS API in batches; returns {cve: {score, percentile}}."""
    out: dict = {}
    for i in range(0, len(cves), 100):
        batch = cves[i:i+100]
        try:
            async with httpx.AsyncClient(timeout=15) as c:
                r = await c.get("https://api.first.org/data/v1/epss",
                                params={"cve": ",".join(batch)})
            if r.status_code != 200:
                continue
            for d in r.json().get("data", []):
                out[d["cve"]] = {
                    "epss_score": float(d.get("epss", 0)),
                    "epss_percentile": float(d.get("percentile", 0)) * 100,
                }
        except Exception as e:
            logger.warning(f"EPSS fetch failed for batch starting {batch[0]}: {e}")
    return out


async def run_nightly_rescore(db) -> dict:
    """Refresh EPSS for every open CVE, recompute KRI+tier, dispatch on escalation."""
    from scoring_v2 import compute_kri, urgency_tier, cwe_prevalence_map
    from scoring import compute_risk
    from notifier import dispatch

    open_states = ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]

    # 1) Collect all unique CVEs with open findings
    cves = await db.findings.distinct("cve", {"cve": {"$ne": None, "$exists": True}, "status": {"$in": open_states}})
    cves = [c for c in cves if c]
    epss_map = await _fetch_epss_batch(cves) if cves else {}

    # 2) Recompute KRI / urgency for each open finding, propagate EPSS, dispatch escalations
    cwe_map = await cwe_prevalence_map(db)
    updated, escalated = 0, 0
    cursor = db.findings.find({"status": {"$in": open_states}}, {"_id": 0})
    async for f in cursor:
        new_epss = epss_map.get(f.get("cve"), {}).get("epss_score", f.get("epss_score") or 0)
        new_pct = epss_map.get(f.get("cve"), {}).get("epss_percentile", f.get("epss_percentile") or 0)
        f_tmp = {**f, "epss_score": new_epss, "epss_percentile": new_pct}
        asset = await db.assets.find_one({"id": f.get("asset_id")}, {"_id": 0}) or {}
        risk = compute_risk(f_tmp, asset)
        cwe_w = cwe_map.get(f.get("cwe"), 1.0)
        kri = compute_kri(f_tmp, cwe_w)["kri_score"]
        new_tier = urgency_tier(kri, bool(f.get("kev_flag")), risk["score"])
        old_tier = f.get("urgency_tier")

        await db.findings.update_one({"id": f["id"]}, {"$set": {
            "epss_score": new_epss, "epss_percentile": new_pct,
            "risk_score": risk["score"], "risk_breakdown": risk["breakdown"],
            "kri_score": kri, "urgency_tier": new_tier,
            "last_rescored_at": datetime.now(timezone.utc).isoformat(),
        }})
        updated += 1
        # Tier escalation? fire notification
        order = {"Deferred": 0, "Standard": 1, "Urgent": 2}
        if old_tier and order.get(new_tier, 0) > order.get(old_tier, 0):
            escalated += 1
            try:
                ctx = {"severity": f.get("severity"), "title": f.get("title"),
                       "cve": f.get("cve") or "—", "asset": f.get("asset_hostname"),
                       "owner_team": f.get("owner_team"), "risk_score": risk["score"],
                       "due_at": (f.get("due_at") or "")[:19],
                       "url": f"/findings/{f.get('id')}",
                       "days_left": 0, "days_overdue": 0}
                await dispatch("ticket_sla_warning", ctx, db)
            except Exception:
                pass

    result = {
        "ran_at": datetime.now(timezone.utc).isoformat(),
        "cves_refreshed": len(epss_map),
        "findings_updated": updated,
        "tiers_escalated": escalated,
    }
    await db.rescoring_runs.insert_one({**result, "id": f"run_{int(datetime.now(timezone.utc).timestamp())}"})
    return result


async def compute_org_snapshot(db, for_date: str = None) -> dict:
    """Compute today's org-wide security posture and upsert it into score_snapshots.

    org_score (0-100, heuristic): starts at 100 and is docked based on the average
    risk_score of currently-open findings, how much of the open backlog is overdue,
    and what fraction is KEV-listed (actively exploited in the wild) -- the same three
    signals already narrated on the Executive tab's "Score Drivers" panel.

    sla_compliance (%): of findings resolved in the last 90 days, what fraction were
    resolved before their due_at.

    mttr_days: mean days between first_seen_at and last_changed_at (the resolution
    timestamp, since there's no separate resolved_at field) for the same 90-day
    resolved cohort.
    """
    date_str = for_date or datetime.now(timezone.utc).date().isoformat()

    open_findings = await db.findings.find(
        {"status": {"$in": OPEN_STATES}}, {"_id": 0, "risk_score": 1, "due_at": 1, "kev_flag": 1}
    ).to_list(50000)
    n_open = len(open_findings)
    avg_risk = statistics.mean([f.get("risk_score") or 0 for f in open_findings]) if n_open else 0
    now = datetime.now(timezone.utc).isoformat()
    overdue_ratio = (sum(1 for f in open_findings if f.get("due_at") and f["due_at"] < now) / n_open) if n_open else 0
    kev_ratio = (sum(1 for f in open_findings if f.get("kev_flag")) / n_open) if n_open else 0

    org_score = round(max(0, min(100, 100 - avg_risk * 0.5 - overdue_ratio * 25 - kev_ratio * 25)))

    cutoff = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()
    resolved = await db.findings.find(
        {"status": {"$in": RESOLVED_STATES}, "last_changed_at": {"$gte": cutoff}},
        {"_id": 0, "due_at": 1, "last_changed_at": 1, "first_seen_at": 1},
    ).to_list(50000)
    n_resolved = len(resolved)
    if n_resolved:
        on_time = sum(1 for f in resolved if f.get("due_at") and f.get("last_changed_at") and f["last_changed_at"] <= f["due_at"])
        sla_compliance = round((on_time / n_resolved) * 100, 1)
        ttr_days = []
        for f in resolved:
            try:
                fs = datetime.fromisoformat((f.get("first_seen_at") or "").replace("Z", "+00:00"))
                lc = datetime.fromisoformat((f.get("last_changed_at") or "").replace("Z", "+00:00"))
                ttr_days.append(max(0, (lc - fs).total_seconds() / 86400))
            except Exception:
                continue
        mttr_days = round(statistics.mean(ttr_days), 1) if ttr_days else 0
    else:
        sla_compliance = 100.0  # nothing overdue yet is not the same as "0% compliant"
        mttr_days = 0

    doc = {
        "date": date_str, "org_score": org_score, "sla_compliance": sla_compliance,
        "mttr_days": mttr_days, "open_findings": n_open, "computed_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.score_snapshots.update_one({"date": date_str}, {"$set": doc}, upsert=True)
    return doc


async def backfill_score_snapshots(db, days: int = 30) -> int:
    """If score_snapshots is empty (fresh install), backfill a short synthetic history
    leading up to today's real computed score, so the Manager/Executive trend charts
    aren't blank on day one. Each backfilled point is today's score with a small,
    deterministic wobble -- clearly a placeholder until real daily runs accumulate,
    not a claim about actual past posture."""
    if await db.score_snapshots.count_documents({}) > 0:
        return 0
    today_snapshot = await compute_org_snapshot(db)
    base_score = today_snapshot["org_score"]
    base_sla = today_snapshot["sla_compliance"]
    inserted = 0
    for i in range(days, 0, -1):
        d = (datetime.now(timezone.utc) - timedelta(days=i)).date().isoformat()
        wobble = ((i * 37) % 11) - 5  # deterministic +/-5 wobble, no randomness dependency
        await db.score_snapshots.update_one({"date": d}, {"$set": {
            "date": d,
            "org_score": max(0, min(100, base_score + wobble)),
            "sla_compliance": max(0, min(100, round(base_sla + wobble, 1))),
            "mttr_days": today_snapshot["mttr_days"],
            "open_findings": today_snapshot["open_findings"],
            "computed_at": datetime.now(timezone.utc).isoformat(),
            "backfilled": True,
        }}, upsert=True)
        inserted += 1
    return inserted


async def threat_intel_loop(db, interval_hours: int = 12):
    """Automatically keep KEV / EPSS / active-attacks flags fresh. Previously these
    only ran when an admin manually hit the sync buttons, so KEV and Active Attacks
    stayed at 0 on the dashboard until someone remembered to trigger them by hand."""
    from enrichers import sync_kev, sync_epss, flag_active_attacks
    await asyncio.sleep(30)  # let the app finish booting first
    while True:
        try:
            kev_result = await sync_kev(db)
            logger.info(f"KEV sync: {kev_result}")
        except Exception as e:
            logger.exception(f"KEV sync failed: {e}")
        try:
            epss_result = await sync_epss(db)
            logger.info(f"EPSS sync: {epss_result}")
        except Exception as e:
            logger.exception(f"EPSS sync failed: {e}")
        try:
            active_result = await flag_active_attacks(db)
            logger.info(f"Active-attacks flag: {active_result}")
        except Exception as e:
            logger.exception(f"Active-attacks flag failed: {e}")
        await asyncio.sleep(interval_hours * 3600)


async def nightly_loop(db, interval_hours: int = 24):
    """Run forever, every interval_hours."""
    # Wait 60s on boot so app stabilizes, then run, then sleep
    await asyncio.sleep(60)
    while True:
        try:
            r = await run_nightly_rescore(db)
            logger.info(f"Nightly rescore: {r}")
        except Exception as e:
            logger.exception(f"Nightly rescore failed: {e}")
        try:
            snap = await compute_org_snapshot(db)
            logger.info(f"Org snapshot: {snap}")
        except Exception as e:
            logger.exception(f"Org snapshot failed: {e}")
        try:
            from routes.workflows import check_exception_expirations
            exc_result = await check_exception_expirations(db)
            logger.info(f"Exception expirations: {exc_result}")
        except Exception as e:
            logger.exception(f"Exception expiration check failed: {e}")
        await asyncio.sleep(interval_hours * 3600)
