"""Nightly re-scoring job — refreshes EPSS from FIRST.org for all open CVEs,
recomputes KRI/urgency, and auto-dispatches notifications on tier escalation."""
import asyncio
import logging
from datetime import datetime, timezone

import httpx

logger = logging.getLogger("vulnops.nightly")


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
        await asyncio.sleep(interval_hours * 3600)
