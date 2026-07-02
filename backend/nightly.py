"""Nightly re-scoring job — refreshes EPSS from FIRST.org for all open CVEs,
recomputes KRI/urgency, and auto-dispatches notifications on tier escalation.
Also computes and stores the daily org-wide score snapshot used by the
Manager/Executive dashboards (score_snapshots collection)."""
import asyncio
import logging
import statistics
import uuid
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
        {"status": {"$in": OPEN_STATES}},
        {"_id": 0, "risk_score": 1, "due_at": 1, "kev_flag": 1, "severity": 1},
    ).to_list(50000)
    n_open = len(open_findings)

    # No findings have ever been ingested at all (fresh install, nothing synced yet) --
    # that's a genuinely different state than "we scanned everything and it's all clean",
    # and showing a confident "100/100 Strong security posture" in that case is misleading.
    # Distinguish "nothing to score" from "scored and healthy" so the dashboard can render
    # a neutral empty-state instead of a false-positive green score.
    total_findings_ever = await db.findings.estimated_document_count()
    if total_findings_ever == 0:
        doc = {
            "date": date_str, "org_score": None, "no_data": True,
            "sla_compliance": None, "mttr_days": None, "open_findings": 0,
            "computed_at": datetime.now(timezone.utc).isoformat(),
        }
        await db.score_snapshots.update_one({"date": date_str}, {"$set": doc}, upsert=True)
        return doc

    now = datetime.now(timezone.utc).isoformat()
    avg_risk = statistics.mean([f.get("risk_score") or 0 for f in open_findings]) if n_open else 0
    overdue_ratio = (sum(1 for f in open_findings if f.get("due_at") and f["due_at"] < now) / n_open) if n_open else 0
    kev_ratio = (sum(1 for f in open_findings if f.get("kev_flag")) / n_open) if n_open else 0
    critical_open = sum(1 for f in open_findings if (f.get("severity") or "").lower() == "critical")
    high_open = sum(1 for f in open_findings if (f.get("severity") or "").lower() == "high")
    kev_critical_open = sum(
        1 for f in open_findings
        if f.get("kev_flag") and (f.get("severity") or "").lower() == "critical"
    )

    # Blend exploitation-likelihood (EPSS-weighted avg_risk) with raw severity load and
    # overdue/KEV ratios. avg_risk alone made the score nearly always land near 100,
    # since most CVEs have very low EPSS even when CVSS-critical -- a portfolio can have
    # thousands of open critical findings and still average out to "low predicted
    # exploitation probability". That's methodologically defensible for EPSS but reads as
    # obviously wrong on a dashboard, so severity volume now has its own, larger say.
    exploit_penalty = avg_risk * 0.35
    severity_penalty = min(45, critical_open * 0.6 + high_open * 0.15)
    overdue_penalty = overdue_ratio * 20
    kev_penalty = kev_ratio * 30

    org_score = round(max(0, min(100, 100 - exploit_penalty - severity_penalty - overdue_penalty - kev_penalty)))

    # Hard ceiling: an actively-exploited (KEV-listed) critical finding sitting open means
    # "strong posture" can't be true no matter how the weighted average nets out.
    if kev_critical_open > 0:
        org_score = min(org_score, 70)

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
        # Nothing resolved in the last 90 days -- that's "not enough data to grade SLA
        # performance yet", not "100% compliant". A brand-new import where nothing has
        # been fixed yet should not claim a perfect on-time-fix rate.
        sla_compliance = None
        mttr_days = None

    doc = {
        "date": date_str, "org_score": org_score, "sla_compliance": sla_compliance,
        "mttr_days": mttr_days, "open_findings": n_open, "critical_open": critical_open,
        "high_open": high_open, "computed_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.score_snapshots.update_one({"date": date_str}, {"$set": doc}, upsert=True)
    return doc


async def _promote_verified(db, finding: dict, note: str) -> dict:
    await db.findings.update_one({"id": finding["id"]}, {"$set": {
        "status": "Fixed validated", "last_changed_at": now_iso_(),
        "verification_status": "passed", "verification_note": note,
    }})
    await db.activity_log.insert_one({
        "id": str(uuid.uuid4()), "entity_type": "finding", "entity_id": finding["id"],
        "action": "status_changed", "actor": "verification_sweep", "timestamp": now_iso_(),
        "details": note,
    })
    return {"verified": True, "status": "Fixed validated", "note": note}


async def check_single_verification(db, finding: dict) -> dict:
    """Shared by the manual 'Verify now' endpoint and the nightly sweep. Two kinds of
    evidence can promote a finding to Fixed validated:

    1. Port evidence (strongest, when available): if the finding has a `port` recorded
       (Nmap-sourced findings always have one) and a Nmap scan of the same asset run
       after the fix no longer lists that port as open, that's a direct, concrete check
       that the specific exposed service is actually gone.
    2. Source-sync evidence (fallback): a successful import from the finding's own
       source_tool with a started_at after fixed_marked_at -- the host was rescanned by
       the same tool that found the issue and it didn't reappear.

    If neither exists yet, it reports that honestly instead of guessing."""
    fixed_at = finding.get("fixed_marked_at") or finding.get("last_changed_at")

    port = finding.get("port")
    if port and finding.get("asset_id") and fixed_at:
        asset = await db.assets.find_one({"id": finding["asset_id"]}, {"_id": 0})
        scan_at = (asset or {}).get("nmap_last_scan_at")
        if asset and scan_at and scan_at > fixed_at:
            still_open = any(p.get("port") == port for p in (asset.get("open_ports") or []))
            if not still_open:
                note = (f"Auto-verified: an Nmap scan run after the fix shows port {port} is no longer "
                        f"open on {asset.get('hostname')}.")
                return await _promote_verified(db, finding, note)
            else:
                return {"verified": False, "status": finding.get("status"),
                        "note": f"Port {port} was still open on the most recent Nmap scan ({scan_at[:10]}) -- not verified yet."}

    source = finding.get("source_tool")
    rescanned = False
    if source and fixed_at:
        rescanned = await db.import_jobs.count_documents({
            "source_name": source, "status": "success", "started_at": {"$gt": fixed_at},
        }) > 0

    if rescanned:
        note = f"Auto-verified: a {source} sync ran after the fix and this finding did not reappear."
        return await _promote_verified(db, finding, note)

    note = (f"Still waiting on a fresh {source} sync since this was marked fixed."
            if source else "No source tool recorded for this finding -- can't confirm a rescan happened.")
    return {"verified": False, "status": finding.get("status"), "note": note}


def now_iso_():
    return datetime.now(timezone.utc).isoformat()


async def decay_stale_ownership(db, stale_days: int = 90, decay_to: float = 0.6) -> dict:
    """Ownership confidence of 1.0 means a human confirmed it at some point -- but trust
    should erode if nobody's looked at it since. Assets that were confidently assigned
    (>=0.9) and haven't been reconfirmed within stale_days get stepped down to decay_to
    and flagged in their rationale, surfacing them on the Ownership Mappings 'stale' view
    instead of silently looking just as trustworthy as a same-day confirmation forever."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=stale_days)).isoformat()
    now = now_iso_()
    stale_assets = await db.assets.find({
        "ownership_confidence": {"$gte": 0.9},
        "$or": [{"ownership_confirmed_at": {"$lt": cutoff}}, {"ownership_confirmed_at": None}],
    }, {"_id": 0, "id": 1}).to_list(5000)
    decayed = 0
    for a in stale_assets:
        await db.assets.update_one({"id": a["id"]}, {"$set": {
            "ownership_confidence": decay_to,
            "ownership_rationale": f"Confidence decayed -- not reconfirmed in {stale_days}+ days.",
        }})
        decayed += 1
    return {"checked": len(stale_assets), "decayed": decayed}


async def run_verification_sweep(db) -> dict:
    """Nightly: check every finding whose verification grace window has elapsed."""
    now = now_iso_()
    pending = await db.findings.find({
        "status": "Fixed pending validation", "verification_due_at": {"$lte": now},
    }, {"_id": 0}).to_list(2000)
    promoted = 0
    for f in pending:
        result = await check_single_verification(db, f)
        if result["verified"]:
            promoted += 1
    return {"checked": len(pending), "promoted": promoted}


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
    if today_snapshot.get("no_data") or base_score is None:
        # Nothing has ever been ingested -- there's no "real score" to wobble a fake
        # history around, so don't fabricate 30 days of trend line. Leave the collection
        # empty; the dashboard renders an explicit empty state instead.
        return 0
    inserted = 0
    for i in range(days, 0, -1):
        d = (datetime.now(timezone.utc) - timedelta(days=i)).date().isoformat()
        wobble = ((i * 37) % 11) - 5  # deterministic +/-5 wobble, no randomness dependency
        snap = {
            "date": d,
            "org_score": max(0, min(100, base_score + wobble)),
            "sla_compliance": (max(0, min(100, round(base_sla + wobble, 1))) if base_sla is not None else None),
            "mttr_days": today_snapshot["mttr_days"],
            "open_findings": today_snapshot["open_findings"],
            "computed_at": datetime.now(timezone.utc).isoformat(),
            "backfilled": True,  # marks this as estimated placeholder history, not a real
                                  # historical measurement -- surfaced in the UI as a dashed
                                  # line so it isn't mistaken for real trend data.
        }
        await db.score_snapshots.update_one({"date": d}, {"$set": snap}, upsert=True)
        inserted += 1
    return inserted


async def digest_dispatch_loop(db, interval_hours: int = 1):
    """Checks hourly whether any daily/weekly notification rule's window has elapsed and
    flushes its queued events as a single digest. Hourly gives daily/weekly cadences
    reasonable precision without needing a dedicated scheduler."""
    from notifier import run_digest_dispatch
    from heartbeat import record_heartbeat
    await asyncio.sleep(45)
    while True:
        ok, detail = True, {}
        try:
            r = await run_digest_dispatch(db)
            logger.info(f"Digest dispatch: {r}")
            detail["result"] = r
        except Exception as e:
            logger.exception(f"Digest dispatch failed: {e}")
            ok, detail["error"] = False, str(e)
        await record_heartbeat(db, "digest_dispatch_loop", "ok" if ok else "error", detail)
        await asyncio.sleep(interval_hours * 3600)


async def threat_intel_loop(db, interval_hours: int = 12):
    """Automatically keep KEV / EPSS / active-attacks flags fresh. Previously these
    only ran when an admin manually hit the sync buttons, so KEV and Active Attacks
    stayed at 0 on the dashboard until someone remembered to trigger them by hand."""
    from enrichers import sync_kev, sync_epss, flag_active_attacks, sync_exploitdb
    from heartbeat import record_heartbeat
    await asyncio.sleep(30)  # let the app finish booting first
    while True:
        ok, detail = True, {}
        try:
            kev_result = await sync_kev(db)
            logger.info(f"KEV sync: {kev_result}")
            detail["kev"] = kev_result
        except Exception as e:
            logger.exception(f"KEV sync failed: {e}")
            ok, detail["kev_error"] = False, str(e)
        try:
            epss_result = await sync_epss(db)
            logger.info(f"EPSS sync: {epss_result}")
            detail["epss"] = epss_result
        except Exception as e:
            logger.exception(f"EPSS sync failed: {e}")
            ok, detail["epss_error"] = False, str(e)
        try:
            active_result = await flag_active_attacks(db)
            logger.info(f"Active-attacks flag: {active_result}")
            detail["active_attacks"] = active_result
        except Exception as e:
            logger.exception(f"Active-attacks flag failed: {e}")
            ok, detail["active_attacks_error"] = False, str(e)
        try:
            exploitdb_result = await sync_exploitdb(db)
            logger.info(f"Exploit-DB sync: {exploitdb_result}")
            detail["exploitdb"] = exploitdb_result
        except Exception as e:
            logger.exception(f"Exploit-DB sync failed: {e}")
            ok, detail["exploitdb_error"] = False, str(e)
        await record_heartbeat(db, "threat_intel_loop", "ok" if ok else "error", detail)
        await asyncio.sleep(interval_hours * 3600)


async def nightly_loop(db, interval_hours: int = 24):
    """Run forever, every interval_hours."""
    from heartbeat import record_heartbeat
    # Wait 60s on boot so app stabilizes, then run, then sleep
    await asyncio.sleep(60)
    while True:
        ok, detail = True, {}
        try:
            r = await run_nightly_rescore(db)
            logger.info(f"Nightly rescore: {r}")
            detail["rescore"] = r
        except Exception as e:
            logger.exception(f"Nightly rescore failed: {e}")
            ok, detail["rescore_error"] = False, str(e)
        try:
            snap = await compute_org_snapshot(db)
            logger.info(f"Org snapshot: {snap}")
            detail["snapshot"] = snap
        except Exception as e:
            logger.exception(f"Org snapshot failed: {e}")
            ok, detail["snapshot_error"] = False, str(e)
        try:
            from routes.workflows import check_exception_expirations
            exc_result = await check_exception_expirations(db)
            logger.info(f"Exception expirations: {exc_result}")
            detail["exceptions"] = exc_result
        except Exception as e:
            logger.exception(f"Exception expiration check failed: {e}")
            ok, detail["exceptions_error"] = False, str(e)
        try:
            from routes.automation import run_all_automation_rules
            auto_result = await run_all_automation_rules(db)
            logger.info(f"Automation sweep: {auto_result}")
            detail["automation"] = auto_result
        except Exception as e:
            logger.exception(f"Automation sweep failed: {e}")
            ok, detail["automation_error"] = False, str(e)
        try:
            verify_result = await run_verification_sweep(db)
            logger.info(f"Verification sweep: {verify_result}")
            detail["verification"] = verify_result
        except Exception as e:
            logger.exception(f"Verification sweep failed: {e}")
            ok, detail["verification_error"] = False, str(e)
        try:
            decay_result = await decay_stale_ownership(db)
            logger.info(f"Ownership decay: {decay_result}")
            detail["ownership_decay"] = decay_result
        except Exception as e:
            logger.exception(f"Ownership decay failed: {e}")
            ok, detail["ownership_decay_error"] = False, str(e)
        await record_heartbeat(db, "nightly_loop", "ok" if ok else "error", detail)
        await asyncio.sleep(interval_hours * 3600)
