"""Dashboards routes: analyst, manager, executive, operational."""
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Depends

from db import db
from rbac import require_module
from auth_utils import get_current_user
from routes.common import now_iso, parse_time_range

router = APIRouter()


@router.get("/v1/dashboards/analyst")
async def dashboard_analyst(
    user: dict = Depends(get_current_user),
    range: Optional[str] = "30d",
    start: Optional[str] = None,
    end: Optional[str] = None,
):
    open_states = ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]
    open_findings = await db.findings.count_documents({"status": {"$in": open_states}})
    start_iso, end_iso, days = parse_time_range(range, start, end)
    new_q: dict = {"status": "New"}
    if start_iso:
        new_q["created_at"] = {"$gte": start_iso, "$lte": end_iso}
    new_findings = await db.findings.count_documents(new_q)
    triage = await db.findings.count_documents({"status": "Needs triage"})
    kev = await db.findings.count_documents({"kev_flag": True, "status": {"$in": open_states}})
    rti_high = await db.findings.count_documents({"rti": "active_attacks", "status": {"$in": open_states}})
    reopened = await db.findings.count_documents({"status": "Reopened"})
    overdue = await db.findings.count_documents({"due_at": {"$lt": now_iso()}, "status": {"$in": open_states}})
    unassigned = await db.findings.count_documents({"assigned_to": None, "status": {"$in": open_states}})
    unassigned_team = await db.findings.count_documents({
        "status": {"$in": open_states},
        "$or": [{"owner_team": None}, {"owner_team": "Unassigned"}, {"owner_team": ""}],
    })
    low_confidence = await db.findings.count_documents({"ownership_confidence": {"$lt": 0.7}, "status": {"$in": open_states}})
    top = await db.findings.find({"status": {"$in": open_states}}, {"_id": 0}).sort("risk_score", -1).limit(10).to_list(10)
    recent_imports = await db.import_jobs.find({}, {"_id": 0}).sort("started_at", -1).limit(6).to_list(6)
    failed_imports = await db.import_jobs.count_documents({"status": "failed"})
    return {
        "open_findings": open_findings, "new_findings": new_findings,
        "needs_triage": triage, "kev_findings": kev, "rti_findings": rti_high,
        "reopened": reopened, "overdue": overdue, "unassigned": unassigned,
        "unassigned_team": unassigned_team,
        "low_confidence_ownership": low_confidence, "top_findings": top,
        "recent_imports": recent_imports, "failed_imports": failed_imports,
        "range": range, "range_days": days, "range_start": start_iso, "range_end": end_iso,
    }


@router.get("/v1/dashboards/manager")
async def dashboard_manager(
    user: dict = Depends(get_current_user),
    range: Optional[str] = "30d",
    start: Optional[str] = None,
    end: Optional[str] = None,
):
    teams: dict = {}
    async for f in db.findings.find({"status": {"$in": ["New", "Needs triage", "Valid", "Reopened"]}}, {"_id": 0, "owner_team": 1, "due_at": 1, "severity": 1}):
        t = f.get("owner_team", "Unassigned")
        teams.setdefault(t, {"open": 0, "overdue": 0, "critical": 0})
        teams[t]["open"] += 1
        if f.get("due_at") and f["due_at"] < now_iso():
            teams[t]["overdue"] += 1
        if f.get("severity") == "Critical":
            teams[t]["critical"] += 1
    snap_q: dict = {}
    start_iso, end_iso, days = parse_time_range(range, start, end)
    if start_iso:
        snap_q["date"] = {"$gte": start_iso[:10], "$lte": end_iso[:10]}
    snapshots = await db.score_snapshots.find(snap_q, {"_id": 0}).sort("date", 1).to_list(400)
    exception_count = await db.exceptions.count_documents({"status": "active"})
    return {
        "by_team": [{"team": k, **v} for k, v in teams.items()],
        "snapshots": snapshots, "active_exceptions": exception_count,
        "range": range, "range_days": days,
    }


@router.get("/v1/dashboards/executive")
async def dashboard_executive(
    user: dict = Depends(get_current_user),
    range: Optional[str] = "30d",
    start: Optional[str] = None,
    end: Optional[str] = None,
    _rbac: dict = Depends(require_module("/")),
):
    snap_q: dict = {}
    start_iso, end_iso, days = parse_time_range(range, start, end)
    if start_iso:
        snap_q["date"] = {"$gte": start_iso[:10], "$lte": end_iso[:10]}
    snapshots = await db.score_snapshots.find(snap_q, {"_id": 0}).sort("date", 1).to_list(400)
    if not snapshots:
        snapshots = await db.score_snapshots.find({}, {"_id": 0}).sort("date", 1).to_list(60)
    current = snapshots[-1] if snapshots else {"org_score": None, "no_data": True, "sla_compliance": None, "mttr_days": None}

    products = await db.products.find({}, {"_id": 0}).to_list(50)
    for p in products:
        p["critical_open"] = await db.findings.count_documents({
            "product_id": p["id"], "severity": {"$in": ["Critical", "High"]},
            "status": {"$in": ["New", "Needs triage", "Valid", "Reopened"]},
        })

    by_env: dict = {}
    async for f in db.findings.find({"severity": {"$in": ["Critical", "High"]}, "status": {"$in": ["New", "Needs triage", "Valid", "Reopened"]}}, {"_id": 0, "asset_environment": 1}):
        env = f.get("asset_environment", "unknown")
        by_env[env] = by_env.get(env, 0) + 1

    score = current.get("org_score")
    no_data = bool(current.get("no_data")) or score is None
    if no_data:
        narrative = "No findings tracked yet. Sync an integration or import scan data to start scoring."
    elif score >= 85:
        narrative = "Strong security posture. Risk well-managed with low SLA breach rate."
    elif score >= 70:
        narrative = "Moderate security posture. A few high-risk findings need attention to push the score higher."
    else:
        narrative = "Elevated risk. Critical findings on internet-facing assets are pulling the score down."

    score_factors = []
    if not no_data:
        open_q = {"status": {"$in": ["New", "Needs triage", "Valid", "Reopened"]}}
        kev_open = await db.findings.count_documents({**open_q, "kev_flag": True})
        internet_crit = await db.findings.count_documents({**open_q, "internet_facing": True, "severity": "Critical"})
        total_assets = await db.assets.count_documents({})
        assets_with_findings = len(await db.findings.distinct("asset_id", open_q)) if total_assets else 0
        coverage_pct = round((assets_with_findings / total_assets) * 100) if total_assets else 0
        sla = current.get("sla_compliance")
        score_factors = [
            {"factor": "Open KEV findings", "impact": f"-{kev_open}" if kev_open else "0", "reason": f"{kev_open} actively exploited (CISA KEV) finding(s) still open"},
            {"factor": "Internet-facing critical", "impact": f"-{internet_crit}" if internet_crit else "0", "reason": f"{internet_crit} open critical finding(s) on internet-exposed assets"},
            {"factor": "SLA adherence", "impact": (f"{sla}%" if sla is not None else "No data"), "reason": (f"{sla}% of the last 90 days' fixes landed on time" if sla is not None else "Nothing resolved in the last 90 days yet")},
            {"factor": "Asset coverage", "impact": f"{coverage_pct}%", "reason": f"{assets_with_findings} of {total_assets} inventoried assets have at least one tracked finding"},
        ]

    return {
        "current_score": score, "narrative": narrative, "no_data": no_data,
        "sla_compliance": current.get("sla_compliance"),
        "mttr_days": current.get("mttr_days"),
        "snapshots": snapshots,
        "by_product": products,
        "by_environment": [{"environment": k, "count": v} for k, v in by_env.items()],
        "score_factors": score_factors,
        "range": range, "range_days": days,
    }


@router.get("/v1/dashboards/exposure")
async def dashboard_exposure(user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/exposure"))):
    """Attack-surface-centric view: what's actually reachable from the internet, and how
    exposed is it -- rather than severity counts across the whole portfolio regardless of
    reachability."""
    open_states = ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]

    total_assets = await db.assets.count_documents({})
    exposed_assets = await db.assets.count_documents({"exposure": {"$in": ["internet", "external"]}})

    exposed_open_flt = {"internet_facing": True, "status": {"$in": open_states}}
    exposed_open = await db.findings.count_documents(exposed_open_flt)
    exposed_crit_high = await db.findings.count_documents({
        **exposed_open_flt, "severity": {"$in": ["Critical", "High"]}})
    exposed_kev = await db.findings.count_documents({**exposed_open_flt, "kev_flag": True})
    exposed_unassigned = await db.findings.count_documents({**exposed_open_flt, "owner_team": None})

    by_env: dict = {}
    async for f in db.findings.find(exposed_open_flt, {"_id": 0, "asset_environment": 1}):
        env = f.get("asset_environment") or "unknown"
        by_env[env] = by_env.get(env, 0) + 1

    # Top exposed assets by open risk -- the "fix these first" list for attack surface.
    pipeline = [
        {"$match": exposed_open_flt},
        {"$group": {"_id": {"asset_id": "$asset_id", "hostname": "$asset_hostname"},
                    "total_risk": {"$sum": "$risk_score"}, "count": {"$sum": 1},
                    "critical": {"$sum": {"$cond": [{"$eq": ["$severity", "Critical"]}, 1, 0]}},
                    "kev": {"$sum": {"$cond": ["$kev_flag", 1, 0]}},
                    "owner_team": {"$first": "$owner_team"}}},
        {"$sort": {"total_risk": -1}}, {"$limit": 15},
    ]
    top_exposed = []
    async for r in db.findings.aggregate(pipeline):
        top_exposed.append({
            "asset_id": r["_id"]["asset_id"], "hostname": r["_id"]["hostname"],
            "open_findings": r["count"], "critical": r["critical"], "kev": r["kev"],
            "risk_sum": round(r["total_risk"], 1), "owner_team": r.get("owner_team"),
        })

    mismatch_assets = await db.assets.find(
        {"exposure_mismatch": True}, {"_id": 0, "id": 1, "hostname": 1, "exposure": 1,
                                       "exposure_mismatch_note": 1, "exposure_verified_at": 1}
    ).to_list(200)

    return {
        "total_assets": total_assets, "exposed_assets": exposed_assets,
        "exposed_open": exposed_open, "exposed_crit_high": exposed_crit_high,
        "exposed_kev": exposed_kev, "exposed_unassigned": exposed_unassigned,
        "by_environment": [{"environment": k, "count": v} for k, v in sorted(by_env.items(), key=lambda x: -x[1])],
        "top_exposed_assets": top_exposed,
        "exposure_mismatches": mismatch_assets,
    }


@router.get("/v1/dashboards/operational")
async def dashboard_operational(user: dict = Depends(get_current_user), team: Optional[str] = None,
                                 _rbac: dict = Depends(require_module("/operational"))):
    base_flt: dict = {}
    if team:
        base_flt["owner_team"] = team
    open_states = ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]

    now_dt = datetime.now(timezone.utc)
    # "Unknown" exists so a finding with a missing/unparseable first_seen_at still
    # gets counted somewhere -- previously the parse failure just silently `pass`ed
    # and the finding vanished from every bucket while still being counted in
    # total_open, so the Aging Buckets chart's bars summed to LESS than the "Open
    # Total" KPI card right next to it on the same dashboard (the exact
    # inconsistency reported). Every open finding now lands in exactly one bucket,
    # so bucket sum == total_open always.
    buckets = {"0-7": 0, "8-30": 0, "31-60": 0, "61-90": 0, "90+": 0, "Unknown": 0}
    by_assignee: dict = {}
    overdue_by_sev: dict = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    total_open = 0
    reopened_total = 0
    async for f in db.findings.find({**base_flt, "status": {"$in": open_states}},
                                    {"_id": 0, "first_seen_at": 1, "owner_team": 1, "assigned_to": 1,
                                     "severity": 1, "due_at": 1, "reopened_count": 1}):
        total_open += 1
        if f.get("reopened_count", 0):
            reopened_total += 1
        try:
            fs = datetime.fromisoformat((f.get("first_seen_at") or "").replace("Z", "+00:00"))
            age = (now_dt - fs).days
            if age <= 7:
                buckets["0-7"] += 1
            elif age <= 30:
                buckets["8-30"] += 1
            elif age <= 60:
                buckets["31-60"] += 1
            elif age <= 90:
                buckets["61-90"] += 1
            else:
                buckets["90+"] += 1
        except Exception:
            buckets["Unknown"] += 1
        a = f.get("assigned_to") or f.get("owner_team") or "Unassigned"
        by_assignee[a] = by_assignee.get(a, 0) + 1
        if f.get("due_at") and f["due_at"] < now_iso():
            overdue_by_sev[f.get("severity", "Info")] = overdue_by_sev.get(f.get("severity", "Info"), 0) + 1

    throughput = []
    for d in range(29, -1, -1):
        day = now_dt - timedelta(days=d)
        start = day.replace(hour=0, minute=0, second=0).isoformat()
        end = (day + timedelta(days=1)).replace(hour=0, minute=0, second=0).isoformat()
        opened = await db.findings.count_documents({**base_flt, "first_seen_at": {"$gte": start, "$lt": end}})
        closed = await db.findings.count_documents({**base_flt, "last_changed_at": {"$gte": start, "$lt": end},
                                                    "status": {"$in": ["Fixed validated", "Mitigated", "Closed administratively"]}})
        throughput.append({"date": day.strftime("%Y-%m-%d"), "opened": opened, "closed": closed, "net": opened - closed})

    mttr_samples = []
    async for f in db.findings.find({**base_flt, "status": {"$in": ["Fixed validated", "Mitigated"]}},
                                    {"first_seen_at": 1, "last_changed_at": 1}).limit(500):
        try:
            fs = datetime.fromisoformat(f["first_seen_at"].replace("Z", "+00:00"))
            lc = datetime.fromisoformat(f["last_changed_at"].replace("Z", "+00:00"))
            mttr_samples.append((lc - fs).days)
        except Exception:
            pass
    mttr = round(sum(mttr_samples) / len(mttr_samples), 1) if mttr_samples else 0
    closed_total = await db.findings.count_documents({**base_flt, "status": {"$in": ["Fixed validated", "Mitigated"]}})
    reopen_rate = round((reopened_total / max(closed_total + reopened_total, 1)) * 100, 1)

    cutoff = (now_dt - timedelta(days=14)).isoformat()
    scanned = await db.observations.distinct("asset_id", {"observed_at": {"$gte": cutoff}})
    total_assets = await db.assets.count_documents({})
    coverage = round((len(scanned) / max(total_assets, 1)) * 100, 1)

    kev_open = await db.findings.count_documents({**base_flt, "kev_flag": True, "status": {"$in": open_states}})
    active_attacks_open = await db.findings.count_documents({**base_flt, "rti": "active_attacks", "status": {"$in": open_states}})
    critical_open = await db.findings.count_documents({**base_flt, "severity": "Critical", "status": {"$in": open_states}})
    unassigned_open = await db.findings.count_documents({**base_flt, "assigned_to": None, "status": {"$in": open_states}})

    # Same "fraction of resolutions that landed on time" convention as the org-wide
    # score on the Executive tab (nightly.compute_org_snapshot), just scoped to this
    # team so a per-team SLA dashboard actually has an SLA number on it.
    from nightly import RESOLVED_STATES
    sla_cutoff = (now_dt - timedelta(days=90)).isoformat()
    resolved_90d = await db.findings.find(
        {**base_flt, "status": {"$in": RESOLVED_STATES}, "last_changed_at": {"$gte": sla_cutoff}},
        {"_id": 0, "due_at": 1, "last_changed_at": 1},
    ).to_list(20000)
    if resolved_90d:
        on_time = sum(1 for f in resolved_90d if f.get("due_at") and f.get("last_changed_at") and f["last_changed_at"] <= f["due_at"])
        sla_compliance = round((on_time / len(resolved_90d)) * 100, 1)
    else:
        sla_compliance = None

    return {
        "total_open": total_open, "aging_buckets": buckets,
        "by_assignee": [{"assignee": k, "count": v} for k, v in sorted(by_assignee.items(), key=lambda x: -x[1])][:15],
        "overdue_by_severity": overdue_by_sev,
        "throughput": throughput, "mttr_days": mttr, "reopen_rate": reopen_rate,
        "scan_coverage_pct": coverage, "reopened_open": reopened_total,
        "active_exceptions": await db.exceptions.count_documents({**base_flt, "status": "active"} if team else {"status": "active"}),
        "kev_open": kev_open, "active_attacks_open": active_attacks_open,
        "critical_open": critical_open, "unassigned_open": unassigned_open,
        "sla_compliance": sla_compliance, "sla_resolved_sample": len(resolved_90d),
        "team_scope": team or "All teams",
    }


@router.get("/v1/dashboards/teams-leaderboard")
async def dashboards_teams_leaderboard(user: dict = Depends(get_current_user)):
    """Side-by-side SLA health for every team, so a manager/exec can see who's
    falling behind without clicking into each team's dashboard one at a time. Each
    team's own drill-down (GET /v1/dashboards/operational?team=X, the existing
    per-team dashboard) is one click away from any row here."""
    from nightly import OPEN_STATES, RESOLVED_STATES
    teams: dict = {}

    def _row(team_name):
        return teams.setdefault(team_name, {
            "team": team_name, "open": 0, "overdue": 0, "critical_open": 0, "kev_open": 0,
            "_resolved_90d": 0, "_on_time_90d": 0, "_ttr_sum": 0.0, "_ttr_n": 0,
        })

    now = now_iso()
    async for f in db.findings.find({"status": {"$in": OPEN_STATES}},
                                    {"_id": 0, "owner_team": 1, "due_at": 1, "severity": 1, "kev_flag": 1}):
        row = _row(f.get("owner_team") or "Unassigned")
        row["open"] += 1
        if f.get("due_at") and f["due_at"] < now:
            row["overdue"] += 1
        if (f.get("severity") or "").lower() == "critical":
            row["critical_open"] += 1
        if f.get("kev_flag"):
            row["kev_open"] += 1

    cutoff = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()
    async for f in db.findings.find(
        {"status": {"$in": RESOLVED_STATES}, "last_changed_at": {"$gte": cutoff}},
        {"_id": 0, "owner_team": 1, "due_at": 1, "last_changed_at": 1, "first_seen_at": 1},
    ):
        row = _row(f.get("owner_team") or "Unassigned")
        row["_resolved_90d"] += 1
        if f.get("due_at") and f.get("last_changed_at") and f["last_changed_at"] <= f["due_at"]:
            row["_on_time_90d"] += 1
        try:
            fs = datetime.fromisoformat((f.get("first_seen_at") or "").replace("Z", "+00:00"))
            lc = datetime.fromisoformat((f.get("last_changed_at") or "").replace("Z", "+00:00"))
            row["_ttr_sum"] += max(0, (lc - fs).total_seconds() / 86400)
            row["_ttr_n"] += 1
        except Exception:
            pass

    items = []
    for team_name, row in teams.items():
        sla = round((row["_on_time_90d"] / row["_resolved_90d"]) * 100, 1) if row["_resolved_90d"] else None
        mttr = round(row["_ttr_sum"] / row["_ttr_n"], 1) if row["_ttr_n"] else None
        items.append({
            "team": team_name, "open": row["open"], "overdue": row["overdue"],
            "critical_open": row["critical_open"], "kev_open": row["kev_open"],
            "sla_compliance": sla, "mttr_days": mttr, "resolved_90d": row["_resolved_90d"],
        })
    items.sort(key=lambda x: (-x["overdue"], -x["critical_open"], -x["open"]))
    return {"items": items}


@router.get("/v1/dashboards/soc")
async def dashboard_soc(
    user: dict = Depends(get_current_user),
    _rbac: dict = Depends(require_module("/soc")),
    range: Optional[str] = "7d",
    start: Optional[str] = None,
    end: Optional[str] = None,
):
    """Unified SOC metrics -- one pane pulling from every detection/response
    surface (security event bus, auth/session security, UEBA, threat intel
    watchlist, Splunk/Wazuh connectors, YARA, IR cases) instead of making an
    analyst hop between six separate admin pages to gauge posture. Deliberately
    thin on any one topic -- each linked module page still has the full detail."""
    start_iso, end_iso, days = parse_time_range(range, start, end)
    range_flt = {"created_at": {"$gte": start_iso, "$lte": end_iso}} if start_iso else {}

    # --- Security event bus ---
    open_by_severity = {}
    async for row in db.security_events.aggregate([
        {"$match": {"status": "open"}},
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
    ]):
        open_by_severity[row["_id"]] = row["count"]
    correlated_open = await db.security_events.count_documents({"status": "open", "event_type": "correlated_alert"})
    events_in_range = await db.security_events.count_documents({**range_flt}) if range_flt else await db.security_events.count_documents({})

    # MTTA / MTTR over events acknowledged/closed within the range (falls back to
    # all-time if no range given) -- gives a rough sense of triage speed, not a
    # precise SLA metric.
    mtta_sum, mtta_n, mttr_sum, mttr_n = 0.0, 0, 0.0, 0
    ack_flt = {"acknowledged_at": {"$ne": None}}
    close_flt = {"closed_at": {"$ne": None}}
    if start_iso:
        ack_flt["acknowledged_at"] = {"$gte": start_iso, "$lte": end_iso}
        close_flt["closed_at"] = {"$gte": start_iso, "$lte": end_iso}
    async for ev in db.security_events.find(ack_flt, {"_id": 0, "created_at": 1, "acknowledged_at": 1}):
        try:
            c = datetime.fromisoformat(ev["created_at"].replace("Z", "+00:00"))
            a = datetime.fromisoformat(ev["acknowledged_at"].replace("Z", "+00:00"))
            mtta_sum += max(0, (a - c).total_seconds() / 60)
            mtta_n += 1
        except Exception:
            pass
    async for ev in db.security_events.find(close_flt, {"_id": 0, "created_at": 1, "closed_at": 1}):
        try:
            c = datetime.fromisoformat(ev["created_at"].replace("Z", "+00:00"))
            z = datetime.fromisoformat(ev["closed_at"].replace("Z", "+00:00"))
            mttr_sum += max(0, (z - c).total_seconds() / 3600)
            mttr_n += 1
        except Exception:
            pass
    mtta_minutes = round(mtta_sum / mtta_n, 1) if mtta_n else None
    mttr_hours = round(mttr_sum / mttr_n, 1) if mttr_n else None

    # --- Auth / session security ---
    brute_force_events = await db.security_events.count_documents({
        "source": "login_audit", "event_type": {"$in": ["brute_force_ip", "brute_force_account"]}, **range_flt,
    })
    active_sessions = await db.active_sessions.count_documents({"revoked": {"$ne": True}})
    total_users = await db.users.count_documents({})
    mfa_users = await db.users.count_documents({"mfa_enabled": True})
    mfa_adoption_pct = round((mfa_users / total_users) * 100, 1) if total_users else 0

    # --- UEBA signals ---
    ueba_flt = {"source": "ueba", **range_flt}
    new_ip_logins = await db.security_events.count_documents({**ueba_flt, "event_type": "new_ip_login"})
    new_country_logins = await db.security_events.count_documents({**ueba_flt, "event_type": "new_country_login"})
    impossible_travel = await db.security_events.count_documents({**ueba_flt, "event_type": "impossible_travel"})

    # --- Threat intel watchlist ---
    watchlist_total = await db.ioc_watchlist.count_documents({})
    watchlist_with_hits = await db.ioc_watchlist.count_documents({"hits": {"$gt": 0}})
    ioc_matches_in_range = await db.security_events.count_documents({"source": "threat_intel", **range_flt})

    # --- Splunk / Wazuh connector health ---
    splunk_configs = await db.splunk_configs.find({}, {"_id": 0, "enabled": 1, "last_result": 1, "last_run_at": 1}).to_list(200)
    wazuh_configs = await db.wazuh_configs.find({}, {"_id": 0, "enabled": 1, "last_result": 1, "last_run_at": 1}).to_list(200)
    def _connector_health(configs):
        enabled = [c for c in configs if c.get("enabled")]
        failing = [c for c in enabled if (c.get("last_result") or {}).get("ok") is False]
        return {"configured": len(configs), "enabled": len(enabled), "failing": len(failing)}
    splunk_health = _connector_health(splunk_configs)
    wazuh_health = _connector_health(wazuh_configs)

    # --- YARA ---
    yara_matches_in_range = await db.yara_scan_history.count_documents(
        {"matched_rule_count": {"$gt": 0}, **({"scanned_at": range_flt["created_at"]} if range_flt else {})}
    )

    # --- IR cases ---
    ir_open = await db.ir_cases.count_documents({"status": "open"})
    ir_opened_in_range = await db.ir_cases.count_documents({**({"opened_at": range_flt["created_at"]} if range_flt else {})})

    return {
        "range": range, "range_days": days, "range_start": start_iso, "range_end": end_iso,
        "events": {
            "open_by_severity": open_by_severity, "correlated_open": correlated_open,
            "events_in_range": events_in_range, "mtta_minutes": mtta_minutes, "mttr_hours": mttr_hours,
        },
        "auth": {
            "brute_force_events": brute_force_events, "active_sessions": active_sessions,
            "mfa_adoption_pct": mfa_adoption_pct, "mfa_users": mfa_users, "total_users": total_users,
        },
        "ueba": {
            "new_ip_logins": new_ip_logins, "new_country_logins": new_country_logins,
            "impossible_travel": impossible_travel,
        },
        "threat_intel": {
            "watchlist_total": watchlist_total, "watchlist_with_hits": watchlist_with_hits,
            "matches_in_range": ioc_matches_in_range,
        },
        "connectors": {"splunk": splunk_health, "wazuh": wazuh_health},
        "yara": {"matches_in_range": yara_matches_in_range},
        "ir": {"open_cases": ir_open, "opened_in_range": ir_opened_in_range},
    }
