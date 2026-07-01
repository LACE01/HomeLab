"""Dashboards routes: analyst, manager, executive, operational."""
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Depends

from db import db
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
async def dashboard_exposure(user: dict = Depends(get_current_user)):
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

    return {
        "total_assets": total_assets, "exposed_assets": exposed_assets,
        "exposed_open": exposed_open, "exposed_crit_high": exposed_crit_high,
        "exposed_kev": exposed_kev, "exposed_unassigned": exposed_unassigned,
        "by_environment": [{"environment": k, "count": v} for k, v in sorted(by_env.items(), key=lambda x: -x[1])],
        "top_exposed_assets": top_exposed,
    }


@router.get("/v1/dashboards/operational")
async def dashboard_operational(user: dict = Depends(get_current_user), team: Optional[str] = None):
    base_flt: dict = {}
    if team:
        base_flt["owner_team"] = team
    open_states = ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]

    now_dt = datetime.now(timezone.utc)
    buckets = {"0-7": 0, "8-30": 0, "31-60": 0, "61-90": 0, "90+": 0}
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
            pass
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

    return {
        "total_open": total_open, "aging_buckets": buckets,
        "by_assignee": [{"assignee": k, "count": v} for k, v in sorted(by_assignee.items(), key=lambda x: -x[1])][:15],
        "overdue_by_severity": overdue_by_sev,
        "throughput": throughput, "mttr_days": mttr, "reopen_rate": reopen_rate,
        "scan_coverage_pct": coverage, "reopened_open": reopened_total,
        "active_exceptions": await db.exceptions.count_documents({"status": "active"}),
        "kev_open": kev_open, "active_attacks_open": active_attacks_open,
        "critical_open": critical_open, "unassigned_open": unassigned_open,
        "team_scope": team or "All teams",
    }
