"""Generic, reusable findings-timeseries endpoint -- one data source powering the
same trend chart everywhere it's embedded (Asset Detail, Reports, Dashboards), instead
of each page growing its own bespoke bucketing logic. Takes the same kind of scoping
filters the rest of the app already uses (asset_id, owner_team, product_id, severity),
so it composes with whatever page it's dropped into.
"""
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Depends

from db import db
from auth_utils import get_current_user

router = APIRouter()

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
SEVERITY_COLORS = {"Critical": "#ef4444", "High": "#f97316", "Medium": "#f59e0b", "Low": "#3b82f6", "Info": "#64748b"}
STATUS_COLORS = {
    "New": "#f59e0b", "Needs triage": "#f97316", "Valid": "#ef4444", "Reopened": "#a855f7",
    "Fixed pending validation": "#3b82f6", "Fixed validated": "#22c55e",
    "Closed administratively": "#64748b", "False positive": "#576069", "Duplicate": "#576069",
    "Accepted risk": "#8b5cf6",
}
PALETTE = ["#2F81F7", "#22c55e", "#f59e0b", "#ef4444", "#a855f7", "#06b6d4", "#f97316", "#64748b"]


def _group_key(f: dict, group_by: str) -> str:
    if group_by == "severity":
        return f.get("severity") or "Unknown"
    if group_by == "status":
        return f.get("status") or "Unknown"
    if group_by == "cwe":
        return f.get("cwe") or "Unclassified"
    if group_by == "source_tool":
        return f.get("source_tool") or "Unknown"
    return "Findings"


def _bucket_date(iso_str: str, granularity: str):
    try:
        dt = datetime.fromisoformat((iso_str or "").replace("Z", "+00:00"))
    except Exception:
        return None
    if granularity == "week":
        monday = dt.date() - timedelta(days=dt.weekday())
        return monday.isoformat()
    return dt.date().isoformat()


@router.get("/v1/charts/findings-timeseries")
async def findings_timeseries(
    user: dict = Depends(get_current_user),
    days: int = 90,
    granularity: str = "day",          # "day" | "week"
    group_by: str = "severity",        # "severity" | "status" | "cwe" | "source_tool" | "none"
    asset_id: Optional[str] = None,
    owner_team: Optional[str] = None,
    product_id: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
):
    days = max(1, min(days, 730))
    granularity = granularity if granularity in ("day", "week") else "day"
    group_by = group_by if group_by in ("severity", "status", "cwe", "source_tool", "none") else "severity"

    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    flt: dict = {"first_seen_at": {"$gte": since}}
    if asset_id:
        flt["asset_id"] = asset_id
    if owner_team:
        flt["owner_team"] = owner_team
    if product_id:
        flt["product_id"] = product_id
    if severity:
        flt["severity"] = severity
    if status:
        flt["status"] = status

    raw_counts: dict = {}       # {group_key: total_count} -- used to pick top-N for cwe/source_tool
    bucketed: dict = {}         # {date_str: {group_key: count}}

    cursor = db.findings.find(flt, {"_id": 0, "first_seen_at": 1, "severity": 1, "status": 1, "cwe": 1, "source_tool": 1})
    async for f in cursor:
        key = _group_key(f, group_by)
        raw_counts[key] = raw_counts.get(key, 0) + 1
        bucket = _bucket_date(f.get("first_seen_at"), granularity)
        if not bucket:
            continue
        bucketed.setdefault(bucket, {})
        bucketed[bucket][key] = bucketed[bucket].get(key, 0) + 1

    # Keep the legend readable for high-cardinality dimensions (CWE, source tool) --
    # top 6 by volume, everything else rolled into "Other".
    if group_by in ("cwe", "source_tool") and len(raw_counts) > 6:
        top_keys = set(sorted(raw_counts, key=lambda k: -raw_counts[k])[:6])
        for date_bucket in bucketed.values():
            other_total = sum(v for k, v in date_bucket.items() if k not in top_keys)
            for k in list(date_bucket):
                if k not in top_keys:
                    del date_bucket[k]
            if other_total:
                date_bucket["Other"] = other_total
        keys = sorted(top_keys, key=lambda k: -raw_counts[k]) + (["Other"] if any("Other" in b for b in bucketed.values()) else [])
    elif group_by == "severity":
        keys = [k for k in SEVERITY_ORDER if k in raw_counts] or list(raw_counts.keys())
    else:
        keys = sorted(raw_counts, key=lambda k: -raw_counts[k])

    # Build a gap-free date axis -- zero-count days still show up as zero, not a
    # missing point, so the trend line doesn't misleadingly jump. For weekly
    # granularity this must align to the same Monday-of-week convention _bucket_date
    # uses, or the axis and the data buckets never match up.
    now_date = datetime.now(timezone.utc).date()
    if granularity == "week":
        start_date = now_date - timedelta(days=days)
        start_monday = start_date - timedelta(days=start_date.weekday())
        end_monday = now_date - timedelta(days=now_date.weekday())
        dates = []
        d = start_monday
        while d <= end_monday:
            dates.append(d.isoformat())
            d += timedelta(days=7)
    else:
        dates = [(now_date - timedelta(days=i)).isoformat() for i in range(days + 1)]
        dates.sort()

    series = []
    for date_str in dates:
        row = {"date": date_str}
        for k in keys:
            row[k] = bucketed.get(date_str, {}).get(k, 0)
        series.append(row)

    if group_by == "severity":
        colors = {k: SEVERITY_COLORS.get(k, "#64748b") for k in keys}
    elif group_by == "status":
        colors = {k: STATUS_COLORS.get(k, "#64748b") for k in keys}
    else:
        colors = {k: PALETTE[i % len(PALETTE)] for i, k in enumerate(keys)}

    return {"series": series, "keys": keys, "colors": colors, "group_by": group_by, "granularity": granularity,
            "total": sum(raw_counts.values())}
