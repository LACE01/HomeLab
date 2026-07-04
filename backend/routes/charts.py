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
    include_patches: bool = False,
):
    days = max(1, min(days, 730))
    granularity = granularity if granularity in ("day", "week") else "day"
    group_by = group_by if group_by in ("severity", "status", "cwe", "source_tool", "none") else "severity"

    now_date = datetime.now(timezone.utc).date()
    since_date = now_date - timedelta(days=days)
    since = since_date.isoformat()

    # Scoping filters only -- deliberately NOT filtering by first_seen_at here. This
    # used to be "first_seen_at >= since", which only counted findings *newly
    # discovered* in the window -- a long-lived finding (first seen years ago, still
    # showing up on every rescan) never appeared on the chart at all, even while the
    # findings table right below it showed it as an active, currently-present finding.
    # A chart titled "Vulnerabilities Over Time" should show what was present each
    # day, not just what was new that day, so the DB query fetches every finding that
    # could possibly overlap the display window and the actual day-by-day presence
    # check happens below.
    flt: dict = {}
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

    cursor = db.findings.find(
        flt, {"_id": 0, "first_seen_at": 1, "last_seen_at": 1, "severity": 1, "status": 1, "cwe": 1, "source_tool": 1}
    )
    async for f in cursor:
        try:
            first_dt = datetime.fromisoformat((f.get("first_seen_at") or "").replace("Z", "+00:00"))
        except Exception:
            continue
        first_date = first_dt.date()
        # last_seen_at is refreshed every time a rescan reconfirms a finding is still
        # present, so it's the best available signal for "how long was this actually
        # open" -- falls back to first_seen_date for a finding that's only ever been
        # seen once (last_seen_at missing or equal to first_seen_at).
        last_raw = f.get("last_seen_at") or f.get("first_seen_at")
        try:
            last_date = datetime.fromisoformat((last_raw or "").replace("Z", "+00:00")).date()
        except Exception:
            last_date = first_date
        if last_date < first_date:
            last_date = first_date  # guard against bad/out-of-order data
        # Skip findings whose entire presence window falls outside the requested
        # range (e.g. something closed well before `since`, or -- pathological but
        # cheap to guard -- first seen after "now").
        if last_date < since_date or first_date > now_date:
            continue

        key = _group_key(f, group_by)
        raw_counts[key] = raw_counts.get(key, 0) + 1

        window_start = max(first_date, since_date)
        window_end = min(last_date, now_date)
        prev_bucket = None
        d = window_start
        while d <= window_end:
            bucket = (d - timedelta(days=d.weekday())).isoformat() if granularity == "week" else d.isoformat()
            if bucket != prev_bucket:
                bucketed.setdefault(bucket, {})
                bucketed[bucket][key] = bucketed[bucket].get(key, 0) + 1
                prev_bucket = bucket
            d += timedelta(days=1)

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
    # granularity this must align to the same Monday-of-week convention used above,
    # or the axis and the data buckets never match up.
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

    # Optional "patches applied" overlay -- a count of patch groups (see
    # nightly.sweep_patch_completions) that finished resolving on each day/week in
    # range, so you can visually correlate patch cadence against the vuln-count
    # trend above it. Only scoped by asset_id (patch-completion events don't carry
    # owner_team/product_id/severity/status, so those filters just leave this off
    # rather than silently ignoring them).
    patches_by_date: dict = {}
    if include_patches and not (owner_team or product_id or severity or status):
        patch_flt: dict = {"resolved_at": {"$gte": since}}
        if asset_id:
            patch_flt["asset_id"] = asset_id
        async for p in db.patches_applied.find(patch_flt, {"_id": 0, "resolved_at": 1}):
            try:
                r_date = datetime.fromisoformat(p["resolved_at"].replace("Z", "+00:00")).date()
            except Exception:
                continue
            bucket = (r_date - timedelta(days=r_date.weekday())).isoformat() if granularity == "week" else r_date.isoformat()
            patches_by_date[bucket] = patches_by_date.get(bucket, 0) + 1

    series = []
    for date_str in dates:
        row = {"date": date_str}
        for k in keys:
            row[k] = bucketed.get(date_str, {}).get(k, 0)
        if include_patches:
            row["patches_applied"] = patches_by_date.get(date_str, 0)
        series.append(row)

    if group_by == "severity":
        colors = {k: SEVERITY_COLORS.get(k, "#64748b") for k in keys}
    elif group_by == "status":
        colors = {k: STATUS_COLORS.get(k, "#64748b") for k in keys}
    else:
        colors = {k: PALETTE[i % len(PALETTE)] for i, k in enumerate(keys)}

    return {"series": series, "keys": keys, "colors": colors, "group_by": group_by, "granularity": granularity,
            "total": sum(raw_counts.values()),
            "patches_total": sum(patches_by_date.values()) if include_patches else None}
