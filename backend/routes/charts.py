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
from routes.common import OPEN_STATUSES
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

    def _parse(raw):
        """Date from an ISO string OR a native BSON datetime (#16). The old version did
        (raw or "").replace(...), which throws on a datetime; the exception was
        swallowed, the timestamp read as missing, and the finding silently vanished
        from the chart -- so hosts whose findings were stored as real datetimes
        showed "No findings" while others rendered fine."""
        if raw is None:
            return None
        if isinstance(raw, datetime):
            return (raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).date()
        if hasattr(raw, "year") and hasattr(raw, "month") and not isinstance(raw, str):
            return raw   # a date
        try:
            return datetime.fromisoformat(str(raw).replace("Z", "+00:00")).date()
        except Exception:
            return None

    # Axis first (gap-free; weekly buckets align to Monday) so presence windows can be
    # mapped straight to bucket indexes.
    if granularity == "week":
        start_date = now_date - timedelta(days=days)
        axis_start = start_date - timedelta(days=start_date.weekday())
        end_monday = now_date - timedelta(days=now_date.weekday())
        dates = []
        d = axis_start
        while d <= end_monday:
            dates.append(d.isoformat())
            d += timedelta(days=7)
        def _idx(day):
            return ((day - timedelta(days=day.weekday())) - axis_start).days // 7
    else:
        axis_start = since_date
        dates = [(since_date + timedelta(days=i)).isoformat() for i in range(days + 1)]
        def _idx(day):
            return (day - axis_start).days
    n = len(dates)

    raw_counts: dict = {}   # {group_key: findings present at any point in range}
    diffs: dict = {}        # {group_key: difference array over bucket indexes}

    cursor = db.findings.find(
        flt, {"_id": 0, "first_seen_at": 1, "last_seen_at": 1, "last_changed_at": 1, "imported_at": 1,
              "severity": 1, "status": 1, "cwe": 1, "source_tool": 1}
    )
    async for f in cursor:
        # Missing/malformed first_seen_at falls back to other timestamps so the finding
        # still lands somewhere instead of vanishing (the original #9 gap).
        first_date = (_parse(f.get("first_seen_at")) or _parse(f.get("last_changed_at"))
                      or _parse(f.get("imported_at")))
        if first_date is None:
            continue
        last_date = _parse(f.get("last_seen_at")) or first_date
        if last_date < first_date:
            last_date = first_date
        # An open finding is present TODAY regardless of when a rescan last refreshed
        # last_seen_at (one-shot imports never refresh it).
        if f.get("status") in OPEN_STATUSES:
            last_date = now_date
        if last_date < since_date or first_date > now_date:
            continue
        key = _group_key(f, group_by)
        raw_counts[key] = raw_counts.get(key, 0) + 1
        a = max(0, _idx(max(first_date, since_date)))
        b = min(n - 1, _idx(min(last_date, now_date)))
        if a > b:
            continue
        arr = diffs.get(key)
        if arr is None:
            arr = diffs[key] = [0] * (n + 1)
        arr[a] += 1          # a contiguous presence window covers a contiguous run of
        arr[b + 1] -= 1      # buckets (days, or the weeks it touches) -> O(1) per finding

    bucketed: dict = {}
    for key, arr in diffs.items():
        run = 0
        for i in range(n):
            run += arr[i]
            if run:
                bucketed.setdefault(dates[i], {})[key] = run

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
            r_date = _parse(p.get("resolved_at"))
            if r_date is None:
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
