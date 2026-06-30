"""Shared helpers used by multiple route modules."""
from datetime import datetime, timezone, timedelta
from typing import Optional


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def _clean(doc: dict) -> dict:
    if not doc:
        return doc
    doc.pop("_id", None)
    return doc


def parse_time_range(range_key: Optional[str], start: Optional[str], end: Optional[str]) -> tuple:
    """Resolve a time range key (7d/30d/90d/4mo/6mo/12mo/custom/all) → (start_iso, end_iso, days).
    Returns (None, None, None) when range is 'all' or unset."""
    now = datetime.now(timezone.utc)
    if range_key == "custom" and start and end:
        return start, end, max(1, (datetime.fromisoformat(end.replace("Z","+00:00")) - datetime.fromisoformat(start.replace("Z","+00:00"))).days)
    presets = {"7d": 7, "30d": 30, "90d": 90, "4mo": 120, "6mo": 180, "12mo": 365}
    if range_key in presets:
        days = presets[range_key]
        return (now - timedelta(days=days)).isoformat(), now.isoformat(), days
    return None, None, None


def finding_ctx(f: dict) -> dict:
    """Build a notification context dict from a finding doc."""
    return {
        "severity": f.get("severity"), "title": f.get("title"),
        "cve": f.get("cve") or "—", "asset": f.get("asset_hostname"),
        "owner_team": f.get("owner_team"), "risk_score": f.get("risk_score"),
        "due_at": (f.get("due_at") or "")[:19],
        "url": f"/findings/{f.get('id')}",
    }


def deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out
