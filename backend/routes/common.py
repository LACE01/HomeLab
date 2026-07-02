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


async def record_engagement(db, name: str, scanner: str, scan_type: str = "on_demand",
                             scan_method: str = "api", status: str = "completed",
                             assets_scanned: int = 0, findings_created: int = 0, findings_updated: int = 0,
                             started_at: Optional[str] = None, error: Optional[str] = None) -> None:
    """Records one row on the Engagements page -- one call per actual scan/import run
    (Qualys poll, Nmap active scan, SBOM upload, EASM sweep, universal ingest). Nothing
    wrote to this collection before, which is why the page was permanently empty."""
    import uuid
    doc = {
        "id": str(uuid.uuid4()), "name": name, "scanner": scanner, "scan_type": scan_type,
        "scan_method": scan_method, "status": status, "assets_scanned": assets_scanned,
        "findings_created": findings_created, "findings_updated": findings_updated,
        "started_at": started_at or now_iso(), "finished_at": now_iso(), "error": error,
    }
    await db.engagements.insert_one(doc)


def deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out
