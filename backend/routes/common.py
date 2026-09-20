"""Shared helpers used by multiple route modules."""
import functools
import hashlib
import json
import time
from datetime import datetime, timezone, timedelta
from typing import Optional


# --- lightweight in-process TTL cache for read-only dashboard endpoints ---------
# Dashboard rollups scan the whole findings set; several widgets reload together and
# users refresh often. A short TTL collapses a burst of identical requests into one
# computation without changing results (reads only). Keyed by endpoint + query args
# + the caller's RBAC scope so two teams never see each other's numbers.
_DASH_CACHE: dict = {}
_DASH_CACHE_MAX = 500


def dashboard_cache(ttl: float = 30.0):
    def deco(fn):
        @functools.wraps(fn)
        async def wrap(*args, **kwargs):
            u = kwargs.get("user") or {}
            keyparts = {k: v for k, v in kwargs.items()
                        if k not in ("user", "_rbac") and isinstance(v, (str, int, float, bool, type(None)))}
            keyparts["_scope"] = f"{u.get('role')}:{u.get('team')}:{','.join(u.get('teams') or [])}"
            key = fn.__name__ + ":" + hashlib.md5(
                json.dumps(keyparts, sort_keys=True, default=str).encode()).hexdigest()
            now = time.monotonic()
            hit = _DASH_CACHE.get(key)
            if hit and hit[0] > now:
                return hit[1]
            res = await fn(*args, **kwargs)
            if len(_DASH_CACHE) > _DASH_CACHE_MAX:
                for k in [k for k, v in _DASH_CACHE.items() if v[0] <= now]:
                    _DASH_CACHE.pop(k, None)
            _DASH_CACHE[key] = (now + ttl, res)
            return res
        return wrap
    return deco


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


def user_teams(user: dict) -> list:
    """A user's full team membership as a de-duped list, whether it came from the
    canonical `teams` array or (for older records / anything that only ever set the
    singular field) the legacy `team` string. Used everywhere data visibility needs
    to be scoped to "any team this user belongs to" now that a user can be on more
    than one team, instead of the old single-string exact match."""
    teams = list(user.get("teams") or [])
    legacy = user.get("team")
    if legacy and legacy not in teams:
        teams.append(legacy)
    return teams


# Canonical finding-status buckets. "Fixed pending validation" is still OPEN --
# it isn't resolved until validated. Everything in RESOLVED_STATUSES is a closed
# outcome and must not be counted as, or shown among, active findings by default.
OPEN_STATUSES = ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]
RESOLVED_STATUSES = ["Fixed validated", "Mitigated", "False positive", "Duplicate",
                     "Accepted risk", "Closed administratively"]


def team_scope_filter(user: dict, field: str = "owner_team") -> dict:
    """Mongo filter fragment restricting to the given user's teams -- analyst and
    executive roles only ever see data belonging to (one of) their own teams; admin
    and manager see everything, so this returns {} (no restriction) for them.
    Centralized here so findings, assets, and anything else that's team-scoped all
    apply the exact same rule instead of each route reimplementing its own slightly
    different version of "is this the user's team"."""
    if user.get("role") not in ("analyst", "executive"):
        return {}
    teams = user_teams(user)
    if not teams:
        return {}
    return {field: {"$in": teams}}


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
