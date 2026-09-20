"""Admin-tunable NUMERIC settings (parallel to feature_flags.py, which is boolean).

SETTINGS_REGISTRY is the single source of truth for what's tunable, its bounds, and
its default. Storage: db.app_settings, one doc per key that's ever been set (an
unset key just means "still at its default"). Values are validated against min/max
on write, applied immediately to the live process where relevant (dashboard cache
TTL), and re-applied at boot from apply_persisted_settings().
"""
from datetime import datetime, timezone

SETTINGS_REGISTRY = [
    {"key": "dashboard_cache_ttl_seconds", "group": "Performance",
     "label": "Dashboard cache TTL (seconds)",
     "description": "How long dashboard results are cached before recomputing. Higher = faster and "
                    "less database load, but numbers can be more stale. Set 0 to disable caching and "
                    "always compute fresh. Applies to all dashboards.",
     "default": 30, "min": 0, "max": 600, "unit": "seconds"},
    {"key": "saved_search_alert_interval_minutes", "group": "Alerting",
     "label": "Saved-search alert check interval (minutes)",
     "description": "How often saved-search alerts scan for new findings that match your saved views. "
                    "Lower = you're notified sooner, at the cost of more frequent scans. Takes effect on "
                    "the next scan cycle.",
     "default": 60, "min": 5, "max": 1440, "unit": "minutes"},
]

_BY_KEY = {s["key"]: s for s in SETTINGS_REGISTRY}


def _now():
    return datetime.now(timezone.utc).isoformat()


async def get_setting(db, key: str):
    reg = _BY_KEY.get(key)
    if not reg:
        raise ValueError(f"Unknown setting: {key}")
    doc = await db.app_settings.find_one({"id": key}, {"_id": 0})
    if doc and isinstance(doc.get("value"), (int, float)):
        return doc["value"]
    return reg["default"]


async def get_all_settings(db) -> list:
    docs = {}
    async for d in db.app_settings.find({}, {"_id": 0}):
        docs[d.get("id")] = d
    out = []
    for reg in SETTINGS_REGISTRY:
        d = docs.get(reg["key"])
        out.append({**reg,
                    "value": d["value"] if d and isinstance(d.get("value"), (int, float)) else reg["default"],
                    "updated_at": d.get("updated_at") if d else None,
                    "updated_by": d.get("updated_by") if d else None})
    return out


async def set_setting(db, key: str, value, actor: str) -> dict:
    reg = _BY_KEY.get(key)
    if not reg:
        raise ValueError(f"Unknown setting: {key}")
    try:
        value = int(value)
    except (TypeError, ValueError):
        raise ValueError("Value must be a whole number")
    if value < reg["min"] or value > reg["max"]:
        raise ValueError(f"Value must be between {reg['min']} and {reg['max']} {reg.get('unit', '')}".strip())
    await db.app_settings.update_one(
        {"id": key},
        {"$set": {"id": key, "value": value, "updated_at": _now(), "updated_by": actor}},
        upsert=True)
    _apply_side_effect(key, value)
    return {"key": key, "value": value}


def _apply_side_effect(key: str, value):
    """Push a changed value into the live process so it takes effect without a restart."""
    if key == "dashboard_cache_ttl_seconds":
        try:
            from routes.common import set_dashboard_ttl_override
            set_dashboard_ttl_override(value)
        except Exception:
            pass
    # saved_search_alert_interval_minutes needs no push: the loop reads it each cycle.


async def apply_persisted_settings(db) -> None:
    """Re-apply stored values to the live process at boot (called from startup)."""
    try:
        ttl = await get_setting(db, "dashboard_cache_ttl_seconds")
        _apply_side_effect("dashboard_cache_ttl_seconds", ttl)
    except Exception:
        pass
