"""Saved-search alerting bridge.

Turns a user's saved Findings view into a standing alert: when NEW findings start
matching that saved filter, notify the view's owner. It reuses the very same filter
builder the Findings list and CSV export use (routes.findings._build_findings_filter),
so "what the alert watches" is byte-for-byte identical to what the saved view shows,
including that user's team scoping and the hide-resolved default.

Newness is defined by a per-view checkpoint (alert_last_checked_at), advanced every
run. A finding is therefore alerted on exactly once -- the run after it first appears
-- with no per-day dedupe needed and no double-counting. first_seen_at is compared in
Python via _dt() coercion, because Mongo stores it as either an ISO string or a native
datetime and a raw $gt across those types is unreliable.
"""
import asyncio
import logging
import uuid
from datetime import datetime, timezone

logger = logging.getLogger("vulnops.saved_search")


def _iso(v):
    if v is None:
        return None
    if hasattr(v, "isoformat"):
        try:
            return v.isoformat()
        except Exception:
            return None
    return str(v)


def _dt(v):
    iso = _iso(v)
    if not iso:
        return None
    try:
        d = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return d.replace(tzinfo=timezone.utc) if d.tzinfo is None else d
    except Exception:
        return None


def _view_to_kwargs(filters: dict) -> dict:
    """Map the saved view's stored UI state (camelCase, from Findings.jsx) to the
    keyword arguments _build_findings_filter expects."""
    f = filters or {}
    return {
        "q": f.get("q") or None,
        "severity": f.get("severities") or None,
        "status": f.get("statuses") or None,
        "exploitability": f.get("exploitability") or None,
        "asset_type": f.get("assetTypes") or None,
        "tags": f.get("tagFilter") or None,
        "kev": True if f.get("kevOnly") else None,
        "internet_facing": True if f.get("internetOnly") else None,
        "include_resolved": bool(f.get("showResolved")),
        "owner_team": f.get("teamFilter") or None,
        "sla": f.get("sla") or None,
        "age_days": f.get("ageDays") or None,
        "confidence": f.get("confidence") or None,
        "entity": f.get("entity") or None,
    }


async def _owner_user(db, owner: str) -> dict:
    u = await db.users.find_one({"email": owner}, {"_id": 0})
    return u or {"email": owner, "role": "admin"}  # unscoped fallback if the user is gone


async def _notify_owner(db, owner: str, view: dict, body: str, count: int) -> int:
    await db.notifications_outbox.insert_one({
        "id": str(uuid.uuid4()),
        "dedupe_key": f"saved_search:{view.get('id')}:{uuid.uuid4().hex}",
        "recipient": owner, "kind": "saved_search_match",
        "title": f"Saved search: {view.get('name')}", "body": body,
        "link": "/findings", "created_at": _iso(datetime.now(timezone.utc)), "read": False,
    })
    try:
        from notifier import dispatch
        await dispatch("saved_search_match",
                       {"recipients": [owner], "view": view.get("name"), "count": count,
                        "body": body, "link": "/findings"}, db)
    except Exception:
        pass
    return 1


async def check_saved_search_alerts(db, *, now: str = None) -> dict:
    """Run every alert-enabled saved view once; notify owners of new matches."""
    from routes.findings import _build_findings_filter
    now = now or _iso(datetime.now(timezone.utc))
    checked = with_new = notified = 0
    async for view in db.saved_findings_views.find({"alert_enabled": True}, {"_id": 0}):
        checked += 1
        try:
            owner = view.get("owner")
            user = await _owner_user(db, owner)
            flt = await _build_findings_filter(user, **_view_to_kwargs(view.get("filters")))
            since_dt = _dt(view.get("alert_last_checked_at") or view.get("alert_enabled_at") or now)
            new_matches = []
            async for f in db.findings.find(
                    flt, {"_id": 0, "id": 1, "title": 1, "cve": 1, "severity": 1,
                          "asset_hostname": 1, "first_seen_at": 1}).limit(5000):
                fs = _dt(f.get("first_seen_at"))
                if fs and since_dt and fs > since_dt:
                    new_matches.append(f)
            if new_matches:
                with_new += 1
                new_matches.sort(key=lambda x: _iso(x.get("first_seen_at")) or "", reverse=True)
                sample = ", ".join((s.get("cve") or s.get("title") or "")[:40] for s in new_matches[:5])
                body = (f"{len(new_matches)} new finding(s) match your saved search "
                        f"\"{view.get('name')}\": {sample}" + ("…" if len(new_matches) > 5 else ""))
                notified += await _notify_owner(db, owner, view, body, len(new_matches))
            await db.saved_findings_views.update_one(
                {"owner": view.get("owner"), "id": view.get("id")},
                {"$set": {"alert_last_checked_at": now, "alert_last_match_count": len(new_matches)}})
        except Exception as e:
            logger.warning("saved-search alert failed for view %s: %s", view.get("id"), e)
    return {"views_checked": checked, "views_with_new": with_new, "notified": notified}


async def saved_search_alert_loop(db, interval_minutes: int = 60):
    while True:
        try:
            res = await check_saved_search_alerts(db)
            if res["views_with_new"]:
                logger.info("Saved-search alerts: %s", res)
        except Exception as e:
            logger.exception("saved_search_alert_loop error: %s", e)
        await asyncio.sleep(interval_minutes * 60)
