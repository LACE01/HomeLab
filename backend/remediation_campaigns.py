"""Item 62 -- Remediation Campaigns / Patch Tracker.

Replaces the shared weekly patch spreadsheet. A campaign groups a set of findings
(picked explicitly, or snapshotted from a filter like "all Critical KEV on the
DMZ") under an owner, a due date and a goal. Progress is AUTO-DRIVEN: it's computed
live from the findings' current status, which Qualys (and every other scanner) keeps
up to date on each sync -- so when a host is patched and the next scan marks the
finding Fixed, the campaign's bar moves on its own. No manual ticking.

Signals the spreadsheet couldn't give you:
  * patched / complete   -- resolved vs total, and "all done"
  * overdue              -- past the due date and not complete
  * regression           -- a finding that was resolved but has REOPENED (the patch
                            didn't hold, or the vuln came back) -- the thing you
                            most want an alert on and least want to hunt for by eye
"""
from datetime import datetime, timezone
import uuid

from routes.common import OPEN_STATUSES, RESOLVED_STATUSES

# Scanner-verified vs provisional. Only "Fixed validated" is a source/human-confirmed
# fix; "Mitigated" is a compensating control (not a patch); "Accepted risk" is an
# exception (closed without patching). Verification-gated close requires every
# baseline finding to be VERIFIED or ACCEPTED -- not merely marked resolved.
VERIFIED_STATUSES = ["Fixed validated"]
ACCEPTED_STATUSES = ["Accepted risk"]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _baseline(camp: dict):
    """The campaign's baseline finding-id set (open at add-time). None for
    pre-baseline campaigns, so they fall back to counting every member."""
    b = camp.get("baseline_open_ids")
    return b if b is not None else None


def compute_progress(findings: list, due_date: str | None = None, baseline_ids=None, require_verification: bool = True) -> dict:
    """Live progress for a campaign.

    The denominator is the BASELINE: the findings that were OPEN when they were
    added to the campaign -- i.e. what this campaign actually set out to patch.
    'patched' therefore counts only findings patched AFTER being added, not ones
    that happened to already be resolved. (Members already resolved at add-time are
    kept for context but excluded from the bar, so 60% means 60% of the work THIS
    campaign owns, not a number inflated by history.) When no baseline is recorded
    (older campaigns), every member counts, preserving the previous behaviour."""
    if baseline_ids is not None:
        base = set(baseline_ids)
        scope = [f for f in findings if f.get("id") in base]
        already_done = len(findings) - len(scope)
    else:
        scope = findings
        already_done = 0
    findings = scope   # progress is computed over the baseline scope only
    total = len(findings)
    resolved = [f for f in findings if f.get("status") in RESOLVED_STATUSES]
    reopened = [f for f in findings if f.get("status") == "Reopened"]   # regressions
    still_open = [f for f in findings if f.get("status") in OPEN_STATUSES]
    pct = round(100 * len(resolved) / total) if total else 0
    complete = total > 0 and len(resolved) == total
    overdue = bool(due_date) and not complete and due_date < _now_iso()
    # aging: how long the still-open findings have been open (days since first seen)
    now = datetime.now(timezone.utc)
    ages = []
    for f in still_open:
        fs = f.get("first_seen_at")
        if fs:
            try:
                dt = datetime.fromisoformat(str(fs).replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                ages.append((now - dt).days)
            except Exception:
                pass
    verified = [f for f in findings if f.get("status") in VERIFIED_STATUSES]
    accepted = [f for f in findings if f.get("status") in ACCEPTED_STATUSES]
    # closeable: verification-gated -> every baseline finding scanner-verified or
    # formally accepted (exception). Ungated -> just resolved.
    if require_verification:
        closeable = total > 0 and all(
            f.get("status") in VERIFIED_STATUSES or f.get("status") in ACCEPTED_STATUSES
            for f in findings)
    else:
        closeable = complete
    return {
        "total": total,
        "patched": len(resolved),
        "verified": len(verified),
        "accepted": len(accepted),
        "unverified_resolved": len(resolved) - len(verified) - len(accepted),
        "open": len(still_open),
        "regressions": len(reopened),
        "percent_complete": pct,
        "percent_verified": round(100 * len(verified) / total) if total else 0,
        "complete": complete,
        "closeable": closeable,
        "overdue": overdue,
        "by_status": _by_status(findings),
        "avg_open_age_days": round(sum(ages) / len(ages)) if ages else 0,
        "max_open_age_days": max(ages) if ages else 0,
        "aging_over_30d": sum(1 for a in ages if a > 30),
        "already_resolved_at_add": already_done,
    }


def _by_status(findings: list) -> dict:
    out: dict = {}
    for f in findings:
        s = f.get("status") or "Unknown"
        out[s] = out.get(s, 0) + 1
    return out


async def _resolve_finding_ids(db, *, finding_ids=None, filt=None) -> list:
    """A campaign's membership is a fixed list of finding ids, snapshotted at
    creation. Bulk selectors resolve to concrete ids so the campaign stays a
    stable cohort even as new findings appear later."""
    ids = set(finding_ids or [])
    if filt:
        q: dict = {}
        if filt.get("severity"):
            q["severity"] = {"$in": filt["severity"]} if isinstance(filt["severity"], list) else filt["severity"]
        if filt.get("owner_team"):
            q["owner_team"] = filt["owner_team"]
        if filt.get("kev"):
            q["kev_flag"] = True
        if filt.get("cve"):
            q["cve"] = filt["cve"]
        if filt.get("asset_id"):
            q["asset_id"] = {"$in": filt["asset_id"]} if isinstance(filt["asset_id"], list) else filt["asset_id"]
        if q:
            for f in await db.findings.find(q, {"_id": 0, "id": 1}).limit(100000).to_list(100000):
                ids.add(f["id"])
    return sorted(ids)


async def _open_subset(db, ids: list) -> list:
    """Which of these finding ids are currently OPEN -- the campaign's baseline."""
    if not ids:
        return []
    rows = await db.findings.find(
        {"id": {"$in": list(ids)}, "status": {"$in": OPEN_STATUSES}},
        {"_id": 0, "id": 1}).to_list(100000)
    return sorted(r["id"] for r in rows)


async def create_campaign(db, *, name, description="", owner_team=None, due_date=None,
                          finding_ids=None, filt=None, assignees=None, created_by="system",
                          require_verification=True, maintenance_window=None, change_ticket=None) -> dict:
    ids = await _resolve_finding_ids(db, finding_ids=finding_ids, filt=filt)
    baseline = await _open_subset(db, ids)
    doc = {
        "id": str(uuid.uuid4()), "name": name, "description": description,
        "owner_team": owner_team, "due_date": due_date,
        "assignees": assignees or [],
        "finding_ids": ids, "filter": filt or None,
        "baseline_open_ids": baseline,
        "require_verification": bool(require_verification),
        "maintenance_window": maintenance_window or None,   # {start, end}
        "change_ticket": change_ticket or None,
        "created_by": created_by, "created_at": _now_iso(),
        "status": "active",
        # what this campaign set out to patch: the members open at add-time
        "baseline_total": len(baseline), "baseline_at": _now_iso(),
    }
    await db.remediation_campaigns.insert_one(dict(doc))
    await log_activity(db, doc["id"], created_by, "created",
                       f"Campaign created — {len(baseline)} open finding(s) to patch"
                       + (f" ({len(ids) - len(baseline)} already resolved)" if len(ids) > len(baseline) else ""))
    if doc["assignees"]:
        await notify_assignees(db, doc, doc["assignees"], "assigned",
                               f"You've been assigned to remediation campaign '{name}'"
                               f" — {len(baseline)} finding(s) to patch"
                               + (f", due {due_date[:10]}" if due_date else ""))
    return {k: v for k, v in doc.items() if k != "_id"}


async def _campaign_findings(db, campaign: dict) -> list:
    ids = campaign.get("finding_ids") or []
    if not ids:
        return []
    findings = await db.findings.find(
        {"id": {"$in": ids}},
        {"_id": 0, "id": 1, "title": 1, "cve": 1, "qid": 1, "severity": 1, "status": 1,
         "asset_id": 1, "asset_hostname": 1, "owner_team": 1, "due_at": 1, "kev_flag": 1,
         "first_seen_at": 1, "assigned_to": 1, "ticket": 1, "entity_name": 1, "epss_score": 1}).to_list(100000)
    # attach the real ticket (db.tickets, e.g. a risk-acceptance ticket) per finding
    tix = {}
    async for t in db.tickets.find({"finding_id": {"$in": ids}}, {"_id": 0}):
        tix.setdefault(t.get("finding_id"), t)
    for f in findings:
        t = tix.get(f["id"])
        if t:
            f["ticket_ref"] = {"external_id": t.get("external_id") or t.get("id"),
                               "url": t.get("url"), "system": t.get("system"), "status": t.get("status")}
    return findings


async def list_campaigns(db, *, owner_team=None) -> list:
    q = {"owner_team": owner_team} if owner_team else {}
    out = []
    for camp in await db.remediation_campaigns.find(q, {"_id": 0}).sort("created_at", -1).to_list(500):
        findings = await _campaign_findings(db, camp)
        out.append({**camp, "progress": compute_progress(findings, camp.get("due_date"), _baseline(camp), camp.get("require_verification", True))})
    return out


_SEV_WEIGHT = {"Critical": 100, "High": 70, "Medium": 40, "Low": 15, "Info": 5}


def priority_score(f: dict) -> int:
    """SLA x severity x exploitability x age -> a single work-next score. Higher =
    do sooner. Resolved findings sink to the bottom so the queue is always the live
    work in priority order."""
    if f.get("status") in RESOLVED_STATUSES:
        return -1
    score = _SEV_WEIGHT.get(f.get("severity"), 20)
    if f.get("kev_flag"):
        score += 50
    due = f.get("due_at")
    now = _now_iso()
    if due:
        if due < now:
            score += 40                      # overdue
        elif due < (datetime.now(timezone.utc) + timedelta(days=7)).isoformat():
            score += 20                      # due this week
    epss = f.get("epss_score")
    if isinstance(epss, (int, float)):
        score += round(epss * 30)
    fs = f.get("first_seen_at")
    if fs:
        try:
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(str(fs).replace("Z","+00:00")).replace(tzinfo=timezone.utc)).days
            score += min(age // 10, 20)      # older nudges up, capped
        except Exception:
            pass
    return score


async def campaign_detail(db, campaign_id: str, *, for_user: dict = None) -> dict | None:
    camp = await db.remediation_campaigns.find_one({"id": campaign_id}, {"_id": 0})
    if not camp:
        return None
    findings = await _campaign_findings(db, camp)
    camp["progress"] = compute_progress(findings, camp.get("due_date"), _baseline(camp), camp.get("require_verification", True))
    _bl = _baseline(camp)
    camp["groups"] = {
        "device": group_breakdown(findings, "device", _bl),
        "vulnerability": group_breakdown(findings, "vulnerability", _bl),
        "team": group_breakdown(findings, "team", _bl),
    }
    camp["activity"] = await activity(db, campaign_id)
    camp["timeline"] = await timeline(db, camp)
    # a "mine" slice for the tech view: findings assigned to the user or their team
    if for_user:
        teams = set(for_user.get("teams") or ([for_user["team"]] if for_user.get("team") else []))
        email = for_user.get("email")
        camp["mine"] = [f["id"] for f in findings
                        if f.get("assigned_to") == email or f.get("owner_team") in teams]
    for f in findings:
        f["priority_score"] = priority_score(f)
    camp["findings"] = sorted(findings, key=lambda f: -f["priority_score"])   # highest-impact first
    return camp


async def alerts(db) -> dict:
    """Cross-campaign alert roll-up: what needs attention right now."""
    overdue, regressions, completed = [], [], []
    for camp in await list_campaigns(db):
        p = camp["progress"]
        if p["overdue"]:
            overdue.append({"id": camp["id"], "name": camp["name"], "open": p["open"]})
        if p["regressions"]:
            regressions.append({"id": camp["id"], "name": camp["name"], "regressions": p["regressions"]})
        if p["complete"] and camp.get("status") != "closed":
            completed.append({"id": camp["id"], "name": camp["name"]})
    return {"overdue": overdue, "regressions": regressions, "newly_complete": completed}


# ------------------------------------------------------------------ activity
async def log_activity(db, campaign_id, actor, action, detail="", **extra) -> dict:
    """Append to a campaign's append-only activity log (the audit + timeline source).
    action is one of: created, note, status_change, added_findings, removed_findings,
    patch_detected, exception_filed, closed, reopened."""
    doc = {"id": str(uuid.uuid4()), "campaign_id": campaign_id, "actor": actor,
           "action": action, "detail": detail, "at": _now_iso(), **extra}
    await db.remediation_campaign_activity.insert_one(dict(doc))
    return {k: v for k, v in doc.items() if k != "_id"}


async def activity(db, campaign_id, limit=300) -> list:
    return await db.remediation_campaign_activity.find(
        {"campaign_id": campaign_id}, {"_id": 0}).sort("at", -1).to_list(limit)


async def add_note(db, campaign_id, *, actor, text, attachments=None, links=None) -> dict:
    """A campaign-level note with optional screenshots (attachments) and links."""
    return await log_activity(db, campaign_id, actor, "note", text,
                              attachments=attachments or [], links=links or [])


# ------------------------------------------------------------- mass note/status
async def mass_note_findings(db, *, finding_ids, actor, text, attachments=None) -> int:
    """Write one note to MANY findings at once (db.comments, the same store the
    Finding detail uses) so the tech doesn't have to open each vulnerability."""
    n = 0
    for fid in finding_ids or []:
        await db.comments.insert_one({
            "id": str(uuid.uuid4()), "finding_id": fid, "author": actor,
            "text": text, "attachments": attachments or [], "created_at": _now_iso()})
        n += 1
    return n


# -------------------------------------------------------------------- grouping
def group_breakdown(findings: list, by: str, baseline_ids=None) -> list:
    """Per-device / per-vulnerability / per-team rollup of a campaign's findings,
    each with its own patched/open/regression progress -- so the work can be sliced
    the same three ways the Findings tab offers."""
    keyer = {
        "device": lambda f: f.get("asset_hostname") or f.get("asset_id") or "Unknown host",
        "vulnerability": lambda f: f.get("cve") or f.get("title") or "Unknown vuln",
        "team": lambda f: f.get("owner_team") or "Unassigned",
    }.get(by, lambda f: "All")
    groups: dict = {}
    for f in findings:
        groups.setdefault(keyer(f), []).append(f)
    out = []
    for k, fs in groups.items():
        p = compute_progress(fs, None, baseline_ids)
        out.append({"key": k, "total": p["total"], "patched": p["patched"],
                    "open": p["open"], "regressions": p["regressions"],
                    "percent_complete": p["percent_complete"]})
    out.sort(key=lambda g: (-g["open"], -g["total"]))
    return out


# -------------------------------------------------------------------- timeline
async def timeline(db, campaign: dict) -> list:
    """Merged timeline: patches applied (from db.patches_applied, scoped to the
    campaign's findings) + campaign activity events, oldest first."""
    ids = set(campaign.get("finding_ids") or [])
    events = []
    if ids:
        async for pa in db.patches_applied.find(
                {"finding_ids": {"$elemMatch": {"$in": list(ids)}}}, {"_id": 0}):
            hits = [fid for fid in (pa.get("finding_ids") or []) if fid in ids]
            if hits:
                events.append({"at": pa.get("resolved_at"), "type": "patch",
                               "detail": f"{pa.get('asset_hostname') or 'host'}: {pa.get('title') or 'patched'}",
                               "count": len(hits)})
    for a in await activity(db, campaign["id"]):
        events.append({"at": a["at"], "type": a["action"], "detail": a.get("detail", ""),
                       "actor": a.get("actor")})
    events.sort(key=lambda e: e.get("at") or "")
    return events


# ---------------------------------------------------------------------- close
async def close_campaign(db, campaign_id, actor, note="") -> None:
    await db.remediation_campaigns.update_one(
        {"id": campaign_id}, {"$set": {"status": "closed", "closed_at": _now_iso()}})
    await log_activity(db, campaign_id, actor, "closed", note or "Campaign closed")


async def maybe_autoclose(db, campaign: dict) -> bool:
    """Auto-close a campaign the moment every finding is resolved."""
    if campaign.get("status") == "closed":
        return False
    findings = await _campaign_findings(db, campaign)
    if compute_progress(findings, None, _baseline(campaign), campaign.get("require_verification", True)).get("closeable"):
        await close_campaign(db, campaign["id"], "system", "All findings verified/accepted — auto-closed.")
        return True
    return False


# -------------------------------------------------------- alerts -> notifications
async def notify_alerts(db) -> dict:
    """Push campaign alerts (overdue, regression) into the notifications outbox --
    the same channel the Notifications tab reads -- deduped per campaign+kind+day."""
    from datetime import date
    today = date.today().isoformat()
    sent = 0
    al = await alerts(db)
    # per-assignee overdue nudges
    camps_by_id = {c["id"]: c for c in await db.remediation_campaigns.find({}, {"_id": 0}).to_list(500)}
    for r in al["overdue"]:
        camp = camps_by_id.get(r["id"])
        if camp and camp.get("assignees"):
            sent += await notify_assignees(db, camp, camp["assignees"], "overdue",
                                           f"Campaign '{camp['name']}' is overdue — {r.get('open','?')} finding(s) still open")
    for kind, rows in (("overdue", al["overdue"]), ("regression", al["regressions"])):
        for r in rows:
            key = f"campaign:{kind}:{r['id']}:{today}"
            if await db.notifications_outbox.find_one({"dedupe_key": key}, {"_id": 0}):
                continue
            body = (f"{r.get('open', '?')} findings still open past due"
                    if kind == "overdue" else f"{r.get('regressions')} regression(s) detected")
            await db.notifications_outbox.insert_one({
                "id": str(uuid.uuid4()), "dedupe_key": key,
                "kind": f"remediation_{kind}", "title": f"Campaign {kind}: {r['name']}",
                "body": body, "link": f"/remediation-campaigns", "created_at": _now_iso(), "read": False})
            sent += 1
            try:
                from notifier import dispatch
                await dispatch(f"remediation_{kind}", {"campaign": r["name"], "body": body,
                                                       "link": "/remediation-campaigns"}, db)
            except Exception:
                pass
    return {"sent": sent}


# ------------------------------------------------------- assignee notifications
async def notify_assignees(db, campaign: dict, recipients, kind: str, body: str) -> int:
    """Write a per-assignee notification to the outbox (the channel the
    Notifications tab records), deduped per campaign+kind+recipient+day."""
    from datetime import date
    today = date.today().isoformat()
    sent = 0
    for r in recipients or []:
        key = f"campaign_assignee:{kind}:{campaign['id']}:{r}:{today}"
        if await db.notifications_outbox.find_one({"dedupe_key": key}, {"_id": 0}):
            continue
        await db.notifications_outbox.insert_one({
            "id": str(uuid.uuid4()), "dedupe_key": key, "recipient": r,
            "kind": f"campaign_{kind}", "title": f"Remediation: {campaign.get('name')}",
            "body": body, "link": "/remediation-campaigns",
            "created_at": _now_iso(), "read": False})
        sent += 1
    # Also fan out through the configured Notifications channels/rules (email/Slack/
    # SMS) -- best-effort, never blocks the outbox record.
    try:
        from notifier import dispatch
        trigger = "remediation_overdue" if kind == "overdue" else "remediation_assigned"
        await dispatch(trigger, {"campaign": campaign.get("name"), "owner_team": campaign.get("owner_team"),
                                 "recipients": list(recipients or []), "body": body,
                                 "link": "/remediation-campaigns"}, db)
    except Exception:
        pass
    return sent


# ------------------------------------------------------- burndown history
async def snapshot_progress(db, *, day: str = None) -> dict:
    """Record today's progress for every active campaign so the detail can show a
    real burndown curve. Idempotent per campaign/day. Meant to run nightly."""
    from datetime import date
    day = day or date.today().isoformat()
    n = 0
    for camp in await db.remediation_campaigns.find({}, {"_id": 0}).to_list(500):
        findings = await _campaign_findings(db, camp)
        p = compute_progress(findings, camp.get("due_date"), _baseline(camp),
                             camp.get("require_verification", True))
        await db.remediation_campaign_snapshots.replace_one(
            {"campaign_id": camp["id"], "day": day},
            {"campaign_id": camp["id"], "day": day, "total": p["total"],
             "patched": p["patched"], "verified": p["verified"], "open": p["open"],
             "regressions": p["regressions"], "at": _now_iso()}, upsert=True)
        n += 1
    return {"campaigns": n, "day": day}


async def burndown(db, campaign_id: str) -> list:
    return await db.remediation_campaign_snapshots.find(
        {"campaign_id": campaign_id}, {"_id": 0}).sort("day", 1).to_list(400)


def in_maintenance_window(campaign: dict) -> bool:
    mw = campaign.get("maintenance_window") or {}
    now = _now_iso()
    return bool(mw.get("start") and mw.get("end") and mw["start"] <= now <= mw["end"])
