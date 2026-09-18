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


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def compute_progress(findings: list, due_date: str | None = None) -> dict:
    """Live progress for a campaign from its findings' CURRENT status."""
    total = len(findings)
    resolved = [f for f in findings if f.get("status") in RESOLVED_STATUSES]
    reopened = [f for f in findings if f.get("status") == "Reopened"]   # regressions
    still_open = [f for f in findings if f.get("status") in OPEN_STATUSES]
    pct = round(100 * len(resolved) / total) if total else 0
    complete = total > 0 and len(resolved) == total
    overdue = bool(due_date) and not complete and due_date < _now_iso()
    return {
        "total": total,
        "patched": len(resolved),
        "open": len(still_open),
        "regressions": len(reopened),
        "percent_complete": pct,
        "complete": complete,
        "overdue": overdue,
        "by_status": _by_status(findings),
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


async def create_campaign(db, *, name, description="", owner_team=None, due_date=None,
                          finding_ids=None, filt=None, created_by="system") -> dict:
    ids = await _resolve_finding_ids(db, finding_ids=finding_ids, filt=filt)
    doc = {
        "id": str(uuid.uuid4()), "name": name, "description": description,
        "owner_team": owner_team, "due_date": due_date,
        "finding_ids": ids, "created_by": created_by, "created_at": _now_iso(),
        "status": "active",
        # snapshot of the baseline so "started at N, X to go" is provable later
        "baseline_total": len(ids), "baseline_at": _now_iso(),
    }
    await db.remediation_campaigns.insert_one(dict(doc))
    return {k: v for k, v in doc.items() if k != "_id"}


async def _campaign_findings(db, campaign: dict) -> list:
    ids = campaign.get("finding_ids") or []
    if not ids:
        return []
    return await db.findings.find(
        {"id": {"$in": ids}},
        {"_id": 0, "id": 1, "title": 1, "cve": 1, "qid": 1, "severity": 1, "status": 1,
         "asset_hostname": 1, "owner_team": 1, "due_at": 1, "kev_flag": 1}).to_list(100000)


async def list_campaigns(db, *, owner_team=None) -> list:
    q = {"owner_team": owner_team} if owner_team else {}
    out = []
    for camp in await db.remediation_campaigns.find(q, {"_id": 0}).sort("created_at", -1).to_list(500):
        findings = await _campaign_findings(db, camp)
        out.append({**camp, "progress": compute_progress(findings, camp.get("due_date"))})
    return out


async def campaign_detail(db, campaign_id: str) -> dict | None:
    camp = await db.remediation_campaigns.find_one({"id": campaign_id}, {"_id": 0})
    if not camp:
        return None
    findings = await _campaign_findings(db, camp)
    camp["progress"] = compute_progress(findings, camp.get("due_date"))
    camp["findings"] = sorted(findings, key=lambda f: (f.get("status") in RESOLVED_STATUSES,
                                                       f.get("severity") or ""))
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
