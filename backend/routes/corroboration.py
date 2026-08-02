"""Corroboration as a first-class view of the backlog.

Two questions this answers that were previously unanswerable:

  * Which findings did more than one tool independently confirm? Those are the
    ones to fix first -- not because they are more severe, but because they are
    more certainly real.
  * Which findings does only one tool report, on an asset the other tools also
    scan? Those are the false-positive candidates, and chasing them is where
    remediation effort quietly disappears.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from db import db
from auth_utils import get_current_user, require_role
import corroboration as corr

router = APIRouter()

OPEN = ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]


@router.get("/v1/findings/corroboration/summary")
async def summary(refresh: bool = False, user: dict = Depends(get_current_user)):
    """How much of the backlog is independently confirmed.

    A high corroboration rate means the backlog is trustworthy. A low one is not
    automatically bad -- it usually means the scanners cover different assets,
    which the coverage split below distinguishes from genuine disagreement.
    """
    # Same reasoning as /v1/mitre/coverage: a whole-backlog statistic that used to
    # be recomputed on every request, walking every open finding and doing one
    # identifier lookup per distinct asset. Cached, and served stale-while-
    # refreshing rather than making anyone wait for it.
    from aggregate_cache import get_or_compute, invalidate
    if refresh:
        await invalidate(db, "corroboration_summary")
    return await get_or_compute(db, "corroboration_summary", _compute_summary,
                                 is_empty=lambda v: not v.get("findings_total"))


async def _compute_summary():
    findings = await db.findings.find(
        {"status": {"$in": OPEN}},
        {"_id": 0, "id": 1, "asset_id": 1, "sources": 1, "severity": 1,
         "source_tool": 1, "title": 1, "cve": 1}).to_list(50000)

    covering_cache: dict = {}
    counts = {"corroborated": 0, "single_source_disputed": 0,
              "single_source_uncorroborated": 0, "unattributed": 0}
    disputed_severity = 0
    examples: dict = {k: [] for k in counts}

    for f in findings:
        asset_id = f.get("asset_id")
        if asset_id and asset_id not in covering_cache:
            covering_cache[asset_id] = await corr.tools_covering(db, asset_id)
        verdict = corr.assess(f, tools_covering_asset=covering_cache.get(asset_id))
        counts[verdict["status"]] = counts.get(verdict["status"], 0) + 1
        if verdict.get("agreement") == "disputed":
            disputed_severity += 1
        if len(examples[verdict["status"]]) < 5:
            examples[verdict["status"]].append({
                "id": f.get("id"), "title": f.get("title"), "cve": f.get("cve"),
                "tools": verdict["tools"], "note": verdict["note"]})

    total = len(findings) or 1
    return {
        "findings_total": len(findings),
        "counts": counts,
        "corroborated_pct": round(100 * counts["corroborated"] / total, 1),
        "severity_disputes": disputed_severity,
        "examples": examples,
        "interpretation": {
            "corroborated": ("Two or more tools independently found these. Highest confidence "
                              "they are real — fix these first."),
            "single_source_disputed": ("Only one tool reports these, and other scanners that DO "
                                        "cover the same asset stayed silent. Weak evidence of a "
                                        "false positive; verify before spending effort."),
            "single_source_uncorroborated": ("Only one tool reports these and nothing else scans "
                                              "that asset, so there is nothing to corroborate "
                                              "against. This is a coverage gap in your tooling, "
                                              "not a judgement about the findings."),
        },
    }


@router.get("/v1/findings/{finding_id}/corroboration")
async def for_finding(finding_id: str, user: dict = Depends(get_current_user)):
    f = await db.findings.find_one({"id": finding_id}, {"_id": 0})
    if not f:
        raise HTTPException(404, "No such finding")
    covering = await corr.tools_covering(db, f["asset_id"]) if f.get("asset_id") else set()
    verdict = corr.assess(f, tools_covering_asset=covering)
    return {**verdict, "sources": f.get("sources") or [],
             "tools_covering_asset": sorted(covering)}


class BackfillBody(BaseModel):
    dry_run: bool = True


@router.post("/v1/findings/corroboration/backfill")
async def backfill(body: BackfillBody, user: dict = Depends(require_role("admin"))):
    """Fold findings duplicated by the old hostname-based key.

    Defaults to a dry run on purpose: this rewrites the live backlog.
    """
    return await corr.backfill_existing(db, dry_run=body.dry_run)


# ---------------------------------------------------------------------------
# The context panel lives here rather than in routes/findings.py for one reason:
# findings.py registers "/v1/findings/{finding_id}", and this router is
# deliberately mounted ahead of it so literal paths resolve first.
# ---------------------------------------------------------------------------
@router.get("/v1/findings/{finding_id}/context")
async def finding_context(finding_id: str, user: dict = Depends(get_current_user)):
    """Why this finding matters on THIS asset -- assembled from every module that
    knows something about it, with a source on every claim."""
    import finding_context as fc
    f = await db.findings.find_one({"id": finding_id}, {"_id": 0})
    if not f:
        raise HTTPException(404, "No such finding")
    return await fc.build(db, f)


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------
@router.get("/v1/correlation/hits")
async def correlation_hits(status: str = "open", limit: int = 100,
                            user: dict = Depends(get_current_user)):
    """Open correlation hits, worst first."""
    import correlation as cx
    q = {} if status == "all" else {"status": status}
    rows = await db.correlation_hits.find(q, {"_id": 0}).to_list(2000)
    rank = {s: i for i, s in enumerate(cx.SEVERITY)}
    rows.sort(key=lambda h: (-rank.get(h.get("severity"), 0), h.get("last_seen_at") or ""))
    return {"items": rows[:limit], "count": len(rows)}


@router.get("/v1/correlation/rules")
async def correlation_rules(user: dict = Depends(get_current_user)):
    """The rule catalogue, with what each one needs to be able to run at all."""
    import correlation as cx
    available = await cx._availability(db)
    return {"rules": [{
        "key": r.key, "title": r.title, "severity": r.severity,
        "requires": r.requires, "why_it_matters": r.why_it_matters,
        "can_run": all(available.get(x, False) for x in r.requires),
        "missing_inputs": [x for x in r.requires if not available.get(x, False)],
    } for r in cx.RULES], "input_availability": available}


@router.post("/v1/correlation/run")
async def correlation_run(user: dict = Depends(require_role("admin"))):
    import correlation as cx
    return await cx.run(db)


@router.patch("/v1/correlation/hits/{hit_id}")
async def correlation_triage(hit_id: str, body: dict,
                              user: dict = Depends(get_current_user)):
    """Acknowledge or dismiss a hit. Dismissal requires a reason, because a hit
    dismissed without one is indistinguishable from one nobody looked at."""
    allowed = {"open", "acknowledged", "dismissed"}
    status = body.get("status")
    if status not in allowed:
        raise HTTPException(400, f"status must be one of {sorted(allowed)}")
    if status == "dismissed" and not (body.get("reason") or "").strip():
        raise HTTPException(400, "A dismissal reason is required.")
    res = await db.correlation_hits.update_one({"id": hit_id}, {"$set": {
        "status": status, "triage_reason": body.get("reason"),
        "triaged_by": user.get("email") or user.get("id"),
        "triaged_at": __import__("correlation")._now_iso()}})
    if not res.matched_count:
        raise HTTPException(404, "No such hit")
    return {"updated": True, "status": status}


# ---------------------------------------------------------------------------
# Blast radius / point-in-time posture / change feed
# ---------------------------------------------------------------------------
@router.get("/v1/assets/{asset_id}/blast-radius")
async def blast_radius(asset_id: str, user: dict = Depends(get_current_user)):
    """If this asset is compromised or taken down, what else is affected."""
    import posture_history as ph
    result = await ph.blast_radius(db, asset_id)
    if result is None:
        raise HTTPException(404, "No such asset")
    return result


@router.get("/v1/posture/changes")
async def posture_changes(since: str = None, to: str = None,
                           user: dict = Depends(get_current_user)):
    """What changed. Defaults to the last 24 hours."""
    import posture_history as ph
    from datetime import datetime, timezone, timedelta
    since = since or (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
    return await ph.changes_between(db, since, to)


@router.get("/v1/posture/snapshot")
async def posture_snapshot(day: str = None, user: dict = Depends(get_current_user)):
    """Posture on a given day. Falls back to the nearest earlier snapshot."""
    import posture_history as ph
    from datetime import datetime, timezone
    day = day or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    snap = await ph.snapshot_for(db, day)
    if not snap:
        raise HTTPException(404, "No snapshot on or before that date")
    snap.pop("ids", None)   # the id lists are for diffing, not for display
    return snap


@router.get("/v1/posture/history")
async def posture_history_list(days: int = 90, user: dict = Depends(get_current_user)):
    """The trend line, for charting."""
    rows = await db.posture_snapshots.find(
        {}, {"_id": 0, "ids": 0}).sort("day", -1).to_list(days)
    return {"items": list(reversed(rows))}


@router.post("/v1/posture/snapshot")
async def take_posture_snapshot(user: dict = Depends(require_role("admin"))):
    import posture_history as ph
    return await ph.take_snapshot(db)
