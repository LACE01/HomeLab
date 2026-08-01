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
async def summary(user: dict = Depends(get_current_user)):
    """How much of the backlog is independently confirmed.

    A high corroboration rate means the backlog is trustworthy. A low one is not
    automatically bad -- it usually means the scanners cover different assets,
    which the coverage split below distinguishes from genuine disagreement.
    """
    findings = await db.findings.find(
        {"status": {"$in": OPEN}},
        {"_id": 0, "id": 1, "asset_id": 1, "sources": 1, "severity": 1,
         "source_tool": 1, "title": 1, "cve": 1}).to_list(None)

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
