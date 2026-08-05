"""OWASP WSTG routes: the methodology, mapped to real findings.

Three surfaces:
  * the catalogue itself, as a reference library
  * per-finding: which WSTG test cases this finding is evidence for
  * coverage: across the open web-facing backlog, which categories have evidence
    and which have none (== untested, not clean)
"""
from fastapi import APIRouter, Depends, HTTPException

from db import db
from auth_utils import get_current_user
import wstg

router = APIRouter()

OPEN = ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]


@router.get("/v1/wstg/catalogue")
async def catalogue(user: dict = Depends(get_current_user)):
    return {"categories": wstg.catalogue(), "test_count": len(wstg.TESTS)}


@router.get("/v1/wstg/coverage")
async def coverage(user: dict = Depends(get_current_user)):
    """WSTG coverage across the open backlog. Cached like the other whole-backlog
    aggregates -- it walks every finding through the mapper."""
    from aggregate_cache import get_or_compute

    async def _compute():
        findings = await db.findings.find(
            {"status": {"$in": OPEN}},
            {"_id": 0, "title": 1, "description": 1, "consequence": 1, "remediation": 1,
             "detection_logic": 1, "cwe": 1}).to_list(50000)
        return wstg.coverage(findings)

    return await get_or_compute(db, "wstg_coverage", _compute, cpu_bound=True,
                                 is_empty=lambda v: not v.get("tests_with_evidence"))


@router.get("/v1/findings/{finding_id}/wstg")
async def for_finding(finding_id: str, user: dict = Depends(get_current_user)):
    f = await db.findings.find_one({"id": finding_id}, {"_id": 0})
    if not f:
        raise HTTPException(404, "No such finding")
    tests = wstg.tests_for_finding(f)
    return {"finding_id": finding_id, "tests": tests,
            "in_scope": bool(tests),
            "note": ("" if tests else
                      "This finding maps to no WSTG test case — WSTG covers web-application "
                      "testing, and this finding is not web-related.")}
