"""Repair the duplicate findings created by the canonical-key change.

WHAT HAPPENED

The finding key moved from f"{cve}::{hostname}" to (cve, resolved asset id)
without a migration path. The first sync afterwards looked up every finding by
the new key, found nothing, and created a second copy of the entire backlog:
7,361 findings created in one run, against fourteen previous runs that created
zero between them.

corroboration.find_existing() stops it happening again. This repairs what was
already written.

WHAT "REPAIR" HAS TO PRESERVE

Not just "delete the newer row". The older row carries everything a person put
there and everything time gave it:

  * first_seen_at, which drives the SLA clock and due date
  * status and triage -- an accepted risk, an assigned owner, a note
  * reopened_count, exception links, ticket references
  * its id, which may appear in an IR case, a report, or an audit entry

while the NEWER row may carry a fresher severity or a scanner field that changed.
So the repair keeps the oldest document, folds the newer one's sources into it,
and marks the newer Superseded with a pointer -- never deletes, because a
dangling id is worse than a redirect.

CONSERVATIVE BY DEFAULT. It dry-runs unless told otherwise, and it only merges
rows it can prove describe the same thing: same asset AND the same CVE, or the
same scanner check id. Anything ambiguous is reported and left alone.
"""
import logging
from datetime import datetime, timezone

from corroboration import make_source, merge_source, reconcile_severity, canonical_key

logger = logging.getLogger("vulnops.dedupe")

# Statuses that mean a human has engaged with the finding. If one of a duplicate
# pair carries one of these, it wins regardless of age -- losing an accepted risk
# or a triage decision is worse than losing a few days of first_seen accuracy.
DECIDED_STATUSES = {
    "Valid", "Risk accepted", "False positive", "Mitigated",
    "Fixed pending validation", "Fixed validated", "Closed administratively",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _identity(f: dict) -> tuple:
    """What makes two findings the same finding.

    A CVE on an asset is the same vulnerability whichever scanner found it. With
    no CVE we fall back to the scanner's own check id, which is only comparable
    within that scanner -- so the tool is part of the key. Two different tools'
    proprietary ids are NOT evidence of the same thing and must not be merged.
    """
    asset = f.get("asset_id")
    if not asset:
        return None
    cve = (f.get("cve") or "").strip().upper()
    if cve:
        return ("cve", cve, asset)
    native = f.get("source_native_id") or f.get("qid") or f.get("plugin_id")
    if native:
        return ("native", (f.get("source_tool") or "").lower(), str(native), asset)
    return None


def _sort_key(f: dict):
    """Which of a duplicate group survives.

    Human engagement first, then age. A row someone has triaged is worth more
    than a row that merely appeared earlier.
    """
    decided = 0 if f.get("status") in DECIDED_STATUSES else 1
    return (decided, f.get("first_seen_at") or "", f.get("id") or "")


def _sources_of(f: dict) -> list:
    if f.get("sources"):
        return list(f["sources"])
    if f.get("source_tool"):
        return [make_source(tool=f["source_tool"],
                             native_id=f.get("source_native_id"),
                             severity=f.get("severity"),
                             first_seen=f.get("first_seen_at"))]
    return []


async def find_duplicates(db, *, include_closed: bool = False) -> dict:
    """Group findings that describe the same vulnerability on the same asset."""
    q = {} if include_closed else {"status": {"$nin": ["Superseded"]}}
    groups: dict = {}
    ungroupable = 0
    async for f in db.findings.find(q, {"_id": 0}):
        ident = _identity(f)
        if not ident:
            ungroupable += 1
            continue
        groups.setdefault(ident, []).append(f)
    dupes = {k: v for k, v in groups.items() if len(v) > 1}
    return {"groups": dupes, "total_findings": sum(len(v) for v in groups.values()),
            "ungroupable": ungroupable}


async def repair(db, *, dry_run: bool = True, include_closed: bool = False) -> dict:
    """Fold each duplicate group into its surviving finding."""
    found = await find_duplicates(db, include_closed=include_closed)
    groups = found["groups"]

    folded = 0
    examples = []
    conflicts = []

    for ident, findings in groups.items():
        ordered = sorted(findings, key=_sort_key)
        keeper, rest = ordered[0], ordered[1:]

        # If more than one row has been triaged differently, a machine should not
        # pick. Report it and leave both alone.
        decided = [f for f in ordered if f.get("status") in DECIDED_STATUSES]
        distinct_decisions = {f.get("status") for f in decided}
        if len(distinct_decisions) > 1:
            conflicts.append({
                "identity": list(ident),
                "reason": ("More than one of these has a human decision on it, and they "
                            "disagree. Merging would silently discard one."),
                "findings": [{"id": f["id"], "status": f.get("status"),
                               "first_seen_at": f.get("first_seen_at")} for f in ordered],
            })
            continue

        sources = _sources_of(keeper)
        for dup in rest:
            for src in _sources_of(dup):
                sources = merge_source(sources, src)

        sev = reconcile_severity(sources)
        new_key = canonical_key(
            asset_id=keeper["asset_id"],
            cve=keeper.get("cve"),
            native_id=keeper.get("source_native_id") or keeper.get("qid"),
            tool=keeper.get("source_tool"))

        # The earliest first_seen across the group -- the duplicate was created
        # later by definition, but the SLA clock should reflect when the
        # vulnerability was actually first observed.
        earliest = min((f.get("first_seen_at") for f in ordered if f.get("first_seen_at")),
                        default=keeper.get("first_seen_at"))

        if len(examples) < 15:
            examples.append({
                "identity": list(ident),
                "keeping": {"id": keeper["id"], "status": keeper.get("status"),
                             "first_seen_at": keeper.get("first_seen_at")},
                "folding": [{"id": d["id"], "status": d.get("status"),
                              "first_seen_at": d.get("first_seen_at")} for d in rest],
                "tools_after_merge": sorted({s["tool"] for s in sources if s.get("tool")}),
            })

        folded += len(rest)
        if dry_run:
            continue

        await db.findings.update_one({"id": keeper["id"]}, {"$set": {
            "canonical_key": new_key,
            "sources": sources,
            "source_count": len({s["tool"] for s in sources if s.get("tool")}),
            "severity": sev["severity"] or keeper.get("severity"),
            "severity_agreement": sev["agreement"],
            "severity_disagreement": sev["disagreement"],
            "first_seen_at": earliest,
            "deduped_at": _now_iso(),
        }})
        for dup in rest:
            await db.findings.update_one({"id": dup["id"]}, {"$set": {
                "status": "Superseded",
                "superseded_by": keeper["id"],
                "superseded_at": _now_iso(),
                "superseded_reason": (
                    "Duplicate created when the finding key changed from hostname-based to "
                    "asset-id-based without a migration path. Folded into the original."),
            }})

    return {
        "dry_run": dry_run,
        "duplicate_groups": len(groups),
        "findings_folded": folded,
        "conflicts": conflicts,
        "conflict_count": len(conflicts),
        "examples": examples,
        "note": ("Nothing was changed. Re-run with dry_run=false to apply." if dry_run else
                  "Duplicates are marked Superseded with a pointer to the survivor, never "
                  "deleted -- a finding id can appear in an IR case, a report or a ticket."),
    }
