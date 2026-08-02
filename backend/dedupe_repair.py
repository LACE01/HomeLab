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


# Every place a finding id can be referenced from. Checked before deleting
# anything: a dangling id turns a working IR case or report into one that
# silently drops a row, and that damage is discovered months later by someone who
# has no idea why the numbers do not add up.
#
# (collection, field, is_array)
REFERENCE_SITES = [
    ("tickets", "finding_id", False),
    ("comments", "finding_id", False),
    ("observations", "finding_id", False),
    ("mitigations", "finding_id", False),
    ("exceptions", "finding_id", False),
    ("exceptions", "finding_ids", True),
    ("security_review_findings", "finding_id", False),
    ("risk_register", "linked_finding_ids", True),
    ("ir_cases", "finding_ids", True),
    ("attack_paths", "breaking_finding_ids", True),
    ("correlation_hits", "evidence.finding_ids", True),
    ("activity_log", "finding_id", False),
    ("notifications", "finding_id", False),
]


async def references_to(db, finding_ids: list) -> dict:
    """Which of these finding ids are referenced from somewhere else.

    Returns {finding_id: [ "collection.field", ... ]}. Only ids that appear here
    are unsafe to delete.
    """
    if not finding_ids:
        return {}
    found: dict = {}
    for coll, field, is_array in REFERENCE_SITES:
        try:
            q = {field: {"$in": finding_ids}}
            async for doc in db[coll].find(q, {"_id": 0, field: 1}):
                value = doc.get(field)
                hits = value if isinstance(value, list) else [value]
                for h in hits:
                    if h in finding_ids:
                        found.setdefault(h, []).append(f"{coll}.{field}")
        except Exception:
            # A collection that does not exist is not a reference.
            continue
    return found


async def purge_superseded(db, *, dry_run: bool = True, created_after: str = None,
                            only_from_key_migration: bool = True) -> dict:
    """Permanently delete superseded duplicates that nothing points at.

    Folding marks duplicates Superseded rather than deleting them, which is the
    right default -- a finding id can appear in an IR case, a report or a ticket,
    and a dangling reference is worse than a redirect.

    But the rows created by the key-change bug are a specific, bounded population:
    machine-generated hours ago, never triaged, and almost certainly referenced by
    nothing. For those, deletion is honest housekeeping rather than data loss.

    Three guards, all of which must pass per row:
      * it is Superseded AND was superseded by this repair (not by a human)
      * nothing anywhere references its id
      * optionally, it was created after `created_after` -- so a purge can be
        scoped to the one bad sync rather than to all history
    """
    q = {"status": "Superseded"}
    if only_from_key_migration:
        q["superseded_reason"] = {"$regex": "key changed from hostname-based"}
    if created_after:
        q["first_seen_at"] = {"$gte": created_after}

    candidates = await db.findings.find(
        q, {"_id": 0, "id": 1, "cve": 1, "title": 1, "first_seen_at": 1,
            "superseded_by": 1}).to_list(200000)
    ids = [c["id"] for c in candidates]
    referenced = await references_to(db, ids)

    deletable = [c for c in candidates if c["id"] not in referenced]
    kept = [{**c, "referenced_by": referenced[c["id"]]}
            for c in candidates if c["id"] in referenced]

    deleted = 0
    if not dry_run and deletable:
        # Chunked, so one enormous $in does not build a multi-megabyte query.
        batch = [c["id"] for c in deletable]
        for i in range(0, len(batch), 1000):
            res = await db.findings.delete_many({"id": {"$in": batch[i:i + 1000]}})
            deleted += res.deleted_count

    return {
        "dry_run": dry_run,
        "candidates": len(candidates),
        "deletable": len(deletable),
        "deleted": deleted,
        "kept_because_referenced": len(kept),
        "referenced_examples": kept[:10],
        "scope": {"created_after": created_after,
                   "only_from_key_migration": only_from_key_migration},
        "note": ("Nothing was deleted." if dry_run else
                  f"Deleted {deleted} superseded duplicate(s). Rows referenced from a ticket, "
                  "case, exception or report were left in place as tombstones."),
    }


# ---------------------------------------------------------------------------
# Command-line entry point.
#
#     docker compose exec backend python dedupe_repair.py          # dry run
#     docker compose exec backend python dedupe_repair.py --apply  # do it
#
# Runs in-process against the database rather than over HTTP, which removes the
# two things that make a one-off repair annoying at exactly the wrong moment:
# needing an admin token, and needing the API to have finished booting. A repair
# you cannot run because the thing you are repairing is unhealthy is not much of
# a repair.
# ---------------------------------------------------------------------------
def _print_report(result: dict) -> None:
    print()
    print("=" * 72)
    print("DUPLICATE FINDINGS " + ("(DRY RUN — nothing changed)" if result["dry_run"]
                                    else "— CHANGES APPLIED"))
    print("=" * 72)
    print(f"  duplicate groups : {result['duplicate_groups']}")
    print(f"  findings folded  : {result['findings_folded']}")
    print(f"  conflicts        : {result['conflict_count']}")
    print()

    if result["examples"]:
        print("Examples (keeping <- folding):")
        for ex in result["examples"][:10]:
            ident = ex["identity"]
            label = ident[1] if ident[0] == "cve" else f"{ident[1]} check {ident[2]}"
            keep = ex["keeping"]
            print(f"  {label} on asset {ident[-1]}")
            print(f"      keep   {keep['id']}  status={keep['status']}  "
                  f"first_seen={keep['first_seen_at']}")
            for d in ex["folding"]:
                print(f"      fold   {d['id']}  status={d['status']}  "
                      f"first_seen={d['first_seen_at']}")
        print()

    if result["conflicts"]:
        print("NOT MERGED — these carry conflicting human decisions, so a machine")
        print("should not pick which one to discard. Resolve them by hand:")
        for c in result["conflicts"][:10]:
            print(f"  {c['identity']}")
            for f in c["findings"]:
                print(f"      {f['id']}  status={f['status']}")
        print()

    print(result["note"])
    print()


def _print_purge(result: dict) -> None:
    print("=" * 72)
    print("PURGE SUPERSEDED DUPLICATES "
          + ("(DRY RUN — nothing deleted)" if result["dry_run"] else "— DELETED"))
    print("=" * 72)
    scope = result["scope"]
    if scope.get("created_after"):
        print(f"  scoped to findings first seen on/after {scope['created_after']}")
    print(f"  superseded duplicates found : {result['candidates']}")
    print(f"  safe to delete              : {result['deletable']}")
    print(f"  kept (referenced elsewhere) : {result['kept_because_referenced']}")
    if not result["dry_run"]:
        print(f"  actually deleted            : {result['deleted']}")
    print()
    if result["referenced_examples"]:
        print("Kept as tombstones because something still points at them:")
        for r in result["referenced_examples"]:
            print(f"  {r['id']}  {r.get('cve') or r.get('title') or ''}")
            print(f"      referenced by: {', '.join(r['referenced_by'])}")
        print()
    print(result["note"])
    print()


async def _main(apply: bool, include_closed: bool, purge: bool,
                 since: str = None) -> None:
    from db import db

    result = await repair(db, dry_run=not apply, include_closed=include_closed)
    _print_report(result)

    if purge:
        purged = await purge_superseded(db, dry_run=not apply, created_after=since)
        _print_purge(purged)

    if apply:
        try:
            from aggregate_cache import invalidate
            await invalidate(db)
            print("Cached backlog statistics cleared; they will recompute on next view.")
        except Exception as e:
            print(f"(could not clear the aggregate cache: {e})")


if __name__ == "__main__":
    import argparse
    import asyncio

    parser = argparse.ArgumentParser(
        description="Fold, and optionally delete, duplicate findings created by the "
                    "canonical-key change.")
    parser.add_argument("--apply", action="store_true",
                        help="actually make the changes (default is a dry run)")
    parser.add_argument("--include-closed", action="store_true",
                        help="also consider closed findings")
    parser.add_argument("--purge", action="store_true",
                        help="after folding, DELETE the superseded duplicates that nothing "
                             "references. Without this they are kept as tombstones.")
    parser.add_argument("--since", metavar="ISO8601",
                        help="only purge findings first seen on/after this timestamp, e.g. "
                             "2026-08-01T18:00:00Z -- use it to scope the purge to the one bad "
                             "sync rather than to all history")
    args = parser.parse_args()
    asyncio.run(_main(args.apply, args.include_closed, args.purge, args.since))
