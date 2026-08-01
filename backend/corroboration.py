"""Multiple scanners finding the same thing is CORROBORATION, not duplication.

WHAT WAS ACTUALLY HAPPENING

Both scanners keyed findings the same way:

    qualys_sync.py:   canonical = f"{cve or qid}::{asset['hostname']}"
    tenable_sync.py:  canonical = f"{primary_cve or plugin}::{asset['hostname']}"

That produces two different failures depending on nothing more than how the two
tools spell the host:

  * SAME hostname string -> the keys collide, the second sync finds the first
    one's document and updates it, overwriting source_tool. The finding now
    claims to come from whichever scanner ran last, and the fact that two
    independent tools confirmed it is destroyed.
  * DIFFERENT hostname strings ("web-1" vs "web-1.corp.local") -> no collision,
    two findings, backlog inflated, and remediation counted twice.

Neither is a display problem. Both are the same root cause: the key is built from
a NAME rather than from the identity the name refers to.

THE MODEL

A finding is keyed on (what is wrong, which resolved asset) -- `asset_id` from
entity_resolution, never a hostname string. Each tool that reports it appends to
a `sources[]` array carrying its own native id, its own severity, and when it
last saw it. Nothing overwrites anything.

That turns a liability into a signal:

  * CORROBORATED (2+ tools): high confidence this is real. Worth fixing first,
    and worth telling the person fixing it that it isn't one scanner's opinion.
  * SINGLE SOURCE: ambiguous, and the ambiguity is resolvable. If the other
    scanners cover this asset and did not report it, that is evidence toward a
    false positive. If they have never scanned this asset at all, it is a
    COVERAGE GAP -- a finding about your tooling, not about the host.

The second case is the one nobody usually gets to make, because it needs to know
which tools cover which asset, which needs identity to be solved first. It is the
concrete payoff of Tier 0.

SEVERITY DISAGREEMENT IS KEPT, NOT AVERAGED. When Qualys says High and Nessus
says Medium, the finding carries the higher rating and records that they
disagree. Averaging would invent a number no tool actually asserted; hiding it
would lose a real signal about scanner tuning.
"""
from datetime import datetime, timezone
from typing import Optional

SEVERITY_ORDER = ["Info", "Low", "Medium", "High", "Critical"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

# Tools that perform host vulnerability assessment, and therefore whose SILENCE
# about a given host is meaningful. A tool that doesn't do host VA (an IDS, a
# secrets scanner) not reporting a CVE says nothing at all, so it must never
# count as a dissenting vote.
VA_TOOLS = {"Qualys VMDR", "Tenable Nessus", "Microsoft Defender for Endpoint"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_key(*, asset_id: str, cve: Optional[str] = None,
                   native_id: Optional[str] = None, tool: Optional[str] = None) -> str:
    """The identity of a FINDING: what is wrong, and on which resolved asset.

    Keyed on asset_id, never hostname -- that is the entire fix. When there is no
    CVE the key falls back to the tool's own id, which is correct: two scanners'
    proprietary check ids are not claims about the same thing, so they should not
    be merged just because they landed on the same host.
    """
    if cve:
        return f"{cve.upper()}::{asset_id}"
    return f"{(tool or 'unknown').lower().replace(' ', '-')}:{native_id}::{asset_id}"


def make_source(*, tool: str, native_id: Optional[str], severity: Optional[str],
                 title: Optional[str] = None, first_seen: Optional[str] = None,
                 evidence: Optional[str] = None) -> dict:
    return {
        "tool": tool,
        "native_id": str(native_id) if native_id is not None else None,
        "severity": severity,
        "title": title,
        "evidence": evidence,
        "first_seen": first_seen or _now_iso(),
        "last_seen": _now_iso(),
    }


def merge_source(sources: list, new: dict) -> list:
    """Add or refresh one tool's report. Never destructive.

    Re-reporting updates last_seen and the tool's own severity (scanners do
    re-rate) but preserves first_seen, which is what SLA clocks are measured
    from and must not silently reset every sync.
    """
    out = list(sources or [])
    for i, existing in enumerate(out):
        if existing.get("tool") == new["tool"] and \
                (existing.get("native_id") == new.get("native_id") or new.get("native_id") is None):
            out[i] = {**existing, **{k: v for k, v in new.items() if v is not None},
                      "first_seen": existing.get("first_seen") or new.get("first_seen")}
            return out
    out.append(new)
    return out


def reconcile_severity(sources: list) -> dict:
    """The finding's severity, and whether the tools actually agree.

    Takes the HIGHEST rating any tool gave. Averaging would produce a severity no
    scanner asserted, and rounding down would mean a tool that saw something
    worse got quietly overruled.
    """
    rated = [s for s in (sources or []) if s.get("severity") in SEVERITY_RANK]
    if not rated:
        return {"severity": None, "agreement": "unknown", "disagreement": None}
    ranks = {s["tool"]: SEVERITY_RANK[s["severity"]] for s in rated}
    best_tool = max(ranks, key=ranks.get)
    severity = SEVERITY_ORDER[ranks[best_tool]]
    if len(set(ranks.values())) == 1:
        return {"severity": severity,
                "agreement": "unanimous" if len(rated) > 1 else "single",
                "disagreement": None}
    low_tool = min(ranks, key=ranks.get)
    return {
        "severity": severity,
        "agreement": "disputed",
        "disagreement": (f"{best_tool} rates this {severity}, {low_tool} rates it "
                          f"{SEVERITY_ORDER[ranks[low_tool]]}. The higher rating is used; the "
                          "disagreement is usually a difference in scanner tuning and is worth "
                          "checking if it recurs."),
    }


def assess(finding: dict, *, tools_covering_asset: Optional[set] = None) -> dict:
    """Corroboration verdict for one finding.

    `tools_covering_asset` is the set of VA tools that have ever scanned this
    asset -- from entity_resolution's identifier sources. It is what separates
    "the other scanners looked and disagreed" from "no other scanner has ever
    looked", which are opposite conclusions from identical-looking data.
    """
    sources = finding.get("sources") or []
    tools = [s.get("tool") for s in sources if s.get("tool")]
    count = len(set(tools))
    sev = reconcile_severity(sources)

    if count >= 2:
        return {
            "status": "corroborated", "source_count": count, "tools": sorted(set(tools)),
            **sev,
            "confidence": "high",
            "note": (f"Independently confirmed by {count} tools ({', '.join(sorted(set(tools)))}). "
                      "Two scanners agreeing is strong evidence this is real, not a false positive."),
        }

    if count == 1:
        tool = tools[0]
        covering = set(tools_covering_asset or set())
        others = (covering & VA_TOOLS) - {tool}
        if others:
            return {
                "status": "single_source_disputed", "source_count": 1, "tools": [tool], **sev,
                "confidence": "low",
                "note": (f"Only {tool} reports this. {', '.join(sorted(others))} also scan this "
                          "asset and did not report it, which is weak evidence toward a false "
                          "positive — worth a look before spending remediation effort."),
            }
        return {
            "status": "single_source_uncorroborated", "source_count": 1, "tools": [tool], **sev,
            "confidence": "medium",
            "note": (f"Only {tool} reports this, and no other vulnerability scanner covers this "
                      "asset — so there is nothing to corroborate it against. This is a COVERAGE "
                      "GAP in the tooling, not evidence either way about the finding."),
        }

    return {"status": "unattributed", "source_count": 0, "tools": [], **sev,
            "confidence": "unknown",
            "note": "No source tool recorded for this finding."}


async def tools_covering(db, asset_id: str) -> set:
    """Which VA tools have ever seen this asset, via its identifiers.

    Reads entity_resolution's identifier sources, which is the only place that
    knows this -- and only knows it because identity was solved first.
    """
    rows = await db.asset_identifiers.find(
        {"asset_id": asset_id}, {"_id": 0, "source": 1}).to_list(500)
    source_to_tool = {
        "qualys": "Qualys VMDR",
        "nessus": "Tenable Nessus",
        "defender": "Microsoft Defender for Endpoint",
    }
    return {source_to_tool[r["source"]] for r in rows if r.get("source") in source_to_tool}


async def upsert_corroborated(db, *, asset_id: str, cve: Optional[str],
                               native_id: Optional[str], tool: str,
                               severity: Optional[str], base: dict) -> dict:
    """Create the finding, or add this tool's report to the existing one.

    This is what each scanner's sync calls instead of building its own
    canonical_key and blindly overwriting whatever it finds there.
    """
    key = canonical_key(asset_id=asset_id, cve=cve, native_id=native_id, tool=tool)
    existing = await db.findings.find_one({"canonical_key": key}, {"_id": 0})
    source = make_source(tool=tool, native_id=native_id, severity=severity,
                          title=base.get("title"))

    if existing:
        sources = merge_source(existing.get("sources") or [], source)
        sev = reconcile_severity(sources)
        patch = {"sources": sources, "source_count": len({s["tool"] for s in sources}),
                 "last_seen_at": _now_iso()}
        if sev["severity"]:
            patch["severity"] = sev["severity"]
            patch["severity_agreement"] = sev["agreement"]
            patch["severity_disagreement"] = sev["disagreement"]
        # Fill blanks only. A second scanner should enrich a finding, never
        # rewrite a description or remediation a human may have edited.
        for field, value in base.items():
            if field in ("severity", "sources", "canonical_key", "id"):
                continue
            if value not in (None, "", [], {}) and existing.get(field) in (None, "", [], {}):
                patch[field] = value
        await db.findings.update_one({"canonical_key": key}, {"$set": patch})
        return {**existing, **patch, "outcome": "corroborated"}

    import uuid
    sev = reconcile_severity([source])
    doc = {
        **base,
        "id": base.get("id") or str(uuid.uuid4()),
        "canonical_key": key,
        "asset_id": asset_id,
        "cve": cve,
        "sources": [source],
        "source_count": 1,
        "severity": sev["severity"] or severity,
        "severity_agreement": sev["agreement"],
        "severity_disagreement": None,
        "first_seen_at": base.get("first_seen_at") or _now_iso(),
        "last_seen_at": _now_iso(),
    }
    await db.findings.insert_one(dict(doc))
    return {**doc, "outcome": "created"}


async def backfill_existing(db, *, dry_run: bool = True) -> dict:
    """Fold findings that are already duplicated into corroborated ones.

    Existing documents were keyed on hostname, so the same CVE on the same
    machine can exist several times over. Groups them by (cve, resolved asset),
    keeps the oldest (its first_seen drives SLA), and folds the rest in as
    additional sources.

    Defaults to a dry run: this rewrites the backlog, and being able to see what
    it WOULD do before it does it is the difference between a migration and an
    accident.
    """
    cursor = db.findings.find(
        {"cve": {"$ne": None}, "status": {"$nin": ["Fixed validated", "Closed"]}},
        {"_id": 0}).sort("first_seen_at", 1)
    groups: dict = {}
    async for f in cursor:
        if not f.get("asset_id") or not f.get("cve"):
            continue
        groups.setdefault((f["cve"].upper(), f["asset_id"]), []).append(f)

    merged, examples = 0, []
    for (cve, asset_id), findings in groups.items():
        if len(findings) < 2:
            continue
        primary, rest = findings[0], findings[1:]
        sources = primary.get("sources") or []
        if not sources and primary.get("source_tool"):
            sources = [make_source(tool=primary["source_tool"],
                                    native_id=primary.get("source_native_id"),
                                    severity=primary.get("severity"),
                                    first_seen=primary.get("first_seen_at"))]
        for dup in rest:
            sources = merge_source(sources, make_source(
                tool=dup.get("source_tool") or "unknown",
                native_id=dup.get("source_native_id"),
                severity=dup.get("severity"),
                first_seen=dup.get("first_seen_at")))
        sev = reconcile_severity(sources)
        if len(examples) < 10:
            examples.append({"cve": cve, "asset_id": asset_id,
                              "kept": primary["id"], "folded": [d["id"] for d in rest],
                              "tools": sorted({s["tool"] for s in sources})})
        merged += len(rest)
        if dry_run:
            continue
        await db.findings.update_one({"id": primary["id"]}, {"$set": {
            "canonical_key": canonical_key(asset_id=asset_id, cve=cve),
            "sources": sources,
            "source_count": len({s["tool"] for s in sources}),
            "severity": sev["severity"] or primary.get("severity"),
            "severity_agreement": sev["agreement"],
            "severity_disagreement": sev["disagreement"],
        }})
        for dup in rest:
            # Superseded, not deleted: the id may be referenced by an IR case, a
            # report, a ticket or the audit trail, and a dangling reference is
            # worse than a redirect.
            await db.findings.update_one({"id": dup["id"]}, {"$set": {
                "status": "Superseded", "superseded_by": primary["id"],
                "superseded_at": _now_iso(),
                "superseded_reason": (f"Folded into {primary['id']}: the same CVE on the same "
                                       "machine, reported separately because the scanners spelled "
                                       "the hostname differently."),
            }})

    return {
        "dry_run": dry_run,
        "duplicate_groups": len([g for g in groups.values() if len(g) > 1]),
        "findings_folded": merged,
        "examples": examples,
        "note": ("Nothing was changed." if dry_run else
                  "Folded findings are marked Superseded with a pointer, not deleted."),
    }
