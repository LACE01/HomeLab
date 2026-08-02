"""Blast radius, point-in-time posture, and what changed.

Three features, one module, because they are the same idea seen from different
angles: the platform should be able to answer questions about RELATIONSHIPS and
about TIME, not only about the present state of one record.

BLAST RADIUS -- "if this is compromised, what else is affected?"
    The question every incident call and every change approval actually turns on,
    and the one no single module can answer. Built by walking the relationships
    that already exist: shared owner team, shared product/service, Entra and
    Intune group membership, attack paths that pass through, security reviews
    that scope it, and the vendor it belongs to.

POINT-IN-TIME POSTURE -- "what did we look like on 3 March?"
    Auditors ask it, post-incident reviews need it, and board decks are built
    from it. Cheap to start now, IMPOSSIBLE to retrofit: you cannot reconstruct
    last quarter's open-finding count once the findings have been closed and
    edited. That asymmetry is the whole argument for doing it early.

CHANGE FEED -- "what changed since yesterday?"
    Falls straight out of snapshots and is the surface that brings people back
    daily. It reports MOVEMENT, not state: newly internet-facing, newly KEV, a
    new attack path, a control that stopped reporting.

A NOTE ON WHAT A SNAPSHOT STORES

Aggregates plus the identity of what was in each bucket -- not full copies of
every document. A snapshot that duplicates the database gets deleted the first
time someone looks at disk usage, which means it is not really a feature. Storing
counts plus id lists keeps a year of daily history small while still supporting
"which findings were open then but not now", which is the question people
actually ask.
"""
import uuid
from datetime import datetime, timezone, timedelta

OPEN_STATUSES = ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]
SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]


def _now():
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now().isoformat()


def _day(dt=None) -> str:
    return (dt or _now()).strftime("%Y-%m-%d")


# ---------------------------------------------------------------------------
# Blast radius
# ---------------------------------------------------------------------------
def _relation(kind: str, label: str, why: str, items: list, link: str = None) -> dict:
    return {"kind": kind, "label": label, "why": why, "count": len(items),
            "items": items[:25], "truncated": len(items) > 25, "link": link}


async def blast_radius(db, asset_id: str) -> dict:
    """What else is affected if this asset is compromised or taken down.

    Relationships are reported SEPARATELY rather than merged into one number,
    because they mean different things: sharing an owner team is an operational
    relationship, sitting on the same attack path is a security one, and running
    the same service is a availability one. Collapsing them would produce a
    "blast radius: 47" that nobody could act on.
    """
    asset = await db.assets.find_one({"id": asset_id}, {"_id": 0})
    if not asset:
        return None

    relations = []

    if asset.get("product_id"):
        peers = await db.assets.find(
            {"product_id": asset["product_id"], "id": {"$ne": asset_id},
             "status": {"$ne": "merged"}},
            {"_id": 0, "id": 1, "hostname": 1, "criticality": 1}).to_list(500)
        if peers:
            relations.append(_relation(
                "service", f"Runs the same service ({asset.get('product_name')})",
                "These hosts deliver the same service, so losing this one degrades it for all of "
                "them, and an attacker who understands one probably understands the rest.",
                peers, link=f"/products/{asset['product_id']}"))

    if asset.get("owner_team") and asset["owner_team"] != "Unassigned":
        team_assets = await db.assets.find(
            {"owner_team": asset["owner_team"], "id": {"$ne": asset_id},
             "status": {"$ne": "merged"}},
            {"_id": 0, "id": 1, "hostname": 1}).to_list(500)
        if team_assets:
            relations.append(_relation(
                "ownership", f"Owned by {asset['owner_team']}",
                "Same team, so probably the same build process, the same credentials and the same "
                "misconfiguration if there is one.",
                team_assets, link=f"/assets?team={asset['owner_team']}"))

    paths = await db.attack_paths.find(
        {"status": {"$ne": "resolved"}, "node_asset_ids": asset_id}, {"_id": 0}).to_list(50)
    downstream = []
    for p in paths:
        nodes = p.get("node_asset_ids") or []
        if asset_id in nodes:
            after = nodes[nodes.index(asset_id) + 1:]
            for nid in after:
                downstream.append({"id": nid, "via_path": p.get("id"),
                                    "target_label": p.get("target_label")})
    if downstream:
        relations.append(_relation(
            "attack_path", "Reachable from here along a known attack path",
            "These are not merely related — an attacker standing on this asset has a demonstrated "
            "route to them.", downstream, link="/attack-paths"))

    reviews = await db.security_reviews.find(
        {"linked_asset_ids": asset_id},
        {"_id": 0, "id": 1, "title": 1, "review_number": 1, "decision": 1}).to_list(20)
    if reviews:
        relations.append(_relation(
            "governance", "In scope of security reviews",
            "A decision was made about this asset. Changing it may invalidate that decision.",
            reviews, link="/security-reviews"))

    users = await db.directory_users.find(
        {"primary_device_id": asset.get("intune_device_id")},
        {"_id": 0, "id": 1, "display_name": 1, "user_principal_name": 1,
         "is_privileged": 1}).to_list(50) if asset.get("intune_device_id") else []
    if users:
        relations.append(_relation(
            "identity", "People whose primary device this is",
            "Compromising the machine reaches these accounts' live sessions and tokens.",
            users, link="/directory"))

    risks = await db.risk_register.find(
        {"linked_asset_ids": asset_id, "status": {"$ne": "closed"}},
        {"_id": 0, "id": 1, "title": 1, "owner": 1}).to_list(20)
    if risks:
        relations.append(_relation(
            "risk", "Tracked risks referencing this asset",
            "Accepted risk positions that assume this asset behaves as it does today.",
            risks, link="/risk-register"))

    total = sum(r["count"] for r in relations)
    privileged = any(u.get("is_privileged") for u in users)
    return {
        "asset": {"id": asset_id, "hostname": asset.get("hostname"),
                   "criticality": asset.get("criticality")},
        "relations": relations,
        "related_total": total,
        "summary": (
            f"{asset.get('hostname')} is connected to {total} other things across "
            f"{len(relations)} kinds of relationship."
            + (" It is a privileged user's primary device, which makes it an identity risk as well "
               "as an availability one." if privileged else "")
            + (" It sits upstream on a known attack path, so compromise here is not contained to "
               "this host." if downstream else "")
            if relations else
            f"{asset.get('hostname')} has no recorded relationships to other assets, services, "
            "people or reviews. That may be true, or it may mean ownership and service mapping "
            "were never filled in — worth confirming before treating it as isolated."),
    }


# ---------------------------------------------------------------------------
# Snapshots
# ---------------------------------------------------------------------------
async def take_snapshot(db, *, day: str = None) -> dict:
    """Record today's posture. Idempotent per day.

    Stores aggregates plus the ids in each bucket, not copies of the documents.
    A snapshot that duplicates the database gets deleted the first time anyone
    looks at disk usage -- and then it was never a feature at all.
    """
    day = day or _day()

    # Explicit limits rather than an unbounded cursor: this runs inside the API
    # process, and reading a whole collection that only ever grows is a memory
    # spike waiting for the estate to get big enough.
    open_findings = await db.findings.find(
        {"status": {"$in": OPEN_STATUSES}},
        {"_id": 0, "id": 1, "severity": 1, "kev_flag": 1, "asset_id": 1,
         "internet_facing": 1, "due_at": 1}).to_list(200000)

    by_sev = {s: 0 for s in SEVERITIES}
    for f in open_findings:
        if f.get("severity") in by_sev:
            by_sev[f["severity"]] += 1

    assets = await db.assets.find(
        {"status": {"$nin": ["merged", "decommissioned"]}},
        {"_id": 0, "id": 1, "internet_facing": 1, "exposure": 1}).to_list(100000)
    internet_facing = [a["id"] for a in assets
                        if a.get("internet_facing") or a.get("exposure") in ("internet", "external")]

    kev_ids = [f["id"] for f in open_findings if f.get("kev_flag")]
    overdue = [f["id"] for f in open_findings
               if f.get("due_at") and f["due_at"] < _now_iso()]

    paths = await db.attack_paths.find({"status": {"$ne": "resolved"}},
                                        {"_id": 0, "id": 1}).to_list(50000)
    hits = await db.correlation_hits.find({"status": "open"}, {"_id": 0, "id": 1}).to_list(50000)

    doc = {
        "id": str(uuid.uuid4()),
        "day": day,
        "taken_at": _now_iso(),
        "counts": {
            "open_findings": len(open_findings),
            "by_severity": by_sev,
            "kev": len(kev_ids),
            "overdue": len(overdue),
            "assets": len(assets),
            "internet_facing_assets": len(internet_facing),
            "attack_paths": len(paths),
            "correlation_hits": len(hits),
        },
        # Ids, so "open then but not now" is answerable without keeping documents.
        "ids": {
            "open_findings": [f["id"] for f in open_findings],
            "kev": kev_ids,
            "internet_facing_assets": internet_facing,
            "attack_paths": [p["id"] for p in paths],
            "correlation_hits": [h["id"] for h in hits],
        },
    }
    await db.posture_snapshots.replace_one({"day": day}, doc, upsert=True)
    return {k: v for k, v in doc.items() if k != "ids"}


async def snapshot_for(db, day: str) -> dict:
    """The snapshot for a day, or the most recent one before it.

    Falling back to the nearest earlier snapshot matters: someone asking for a
    specific date does not want an empty answer because the platform was down
    that night.
    """
    exact = await db.posture_snapshots.find_one({"day": day}, {"_id": 0})
    if exact:
        return {**exact, "exact": True}
    rows = await db.posture_snapshots.find(
        {"day": {"$lt": day}}, {"_id": 0}).sort("day", -1).to_list(1)
    if not rows:
        return None
    return {**rows[0], "exact": False,
            "note": f"No snapshot for {day}; showing the closest earlier one ({rows[0]['day']})."}


# ---------------------------------------------------------------------------
# Change feed
# ---------------------------------------------------------------------------
def _delta(label: str, before: int, after: int, *, good_direction: str = "down") -> dict:
    change = after - before
    if change == 0:
        direction = "flat"
    elif (change < 0 and good_direction == "down") or (change > 0 and good_direction == "up"):
        direction = "improved"
    else:
        direction = "worsened"
    return {"label": label, "before": before, "after": after,
            "change": change, "direction": direction}


async def changes_between(db, day_from: str, day_to: str = None) -> dict:
    """What moved between two snapshots.

    Reports MOVEMENT, not state. A dashboard shows what is true; this shows what
    became true, which is the thing worth a person's attention each morning.
    """
    day_to = day_to or _day()
    before = await snapshot_for(db, day_from)
    after = await db.posture_snapshots.find_one({"day": day_to}, {"_id": 0})
    if not after:
        after = await take_snapshot(db, day=day_to)
        after = await db.posture_snapshots.find_one({"day": day_to}, {"_id": 0})
    if not before:
        return {"available": False,
                "note": (f"No snapshot on or before {day_from} to compare against. Change "
                          "tracking starts from the first snapshot taken.")}

    bc, ac = before["counts"], after["counts"]
    deltas = [
        _delta("Open findings", bc["open_findings"], ac["open_findings"]),
        _delta("Critical", bc["by_severity"]["Critical"], ac["by_severity"]["Critical"]),
        _delta("High", bc["by_severity"]["High"], ac["by_severity"]["High"]),
        _delta("Known-exploited (KEV)", bc["kev"], ac["kev"]),
        _delta("Overdue", bc["overdue"], ac["overdue"]),
        _delta("Internet-facing assets", bc["internet_facing_assets"],
               ac["internet_facing_assets"]),
        _delta("Attack paths", bc["attack_paths"], ac["attack_paths"]),
        _delta("Correlation hits", bc["correlation_hits"], ac["correlation_hits"]),
    ]

    b_ids, a_ids = before.get("ids", {}), after.get("ids", {})

    def added(key):
        return sorted(set(a_ids.get(key) or []) - set(b_ids.get(key) or []))

    def removed(key):
        return sorted(set(b_ids.get(key) or []) - set(a_ids.get(key) or []))

    new_kev = added("kev")
    new_exposed = added("internet_facing_assets")
    new_paths = added("attack_paths")

    events = []
    if new_kev:
        docs = await db.findings.find({"id": {"$in": new_kev[:20]}},
                                       {"_id": 0, "id": 1, "cve": 1, "title": 1,
                                        "asset_hostname": 1}).to_list(20)
        events.append({
            "kind": "newly_kev", "severity": "high", "count": len(new_kev),
            "headline": f"{len(new_kev)} finding(s) became known-exploited.",
            "detail": ("CISA added the underlying CVE to the KEV catalogue, or a scan found it "
                        "here for the first time. These moved from theoretical to confirmed."),
            "items": docs})
    if new_exposed:
        docs = await db.assets.find({"id": {"$in": new_exposed[:20]}},
                                     {"_id": 0, "id": 1, "hostname": 1, "ip": 1}).to_list(20)
        events.append({
            "kind": "newly_internet_facing", "severity": "high", "count": len(new_exposed),
            "headline": f"{len(new_exposed)} asset(s) became internet-facing.",
            "detail": ("Either genuinely newly exposed, or discovered by external scanning for the "
                        "first time. Both are worth a look on the day it happens rather than at "
                        "the next review."),
            "items": docs})
    if new_paths:
        docs = await db.attack_paths.find({"id": {"$in": new_paths[:20]}},
                                           {"_id": 0, "id": 1, "target_label": 1,
                                            "score": 1}).to_list(20)
        events.append({
            "kind": "new_attack_path", "severity": "high", "count": len(new_paths),
            "headline": f"{len(new_paths)} new attack path(s) to a crown jewel.",
            "detail": "A route that did not exist at the last snapshot now does.",
            "items": docs})

    closed = removed("open_findings")
    if closed:
        events.append({
            "kind": "closed", "severity": "info", "count": len(closed),
            "headline": f"{len(closed)} finding(s) closed.",
            "detail": "Remediated, accepted, or superseded since the comparison point.",
            "items": []})

    return {
        "available": True,
        "from": before["day"], "to": after["day"],
        "exact_from": before.get("exact", True),
        "deltas": deltas,
        "events": sorted(events, key=lambda e: {"high": 0, "info": 1}.get(e["severity"], 2)),
        "summary": _summarize(deltas, events),
    }


def _summarize(deltas, events) -> str:
    worse = [d for d in deltas if d["direction"] == "worsened"]
    better = [d for d in deltas if d["direction"] == "improved"]
    urgent = [e for e in events if e["severity"] == "high"]
    if not worse and not urgent:
        return ("Nothing got worse in this period"
                 + (f", and {', '.join(d['label'].lower() for d in better[:3])} improved."
                    if better else "."))
    parts = []
    if urgent:
        parts.append(" ".join(e["headline"] for e in urgent[:3]))
    if worse:
        parts.append("Up: " + ", ".join(
            f"{d['label'].lower()} {d['before']}→{d['after']}" for d in worse[:4]) + ".")
    if better:
        parts.append("Down: " + ", ".join(
            f"{d['label'].lower()} {d['before']}→{d['after']}" for d in better[:3]) + ".")
    return " ".join(parts)
