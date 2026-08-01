"""One canonical identity per real-world asset, across every source.

THE PROBLEM

Qualys, Nessus, Defender, Intune, Entra, Albert, AWS, nmap and EASM all describe
the same laptop, and every one of them names it differently: Defender sends
`computerDnsName` (an FQDN), Intune sends `deviceName` (usually the short
NetBIOS name), Qualys sends whatever the scan target was, Albert and EASM
frequently have only an IP.

Until now each connector did its own `_hostname_key()` string match against
`assets.hostname`. That has two failure modes, and both are quiet:

  * MISSED MATCHES. Defender's "LAPTOP-7.corp.eaglecounty.us" never equals
    Qualys' "laptop-7", so the EDR data silently never lands. The connector
    reports "devices_matched: 0" and nobody reads it. Every downstream feature
    then reasons about an asset it believes has no EDR.

  * FALSE MATCHES, which are worse. Two different machines legitimately named
    "SERVER1" in two different domains collapse into one record, and now a
    finding from one is attributed to the other. Nothing in the system says so.

Everything in the roadmap above this line -- context panels, correlation rules,
blast radius, attack paths -- is a join. A join over unreliable identity produces
confident, wrong answers, which is strictly worse than no answer.

THE MODEL

Sources contribute IDENTIFIERS. An identifier is (kind, value) -- a serial
number, an Entra device GUID, a MAC, an FQDN, a short hostname, an IP observed at
a time. Identifiers are stored in their own collection, one row per
(asset, kind, value, source), so:

  * matching is a lookup, not a scan across every asset;
  * an asset accumulates identity over time as more sources see it;
  * every merge can name the identifier that caused it;
  * removing a source's claims is possible, which is what makes a merge
    reversible.

KEY STRENGTH IS NOT UNIFORM, and pretending otherwise is the whole bug class.
A hardware serial is globally unique. A short hostname is unique within a domain,
at best. So each kind carries a strength, and:

  * STRONG keys (serial, vendor device GUIDs) merge on their own.
  * MEDIUM keys (MAC, FQDN) merge on their own but are recorded as such.
  * WEAK keys (short hostname, IP) NEVER merge by themselves. They need either a
    corroborating key or an explicit absence of conflict, and they always produce
    a lower-confidence link that the UI can show and a human can reject.

CONFLICT BEATS AGREEMENT. If two records share a weak key but disagree on a
strong one -- same short hostname, different serial -- they are DIFFERENT
MACHINES, and the weak match is discarded. Getting this backwards is how identity
systems silently corrupt themselves.
"""
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

# --------------------------------------------------------------------------
# Identifier kinds, strongest first. Order matters: resolution walks this list
# and takes the first confident answer.
# --------------------------------------------------------------------------
STRONG = "strong"
MEDIUM = "medium"
WEAK = "weak"

IDENTIFIER_KINDS = [
    # (kind, strength, human label)
    ("serial",              STRONG, "hardware serial number"),
    ("aad_device_id",       STRONG, "Entra (Azure AD) device ID"),
    ("defender_device_id",  STRONG, "Defender device ID"),
    ("intune_device_id",    STRONG, "Intune device ID"),
    ("qualys_host_id",      STRONG, "Qualys host ID"),
    ("nessus_uuid",         STRONG, "Nessus agent UUID"),
    ("cloud_instance_id",   STRONG, "cloud instance ID"),
    ("mac",                 MEDIUM, "MAC address"),
    ("fqdn",                MEDIUM, "fully-qualified domain name"),
    ("hostname",            WEAK,   "short hostname"),
    ("ip",                  WEAK,   "IP address"),
]

STRENGTH = {k: s for k, s, _ in IDENTIFIER_KINDS}
KIND_LABEL = {k: label for k, _, label in IDENTIFIER_KINDS}
KIND_ORDER = [k for k, _, _ in IDENTIFIER_KINDS]

# An IP identifies a machine only for as long as the lease holds. Beyond this
# window an IP match is not evidence of anything -- DHCP will have moved it.
IP_MATCH_WINDOW = timedelta(hours=24)

CONFIDENCE_BY_STRENGTH = {STRONG: 1.0, MEDIUM: 0.8, WEAK: 0.5}


def _now():
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now().isoformat()


# --------------------------------------------------------------------------
# Normalization. Every comparison happens on normalized values, so "LAPTOP-7",
# "laptop-7." and "LAPTOP-7.corp.example.com" resolve consistently.
# --------------------------------------------------------------------------
def normalize(kind: str, value) -> Optional[str]:
    """Canonical form of an identifier value, or None if it isn't usable.

    Returning None for junk is deliberate and load-bearing: sources emit
    placeholders ("unknown", "N/A", all-zero MACs, 0.0.0.0) and a placeholder
    that gets stored as a real identifier will merge every asset that shares it
    into one. That is the single most destructive thing this module could do.
    """
    if value is None:
        return None
    v = str(value).strip()
    if not v:
        return None
    low = v.lower()
    if low in {"unknown", "n/a", "na", "none", "null", "-", "not available",
                "to be filled by o.e.m.", "system serial number", "default string",
                "0", "00000000-0000-0000-0000-000000000000"}:
        return None

    if kind == "mac":
        hexes = "".join(c for c in low if c in "0123456789abcdef")
        if len(hexes) != 12 or hexes == "0" * 12:
            return None
        return ":".join(hexes[i:i + 2] for i in range(0, 12, 2))

    if kind == "ip":
        import ipaddress
        try:
            ip = ipaddress.ip_address(v)
        except ValueError:
            return None
        # Loopback/unspecified/link-local identify nothing about WHICH machine.
        if ip.is_loopback or ip.is_unspecified or ip.is_link_local or ip.is_multicast:
            return None
        return str(ip)

    if kind in ("fqdn", "hostname"):
        name = low.rstrip(".")
        # Some sources put an IP in the hostname field; that is an ip, not a name.
        if name.replace(".", "").isdigit():
            return None
        if kind == "hostname":
            name = name.split(".")[0]
            # Only a single character is rejected. It is tempting to require more
            # -- short names collide -- but that trades a rare false match for a
            # guaranteed miss on every legitimately short host ("h1", "dc1",
            # "fw2"), and collisions are already handled properly downstream: an
            # identifier that points at more than one asset is treated as
            # non-identifying, and a strong-key conflict vetoes the match. Length
            # is the wrong tool for a problem the resolver already solves.
            if len(name) < 2:
                return None
        elif "." not in name:
            return None  # not actually qualified
        return name or None

    return low


def identifiers_from(record: dict) -> list:
    """Every identifier a source record offers, normalized and deduped.

    Accepts the shapes the various connectors already produce, so a caller can
    hand over a raw device dict without reshaping it first.
    """
    raw = {
        "serial": record.get("serial") or record.get("serial_number")
                   or record.get("serialNumber") or record.get("chassis_serial"),
        "aad_device_id": record.get("aad_device_id") or record.get("azureADDeviceId"),
        "defender_device_id": record.get("defender_device_id"),
        "intune_device_id": record.get("intune_device_id"),
        "qualys_host_id": record.get("qualys_host_id"),
        "nessus_uuid": record.get("nessus_uuid"),
        "cloud_instance_id": (record.get("cloud_instance_id") or record.get("instance_id")
                               or record.get("InstanceId")),
        "mac": record.get("mac") or record.get("mac_address") or record.get("macAddress")
                or record.get("wiFiMacAddress") or record.get("ethernetMacAddress"),
        "fqdn": record.get("fqdn") or record.get("computerDnsName") or record.get("dns_name"),
        "hostname": (record.get("hostname") or record.get("deviceName")
                      or record.get("computerDnsName") or record.get("name")),
        "ip": record.get("ip") or record.get("ip_address") or record.get("lastIpAddress"),
    }
    out = []
    seen = set()
    for kind in KIND_ORDER:
        value = raw.get(kind)
        # A field can carry several values (multiple MACs, multiple IPs).
        values = value if isinstance(value, (list, tuple, set)) else [value]
        for item in values:
            norm = normalize(kind, item)
            if norm and (kind, norm) not in seen:
                seen.add((kind, norm))
                out.append({"kind": kind, "value": norm, "strength": STRENGTH[kind]})
    return out


# --------------------------------------------------------------------------
# Storage
# --------------------------------------------------------------------------
async def ensure_indexes(db):
    """Identity lookup happens on every ingested record from every connector, so
    it must be an index hit rather than a collection scan."""
    try:
        await db.asset_identifiers.create_index([("kind", 1), ("value", 1)])
        await db.asset_identifiers.create_index([("asset_id", 1)])
        await db.asset_identifiers.create_index([("source", 1)])
    except Exception:
        pass  # mongomock and older servers; correctness doesn't depend on it


async def record_identifiers(db, asset_id: str, identifiers: list, source: str) -> int:
    """Attach identifiers to an asset. Idempotent per (asset, kind, value, source)."""
    written = 0
    for ident in identifiers:
        key = {"asset_id": asset_id, "kind": ident["kind"],
               "value": ident["value"], "source": source}
        existing = await db.asset_identifiers.find_one(key, {"_id": 0, "id": 1})
        if existing:
            await db.asset_identifiers.update_one(key, {"$set": {"last_seen_at": _now_iso()}})
            continue
        await db.asset_identifiers.insert_one({
            **key, "id": str(uuid.uuid4()), "strength": ident["strength"],
            "first_seen_at": _now_iso(), "last_seen_at": _now_iso(),
        })
        written += 1
    return written


# --------------------------------------------------------------------------
# Resolution
# --------------------------------------------------------------------------
async def _assets_for(db, kind: str, value: str, *, within=None) -> list:
    q = {"kind": kind, "value": value}
    rows = await db.asset_identifiers.find(q, {"_id": 0}).to_list(200)
    if within is not None:
        cutoff = (_now() - within).isoformat()
        rows = [r for r in rows if (r.get("last_seen_at") or "") >= cutoff]
    # preserve order, dedupe
    out, seen = [], set()
    for r in rows:
        if r["asset_id"] not in seen:
            seen.add(r["asset_id"])
            out.append(r["asset_id"])
    return out


async def _conflicts(db, asset_id: str, identifiers: list) -> Optional[dict]:
    """Does this candidate asset DISAGREE with the incoming record on a strong key?

    Two records sharing a short hostname but carrying different serial numbers are
    two machines that happen to be named the same -- extremely common with
    imaging conventions like SERVER1/LAPTOP-7. Treating agreement as decisive
    while ignoring disagreement is how identity systems corrupt themselves.
    """
    incoming = {i["kind"]: i["value"] for i in identifiers if i["strength"] == STRONG}
    if not incoming:
        return None
    rows = await db.asset_identifiers.find(
        {"asset_id": asset_id, "kind": {"$in": list(incoming)}}, {"_id": 0}).to_list(200)
    held: dict = {}
    for r in rows:
        held.setdefault(r["kind"], set()).add(r["value"])
    for kind, value in incoming.items():
        known = held.get(kind)
        if known and value not in known:
            return {"kind": kind, "incoming": value, "existing": sorted(known)[0]}
    return None


async def resolve(db, record: dict, *, source: str) -> dict:
    """Which existing asset is this record about?

    Returns {asset_id, confidence, matched_on, reason, conflict, identifiers}.
    `asset_id` is None when nothing matched confidently -- the caller then creates
    a new asset and calls record_identifiers() on it.

    Never guesses silently: `reason` is a sentence naming the identifier that
    decided it, and it is stored on the link so a wrong merge can be understood
    later rather than just discovered.
    """
    identifiers = identifiers_from(record)
    if not identifiers:
        return {"asset_id": None, "confidence": 0.0, "matched_on": None,
                "reason": "The record carried no usable identifier at all.",
                "conflict": None, "identifiers": []}

    weak_candidates: list = []

    for ident in identifiers:
        kind, value, strength = ident["kind"], ident["value"], ident["strength"]
        within = IP_MATCH_WINDOW if kind == "ip" else None
        candidates = await _assets_for(db, kind, value, within=within)
        if not candidates:
            continue

        if len(candidates) > 1:
            # An identifier that points at several assets is not identifying.
            # Usually a placeholder that slipped through normalization, or a
            # genuine duplicate that needs merging -- either way, don't pick one.
            continue

        asset_id = candidates[0]
        conflict = await _conflicts(db, asset_id, identifiers)
        if conflict:
            # Disagreement on a strong key vetoes the match outright.
            continue

        if strength in (STRONG, MEDIUM):
            return {
                "asset_id": asset_id,
                "confidence": CONFIDENCE_BY_STRENGTH[strength],
                "matched_on": {"kind": kind, "value": value},
                "reason": (f"Matched an existing asset on {KIND_LABEL[kind]} "
                            f"'{value}', which is unique to one machine."),
                "conflict": None, "identifiers": identifiers,
            }
        weak_candidates.append((asset_id, kind, value))

    # Weak keys only, so require corroboration: two independent weak keys
    # agreeing on the same asset (e.g. short hostname AND current IP) is
    # meaningfully better than either alone.
    if weak_candidates:
        by_asset: dict = {}
        for asset_id, kind, value in weak_candidates:
            by_asset.setdefault(asset_id, []).append((kind, value))
        best_id, matches = max(by_asset.items(), key=lambda kv: len(kv[1]))
        kinds = ", ".join(f"{KIND_LABEL[k]} '{v}'" for k, v in matches)
        if len(matches) >= 2:
            return {
                "asset_id": best_id, "confidence": 0.75,
                "matched_on": {"kind": matches[0][0], "value": matches[0][1]},
                "reason": (f"No strong identifier was available, but two independent weak ones "
                            f"agree on the same asset: {kinds}."),
                "conflict": None, "identifiers": identifiers,
            }
        kind, value = matches[0]
        return {
            "asset_id": best_id, "confidence": CONFIDENCE_BY_STRENGTH[WEAK],
            "matched_on": {"kind": kind, "value": value},
            "reason": (f"Matched only on {KIND_LABEL[kind]} '{value}'. Short names and IPs are "
                        "not globally unique, so this link is low confidence and worth "
                        "reviewing."),
            "conflict": None, "identifiers": identifiers,
        }

    return {"asset_id": None, "confidence": 0.0, "matched_on": None,
            "reason": ("No existing asset shares any identifier with this record; "
                        "treating it as a new machine."),
            "conflict": None, "identifiers": identifiers}


async def resolve_and_link(db, record: dict, *, source: str,
                            create=None) -> dict:
    """resolve(), then attach the record's identifiers to whatever it resolved to.

    `create` is an async callable invoked only when nothing matched; it must
    return the new asset dict. Keeping creation in the caller means this module
    never has to know each connector's asset schema.
    """
    verdict = await resolve(db, record, source=source)
    asset_id = verdict["asset_id"]
    created = False
    if not asset_id:
        if create is None:
            return {**verdict, "created": False}
        asset = await create()
        asset_id = asset["id"]
        created = True
    await record_identifiers(db, asset_id, verdict["identifiers"], source)
    if not created and verdict["confidence"] < 1.0:
        # Low/medium-confidence links are the ones a human might need to undo, so
        # they leave a durable trail rather than only a log line.
        await db.asset_identity_links.insert_one({
            "id": str(uuid.uuid4()), "asset_id": asset_id, "source": source,
            "confidence": verdict["confidence"], "matched_on": verdict["matched_on"],
            "reason": verdict["reason"], "created_at": _now_iso(), "reviewed": False,
        })
    return {**verdict, "asset_id": asset_id, "created": created}


# --------------------------------------------------------------------------
# Duplicate detection and merging
# --------------------------------------------------------------------------
async def find_duplicate_candidates(db, limit: int = 100) -> list:
    """Assets that share an identifier and are therefore probably one machine.

    This is what surfaces the damage already done by hostname-only matching --
    every asset created twice because two sources spelled its name differently.
    """
    pipeline = [
        {"$group": {"_id": {"kind": "$kind", "value": "$value"},
                     "assets": {"$addToSet": "$asset_id"},
                     "sources": {"$addToSet": "$source"}}},
        {"$match": {"assets.1": {"$exists": True}}},
    ]
    out = []
    async for row in db.asset_identifiers.aggregate(pipeline):
        kind = row["_id"]["kind"]
        out.append({
            "kind": kind, "value": row["_id"]["value"],
            "strength": STRENGTH.get(kind, WEAK),
            "asset_ids": row["assets"], "sources": row["sources"],
            "reason": (f"{len(row['assets'])} assets share the same {KIND_LABEL.get(kind, kind)} "
                        f"'{row['_id']['value']}'"),
        })
    # Strong-key collisions first: those are near-certainly the same machine.
    out.sort(key=lambda d: ({STRONG: 0, MEDIUM: 1, WEAK: 2}[d["strength"]], -len(d["asset_ids"])))
    return out[:limit]


async def merge_assets(db, keep_id: str, absorb_id: str, *, actor: str = "system",
                        reason: str = "") -> dict:
    """Fold `absorb_id` into `keep_id`, recording enough to undo it.

    Findings, identifiers and links are repointed; the absorbed asset is kept as a
    tombstone rather than deleted, because an asset id appears in findings, IR
    cases, reports and audit history, and a dangling reference is worse than a
    redirect.
    """
    keep = await db.assets.find_one({"id": keep_id}, {"_id": 0})
    absorb = await db.assets.find_one({"id": absorb_id}, {"_id": 0})
    if not keep or not absorb:
        raise ValueError("both assets must exist")
    if keep_id == absorb_id:
        raise ValueError("cannot merge an asset into itself")

    # Fill blanks on the survivor from the absorbed record -- a merge should never
    # lose data. Existing values win; this is additive only.
    patch = {}
    for field, value in absorb.items():
        if field in ("id", "_id", "created_at"):
            continue
        if value in (None, "", [], {}, "unknown") :
            continue
        if keep.get(field) in (None, "", [], {}, "unknown"):
            patch[field] = value
    merged_tags = sorted({*(keep.get("tags") or []), *(absorb.get("tags") or [])})
    if merged_tags:
        patch["tags"] = merged_tags

    # Same reasoning as the identifiers: capture WHICH findings move, by id, so
    # undo restores exactly those and not every finding the survivor happens to
    # have accumulated since.
    moved_finding_ids = [f["id"] for f in await db.findings.find(
        {"asset_id": absorb_id}, {"_id": 0, "id": 1}).to_list(20000)]
    finding_count = (await db.findings.update_many(
        {"asset_id": absorb_id}, {"$set": {"asset_id": keep_id}})).modified_count
    # Capture the exact identifier rows being moved BEFORE moving them. Undo used
    # to try to work out afterwards which rows had come from the absorbed asset,
    # which is unanswerable once they all point at the survivor -- so undo quietly
    # restored the asset record while leaving its identity behind, and the pair
    # would not re-appear as duplicates.
    moved_identifier_ids = [r["id"] for r in await db.asset_identifiers.find(
        {"asset_id": absorb_id}, {"_id": 0, "id": 1}).to_list(1000)]
    await db.asset_identifiers.update_many({"asset_id": absorb_id},
                                            {"$set": {"asset_id": keep_id}})
    await db.asset_identity_links.update_many({"asset_id": absorb_id},
                                               {"$set": {"asset_id": keep_id}})
    if patch:
        await db.assets.update_one({"id": keep_id}, {"$set": patch})
    await db.assets.update_one({"id": absorb_id}, {"$set": {
        "status": "merged", "merged_into": keep_id, "merged_at": _now_iso(),
    }})

    record = {
        "id": str(uuid.uuid4()), "keep_id": keep_id, "absorb_id": absorb_id,
        "actor": actor, "reason": reason, "at": _now_iso(),
        "findings_moved": finding_count,
        "moved_identifier_ids": moved_identifier_ids,
        "moved_finding_ids": moved_finding_ids,
        "absorbed_snapshot": absorb,   # the whole record, so undo is exact
        "fields_filled": sorted(patch),
        "undone": False,
    }
    await db.asset_merges.insert_one(dict(record))
    record.pop("absorbed_snapshot", None)
    return record


async def undo_merge(db, merge_id: str, *, actor: str = "system") -> dict:
    """Reverse a merge. Its existence is what makes weak-key matching acceptable:
    an automated join you cannot undo has to be perfect, and nothing is."""
    m = await db.asset_merges.find_one({"id": merge_id}, {"_id": 0})
    if not m:
        raise ValueError("no such merge")
    if m.get("undone"):
        raise ValueError("already undone")
    snapshot = m["absorbed_snapshot"]
    await db.assets.update_one({"id": m["absorb_id"]}, {"$set": {
        **{k: v for k, v in snapshot.items() if k not in ("_id",)},
        "status": snapshot.get("status", "active"),
        "merged_into": None,
    }})
    # Exactly the rows the merge moved, by id.
    await db.asset_identifiers.update_many(
        {"id": {"$in": m.get("moved_identifier_ids") or []}},
        {"$set": {"asset_id": m["absorb_id"]}})
    # Findings go back too -- an undo that restores the asset record but leaves
    # its findings attributed elsewhere is not an undo.
    await db.findings.update_many(
        {"id": {"$in": m.get("moved_finding_ids") or []}},
        {"$set": {"asset_id": m["absorb_id"]}})
    await db.asset_merges.update_one({"id": merge_id}, {"$set": {
        "undone": True, "undone_at": _now_iso(), "undone_by": actor}})
    return {"restored": m["absorb_id"], "from": m["keep_id"]}


# Which connector a pre-existing asset field must have come from. Used by the
# backfill: attributing everything to a generic "backfill" source would make the
# coverage answer ("no Defender identifier => no EDR on this machine") wrong for
# every asset that predates identity resolution -- i.e. all of them.
FIELD_SOURCE = {
    "qualys_host_id": "qualys",
    "defender_device_id": "defender",
    "intune_device_id": "intune",
    "aad_device_id": "entra",
    "nessus_uuid": "nessus",
    "cloud_instance_id": "aws",
}


def attribute_sources(asset: dict) -> dict:
    """Group an existing asset's identifiers by the connector that produced them.

    Returns {source: [identifier, ...]}. Identifiers that no specific connector
    can claim (hostname, ip, mac, serial) are attributed to "backfill", which is
    honest: we know the value, not who told us.
    """
    grouped: dict = {}
    for ident in identifiers_from(asset):
        source = FIELD_SOURCE.get(ident["kind"], "backfill")
        grouped.setdefault(source, []).append(ident)
    # A vendor id proves that vendor has seen this machine, so its generic
    # identifiers (the name it knows the box by) belong to it as well.
    for kind, source in FIELD_SOURCE.items():
        if source in grouped:
            grouped[source].extend(
                i for i in grouped.get("backfill", [])
                if i["kind"] in ("hostname", "fqdn"))
    return grouped


async def _sources_of(db, asset_id: str) -> list:
    rows = await db.asset_identifiers.find({"asset_id": asset_id}, {"_id": 0, "source": 1}).to_list(500)
    return sorted({r["source"] for r in rows})


async def identity_of(db, asset_id: str) -> dict:
    """Everything known about who this asset is, for the UI.

    Shows which systems have seen it -- which doubles as a coverage answer:
    an asset with no Defender identifier has no EDR, and that is a finding in
    itself rather than a gap in the display.
    """
    rows = await db.asset_identifiers.find({"asset_id": asset_id}, {"_id": 0}).to_list(500)
    by_kind: dict = {}
    for r in rows:
        by_kind.setdefault(r["kind"], []).append(r)
    ordered = []
    for kind in KIND_ORDER:
        if kind in by_kind:
            ordered.append({
                "kind": kind, "label": KIND_LABEL[kind], "strength": STRENGTH[kind],
                "values": sorted({r["value"] for r in by_kind[kind]}),
                "sources": sorted({r["source"] for r in by_kind[kind]}),
            })
    links = await db.asset_identity_links.find(
        {"asset_id": asset_id}, {"_id": 0}).sort("created_at", -1).to_list(20)
    return {
        "asset_id": asset_id,
        "identifiers": ordered,
        "sources": sorted({r["source"] for r in rows}),
        "strongest": ordered[0]["strength"] if ordered else None,
        "uncertain_links": [l for l in links if not l.get("reviewed")],
    }
