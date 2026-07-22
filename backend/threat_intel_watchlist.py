"""Threat intel watchlist -- a persistent, growing list of known-bad IOCs (IPs,
domains, hashes, malicious packages) that gets checked automatically against new
assets/findings/files/dependencies, instead of the existing recon-ng threat-intel
modules which only check one target at a time when someone remembers to run them.

Four ways IOCs land here: manually added/pasted by an analyst (source="manual"),
pulled in bulk from abuse.ch's ThreatFox feed on a schedule
(source="abuse.ch_threatfox_feed", via sync_threatfox_feed below), pulled in
bulk from OpenSourceMalware.com's feed of verified malicious open-source packages
(source="opensourcemalware_feed", via sync_opensourcemalware_feed below), pulled
in bulk from our own OpenCTI instance's recent Indicators
(source="opencti_feed", via sync_opencti_feed below), or pulled in bulk from
AlienVault OTX's subscribed pulses (source="otx_feed", via sync_otx_feed below).
All four bulk syncs reuse the same generic Integrations catalog config
(endpoint + API key, + OpenCTI's optional CF-Access service token) the existing
on-demand recon-ng lookup modules already use, rather than inventing a second
credential store for the same accounts -- see reconng.py's run_opencti_lookup/
run_otx_lookup/run_abusech_lookup for the per-target lookup versions of these
same connectors (those check one value on demand from Finding Detail/Vendor
Detail; the sync_*_feed functions below instead pull each source's own recent-
indicators list in bulk so the watchlist has known-bad values BEFORE anything
in this environment happens to match one, not just after).

Every IOC doc carries an optional `detail` dict alongside the human-readable
`notes` string -- the raw, source-specific fields (malware family, STIX pattern,
OTX pulse name/references, confidence score, tags, etc.) that explain WHY a
value is considered malicious. `notes` stays a short one-line summary for the
table view; `detail` is what the click-to-expand IOC Detail modal on the
frontend renders in full. Manually-added IOCs have detail=None -- there's
nothing to show beyond whatever the analyst typed into notes.

match_ioc() is the one function other modules call to check a value against this
list -- see its call sites in qualys_sync.py (new asset IP), yara_scan.py (file
hash), and sbom.py (dependency package name) for the pattern to copy when wiring
up a new one. Every match_ioc() hit also gets recorded as a security_event (via
check_and_emit) with raw={"watchlist_id": ..., "matched_value": ...} -- that's
what lets the IOC Detail modal's "Recent matches" panel look up exactly which
assets/files/packages tripped a given watchlist entry and when.
"""
import re
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

IOC_TYPES = ["ip", "domain", "hash", "url", "package"]

# ThreatFox's own ioc_type values, normalized down to our buckets.
_THREATFOX_TYPE_MAP = {
    "ip:port": "ip", "ip": "ip", "domain": "domain", "url": "url",
    "md5_hash": "hash", "sha1_hash": "hash", "sha256_hash": "hash",
}

# OpenSourceMalware.com ecosystem query-param values covered by the default bulk
# sync. "domains"/"repositories"/"vscode"/"openvsx" are supported by their API
# but deliberately left out of the default poll list -- this app doesn't have a
# natural place to check a repo URL or VS Code extension against yet, and their
# response shape for those categories isn't documented the same way packages are.
# Pass an explicit `ecosystems` list to sync_opensourcemalware_feed to cover more.
OSM_DEFAULT_ECOSYSTEMS = ["npm", "pypi", "crates", "nuget", "maven", "go", "packagist", "rubygems"]

# Maps this app's own SBOM ecosystem labels (see sbom.py's ECOSYSTEM_MAP) to
# OpenSourceMalware's query-param ecosystem keys, so a scanned dependency's
# (ecosystem, name) can be turned into the same watchlist value format the feed
# sync uses. Ecosystems OSM doesn't cover (Hex, Pub, Debian, Alpine) map to None.
SBOM_TO_OSM_ECOSYSTEM = {
    "npm": "npm", "PyPI": "pypi", "Maven": "maven", "Go": "go", "crates.io": "crates",
    "NuGet": "nuget", "RubyGems": "rubygems", "Packagist": "packagist",
    "Hex": None, "Pub": None, "Debian": None, "Alpine": None,
}

_OSM_SEVERITY_MAP = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}

# STIX 2.1 "main_observable_type"/pattern object-path prefixes -> our ioc_type
# buckets, used to interpret OpenCTI indicator patterns like
# "[ipv4-addr:value = '1.2.3.4']" or "[file:hashes.'SHA-256' = 'abc...']".
_STIX_TYPE_MAP = {
    "ipv4-addr": "ip", "ipv6-addr": "ip", "domain-name": "domain",
    "url": "url", "file": "hash",
}
# Matches the first `<object-path> = '<value>'` (or `!=`, but we only care about
# equality patterns -- OpenCTI's simple indicators are always this shape) term
# inside a STIX pattern, capturing the object-path prefix and the quoted value.
_STIX_PATTERN_RE = re.compile(r"\[?\s*([a-zA-Z0-9\-]+):[\w'.\-]+\s*=\s*'([^']+)'")

# OTX indicator "type" values -> our ioc_type buckets. Anything not listed here
# (CIDR, CVE, YARA, Mutex, FilePath, ...) isn't a value we can usefully match
# against an asset IP/file hash/package name, so it's skipped.
_OTX_TYPE_MAP = {
    "IPv4": "ip", "IPv6": "ip", "domain": "domain", "hostname": "domain",
    "URL": "url", "URI": "url",
    "FileHash-MD5": "hash", "FileHash-SHA1": "hash", "FileHash-SHA256": "hash",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize(value: str) -> str:
    # "1.2.3.4:8080" (ThreatFox's ip:port shape) -> just the IP, since that's what
    # we'll actually be comparing asset/finding IPs against.
    v = (value or "").strip().lower()
    if v.count(":") == 1 and v.split(":")[0].replace(".", "").isdigit():
        v = v.split(":")[0]
    return v


def _parse_stix_pattern(pattern: str) -> tuple:
    """Best-effort extraction of (ioc_type, value) from a simple STIX indicator
    pattern. Returns (None, None) for patterns we don't recognize (compound
    AND/OR patterns, object types we don't track, hash algorithms we don't
    bucket, etc.) -- OpenCTI indicators that don't reduce to one of our IOC
    types are skipped by the caller rather than guessed at."""
    if not pattern:
        return None, None
    m = _STIX_PATTERN_RE.search(pattern)
    if not m:
        return None, None
    stix_type, value = m.group(1), m.group(2)
    ioc_type = _STIX_TYPE_MAP.get(stix_type)
    if not ioc_type:
        return None, None
    return ioc_type, value


async def add_ioc(db, *, ioc_type: str, value: str, source: str = "manual", severity: str = "High",
                   notes: Optional[str] = None, added_by: Optional[str] = None,
                   detail: Optional[dict] = None) -> dict:
    from routes.common import _clean
    value_norm = _normalize(value)
    existing = await db.ioc_watchlist.find_one({"value": value_norm}, {"_id": 0})
    if existing:
        return existing
    doc = {
        "id": str(uuid.uuid4()), "ioc_type": ioc_type, "value": value_norm, "source": source,
        "severity": severity, "notes": notes, "detail": detail, "added_by": added_by, "added_at": _now_iso(),
        "hits": 0, "last_hit_at": None,
    }
    await db.ioc_watchlist.insert_one(doc)
    return _clean(doc)


async def match_ioc(db, value: str) -> Optional[dict]:
    """Exact, case-insensitive match. Bumps hit count/last_hit_at on the watchlist
    entry itself so 'how often has this actually been seen' is visible from the
    watchlist page, not just from the security_events it generates."""
    if not value:
        return None
    value_norm = _normalize(value)
    doc = await db.ioc_watchlist.find_one({"value": value_norm}, {"_id": 0})
    if not doc:
        return None
    await db.ioc_watchlist.update_one({"value": value_norm}, {"$set": {"last_hit_at": _now_iso()}, "$inc": {"hits": 1}})
    doc["hits"] = doc.get("hits", 0) + 1
    return doc


async def check_and_emit(db, value: str, *, entity_type: str, entity_id: str, entity_label: str) -> Optional[dict]:
    """Convenience wrapper: match_ioc() + emit_event() together, since every call
    site wants both. Returns the matched watchlist doc, or None."""
    match = await match_ioc(db, value)
    if not match:
        return None
    from security_events import emit_event
    await emit_event(
        db, source="threat_intel", event_type="ioc_match", severity=match.get("severity", "High"),
        title=f"Known-bad {match['ioc_type']} matched: {match['value']}",
        entity_type=entity_type, entity_id=entity_id, entity_label=entity_label,
        description=f"{entity_label or entity_id} matched a watchlisted {match['ioc_type']} "
                    f"(source: {match['source']}){' -- ' + match['notes'] if match.get('notes') else ''}.",
        raw={"watchlist_id": match["id"], "matched_value": match["value"]},
    )
    return match


async def sync_threatfox_feed(db, days: int = 3) -> dict:
    """Pulls ThreatFox's recent-IOCs bulk feed (their documented `get_iocs` query,
    not the per-target `search_ioc` the recon-ng module uses) and upserts everything
    into the watchlist. Requires the same Auth-Key already configured under
    Integrations -> abuse.ch (ThreatFox) for the on-demand lookup module."""
    import httpx
    integration = await db.integrations.find_one({"name": "abuse.ch (ThreatFox)"}, {"_id": 0})
    cfg = (integration or {}).get("config") or {}
    endpoint = cfg.get("endpoint") or "https://threatfox-api.abuse.ch"
    auth_key = cfg.get("api_key")
    if not auth_key:
        raise ValueError("abuse.ch (ThreatFox) isn't configured -- add an Auth-Key under Integrations -> "
                          "abuse.ch (ThreatFox) first (free at https://auth.abuse.ch/).")

    url = f"{endpoint.rstrip('/')}/api/v1/"
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(url, headers={"Auth-Key": auth_key}, json={"query": "get_iocs", "days": days})
    r.raise_for_status()
    data = r.json()
    if data.get("query_status") != "ok":
        return {"ok": True, "added": 0, "note": "no IOCs returned for this window"}

    added = 0
    for ioc in data.get("data") or []:
        ioc_type = _THREATFOX_TYPE_MAP.get(ioc.get("ioc_type"), None)
        if not ioc_type:
            continue
        value = _normalize(ioc.get("ioc", ""))
        if not value:
            continue
        existing = await db.ioc_watchlist.find_one({"value": value})
        if existing:
            continue
        await db.ioc_watchlist.insert_one({
            "id": str(uuid.uuid4()), "ioc_type": ioc_type, "value": value,
            "source": "abuse.ch_threatfox_feed", "severity": "High",
            "notes": f"{ioc.get('malware_printable') or ioc.get('threat_type', 'malware IOC')} "
                     f"(confidence {ioc.get('confidence_level', '?')})",
            "detail": {
                "malware": ioc.get("malware_printable") or ioc.get("malware"),
                "malware_alias": ioc.get("malware_alias"),
                "threat_type": ioc.get("threat_type"),
                "confidence_level": ioc.get("confidence_level"),
                "first_seen": ioc.get("first_seen"),
                "last_seen": ioc.get("last_seen"),
                "reference": ioc.get("reference"),
                "reporter": ioc.get("reporter"),
                "tags": ioc.get("tags") or [],
                "threatfox_ioc_id": ioc.get("id"),
            },
            "added_by": None, "added_at": _now_iso(), "hits": 0, "last_hit_at": None,
        })
        added += 1
    return {"ok": True, "added": added, "seen": len(data.get("data") or [])}


async def sync_opensourcemalware_feed(db, ecosystems: Optional[list] = None) -> dict:
    """Pulls OpenSourceMalware.com's `query-latest` endpoint (up to 100 most-recent
    verified threats per ecosystem) for each ecosystem in `ecosystems` (defaults to
    OSM_DEFAULT_ECOSYSTEMS) and upserts them into the watchlist as ioc_type="package"
    with value f"{ecosystem}:{package_name}". Requires an API token configured under
    Integrations -> OpenSourceMalware (same "Bearer osm_..." token used for the
    on-demand check-malicious lookup, if one gets added later)."""
    import asyncio
    import httpx

    integration = await db.integrations.find_one({"name": "OpenSourceMalware"}, {"_id": 0})
    cfg = (integration or {}).get("config") or {}
    endpoint = cfg.get("endpoint") or "https://api.opensourcemalware.com"
    api_key = cfg.get("api_key")
    if not api_key:
        raise ValueError("OpenSourceMalware isn't configured yet -- add an API token under Integrations -> "
                          "OpenSourceMalware (free at https://opensourcemalware.com/auth) first.")

    ecosystems = ecosystems or OSM_DEFAULT_ECOSYSTEMS
    url = f"{endpoint.rstrip('/')}/functions/v1/query-latest"
    headers = {"Authorization": f"Bearer {api_key}"}

    added, seen, errors = 0, 0, []
    async with httpx.AsyncClient(timeout=20) as client:
        for i, eco in enumerate(ecosystems):
            if i > 0:
                await asyncio.sleep(1)  # stay well under the 60/min free-tier limit
            try:
                r = await client.get(url, headers=headers, params={"ecosystem": eco})
            except httpx.HTTPError as e:
                errors.append(f"{eco}: could not reach OpenSourceMalware ({e})")
                continue
            if r.status_code == 401:
                raise RuntimeError("OpenSourceMalware rejected this API token (401) -- check it under "
                                   "Integrations -> OpenSourceMalware.")
            if r.status_code == 429:
                errors.append(f"{eco}: rate limited (429), skipped this run")
                continue
            if r.status_code != 200:
                errors.append(f"{eco}: HTTP {r.status_code}")
                continue

            data = r.json()
            threats = data.get("threats") or []
            seen += len(threats)
            for threat in threats:
                name = (threat.get("package_name") or "").strip()
                if not name:
                    continue
                value = _normalize(f"{eco}:{name}")
                existing = await db.ioc_watchlist.find_one({"value": value})
                if existing:
                    continue
                severity = _OSM_SEVERITY_MAP.get((threat.get("severity_level") or "").lower(), "High")
                tags = ", ".join(threat.get("tags") or [])
                notes = threat.get("threat_description") or "Malicious package"
                if tags:
                    notes += f" (tags: {tags})"
                await db.ioc_watchlist.insert_one({
                    "id": str(uuid.uuid4()), "ioc_type": "package", "value": value,
                    "source": "opensourcemalware_feed", "severity": severity, "notes": notes,
                    "detail": {
                        "ecosystem": eco,
                        "package_name": name,
                        "severity_level": threat.get("severity_level"),
                        "threat_description": threat.get("threat_description"),
                        "tags": threat.get("tags") or [],
                        "discovered_date": threat.get("discovered_date") or threat.get("created_at"),
                        "advisory_url": threat.get("advisory_url") or threat.get("source_url"),
                    },
                    "added_by": None, "added_at": _now_iso(), "hits": 0, "last_hit_at": None,
                })
                added += 1

    return {"ok": True, "added": added, "seen": seen, "ecosystems": ecosystems, "errors": errors}


async def sync_opencti_feed(db, limit: int = 200) -> dict:
    """Pulls our own OpenCTI instance's most-recently-created Indicators (GraphQL
    `indicators` connection, sorted by `created` desc) and upserts each one whose
    STIX pattern resolves to an IP/domain/URL/hash into the watchlist as
    source="opencti_feed". This is the bulk-feed sibling of reconng.py's
    run_opencti_lookup -- that one checks a single target on demand from Finding/
    Vendor Detail; this pulls OpenCTI's own indicator library in bulk the same way
    sync_threatfox_feed pulls ThreatFox's, so a value can be on the watchlist
    (and get checked against new assets/files/packages) before anything here
    happens to match it. Requires the same endpoint/api_key (+ optional CF-Access
    service token) already configured under Integrations -> OpenCTI."""
    import httpx
    integration = await db.integrations.find_one({"name": "OpenCTI"}, {"_id": 0})
    cfg = (integration or {}).get("config") or {}
    endpoint, api_key = cfg.get("endpoint"), cfg.get("api_key")
    if not endpoint or not api_key:
        raise ValueError("OpenCTI isn't configured yet -- add endpoint + api_key under Integrations -> OpenCTI first.")

    query = (
        "query($first: Int) { indicators(first: $first, orderBy: created, orderMode: desc) { "
        "edges { node { id name pattern description valid_until x_opencti_score "
        "  objectLabel { value } "
        "  indicatorPatterns: pattern "
        "} } } }"
    )
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    if cfg.get("cf_access_client_id"):
        headers["CF-Access-Client-Id"] = cfg["cf_access_client_id"]
    if cfg.get("cf_access_client_secret"):
        headers["CF-Access-Client-Secret"] = cfg["cf_access_client_secret"]

    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=False) as c:
            r = await c.post(endpoint.rstrip("/") + "/graphql", headers=headers,
                              json={"query": query, "variables": {"first": limit}})
    except httpx.HTTPError as e:
        raise RuntimeError(f"Could not reach OpenCTI: {e}")
    if r.status_code in (301, 302, 303, 307, 308):
        raise RuntimeError("OpenCTI redirected (likely Cloudflare Access) -- check the connection under "
                            "Integrations -> OpenCTI, same as the CVE threat-intel panel.")
    if r.status_code != 200:
        raise RuntimeError(f"OpenCTI HTTP {r.status_code}: {r.text[:200]}")
    data = r.json()
    if data.get("errors"):
        raise RuntimeError(f"OpenCTI GraphQL error: {data['errors'][0].get('message', data['errors'])}")

    edges = ((data.get("data") or {}).get("indicators") or {}).get("edges") or []
    added, skipped_unparsed = 0, 0
    for e in edges:
        node = e.get("node") or {}
        ioc_type, value = _parse_stix_pattern(node.get("pattern") or "")
        if not ioc_type or not value:
            skipped_unparsed += 1
            continue
        value_norm = _normalize(value)
        existing = await db.ioc_watchlist.find_one({"value": value_norm})
        if existing:
            continue
        labels = [lbl.get("value") for lbl in (node.get("objectLabel") or []) if lbl.get("value")]
        score = node.get("x_opencti_score")
        severity = "Critical" if isinstance(score, (int, float)) and score >= 80 else \
                   "High" if isinstance(score, (int, float)) and score >= 50 else "Medium"
        await db.ioc_watchlist.insert_one({
            "id": str(uuid.uuid4()), "ioc_type": ioc_type, "value": value_norm,
            "source": "opencti_feed", "severity": severity,
            "notes": node.get("name") or "OpenCTI indicator",
            "detail": {
                "indicator_name": node.get("name"),
                "description": node.get("description"),
                "pattern": node.get("pattern"),
                "valid_until": node.get("valid_until"),
                "score": score,
                "labels": labels,
                "opencti_indicator_id": node.get("id"),
            },
            "added_by": None, "added_at": _now_iso(), "hits": 0, "last_hit_at": None,
        })
        added += 1
    return {"ok": True, "added": added, "seen": len(edges), "skipped_unparsed": skipped_unparsed}


async def sync_otx_feed(db, pulse_limit: int = 20) -> dict:
    """Pulls AlienVault OTX's `/pulses/subscribed` feed (the pulses this account
    follows/subscribes to -- community threat reports, each bundling a batch of
    indicators) and upserts every indicator whose OTX type maps to one of our IOC
    types. This is the bulk-feed sibling of reconng.py's run_otx_lookup -- that one
    checks a single target on demand; this pulls OTX's own recent pulses in bulk.
    Requires an API key configured under Integrations -> AlienVault OTX (OTX's
    unauthenticated tier doesn't expose the subscribed-pulses feed)."""
    import httpx
    integration = await db.integrations.find_one({"name": "AlienVault OTX"}, {"_id": 0})
    cfg = (integration or {}).get("config") or {}
    endpoint = cfg.get("endpoint") or "https://otx.alienvault.com"
    api_key = cfg.get("api_key")
    if not api_key:
        raise ValueError("AlienVault OTX isn't configured yet -- add an API key under Integrations -> "
                          "AlienVault OTX first (free at https://otx.alienvault.com/).")

    url = f"{endpoint.rstrip('/')}/api/v1/pulses/subscribed"
    try:
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.get(url, headers={"X-OTX-API-KEY": api_key}, params={"limit": pulse_limit})
    except httpx.HTTPError as e:
        raise RuntimeError(f"Could not reach AlienVault OTX: {e}")
    if r.status_code == 403:
        raise RuntimeError("AlienVault OTX rejected this API key (403) -- check it under Integrations -> AlienVault OTX.")
    if r.status_code != 200:
        raise RuntimeError(f"AlienVault OTX HTTP {r.status_code}: {r.text[:200]}")
    data = r.json()
    pulses = data.get("results") or []

    added, seen = 0, 0
    for pulse in pulses:
        pulse_name = pulse.get("name")
        pulse_id = pulse.get("id")
        pulse_desc = pulse.get("description")
        author = (pulse.get("author_name") or (pulse.get("author") or {}).get("username"))
        tags = pulse.get("tags") or []
        references = pulse.get("references") or []
        for ind in pulse.get("indicators") or []:
            seen += 1
            ioc_type = _OTX_TYPE_MAP.get(ind.get("type"))
            if not ioc_type:
                continue
            raw_value = ind.get("indicator") or ""
            if not raw_value:
                continue
            value_norm = _normalize(raw_value)
            existing = await db.ioc_watchlist.find_one({"value": value_norm})
            if existing:
                continue
            await db.ioc_watchlist.insert_one({
                "id": str(uuid.uuid4()), "ioc_type": ioc_type, "value": value_norm,
                "source": "otx_feed", "severity": "High",
                "notes": f"OTX pulse: {pulse_name or 'unnamed'}",
                "detail": {
                    "pulse_name": pulse_name,
                    "pulse_id": pulse_id,
                    "pulse_description": pulse_desc,
                    "author": author,
                    "tags": tags,
                    "references": references,
                    "indicator_type": ind.get("type"),
                    "indicator_description": ind.get("description"),
                    "indicator_created": ind.get("created"),
                },
                "added_by": None, "added_at": _now_iso(), "hits": 0, "last_hit_at": None,
            })
            added += 1
    return {"ok": True, "added": added, "seen": seen, "pulses_checked": len(pulses)}
