"""SBOM / software composition analysis -- parses CycloneDX or SPDX JSON SBOMs and
matches components against OSV.dev (osv.dev, run by Google/OpenSSF, no API key
required, covers npm/PyPI/Go/crates.io/NuGet/RubyGems/Maven/Packagist/etc.) to create
findings for known-vulnerable dependencies.

Chose OSV over bundling a full scanner (Trivy/Grype) because those need their own
multi-hundred-MB vulnerability database mirrored and refreshed inside the container --
OSV's free batch API gives the same underlying data (it's itself one of Trivy's
sources) with zero extra infrastructure, which fits a self-hosted single-container
deployment better.
"""
import asyncio
import json
import re
import urllib.parse
import uuid
from datetime import datetime, timezone

import httpx

OSV_QUERY_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{}"
MAX_DETAIL_FETCH = 300  # cap per-run OSV detail lookups so one huge SBOM can't run forever

PURL_RE = re.compile(r"^pkg:([A-Za-z.\-]+)/(.+)$")
ECOSYSTEM_MAP = {
    "npm": "npm", "pypi": "PyPI", "maven": "Maven", "golang": "Go", "cargo": "crates.io",
    "nuget": "NuGet", "gem": "RubyGems", "composer": "Packagist", "hex": "Hex", "pub": "Pub",
    "deb": "Debian", "apk": "Alpine",
}
SEVERITY_MAP = {"CRITICAL": "Critical", "HIGH": "High", "MODERATE": "Medium", "MEDIUM": "Medium", "LOW": "Low"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_purl(purl: str) -> dict | None:
    m = PURL_RE.match(purl or "")
    if not m:
        return None
    pkg_type, rest = m.group(1).lower(), m.group(2)
    rest = rest.split("?")[0].split("#")[0]
    if "@" not in rest:
        return None
    path, version = rest.rsplit("@", 1)
    ecosystem = ECOSYSTEM_MAP.get(pkg_type)
    if not ecosystem:
        return None
    if pkg_type == "maven" and "/" in path:
        group, _, artifact = path.rpartition("/")
        name = f"{group}:{artifact}"
    else:
        name = path
    return {
        "name": urllib.parse.unquote(name), "version": urllib.parse.unquote(version),
        "ecosystem": ecosystem, "purl": purl,
    }


def parse_sbom(content: bytes) -> list:
    """Accepts CycloneDX or SPDX JSON. Only components with a resolvable package URL
    (purl) are usable -- without one there's no reliable way to know which ecosystem
    to query, so those are silently skipped rather than guessed at."""
    try:
        data = json.loads(content)
    except Exception as e:
        raise ValueError(f"Not valid JSON: {e}")
    if not isinstance(data, dict):
        raise ValueError("Doesn't look like a CycloneDX or SPDX JSON SBOM")

    components = []
    if data.get("bomFormat") == "CycloneDX":
        for c in data.get("components", []) or []:
            parsed = _parse_purl(c.get("purl")) if c.get("purl") else None
            if parsed:
                components.append(parsed)
    elif "spdxVersion" in data:
        for p in data.get("packages", []) or []:
            purl = None
            for ref in p.get("externalRefs", []) or []:
                if ref.get("referenceType") == "purl":
                    purl = ref.get("referenceLocator")
                    break
            parsed = _parse_purl(purl) if purl else None
            if parsed:
                components.append(parsed)
    else:
        raise ValueError("Doesn't look like a CycloneDX ('bomFormat': 'CycloneDX') or SPDX ('spdxVersion') JSON SBOM")

    if not components:
        raise ValueError("No components with a resolvable package URL (purl) were found in this SBOM")
    return components


async def _query_osv(components: list) -> dict:
    """Returns {component_index: [vuln_id, ...]} for components with at least one hit."""
    results_map = {}
    async with httpx.AsyncClient(timeout=60) as c:
        for i in range(0, len(components), 1000):  # OSV batch cap
            batch = components[i:i + 1000]
            queries = [{"version": comp["version"], "package": {"name": comp["name"], "ecosystem": comp["ecosystem"]}} for comp in batch]
            r = await c.post(OSV_QUERY_URL, json={"queries": queries})
            r.raise_for_status()
            data = r.json()
            for offset, result in enumerate(data.get("results", []) or []):
                ids = [v["id"] for v in (result.get("vulns") or []) if v.get("id")]
                if ids:
                    results_map[i + offset] = ids
    return results_map


async def _fetch_vuln_details(vuln_ids, concurrency: int = 10) -> dict:
    details = {}
    sem = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(timeout=30) as c:
        async def _one(vid):
            async with sem:
                try:
                    r = await c.get(OSV_VULN_URL.format(vid))
                    if r.status_code == 200:
                        details[vid] = r.json()
                except Exception:
                    pass
        await asyncio.gather(*[_one(v) for v in vuln_ids])
    return details


def _extract_severity(vuln: dict) -> str:
    ds = (vuln.get("database_specific") or {}).get("severity")
    if ds and str(ds).upper() in SEVERITY_MAP:
        return SEVERITY_MAP[str(ds).upper()]
    for aff in vuln.get("affected", []) or []:
        ds2 = (aff.get("database_specific") or {}).get("severity")
        if ds2 and str(ds2).upper() in SEVERITY_MAP:
            return SEVERITY_MAP[str(ds2).upper()]
    return "Medium"


def _extract_cve(vuln: dict) -> str | None:
    for alias in vuln.get("aliases", []) or []:
        if alias.startswith("CVE-"):
            return alias
    if (vuln.get("id") or "").startswith("CVE-"):
        return vuln["id"]
    return None


async def import_sbom(db, content: bytes, filename: str = "", label: str | None = None,
                       asset_id: str | None = None, source_tool: str = "SBOM / OSV.dev",
                       detection_channel: str = "SBOM upload") -> dict:
    """source_tool/detection_channel default to the manual-upload labels but can be
    overridden -- container_scan.py reuses this exact pipeline for Trivy-generated
    image SBOMs and passes its own labels so those findings read as "Container Image
    Scan" rather than a generic upload, without duplicating any of the parsing/OSV
    lookup/finding-dedup logic below."""
    components = parse_sbom(content)

    # Check each unique dependency against the threat intel watchlist's malicious-
    # package feed (OpenSourceMalware.com) -- independent of the OSV vuln lookup
    # below, since a supply-chain-compromised package may have no assigned CVE at
    # all. Raises a Security Alert on a match rather than a Finding, consistent
    # with how the watchlist surfaces IP/hash matches elsewhere.
    from threat_intel_watchlist import check_and_emit, SBOM_TO_OSM_ECOSYSTEM
    checked_packages = set()
    for comp in components:
        osm_eco = SBOM_TO_OSM_ECOSYSTEM.get(comp["ecosystem"])
        if not osm_eco:
            continue
        dedupe_key = (osm_eco, comp["name"].lower())
        if dedupe_key in checked_packages:
            continue
        checked_packages.add(dedupe_key)
        value = f"{osm_eco}:{comp['name']}"
        await check_and_emit(db, value, entity_type="package", entity_id=value,
                              entity_label=f"{comp['name']}@{comp['version']} ({comp['ecosystem']})")

    vuln_map = await _query_osv(components)

    all_vuln_ids = set()
    for ids in vuln_map.values():
        all_vuln_ids.update(ids)
    capped_ids = set(list(all_vuln_ids)[:MAX_DETAIL_FETCH])
    details = await _fetch_vuln_details(capped_ids)

    now = _now_iso()
    findings_created = findings_updated = 0
    asset = await db.assets.find_one({"id": asset_id}, {"_id": 0}) if asset_id else None
    open_states = ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]
    source_label = (asset or {}).get("hostname") or label or filename or "SBOM upload"

    for idx, vuln_ids in vuln_map.items():
        comp = components[idx]
        for vid in vuln_ids:
            vuln = details.get(vid, {"id": vid})
            severity = _extract_severity(vuln)
            cve = _extract_cve(vuln)
            canonical_key = f"sbom:{comp['ecosystem']}:{comp['name']}@{comp['version']}:{vid}"
            existing = await db.findings.find_one({"canonical_key": canonical_key}, {"_id": 0})
            if existing:
                if existing.get("status") in open_states:
                    await db.findings.update_one({"id": existing["id"]}, {"$set": {"last_seen_at": now}})
                    findings_updated += 1
                continue
            title = f"{comp['name']}@{comp['version']} — {vid}"
            if cve and cve != vid:
                title += f" ({cve})"
            finding = {
                "id": str(uuid.uuid4()), "canonical_key": canonical_key, "title": title,
                "description": (vuln.get("summary") or vuln.get("details") or
                                 f"Known vulnerability {vid} in {comp['ecosystem']} package {comp['name']} {comp['version']}")[:2000],
                "severity": severity, "status": "New", "cve": cve,
                "source_tool": source_tool, "source_tool_type": "Software Composition Analysis",
                "detection_channel": detection_channel,
                "asset_id": asset_id, "asset_hostname": source_label,
                "asset_ip": (asset or {}).get("ip"), "asset_criticality": (asset or {}).get("criticality"),
                "asset_exposure": (asset or {}).get("exposure"),
                "component_name": comp["name"], "component_version": comp["version"], "component_ecosystem": comp["ecosystem"],
                "external_references": [{"source": "OSV.dev", "url": f"https://osv.dev/vulnerability/{vid}"}],
                "first_seen_at": now, "last_seen_at": now, "rti": [],
            }
            await db.findings.insert_one(finding)
            findings_created += 1

    record = {
        "id": str(uuid.uuid4()), "filename": filename, "label": label, "asset_id": asset_id,
        "components_total": len(components), "components_vulnerable": len(vuln_map),
        "findings_created": findings_created, "findings_updated": findings_updated,
        "unique_vulns": len(all_vuln_ids), "uploaded_at": now,
    }
    await db.sbom_uploads.insert_one(dict(record))

    return {
        "components_parsed": len(components), "components_vulnerable": len(vuln_map),
        "findings_created": findings_created, "findings_updated": findings_updated,
        "unique_vulns": len(all_vuln_ids),
    }
