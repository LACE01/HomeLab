"""Tenable Nessus live sync.

Pulls vulnerability results from a self-hosted Nessus Essentials/Professional/
Manager scanner's own REST API (the same API surface documented at
https://<scanner-host>:8834/api# on every Nessus install) and feeds them
through the same canonical findings pipeline used by qualys_sync.py -- this
module is deliberately modeled on qualys_sync.py's structure (same "integration
config → fetch → upsert asset/finding → auto-resolve stale → record run" shape)
since Tenable Nessus is the same category of connector: a paid/licensed
third-party scanner this app polls for already-completed scan results, not a
scan-execution tool this app runs itself (contrast container_scan.py /
secrets_scan.py, which actually invoke a scanner as a subprocess).

Nessus's data model is scan-centric, not detection-centric like Qualys: there is
no single "list all current detections" endpoint. Instead: GET /scans lists scan
jobs, GET /scans/{id} lists that scan's hosts (with an aggregate severity
breakdown), and GET /scans/{id}/hosts/{host_id} lists that specific host's
vulnerabilities (plugin_id/plugin_name/plugin_family/severity/count -- no CVE/
CVSS/remediation text at this level). Per-plugin detail (CVE list, CVSS score,
synopsis, solution) is a separate call, GET /plugins/plugin/{plugin_id} --
cached per plugin_id within a single sync run since the same plugin fires on
many hosts.

Authentication -- Nessus supports two modes, both handled here:
  - API Keys (recommended by Tenable for new setups): accessKey/secretKey sent
    as one `X-ApiKeys` header. Stored on the integration as api_key=accessKey,
    api_secret=secretKey (auth_type "api_key", the default).
  - Username/password session token (older Nessus versions; some admins still
    just use their console login): POST /session with {username,password}
    returns a short-lived token used as `X-Cookie: token=<token>` on every
    subsequent call. Stored as username + api_key=password (auth_type "basic").
Both are exactly the two auth_type options the existing generic Integrations
config UI already offers (see AdminAndIntegrations.jsx) -- no new auth concept
was introduced for this connector.

TLS: self-hosted Nessus almost always presents a self-signed certificate (every
Tenable tutorial/doc uses `curl -k` for exactly this reason) -- verify=False is
used unconditionally here, a deliberate, documented choice for a scanner
appliance on the same trusted network, not a general-purpose recommendation.

Scope: by default every scan with status "completed" is pulled. An optional
`scan_name_filter` (list of substrings) can be set directly on the integration's
config in Mongo to restrict which scans get synced, mirroring qualys_sync.py's
`sync_scope` override convention -- not surfaced in the generic UI, an escape
hatch for advanced setups rather than a day-one requirement.
"""
import asyncio
import logging
import uuid
from datetime import datetime, timezone

import httpx

from scoring import compute_risk, compute_sla_days
from asset_classify import classify_asset_type

logger = logging.getLogger("vulnops.tenable")

# Nessus plugin severity ints (0-4) -> our normalized severity strings.
_NESSUS_SEV = {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Info"}

OPEN_STATES = ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _norm_severity(sev_raw) -> str:
    try:
        return _NESSUS_SEV.get(int(sev_raw), "Medium")
    except (TypeError, ValueError):
        return "Medium"


async def _get_integration(db) -> dict | None:
    return await db.integrations.find_one({"name": "Tenable Nessus"}, {"_id": 0})


async def _record_run(db, status: str, summary: dict, errors: list):
    doc = {
        "id": str(uuid.uuid4()),
        "ran_at": _now_iso(),
        "status": status,
        "summary": summary,
        "errors": errors[:50],
    }
    await db.tenable_sync_runs.insert_one(dict(doc))
    await db.import_jobs.insert_one({
        "id": doc["id"],
        "source_name": "Tenable Nessus",
        "mode": "live_sync",
        "status": status,
        "request_id": f"tenable_{doc['id'][:12]}",
        "started_at": summary.get("started_at", doc["ran_at"]),
        "finished_at": doc["ran_at"],
        "created_count": summary.get("created", 0),
        "updated_count": summary.get("updated", 0),
        "deduplicated_count": summary.get("deduped", 0),
        "failed_count": summary.get("failed", 0),
        "retry_count": 0,
        "errors": errors[:50],
    })
    return doc


async def _auth_headers(endpoint: str, cfg: dict) -> dict:
    """Returns the header dict used on every subsequent Nessus API call.
    API-key mode (default) needs no network round-trip; session mode does a
    one-time POST /session to trade username/password for a short-lived token."""
    auth_type = cfg.get("auth_type") or "api_key"
    if auth_type == "basic":
        username = cfg.get("username")
        password = cfg.get("api_key")  # password stored in the generic "api_key" slot for basic auth
        if not username or not password:
            raise RuntimeError("Tenable integration is set to username/password auth but username or password is missing")
        async with httpx.AsyncClient(timeout=30, verify=False) as c:
            r = await c.post(endpoint.rstrip("/") + "/session",
                              json={"username": username, "password": password})
            r.raise_for_status()
            token = r.json().get("token")
        if not token:
            raise RuntimeError("Nessus /session did not return a token")
        return {"X-Cookie": f"token={token}"}

    access_key = cfg.get("api_key")
    secret_key = cfg.get("api_secret")
    if not access_key or not secret_key:
        raise RuntimeError("Tenable integration is set to API-key auth but api_key/api_secret is missing")
    return {"X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key}"}


async def _get(endpoint: str, headers: dict, path: str, timeout: int = 60) -> dict:
    async with httpx.AsyncClient(timeout=timeout, verify=False) as c:
        r = await c.get(endpoint.rstrip("/") + path, headers=headers)
        r.raise_for_status()
        return r.json()


async def _list_scans(endpoint: str, headers: dict, name_filter: list[str] | None = None) -> list[dict]:
    data = await _get(endpoint, headers, "/scans")
    scans = data.get("scans") or []
    out = [s for s in scans if s and s.get("status") == "completed"]
    if name_filter:
        needles = [n.lower() for n in name_filter]
        out = [s for s in out if any(n in (s.get("name") or "").lower() for n in needles)]
    return out


async def _scan_hosts(endpoint: str, headers: dict, scan_id) -> tuple[list[dict], dict]:
    """Returns (hosts list, scan info dict) for one scan via GET /scans/{id}."""
    data = await _get(endpoint, headers, f"/scans/{scan_id}")
    return data.get("hosts") or [], data.get("info") or {}


async def _host_vulnerabilities(endpoint: str, headers: dict, scan_id, host_id) -> list[dict]:
    data = await _get(endpoint, headers, f"/scans/{scan_id}/hosts/{host_id}")
    return data.get("vulnerabilities") or []


def _parse_plugin_attributes(data: dict) -> dict:
    """Nessus returns plugin detail as {"attributes": [{"attribute_name": "...",
    "attribute_value": "..."}, ...]} -- flatten to a plain dict, keeping every
    repeated key (e.g. multiple `cve` attributes for a plugin with several CVEs)
    as a list."""
    out: dict = {}
    for attr in data.get("attributes") or []:
        name = attr.get("attribute_name")
        val = attr.get("attribute_value")
        if not name:
            continue
        if name in out:
            if isinstance(out[name], list):
                out[name].append(val)
            else:
                out[name] = [out[name], val]
        else:
            out[name] = val
    return out


async def _plugin_detail(endpoint: str, headers: dict, plugin_id, cache: dict) -> dict:
    key = str(plugin_id)
    if key in cache:
        return cache[key]
    try:
        data = await _get(endpoint, headers, f"/plugins/plugin/{plugin_id}", timeout=30)
        attrs = _parse_plugin_attributes(data)
        cves = attrs.get("cve")
        cve_list = cves if isinstance(cves, list) else ([cves] if cves else [])

        def _first_num(v):
            try:
                return float(v)
            except (TypeError, ValueError):
                return None

        detail = {
            "name": data.get("name"),
            "family_name": data.get("family_name"),
            "synopsis": attrs.get("synopsis"),
            "description": attrs.get("description"),
            "solution": attrs.get("solution"),
            "cve_list": cve_list,
            "cvss_score": _first_num(attrs.get("cvss3_base_score")) or _first_num(attrs.get("cvss_base_score")),
            "cvss_vector": attrs.get("cvss3_vector") or attrs.get("cvss_vector"),
        }
    except Exception as e:
        detail = {"error": str(e)}
    cache[key] = detail
    return detail


async def _upsert_asset(db, hostname: str) -> dict:
    asset = await db.assets.find_one({"hostname": hostname}, {"_id": 0})
    if asset:
        return asset
    asset = {
        "id": str(uuid.uuid4()), "hostname": hostname, "ip": hostname if _looks_like_ip(hostname) else None,
        "fqdn": None, "environment": "unknown", "criticality": "medium", "exposure": "internal",
        "platform": "unknown", "operating_system": "unknown",
        "asset_type": classify_asset_type(None) or "server",
        "owner_team": "Unassigned", "product_id": None, "product_name": None,
        "tags": ["tenable"], "status": "active", "created_at": _now_iso(),
        "ownership_confidence": 0.3,
        "ownership_rationale": "Auto-created from Tenable Nessus live sync (no tag rule match)",
    }
    await db.assets.insert_one(asset)
    if asset.get("ip"):
        from threat_intel_watchlist import check_and_emit
        await check_and_emit(db, asset["ip"], entity_type="asset", entity_id=asset["id"], entity_label=hostname)
    return asset


def _looks_like_ip(s: str) -> bool:
    parts = (s or "").split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


async def _upsert_finding(db, asset: dict, vuln: dict, plugin: dict, scan_name: str) -> tuple[str, str | None]:
    """Returns (outcome, canonical_key). outcome is 'created' | 'updated' | 'skipped'
    (skipped only for the plugin-detail-lookup-failed case, so one bad plugin fetch
    doesn't drop the whole host's results)."""
    if plugin.get("error"):
        return "skipped", None

    plugin_id = vuln.get("plugin_id")
    severity = _norm_severity(vuln.get("severity"))
    cve_list = plugin.get("cve_list") or []
    primary_cve = cve_list[0] if cve_list else None
    # Keyed on the resolved asset id -- see corroboration.py. With a CVE this
    # deliberately produces the SAME key Qualys produces, so the two scanners
    # corroborate one finding instead of racing to overwrite each other.
    from corroboration import find_existing as _find_existing
    existing, canonical = await _find_existing(
        db, asset_id=asset["id"], hostname=asset["hostname"], cve=primary_cve,
        native_id=plugin_id, tool="Tenable Nessus")

    base = {
        "source_tool": "Tenable Nessus",
        "source_observation_id": str(plugin_id),
        "source_native_id": str(plugin_id),
        "plugin_id": plugin_id,
        "plugin_family": vuln.get("plugin_family") or plugin.get("family_name"),
        "title": plugin.get("name") or vuln.get("plugin_name") or f"Nessus Plugin {plugin_id}",
        "description": plugin.get("description") or plugin.get("synopsis"),
        "severity": severity,
        "cve": primary_cve, "cve_list": cve_list,
        "cvss_score": plugin.get("cvss_score"),
        "cvss_vector": plugin.get("cvss_vector"),
        "epss_score": 0,  # enriched by nightly_rescore / enrichers.sync_epss below
        "kev_flag": False,
        "rti": [],
        "remediation": plugin.get("solution"),
        "detection_logic": vuln.get("plugin_family") or plugin.get("family_name"),
        "advisory_links": [{"source": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{primary_cve}"}] if primary_cve else [],
        "asset_id": asset["id"], "asset_hostname": asset["hostname"], "asset_ip": asset.get("ip"),
        "asset_criticality": asset["criticality"], "asset_exposure": asset["exposure"],
        "asset_environment": asset["environment"], "asset_os": asset.get("operating_system"),
        "internet_facing": asset["exposure"] in ("internet", "external"),
        "owner_team": asset["owner_team"],
        "ownership_confidence": asset.get("ownership_confidence", 0.5),
        "product_id": asset.get("product_id"), "product_name": asset.get("product_name"),
        "last_seen_at": _now_iso(), "last_changed_at": _now_iso(),
        "imported_at": _now_iso(), "detection_channel": "tenable_api",
        "nessus_scan_name": scan_name,
    }

    if existing:
        new_status = existing["status"]
        reopened = existing.get("reopened_count", 0)
        if existing["status"] in ("Fixed validated", "Mitigated", "Closed administratively"):
            new_status = "Reopened"
            reopened += 1
        base["status"] = new_status
        base["reopened_count"] = reopened
        base["first_seen_at"] = existing["first_seen_at"]
        base["canonical_key"] = canonical
        from corroboration import merge_source, make_source, reconcile_severity
        _sources = merge_source(existing.get("sources") or (
            [make_source(tool=existing.get("source_tool"),
                          native_id=existing.get("source_native_id"),
                          severity=existing.get("severity"),
                          first_seen=existing.get("first_seen_at"))]
            if existing.get("source_tool") else []),
            make_source(tool="Tenable Nessus", native_id=str(plugin_id),
                         severity=severity, title=base.get("title")))
        base["sources"] = _sources
        base["source_count"] = len({x["tool"] for x in _sources})
        _sev = reconcile_severity(_sources)
        if _sev["severity"]:
            base["severity"] = _sev["severity"]
            base["severity_agreement"] = _sev["agreement"]
            base["severity_disagreement"] = _sev["disagreement"]
        # A second scanner enriches, it does not rewrite. Without this guard the
        # Nessus description and remediation would replace Qualys' (and any human
        # edit) on every sync, and vice versa -- the two tools would overwrite
        # each other forever.
        for _f in ("description", "remediation", "title"):
            if existing.get(_f) and base.get(_f):
                base.pop(_f)
        risk = compute_risk({**existing, **base}, asset)
        base["risk_score"] = risk["score"]
        base["risk_breakdown"] = risk["breakdown"]
        await db.findings.update_one({"id": existing["id"]}, {"$set": base})
        return "corroborated" if base["source_count"] > 1 else "updated", canonical

    sla_days_val = compute_sla_days(severity, asset["criticality"])
    now = _now_iso()
    new_finding = {
        "id": str(uuid.uuid4()), "canonical_key": canonical,
        "sources": [__import__("corroboration").make_source(
            tool="Tenable Nessus", native_id=str(plugin_id), severity=severity,
            title=base.get("title"))],
        "source_count": 1,
        "first_seen_at": now, "reopened_count": 0,
        "status": "New", "validation_status": "pending",
        "sla_days": sla_days_val,
        "due_at": now, "tags": asset.get("tags", []),
        "compliance_scope": [], "advisory_links": base["advisory_links"], "exploit_references": [],
        **base,
    }
    risk = compute_risk(new_finding, asset)
    new_finding["risk_score"] = risk["score"]
    new_finding["risk_breakdown"] = risk["breakdown"]
    await db.findings.insert_one(new_finding)
    if severity in ("Critical", "High"):
        from security_events import emit_event
        await emit_event(db, source="findings", event_type="new_high_severity_finding", severity=severity,
            title=f"{severity} finding on {asset['hostname']}: {new_finding['title']}",
            entity_type="asset", entity_id=asset["id"], entity_label=asset["hostname"],
            description=f"New {severity} finding (plugin {plugin_id}{', ' + primary_cve if primary_cve else ''}) detected by Tenable Nessus.",
            raw={"finding_id": new_finding["id"], "cve": primary_cve, "plugin_id": plugin_id})
    return "created", canonical


async def _auto_resolve_stale(db, hostname: str, seen_keys: set) -> int:
    """Closes previously-open Tenable findings on this exact host that this run's
    fresh host-vulnerabilities pull didn't reproduce. Scoped to `hostname` (only
    hosts actually re-scanned this run) -- a host simply absent from this batch of
    scans (e.g. its scan wasn't due yet) must never be treated as "all clear"."""
    prior = await db.findings.find(
        {"detection_channel": "tenable_api", "asset_hostname": hostname, "status": {"$in": OPEN_STATES}},
        {"_id": 0},
    ).to_list(2000)
    resolved = 0
    for f in prior:
        if f.get("canonical_key") not in seen_keys:
            await db.findings.update_one({"id": f["id"]}, {"$set": {
                "status": "Fixed validated", "last_changed_at": _now_iso(),
                "verification_status": "passed",
                "verification_note": "No longer reported by Tenable Nessus on the most recent scan of this host -- auto-closed.",
            }})
            resolved += 1
    return resolved


async def run_tenable_sync(db) -> dict:
    """Pulls every completed scan's results, upserts findings + assets, writes a
    job + run record."""
    integration = await _get_integration(db)
    if not integration:
        raise RuntimeError("Tenable Nessus integration not found")
    cfg = integration.get("config") or {}
    endpoint = cfg.get("endpoint")
    if not endpoint:
        raise RuntimeError("Tenable integration missing endpoint")

    started_at = _now_iso()
    errors: list = []
    created = updated = skipped = 0
    plugin_cache: dict = {}
    hosts_seen_keys: dict[str, set] = {}
    scans_processed = 0

    try:
        headers = await _auth_headers(endpoint, cfg)
    except Exception as e:
        errors.append({"stage": "auth", "error": str(e)})
        return await _record_run(db, "failed",
                                  {"started_at": started_at, "scans": 0, "created": 0,
                                   "updated": 0, "deduped": 0, "failed": 1}, errors)

    try:
        scans = await _list_scans(endpoint, headers, cfg.get("scan_name_filter"))
    except Exception as e:
        errors.append({"stage": "list_scans", "error": str(e)})
        return await _record_run(db, "failed",
                                  {"started_at": started_at, "scans": 0, "created": 0,
                                   "updated": 0, "deduped": 0, "failed": 1}, errors)

    for scan in scans:
        scan_id = scan.get("id")
        scan_name = scan.get("name") or f"scan-{scan_id}"
        try:
            hosts, _info = await _scan_hosts(endpoint, headers, scan_id)
        except Exception as e:
            errors.append({"stage": "scan_hosts", "scan_id": scan_id, "error": str(e)})
            continue
        scans_processed += 1

        for host in hosts:
            host_id = host.get("host_id")
            hostname = host.get("hostname") or f"nessus-host-{host_id}"
            try:
                vulns = await _host_vulnerabilities(endpoint, headers, scan_id, host_id)
            except Exception as e:
                errors.append({"stage": "host_vulns", "scan_id": scan_id, "host_id": host_id, "error": str(e)})
                continue

            asset = await _upsert_asset(db, hostname)
            seen = hosts_seen_keys.setdefault(hostname, set())
            for vuln in vulns:
                plugin_id = vuln.get("plugin_id")
                if not plugin_id:
                    continue
                plugin = await _plugin_detail(endpoint, headers, plugin_id, plugin_cache)
                try:
                    outcome, canonical = await _upsert_finding(db, asset, vuln, plugin, scan_name)
                except Exception as e:
                    errors.append({"stage": "upsert", "plugin_id": plugin_id, "hostname": hostname, "error": str(e)})
                    continue
                if outcome == "created":
                    created += 1
                    seen.add(canonical)
                elif outcome == "updated":
                    updated += 1
                    seen.add(canonical)
                else:
                    skipped += 1

    auto_closed = 0
    for hostname, seen in hosts_seen_keys.items():
        try:
            auto_closed += await _auto_resolve_stale(db, hostname, seen)
        except Exception as e:
            errors.append({"stage": "auto_resolve", "hostname": hostname, "error": str(e)})

    summary = {
        "started_at": started_at,
        "scans_found": len(scans),
        "scans_processed": scans_processed,
        "hosts_seen": len(hosts_seen_keys),
        "created": created, "updated": updated, "deduped": updated,
        "skipped_plugin_lookup_failed": skipped,
        "auto_closed": auto_closed,
        "failed": len(errors),
    }

    # KEV + EPSS enrichment -- same free CISA/FIRST.org catalogs qualys_sync.py
    # already reuses; both operate over every finding's `cve` field regardless of
    # which connector created it, so re-running them here is not redundant work,
    # it's the only way Tenable-sourced findings ever get this enrichment at all
    # (neither runs on its own independent schedule -- see server.py).
    try:
        from enrichers import sync_kev, sync_epss
        kev_res = await sync_kev(db)
        summary["kev"] = {"matched": kev_res.get("matched"), "catalog_size": kev_res.get("catalog_size")}
        epss_res = await sync_epss(db)
        summary["epss"] = {"matched": epss_res.get("matched"), "cves_with_score": epss_res.get("cves_with_score")}
    except Exception as e:
        errors.append({"stage": "enrichment", "error": str(e)})

    status = "success" if (created or updated or scans_processed) else ("failed" if errors else "success")
    await db.integrations.update_one(
        {"id": integration["id"]},
        {"$set": {"status": "healthy" if status == "success" else "degraded",
                  "last_sync_at": _now_iso(),
                  "sync_errors": 0 if status == "success" else (integration.get("sync_errors", 0) + 1)}},
    )
    from routes.common import record_engagement
    await record_engagement(
        db, name=f"Tenable Nessus sync — {started_at[:10]}", scanner="Tenable Nessus",
        scan_type="scheduled", scan_method="api",
        status="completed" if status == "success" else "failed",
        assets_scanned=len(hosts_seen_keys),
        findings_created=created, findings_updated=updated, started_at=started_at,
        error="; ".join(str(e) for e in errors[:3]) if errors else None,
    )
    return await _record_run(db, status, summary, errors)


async def tenable_poll_loop(db, interval_minutes: int = 60):
    """Background poll. Skips silently if the Tenable Nessus integration is not
    configured; gated by the tenable_nightly_sync feature flag (manual "Sync now"
    from Integrations is never gated, only this automatic sweep)."""
    from heartbeat import record_heartbeat
    from feature_flags import is_enabled
    await asyncio.sleep(25)
    while True:
        ok, detail = True, {}
        try:
            integration = await _get_integration(db)
            cfg = (integration or {}).get("config") or {}
            configured = bool(cfg.get("endpoint")) and (
                (cfg.get("auth_type") == "basic" and cfg.get("username") and cfg.get("api_key")) or
                (cfg.get("auth_type") != "basic" and cfg.get("api_key") and cfg.get("api_secret"))
            )
            if configured and await is_enabled(db, "tenable_nightly_sync"):
                logger.info("Tenable poll: running sync")
                run = await run_tenable_sync(db)
                logger.info(f"Tenable poll done: {run.get('summary')}")
                detail["summary"] = run.get("summary")
            elif not configured:
                detail["skipped"] = "not configured"
            else:
                detail["skipped"] = "disabled in Settings"
        except Exception as e:
            logger.exception(f"Tenable poll error: {e}")
            ok, detail["error"] = False, str(e)
        await record_heartbeat(db, "tenable_poll_loop", "ok" if ok else "error", detail)
        await asyncio.sleep(interval_minutes * 60)
