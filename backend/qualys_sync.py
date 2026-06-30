"""Qualys VMDR live sync.

Pulls real vulnerability detections from the Qualys VMDR API using HTTP Basic auth
and feeds them through the same canonical ingestion pipeline used by /v1/ingest/universal.

Default scope: severity 4–5, status Active/Re-Opened (Confirmed only).
Override via the integration config["sync_scope"] field if needed.

Background loop is started from server.on_startup at a configurable interval (default 60 min).
"""
import asyncio
import logging
import uuid
from datetime import datetime, timezone, timedelta

import httpx
import xml.etree.ElementTree as ET

from scoring import compute_risk, compute_sla_days

logger = logging.getLogger("vulnops.qualys")


# Qualys severity (1–5) → our normalized severity
_QUALYS_SEV = {5: "Critical", 4: "High", 3: "Medium", 2: "Low", 1: "Info"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _norm_severity(sev_raw) -> str:
    try:
        return _QUALYS_SEV.get(int(sev_raw), "Medium")
    except (TypeError, ValueError):
        return "Medium"


async def _get_integration(db) -> dict | None:
    return await db.integrations.find_one({"name": "Qualys VMDR"}, {"_id": 0})


async def _record_run(db, status: str, summary: dict, errors: list):
    doc = {
        "id": str(uuid.uuid4()),
        "ran_at": _now_iso(),
        "status": status,
        "summary": summary,
        "errors": errors[:50],
    }
    await db.qualys_sync_runs.insert_one(dict(doc))
    # Also surface in the standard import_jobs feed so the dashboard shows it
    await db.import_jobs.insert_one({
        "id": doc["id"],
        "source_name": "Qualys VMDR",
        "mode": "live_sync",
        "status": status,
        "request_id": f"qualys_{doc['id'][:12]}",
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


async def _fetch_qualys_detections(endpoint: str, username: str, password: str,
                                   severities: str = "4-5",
                                   statuses: str = "Active,Re-Opened") -> bytes:
    """Call Qualys VMDR /api/2.0/fo/asset/host/vm/detection/?action=list and return XML body."""
    url = endpoint.rstrip("/") + "/api/2.0/fo/asset/host/vm/detection/"
    params = {
        "action": "list",
        "show_results": 1,
        "show_igs": 0,
        "severities": severities,
        "status": statuses,
        "truncation_limit": 500,
    }
    headers = {"X-Requested-With": "VulnOps"}
    async with httpx.AsyncClient(timeout=120, auth=(username, password)) as c:
        r = await c.post(url, params=params, headers=headers)
        r.raise_for_status()
        return r.content


def _parse_detections(xml_body: bytes) -> list[dict]:
    """Parse the Qualys HOST_LIST_VM_DETECTION XML into a flat list of per-detection dicts."""
    out: list[dict] = []
    try:
        root = ET.fromstring(xml_body)
    except ET.ParseError as e:
        raise RuntimeError(f"Qualys XML parse error: {e}")

    for host in root.iter("HOST"):
        h = {child.tag: (child.text or "").strip() for child in host
             if child.tag not in ("DETECTION_LIST",)}
        hostname = h.get("DNS") or h.get("NETBIOS") or h.get("IP") or f"qualys-host-{h.get('ID','?')}"
        det_list = host.find("DETECTION_LIST")
        if det_list is None:
            continue
        for det in det_list.findall("DETECTION"):
            d = {child.tag: (child.text or "").strip() for child in det}
            out.append({
                "qid": d.get("QID"),
                "severity": d.get("SEVERITY"),
                "type": d.get("TYPE"),
                "status": d.get("STATUS"),
                "results": d.get("RESULTS"),
                "first_found": d.get("FIRST_FOUND_DATETIME"),
                "last_found": d.get("LAST_FOUND_DATETIME"),
                "hostname": hostname,
                "ip": h.get("IP"),
                "os": h.get("OS"),
                "qualys_host_id": h.get("ID"),
            })
    return out


async def _fetch_knowledgebase(endpoint: str, username: str, password: str, qids: list[str]) -> dict:
    """Fetch QID → {title, cve, cvss, cwe, remediation} from the Qualys knowledgebase."""
    if not qids:
        return {}
    url = endpoint.rstrip("/") + "/api/2.0/fo/knowledge_base/vuln/"
    params = {"action": "list", "ids": ",".join(qids)}
    headers = {"X-Requested-With": "VulnOps"}
    async with httpx.AsyncClient(timeout=120, auth=(username, password)) as c:
        r = await c.post(url, params=params, headers=headers)
        r.raise_for_status()
    kb: dict = {}
    try:
        root = ET.fromstring(r.content)
    except ET.ParseError:
        return {}
    for v in root.iter("VULN"):
        qid = v.findtext("QID") or ""
        cves = [cv.findtext("ID") or "" for cv in v.iter("CVE")]
        kb[qid] = {
            "title": v.findtext("TITLE") or f"QID {qid}",
            "cve": cves[0] if cves else None,
            "cvss": float(v.findtext("CVSS_V3/BASE") or v.findtext("CVSS/BASE") or 0) or None,
            "cwe": (v.findtext("CWE/CWE_ID") or None),
            "category": v.findtext("CATEGORY"),
            "consequence": v.findtext("CONSEQUENCE"),
            "diagnosis": v.findtext("DIAGNOSIS"),
            "solution": v.findtext("SOLUTION"),
        }
    return kb


async def _upsert_asset(db, hostname: str, ip: str | None, os_name: str | None) -> dict:
    asset = await db.assets.find_one({"hostname": hostname}, {"_id": 0})
    if asset:
        return asset
    asset = {
        "id": str(uuid.uuid4()), "hostname": hostname, "ip": ip, "fqdn": None,
        "environment": "unknown", "criticality": "medium",
        "exposure": "internal", "platform": "Linux" if "linux" in (os_name or "").lower() else ("Windows" if "windows" in (os_name or "").lower() else "unknown"),
        "operating_system": os_name or "unknown",
        "asset_type": "server",
        "owner_team": "Unassigned", "product_id": None, "product_name": None,
        "tags": ["qualys"],
        "status": "active", "created_at": _now_iso(),
        "ownership_confidence": 0.3,
        "ownership_rationale": "Auto-created from Qualys VMDR live sync (no tag rule match)",
    }
    await db.assets.insert_one(asset)
    return asset


async def _upsert_finding(db, det: dict, kb: dict) -> str:
    qid = det["qid"]
    kb_entry = kb.get(qid, {})
    asset = await _upsert_asset(db, det["hostname"], det.get("ip"), det.get("os"))
    severity = _norm_severity(det.get("severity"))
    cve = kb_entry.get("cve")
    canonical = f"{cve or qid}::{asset['hostname']}"
    existing = await db.findings.find_one({"canonical_key": canonical}, {"_id": 0})

    base = {
        "source_tool": "Qualys VMDR",
        "source_observation_id": qid,
        "source_native_id": qid,
        "qid": qid, "plugin_id": None,
        "title": kb_entry.get("title") or f"Qualys QID {qid}",
        "description": kb_entry.get("diagnosis") or kb_entry.get("consequence"),
        "severity": severity,
        "cve": cve, "cwe": kb_entry.get("cwe"),
        "cvss_score": kb_entry.get("cvss"),
        "epss_score": 0,  # EPSS enriched by nightly_rescore
        "kev_flag": False,
        "rti": [],
        "remediation": kb_entry.get("solution"),
        "detection_logic": kb_entry.get("category"),
        "asset_id": asset["id"], "asset_hostname": asset["hostname"], "asset_ip": asset.get("ip"),
        "asset_criticality": asset["criticality"], "asset_exposure": asset["exposure"],
        "asset_environment": asset["environment"], "asset_os": asset.get("operating_system"),
        "internet_facing": asset["exposure"] in ("internet", "external"),
        "owner_team": asset["owner_team"],
        "ownership_confidence": asset.get("ownership_confidence", 0.5),
        "product_id": asset.get("product_id"), "product_name": asset.get("product_name"),
        "last_seen_at": det.get("last_found") or _now_iso(),
        "last_changed_at": _now_iso(),
        "imported_at": _now_iso(), "detection_channel": "qualys_api",
        "qualys_status": det.get("status"),
        "qualys_results": (det.get("results") or "")[:5000],
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
        risk = compute_risk({**existing, **base}, asset)
        base["risk_score"] = risk["score"]
        base["risk_breakdown"] = risk["breakdown"]
        await db.findings.update_one({"id": existing["id"]}, {"$set": base})
        return "updated"

    new_finding = {
        "id": str(uuid.uuid4()), "canonical_key": canonical,
        "first_seen_at": det.get("first_found") or _now_iso(),
        "reopened_count": 0,
        "status": "New", "validation_status": "pending",
        "sla_days": compute_sla_days(severity, asset["criticality"]),
        "due_at": (datetime.now(timezone.utc) + timedelta(days=compute_sla_days(severity, asset["criticality"]))).isoformat(),
        "tags": asset.get("tags", []),
        "compliance_scope": [], "advisory_links": [], "exploit_references": [],
        **base,
    }
    risk = compute_risk(new_finding, asset)
    new_finding["risk_score"] = risk["score"]
    new_finding["risk_breakdown"] = risk["breakdown"]
    await db.findings.insert_one(new_finding)
    return "created"


async def run_qualys_sync(db) -> dict:
    """Pull detections from Qualys, upsert findings + assets, write a job + run record."""
    integration = await _get_integration(db)
    if not integration:
        raise RuntimeError("Qualys VMDR integration not found")
    cfg = integration.get("config") or {}
    endpoint = cfg.get("endpoint")
    username = cfg.get("username")
    password = cfg.get("api_key")  # stored in api_key per existing UI
    if not endpoint or not username or not password:
        raise RuntimeError("Qualys integration missing endpoint/username/api_key")

    sync_scope = cfg.get("sync_scope") or {}
    severities = sync_scope.get("severities", "4-5")
    statuses = sync_scope.get("statuses", "Active,Re-Opened")

    started_at = _now_iso()
    errors: list = []
    created = updated = 0

    try:
        xml_body = await _fetch_qualys_detections(endpoint, username, password,
                                                  severities=severities,
                                                  statuses=statuses)
        detections = _parse_detections(xml_body)
    except httpx.HTTPStatusError as e:
        errors.append({"stage": "fetch", "error": f"HTTP {e.response.status_code}: {e.response.text[:200]}"})
        return await _record_run(db, "failed",
                                 {"started_at": started_at, "detections": 0, "created": 0,
                                  "updated": 0, "deduped": 0, "failed": 1}, errors)
    except Exception as e:
        errors.append({"stage": "fetch", "error": str(e)})
        return await _record_run(db, "failed",
                                 {"started_at": started_at, "detections": 0, "created": 0,
                                  "updated": 0, "deduped": 0, "failed": 1}, errors)

    qids = sorted({d["qid"] for d in detections if d.get("qid")})
    kb: dict = {}
    # Chunk knowledge-base fetches to keep the URL short
    for i in range(0, len(qids), 100):
        chunk = qids[i:i + 100]
        try:
            kb.update(await _fetch_knowledgebase(endpoint, username, password, chunk))
        except Exception as e:
            errors.append({"stage": "kb_fetch", "qids": chunk[:5], "error": str(e)})

    for det in detections:
        try:
            outcome = await _upsert_finding(db, det, kb)
            if outcome == "created":
                created += 1
            else:
                updated += 1
        except Exception as e:
            errors.append({"stage": "upsert", "qid": det.get("qid"), "hostname": det.get("hostname"), "error": str(e)})

    summary = {
        "started_at": started_at,
        "detections": len(detections),
        "unique_qids": len(qids),
        "kb_entries": len(kb),
        "created": created,
        "updated": updated,
        "deduped": updated,
        "failed": len(errors),
    }
    status = "success" if created or updated else ("failed" if errors else "success")
    await db.integrations.update_one(
        {"id": integration["id"]},
        {"$set": {"status": "healthy" if status == "success" else "degraded",
                  "last_sync_at": _now_iso(),
                  "sync_errors": 0 if status == "success" else (integration.get("sync_errors", 0) + 1)}},
    )
    return await _record_run(db, status, summary, errors)


async def qualys_poll_loop(db, interval_minutes: int = 60):
    """Background poll. Skips silently if Qualys integration is not configured."""
    # Initial small delay so other startup tasks (seed, index creation) settle
    await asyncio.sleep(20)
    while True:
        try:
            integration = await _get_integration(db)
            cfg = (integration or {}).get("config") or {}
            if cfg.get("endpoint") and cfg.get("username") and cfg.get("api_key"):
                logger.info("Qualys poll: running sync")
                summary = await run_qualys_sync(db)
                logger.info(f"Qualys poll done: {summary.get('summary')}")
            else:
                logger.info("Qualys poll: integration not configured, skipping")
        except Exception as e:
            logger.exception(f"Qualys poll error: {e}")
        await asyncio.sleep(interval_minutes * 60)
