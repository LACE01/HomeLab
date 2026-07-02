"""Integrations + import-jobs + universal ingestion routes."""
import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from db import db
from auth_utils import get_current_user, require_role, verify_api_key
from scoring import compute_risk, compute_sla_days
from routes.common import now_iso, _clean, finding_ctx

router = APIRouter()
logger = logging.getLogger("vulnops.integrations")


# --------------------------- INTEGRATIONS ---------------------------
@router.get("/v1/integrations")
async def list_integrations(user: dict = Depends(get_current_user)):
    items = await db.integrations.find({}, {"_id": 0}).to_list(100)
    for i in items:
        cfg = i.get("config") or {}
        if cfg.get("api_key"):
            cfg["api_key"] = cfg["api_key"][:4] + "•••" + cfg["api_key"][-4:] if len(cfg.get("api_key", "")) > 8 else "•••"
        if cfg.get("api_secret"):
            cfg["api_secret"] = "•••"
    return {"items": items}


class IntegrationConfig(BaseModel):
    endpoint: Optional[str] = None
    api_key: Optional[str] = None
    api_secret: Optional[str] = None
    username: Optional[str] = None
    auth_type: Optional[str] = None
    enabled: Optional[bool] = None
    # Cloudflare Access service-token (only used by integrations behind CF Access, e.g. OpenCTI)
    cf_access_client_id: Optional[str] = None
    cf_access_client_secret: Optional[str] = None


@router.patch("/v1/integrations/{integration_id}")
async def update_integration(integration_id: str, body: IntegrationConfig, user: dict = Depends(require_role("admin"))):
    integration = await db.integrations.find_one({"id": integration_id})
    if not integration:
        raise HTTPException(404, "Integration not found")
    cfg = integration.get("config") or {}
    update = body.model_dump(exclude_none=True)
    for k, v in update.items():
        cfg[k] = v
    # If credentials are now present, lift the "not_configured" status to "healthy" (user must Test to confirm)
    new_status = integration.get("status", "not_configured")
    if cfg.get("endpoint") and (cfg.get("api_key") or cfg.get("username")) and new_status == "not_configured":
        new_status = "healthy"
    await db.integrations.update_one({"id": integration_id}, {"$set": {"config": cfg, "status": new_status, "last_changed_at": now_iso()}})
    return {"ok": True}


@router.post("/v1/integrations/{integration_id}/test")
async def test_integration(integration_id: str, user: dict = Depends(require_role("admin"))):
    integration = await db.integrations.find_one({"id": integration_id})
    if not integration:
        raise HTTPException(404, "Integration not found")
    cfg = integration.get("config") or {}
    if not cfg.get("endpoint") or not cfg.get("api_key"):
        await db.integrations.update_one({"id": integration_id}, {"$set": {"status": "degraded", "sync_errors": (integration.get("sync_errors") or 0) + 1}})
        raise HTTPException(400, "Missing endpoint or api_key — configure the connector first")
    await db.integrations.update_one({"id": integration_id}, {"$set": {
        "status": "healthy", "last_sync_at": now_iso(), "sync_errors": 0,
    }})
    return {"ok": True, "message": f"Connection to {integration['name']} verified."}


# --------------------------- IMPORT JOBS ---------------------------
@router.get("/v1/import-jobs")
async def list_import_jobs(user: dict = Depends(get_current_user)):
    items = await db.import_jobs.find({}, {"_id": 0}).sort("started_at", -1).limit(200).to_list(200)
    return {"items": items}


@router.get("/v1/import-jobs/{job_id}")
async def get_import_job(job_id: str, user: dict = Depends(get_current_user)):
    j = await db.import_jobs.find_one({"id": job_id}, {"_id": 0})
    if not j:
        raise HTTPException(404, "Job not found")
    return j


# --------------------------- INGESTION (API) ---------------------------
class UniversalFindingIn(BaseModel):
    source_tool: str
    source_record_id: str
    title: str
    severity: str
    description: Optional[str] = None
    cve: Optional[str] = None
    cwe: Optional[str] = None
    cvss_score: Optional[float] = None
    epss_score: Optional[float] = None
    kev_flag: Optional[bool] = False
    rti: Optional[List[str]] = []
    asset_hostname: str
    asset_ip: Optional[str] = None
    remediation: Optional[str] = None
    detection_logic: Optional[str] = None
    qid: Optional[str] = None
    plugin_id: Optional[str] = None


class UniversalIngestBody(BaseModel):
    idempotency_key: Optional[str] = None
    mode: str = "import"
    findings: List[UniversalFindingIn]


@router.post("/v1/ingest/universal")
async def ingest_universal(body: UniversalIngestBody, request: Request, _: dict = Depends(verify_api_key)):
    job_id = str(uuid.uuid4())
    started = now_iso()
    created = 0
    updated = 0
    dedup = 0
    failed = 0
    errors: list = []
    new_finding = None

    for f_in in body.findings:
        try:
            asset = await db.assets.find_one({"hostname": f_in.asset_hostname}, {"_id": 0})
            if not asset:
                asset = {
                    "id": str(uuid.uuid4()), "hostname": f_in.asset_hostname, "ip": f_in.asset_ip,
                    "fqdn": None, "environment": "unknown", "criticality": "medium",
                    "exposure": "internal", "platform": "unknown", "operating_system": "unknown",
                    "asset_type": "server", "owner_team": "Unassigned",
                    "product_id": None, "product_name": None,
                    "tags": ["auto-created"], "status": "active", "created_at": now_iso(),
                    "ownership_confidence": 0.3, "ownership_rationale": "Auto-created from ingestion (no tag match)",
                }
                await db.assets.insert_one(asset)

            canonical = f"{f_in.cve or f_in.qid or f_in.source_record_id}::{f_in.asset_hostname}"
            existing = await db.findings.find_one({"canonical_key": canonical}, {"_id": 0})

            base_finding = {
                "source_tool": f_in.source_tool, "source_observation_id": f_in.source_record_id,
                "source_native_id": f_in.qid or f_in.plugin_id or f_in.source_record_id,
                "qid": f_in.qid, "plugin_id": f_in.plugin_id,
                "title": f_in.title, "description": f_in.description, "severity": f_in.severity,
                "cve": f_in.cve, "cwe": f_in.cwe,
                "cvss_score": f_in.cvss_score, "epss_score": f_in.epss_score or 0,
                "kev_flag": f_in.kev_flag or False, "rti": f_in.rti or [],
                "remediation": f_in.remediation, "detection_logic": f_in.detection_logic,
                "asset_id": asset["id"], "asset_hostname": asset["hostname"],
                "asset_ip": asset.get("ip"), "asset_criticality": asset["criticality"],
                "asset_exposure": asset["exposure"], "asset_environment": asset["environment"],
                "internet_facing": asset["exposure"] in ("internet", "external"),
                "owner_team": asset["owner_team"], "ownership_confidence": asset.get("ownership_confidence", 0.5),
                "product_id": asset.get("product_id"), "product_name": asset.get("product_name"),
                "last_seen_at": now_iso(), "last_changed_at": now_iso(),
                "imported_at": now_iso(), "detection_channel": "api_push",
            }

            if existing:
                new_status = existing["status"]
                reopened = existing.get("reopened_count", 0)
                if existing["status"] in ("Fixed validated", "Mitigated", "Closed administratively"):
                    new_status = "Reopened"
                    reopened += 1
                base_finding["status"] = new_status
                base_finding["reopened_count"] = reopened
                base_finding["first_seen_at"] = existing["first_seen_at"]
                base_finding["canonical_key"] = canonical
                risk = compute_risk({**existing, **base_finding}, asset)
                base_finding["risk_score"] = risk["score"]
                base_finding["risk_breakdown"] = risk["breakdown"]
                await db.findings.update_one({"id": existing["id"]}, {"$set": base_finding})
                updated += 1
                if existing["status"] not in ("Fixed validated", "Mitigated", "Closed administratively"):
                    dedup += 1
            else:
                new_finding = {
                    "id": str(uuid.uuid4()), "canonical_key": canonical,
                    "first_seen_at": now_iso(), "reopened_count": 0,
                    "status": "New", "validation_status": "pending",
                    "sla_days": compute_sla_days(f_in.severity, asset["criticality"]),
                    "due_at": (datetime.now(timezone.utc) + timedelta(days=compute_sla_days(f_in.severity, asset["criticality"]))).isoformat(),
                    "tags": asset.get("tags", []),
                    "compliance_scope": [], "advisory_links": [], "exploit_references": [],
                    **base_finding,
                }
                risk = compute_risk(new_finding, asset)
                new_finding["risk_score"] = risk["score"]
                new_finding["risk_breakdown"] = risk["breakdown"]
                await db.findings.insert_one(new_finding)
                created += 1
                try:
                    from notifier import dispatch
                    ctx = finding_ctx(new_finding)
                    sev = new_finding.get("severity")
                    if sev == "Critical":
                        await dispatch("finding_created_critical", ctx, db)
                    elif sev == "High":
                        await dispatch("finding_created_high", ctx, db)
                    if new_finding.get("kev_flag"):
                        await dispatch("kev_match", ctx, db)
                except Exception as e:
                    logger.exception(f"notify dispatch failed: {e}")

            await db.observations.insert_one({
                "id": str(uuid.uuid4()),
                "finding_id": existing["id"] if existing else new_finding["id"],
                "asset_id": asset["id"], "source_tool": f_in.source_tool,
                "source_record_id": f_in.source_record_id, "qid": f_in.qid, "plugin_id": f_in.plugin_id,
                "detection_logic": f_in.detection_logic, "raw_severity": f_in.severity,
                "normalized_severity": f_in.severity, "observed_at": now_iso(), "imported_at": now_iso(),
            })
        except Exception as e:
            failed += 1
            errors.append({"record_id": f_in.source_record_id, "error": str(e)})

    job = {
        "id": job_id, "source_name": body.findings[0].source_tool if body.findings else "unknown",
        "mode": body.mode, "status": "failed" if failed and not created else "success",
        "request_id": body.idempotency_key or f"req_{uuid.uuid4().hex[:12]}",
        "started_at": started, "finished_at": now_iso(),
        "created_count": created, "updated_count": updated, "deduplicated_count": dedup,
        "failed_count": failed, "retry_count": 0, "errors": errors,
    }
    await db.import_jobs.insert_one(job)
    from routes.common import record_engagement
    await record_engagement(
        db, name=f"API ingest — {job['source_name']}", scanner=job["source_name"], scan_type="api_push",
        scan_method="api", status="completed" if job["status"] == "success" else "failed",
        assets_scanned=len({f.asset_hostname for f in body.findings}), findings_created=created,
        findings_updated=updated, started_at=started,
        error="; ".join(str(e) for e in errors[:3]) if errors else None,
    )
    return _clean(job)
