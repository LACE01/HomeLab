"""Integrations + import-jobs + universal ingestion routes."""
import logging
import re
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from db import db
from rbac import require_module
from auth_utils import get_current_user, require_role, verify_api_key
from scoring import compute_risk, compute_sla_days
from routes.common import now_iso, _clean, finding_ctx

router = APIRouter()
logger = logging.getLogger("vulnops.integrations")

# Azure AD app-registration-backed connectors (client-credentials OAuth via msgraph.py)
# and the OAuth "resource"/scope each authenticates against. Entra ID and Intune both
# go through Microsoft Graph; Defender for Endpoint uses its own separate API surface
# with its own token audience -- a Graph token will NOT work against it and vice versa,
# so these are NOT interchangeable even though the same tenant_id/client_id/client_secret
# COULD be reused across all three if a single app registration was granted every
# permission (not recommended -- see IntegrationConfig's docstring above).
MSGRAPH_CONNECTOR_SCOPES = {
    "Microsoft Entra ID": "https://graph.microsoft.com/.default",
    "Microsoft Intune": "https://graph.microsoft.com/.default",
    "Microsoft Defender for Endpoint": "https://api.security.microsoft.com/.default",
}


# --------------------------- INTEGRATIONS ---------------------------
@router.get("/v1/integrations")
async def list_integrations(user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/integrations"))):
    items = await db.integrations.find({}, {"_id": 0}).to_list(100)
    for i in items:
        cfg = i.get("config") or {}
        if cfg.get("api_key"):
            cfg["api_key"] = cfg["api_key"][:4] + "•••" + cfg["api_key"][-4:] if len(cfg.get("api_key", "")) > 8 else "•••"
        if cfg.get("api_secret"):
            cfg["api_secret"] = "•••"
        if cfg.get("cf_access_client_secret"):
            cfg["cf_access_client_secret"] = "•••"
        if cfg.get("client_secret"):
            cfg["client_secret"] = "•••"
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
    # Microsoft Graph / Defender-for-Endpoint client-credentials app registration --
    # used by Microsoft Entra ID, Microsoft Defender for Endpoint, and Microsoft
    # Intune (see msgraph.py). Each of those three is its own integration card with
    # its own tenant_id/client_id/client_secret because real-world Azure AD app
    # registrations are typically scoped per-product (least privilege: an Entra ID
    # read-only app shouldn't also hold Defender machine-read permissions), even
    # though nothing stops an org from pointing all three at the same app registration.
    tenant_id: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    # Org's own domain for domain-wide breach monitoring (HaveIBeenPwned Domain Search)
    domain: Optional[str] = None


# Cloudflare's own service-token detail page (and most API docs, including OpenCTI's
# "Required Headers" panel) show copy-pasteable text in the form "Header-Name: value"
# specifically so it can be dropped straight into a curl command or client config --
# which is exactly the wrong thing to paste into a field that expects ONLY the value
# and constructs the header name itself. Pasting "CF-Access-Client-Id: abc123.access"
# into the Client ID field produces a real HTTP header of
# "CF-Access-Client-Id: CF-Access-Client-Id: abc123.access", which Cloudflare will
# never match against any real service token -- indistinguishable from the token
# being wrong entirely, and exactly what was found live in one user's config. Strip
# a leading "Header-Name:" prefix (for any of the header-shaped fields) and a leading
# "Bearer " prefix (for API key/token fields, since "Authorization: Bearer <token>" is
# the single most commonly copy-pasted example format for that kind of credential).
_HEADER_PREFIX_RE = re.compile(r"^\s*(?:cf-access-client-id|cf-access-client-secret|authorization)\s*:\s*", re.IGNORECASE)
_BEARER_PREFIX_RE = re.compile(r"^\s*bearer\s+", re.IGNORECASE)


def _clean_credential(field: str, v: str) -> str:
    v = v.strip()
    v = _HEADER_PREFIX_RE.sub("", v)
    if field in ("api_key", "api_secret", "client_secret"):
        v = _BEARER_PREFIX_RE.sub("", v)
    return v.strip()


@router.patch("/v1/integrations/{integration_id}")
async def update_integration(integration_id: str, body: IntegrationConfig, user: dict = Depends(require_role("admin"))):
    integration = await db.integrations.find_one({"id": integration_id})
    if not integration:
        raise HTTPException(404, "Integration not found")
    cfg = integration.get("config") or {}
    update = body.model_dump(exclude_none=True)
    for k, v in update.items():
        # Defensive clean: copy-pasted endpoints/keys/CF-Access tokens frequently carry
        # a trailing newline, stray leading/trailing space, or (see _clean_credential
        # above) an accidentally-included "Header-Name:" / "Bearer " prefix from
        # whatever docs page the value was copied from. A value that LOOKS right but
        # has any of these will fail auth silently -- Cloudflare Access won't even
        # register the service token as "seen" since the header value never matches
        # a real token -- so normalize every string field before it's persisted.
        if isinstance(v, str):
            v = _clean_credential(k, v)
        cfg[k] = v
    # If credentials are now present, lift the "not_configured" status to "healthy" (user must Test to confirm)
    new_status = integration.get("status", "not_configured")
    has_creds = cfg.get("api_key") or cfg.get("username") or (cfg.get("client_id") and cfg.get("client_secret") and cfg.get("tenant_id"))
    if cfg.get("endpoint") and has_creds and new_status == "not_configured":
        new_status = "healthy"
    await db.integrations.update_one({"id": integration_id}, {"$set": {"config": cfg, "status": new_status, "last_changed_at": now_iso()}})
    return {"ok": True}


@router.post("/v1/integrations/{integration_id}/test")
async def test_integration(integration_id: str, user: dict = Depends(require_role("admin"))):
    """Actually reaches out to the configured endpoint rather than just checking that
    endpoint/api_key are non-empty -- a prior version of this rubber-stamped "healthy"
    for any non-blank config, which could report a connector as working when it was
    actually still failing (e.g. an OpenCTI instance stuck behind a Cloudflare Access
    redirect)."""
    integration = await db.integrations.find_one({"id": integration_id})
    if not integration:
        raise HTTPException(404, "Integration not found")
    cfg = integration.get("config") or {}
    name = integration["name"]

    if name in MSGRAPH_CONNECTOR_SCOPES:
        # These three authenticate via an Azure AD app registration (client-credentials
        # OAuth), not an api_key -- the generic endpoint/api_key precheck below doesn't
        # apply to them at all. A real token fetch is also a *stronger* test than the
        # generic reachability probe every other connector gets: it proves tenant_id/
        # client_id/client_secret are actually valid together, not just that some host
        # answered HTTP.
        if not (cfg.get("tenant_id") and cfg.get("client_id") and cfg.get("client_secret")):
            await db.integrations.update_one({"id": integration_id}, {"$set": {"status": "degraded", "sync_errors": (integration.get("sync_errors") or 0) + 1}})
            raise HTTPException(400, "Missing tenant ID, client ID, or client secret — configure the connector first")
        from msgraph import get_client_credentials_token
        try:
            await get_client_credentials_token(db, name, MSGRAPH_CONNECTOR_SCOPES[name], force_refresh=True)
            result = {"ok": True, "message": f"{name}: Azure AD app registration authenticated successfully (token acquired)."}
        except Exception as e:
            result = {"ok": False, "message": str(e)}
    else:
        if not cfg.get("endpoint") or not cfg.get("api_key"):
            await db.integrations.update_one({"id": integration_id}, {"$set": {"status": "degraded", "sync_errors": (integration.get("sync_errors") or 0) + 1}})
            raise HTTPException(400, "Missing endpoint or api_key — configure the connector first")

        if name == "OpenCTI":
            from routes.findings import opencti_ping
            result = await opencti_ping(cfg)
        else:
            result = await _generic_reachability_check(cfg)

    if result["ok"]:
        await db.integrations.update_one({"id": integration_id}, {"$set": {
            "status": "healthy", "last_sync_at": now_iso(), "sync_errors": 0,
        }})
        return {"ok": True, "message": result["message"]}
    else:
        await db.integrations.update_one({"id": integration_id}, {"$set": {
            "status": "degraded", "sync_errors": (integration.get("sync_errors") or 0) + 1,
        }})
        raise HTTPException(502, result["message"])


async def _generic_reachability_check(cfg: dict) -> dict:
    """Best-effort live reachability probe for non-OpenCTI connectors: any HTTP
    response (even 401/403 -- some APIs reject a bare GET but that still proves the
    host is reachable) counts as reachable; connection failures do not. Detects a
    Cloudflare Access login redirect the same way the OpenCTI check does, since any
    connector could sit behind CF Access."""
    import httpx
    endpoint = cfg.get("endpoint")
    headers = {}
    if cfg.get("api_key"):
        headers["Authorization"] = f"Bearer {cfg['api_key']}"
    if cfg.get("cf_access_client_id"):
        headers["CF-Access-Client-Id"] = cfg["cf_access_client_id"]
    if cfg.get("cf_access_client_secret"):
        headers["CF-Access-Client-Secret"] = cfg["cf_access_client_secret"]
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=False) as c:
            r = await c.get(endpoint, headers=headers)
        if r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("location", "")
            if "cloudflareaccess.com" in loc or "/cdn-cgi/access/login" in loc:
                return {"ok": False, "message": "Redirecting to Cloudflare Access login — add a CF Access service token (and make sure it's attached to the Application's policy) or disable Access on this route."}
        return {"ok": True, "message": f"Endpoint reachable (HTTP {r.status_code})."}
    except httpx.TimeoutException:
        return {"ok": False, "message": "Connection timed out — check the endpoint URL and that the server is reachable from this host."}
    except httpx.ConnectError as e:
        return {"ok": False, "message": f"Could not connect: {e}"}
    except Exception as e:
        return {"ok": False, "message": f"Unexpected error: {e}"}


# Connectors with real sync logic wired up (beyond the generic reachability "Test")
# -- dispatch by integration name, same pattern test_integration already uses for
# OpenCTI. Qualys VMDR has its own dedicated /v1/admin/qualys/sync/run endpoint
# (it needs a long-running background job + its own run-history collection), so
# it's deliberately not listed here.
async def _dispatch_sync(name: str, db):
    if name == "Shodan":
        from shodan_sync import sync_shodan_assets
        return await sync_shodan_assets(db)
    if name == "Censys":
        from censys_sync import sync_censys_assets
        return await sync_censys_assets(db)
    if name == "Microsoft Entra ID":
        from entra_sync import sync_entra_directory
        return await sync_entra_directory(db)
    if name == "Microsoft Defender for Endpoint":
        from defender_sync import sync_defender
        return await sync_defender(db)
    if name == "Microsoft Intune":
        from intune_sync import sync_intune
        return await sync_intune(db)
    if name == "HaveIBeenPwned":
        from hibp_domain import sync_hibp_domain_breaches, sync_hibp_stealer_logs
        breach_result = await sync_hibp_domain_breaches(db)
        # Stealer logs are a separate, subscription-tier-gated HIBP entitlement --
        # if this account's plan doesn't include them, don't let that failure hide
        # the breach sync result that DID succeed above; report it alongside
        # instead of raising.
        try:
            stealer_result = await sync_hibp_stealer_logs(db)
        except Exception as e:
            stealer_result = {"error": str(e)}
        return {**breach_result, "stealer_logs": stealer_result}
    raise HTTPException(400, f"'{name}' doesn't have a sync job -- only Test (reachability) is available for it yet.")


@router.post("/v1/integrations/{integration_id}/sync")
async def sync_integration(integration_id: str, user: dict = Depends(require_role("admin"))):
    integration = await db.integrations.find_one({"id": integration_id}, {"_id": 0})
    if not integration:
        raise HTTPException(404, "Integration not found")
    try:
        result = await _dispatch_sync(integration["name"], db)
    except HTTPException:
        raise
    except Exception as e:
        await db.integrations.update_one({"id": integration_id}, {"$set": {
            "status": "degraded", "sync_errors": (integration.get("sync_errors") or 0) + 1,
        }})
        raise HTTPException(502, str(e))
    await db.integrations.update_one({"id": integration_id}, {"$set": {
        "status": "healthy", "last_sync_at": now_iso(), "sync_errors": 0,
    }})
    return {"ok": True, "result": result}


# --------------------------- IMPORT JOBS ---------------------------
@router.get("/v1/import-jobs")
async def list_import_jobs(user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/imports"))):
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
                    # The universal ingest payload has no OS field to classify from,
                    # so this stays a plain default -- edit the asset (or backfill via
                    # POST /v1/admin/assets/recompute-types) once its real OS is known.
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
