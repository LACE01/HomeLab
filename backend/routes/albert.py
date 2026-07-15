"""Albert (CIS/MS-ISAC network monitoring) alert export ingestion and dashboard.

Uploads are .xlsx exports pulled manually from the CIS ANET portal -- there's no
API to pull these automatically, so this is a file-upload workflow (same shape as
the SBOM upload in routes/sbom.py), not a scheduled sync.
"""
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel

from db import db
from rbac import require_module
from routes.common import record_engagement, now_iso
from albert_ingest import (
    import_albert_export, compute_albert_stats, compute_albert_signatures,
    compute_albert_sankey, _is_public_ip,
)
from albert_enrichment import enrich_ip, get_enrichment, auto_enrich_top_ips
from albert_allowlist import (
    list_allowlist, add_allowlist_entry, delete_allowlist_entry, reapply_allowlist,
)
from threat_intel_watchlist import add_ioc

router = APIRouter()


def _clean(d: dict) -> dict:
    d = dict(d)
    d.pop("_id", None)
    return d


@router.post("/v1/admin/albert/upload")
async def upload_albert_export(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    user: dict = Depends(require_module("/admin/albert", level="edit")),
):
    if not file.filename or not file.filename.lower().endswith(".xlsx"):
        raise HTTPException(400, "Upload an Albert alert export as .xlsx")
    content = await file.read()
    if not content:
        raise HTTPException(400, "That file is empty")

    started_at = now_iso()
    try:
        result = await import_albert_export(db, content, file.filename, uploaded_by=user.get("email"))
    except ValueError as e:
        await record_engagement(
            db, name=file.filename, scanner="Albert (CIS/MS-ISAC)", scan_type="file_upload",
            scan_method="manual_upload", status="failed", started_at=started_at, error=str(e),
        )
        raise HTTPException(400, str(e))
    except Exception as e:
        await record_engagement(
            db, name=file.filename, scanner="Albert (CIS/MS-ISAC)", scan_type="file_upload",
            scan_method="manual_upload", status="failed", started_at=started_at, error=str(e),
        )
        raise HTTPException(500, f"Couldn't process that file: {e}")

    await record_engagement(
        db, name=file.filename, scanner="Albert (CIS/MS-ISAC)", scan_type="file_upload",
        scan_method="manual_upload", status="completed", started_at=started_at,
        assets_scanned=result["rows_parsed"], findings_created=result["rows_parsed"],
    )

    # Auto-enrich the top public destination IPs from this import against the
    # existing threat-intel connectors, in the background so the upload response
    # doesn't wait on a handful of external API calls. Bounded (see
    # auto_enrich_top_ips) to stay well under tight free-tier rate limits.
    top_ips = result.pop("top_public_destination_ips", [])
    if top_ips:
        background_tasks.add_task(auto_enrich_top_ips, db, top_ips)
        result["auto_enrichment_queued"] = top_ips[:8]

    return result


@router.get("/v1/admin/albert/imports")
async def list_albert_imports(user: dict = Depends(require_module("/admin/albert"))):
    docs = await db.albert_imports.find({}, {"_id": 0}).sort("uploaded_at", -1).to_list(200)
    return docs


@router.get("/v1/admin/albert/stats")
async def albert_stats(days: int = 30, include_suppressed: bool = False, user: dict = Depends(require_module("/admin/albert"))):
    days = max(1, min(days, 365))
    return await compute_albert_stats(db, days=days, include_suppressed=include_suppressed)


@router.get("/v1/admin/albert/signatures")
async def albert_signatures(days: int = 90, user: dict = Depends(require_module("/admin/albert"))):
    days = max(1, min(days, 365))
    return await compute_albert_signatures(db, days=days)


@router.get("/v1/admin/albert/sankey")
async def albert_sankey(days: int = 30, user: dict = Depends(require_module("/admin/albert"))):
    days = max(1, min(days, 365))
    return await compute_albert_sankey(db, days=days)


@router.get("/v1/admin/albert/enrichment/{ip}")
async def get_ip_enrichment(ip: str, user: dict = Depends(require_module("/admin/albert"))):
    doc = await get_enrichment(db, ip)
    return doc or {"ip": ip, "results": [], "checked_at": None}


@router.post("/v1/admin/albert/enrichment/{ip}/refresh")
async def refresh_ip_enrichment(ip: str, user: dict = Depends(require_module("/admin/albert", level="edit"))):
    if not _is_public_ip(ip):
        raise HTTPException(400, "Only public IPs can be checked against external threat-intel connectors")
    return await enrich_ip(db, ip)


@router.get("/v1/admin/albert/alerts")
async def list_albert_alerts(
    severity: Optional[str] = None,
    category: Optional[str] = None,
    device: Optional[str] = None,
    q: Optional[str] = None,
    alert_message: Optional[str] = None,
    acknowledged: Optional[bool] = None,
    include_suppressed: bool = False,
    page: int = 1,
    page_size: int = 50,
    user: dict = Depends(require_module("/admin/albert")),
):
    flt = {}
    if not include_suppressed:
        flt["suppressed"] = {"$ne": True}
    if acknowledged is not None:
        flt["acknowledged"] = acknowledged if acknowledged else {"$ne": True}
    if severity:
        flt["severity"] = severity
    if category:
        flt["category"] = category
    if device:
        flt["device"] = device
    if alert_message:
        # Exact match, used for "drill into this exact signature" clicks from the
        # Alert Signatures Explained panel -- deliberately not folded into `q`
        # (regex substring search) since signature text can contain regex
        # metacharacters (., -, parentheses) that would otherwise need escaping.
        flt["alert_message"] = alert_message
    if q:
        flt["$or"] = [
            {"alert_message": {"$regex": q, "$options": "i"}},
            {"source_ip": {"$regex": q, "$options": "i"}},
            {"destination_ip": {"$regex": q, "$options": "i"}},
        ]
    page = max(1, page)
    page_size = max(1, min(page_size, 200))
    total = await db.albert_alerts.count_documents(flt)
    items = await db.albert_alerts.find(flt, {"_id": 0}).sort("time_gmt", -1).skip((page - 1) * page_size).limit(page_size).to_list(page_size)
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.get("/v1/admin/albert/alerts/{alert_id}")
async def get_albert_alert(alert_id: str, user: dict = Depends(require_module("/admin/albert"))):
    doc = await db.albert_alerts.find_one({"id": alert_id}, {"_id": 0})
    if not doc:
        raise HTTPException(404, "Alert not found")
    # Match source/destination IPs against inventory so the alert can link straight
    # to an asset page instead of just showing a bare IP -- asset docs store a
    # single "ip" field (see routes/inventory.py's IP search filter).
    for field, out_key in (("source_ip", "source_asset"), ("destination_ip", "destination_asset")):
        ip = doc.get(field)
        doc[out_key] = None
        if ip:
            asset = await db.assets.find_one({"ip": ip}, {"_id": 0, "id": 1, "hostname": 1, "criticality": 1, "environment": 1})
            if asset:
                doc[out_key] = asset
    return doc


class BulkAlertIds(BaseModel):
    alert_ids: List[str]


class BulkWatchlistBody(BaseModel):
    alert_ids: List[str]
    field: str = "destination_ip"  # "source_ip" | "destination_ip"
    severity: str = "High"


@router.post("/v1/admin/albert/alerts/bulk-acknowledge")
async def bulk_acknowledge_alerts(body: BulkAlertIds, user: dict = Depends(require_module("/admin/albert", level="edit"))):
    if not body.alert_ids:
        raise HTTPException(400, "No alerts selected")
    result = await db.albert_alerts.update_many(
        {"id": {"$in": body.alert_ids}}, {"$set": {"acknowledged": True, "acknowledged_by": user["email"], "acknowledged_at": now_iso()}},
    )
    return {"ok": True, "updated": getattr(result, "modified_count", len(body.alert_ids))}


@router.post("/v1/admin/albert/alerts/bulk-unacknowledge")
async def bulk_unacknowledge_alerts(body: BulkAlertIds, user: dict = Depends(require_module("/admin/albert", level="edit"))):
    if not body.alert_ids:
        raise HTTPException(400, "No alerts selected")
    result = await db.albert_alerts.update_many(
        {"id": {"$in": body.alert_ids}}, {"$set": {"acknowledged": False}},
    )
    return {"ok": True, "updated": getattr(result, "modified_count", len(body.alert_ids))}


@router.post("/v1/admin/albert/alerts/bulk-watchlist")
async def bulk_add_to_watchlist(body: BulkWatchlistBody, user: dict = Depends(require_module("/admin/albert", level="edit"))):
    if not body.alert_ids:
        raise HTTPException(400, "No alerts selected")
    if body.field not in ("source_ip", "destination_ip"):
        raise HTTPException(400, "field must be source_ip or destination_ip")
    alerts = await db.albert_alerts.find({"id": {"$in": body.alert_ids}}, {"_id": 0, body.field: 1}).to_list(len(body.alert_ids))
    ips = sorted({a[body.field] for a in alerts if a.get(body.field) and _is_public_ip(a[body.field])})
    added = []
    for ip in ips:
        await add_ioc(db, ioc_type="ip", value=ip, source="albert_manual", severity=body.severity,
                       notes=f"Added from Albert alert bulk action by {user['email']}", added_by=user["email"])
        added.append(ip)
    return {"ok": True, "added": added, "skipped_private_or_missing": len(alerts) - len(ips)}


@router.get("/v1/admin/albert/allowlist")
async def get_allowlist(user: dict = Depends(require_module("/admin/albert"))):
    return await list_allowlist(db)


@router.post("/v1/admin/albert/allowlist")
async def post_allowlist(body: dict, user: dict = Depends(require_module("/admin/albert", level="edit"))):
    source_ip = (body or {}).get("source_ip")
    notes = (body or {}).get("notes")
    try:
        entry = await add_allowlist_entry(db, source_ip, notes=notes, added_by=user["email"])
    except ValueError as e:
        raise HTTPException(400, str(e))
    return entry


@router.delete("/v1/admin/albert/allowlist/{entry_id}")
async def remove_allowlist_entry(entry_id: str, user: dict = Depends(require_module("/admin/albert", level="edit"))):
    ok = await delete_allowlist_entry(db, entry_id)
    if not ok:
        raise HTTPException(404, "Allowlist entry not found")
    return {"ok": True}


@router.post("/v1/admin/albert/allowlist/reapply")
async def post_reapply_allowlist(user: dict = Depends(require_module("/admin/albert", level="edit"))):
    return await reapply_allowlist(db)
