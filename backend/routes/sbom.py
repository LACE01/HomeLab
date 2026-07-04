"""SBOM upload endpoint + history."""
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile

from db import db
from rbac import require_module
from auth_utils import require_role

router = APIRouter()


@router.post("/v1/admin/sbom/upload")
async def upload_sbom(
    file: UploadFile = File(...),
    label: str = Form(""),
    asset_id: str = Form(""),
    user: dict = Depends(require_role("admin")),
):
    if not file.filename or not file.filename.lower().endswith((".json", ".cdx.json", ".spdx.json")):
        raise HTTPException(400, "Upload a CycloneDX or SPDX SBOM as JSON")
    content = await file.read()
    from sbom import import_sbom
    from routes.common import record_engagement, now_iso
    started = now_iso()
    try:
        result = await import_sbom(db, content, filename=file.filename, label=label or None, asset_id=asset_id or None)
    except ValueError as e:
        await record_engagement(db, name=label or file.filename, scanner="SBOM / OSV.dev", scan_type="manual_upload",
                                 scan_method="file_upload", status="failed", started_at=started, error=str(e))
        raise HTTPException(400, str(e))
    except Exception as e:
        await record_engagement(db, name=label or file.filename, scanner="SBOM / OSV.dev", scan_type="manual_upload",
                                 scan_method="file_upload", status="failed", started_at=started, error=str(e))
        raise HTTPException(502, f"OSV.dev lookup failed: {e}")
    await record_engagement(
        db, name=label or file.filename, scanner="SBOM / OSV.dev", scan_type="manual_upload",
        scan_method="file_upload", status="completed",
        assets_scanned=result.get("components_parsed", 0), findings_created=result.get("findings_created", 0),
        findings_updated=result.get("findings_updated", 0), started_at=started,
    )
    return result


@router.get("/v1/admin/sbom/uploads")
async def list_sbom_uploads(user: dict = Depends(require_role("admin")), _rbac: dict = Depends(require_module("/admin/sbom"))):
    items = await db.sbom_uploads.find({}, {"_id": 0}).sort("uploaded_at", -1).to_list(100)
    return {"items": items}
