"""SBOM upload endpoint + history."""
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile

from db import db
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
    try:
        result = await import_sbom(db, content, filename=file.filename, label=label or None, asset_id=asset_id or None)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(502, f"OSV.dev lookup failed: {e}")
    return result


@router.get("/v1/admin/sbom/uploads")
async def list_sbom_uploads(user: dict = Depends(require_role("admin"))):
    items = await db.sbom_uploads.find({}, {"_id": 0}).sort("uploaded_at", -1).to_list(100)
    return {"items": items}
