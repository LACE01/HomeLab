"""YARA rule library CRUD + file-upload scanning + scan history."""
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel

from db import db
from rbac import require_module
from auth_utils import get_current_user, require_role
from routes.common import now_iso, _clean

router = APIRouter()

MAX_UPLOAD_BYTES = 25 * 1024 * 1024  # 25MB -- plenty for scripts/binaries/archives, not for disk images


class RuleBody(BaseModel):
    name: str
    description: Optional[str] = ""
    source: str
    enabled: bool = True


class ValidateBody(BaseModel):
    source: str


@router.get("/v1/admin/yara/rules")
async def list_rules(user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/admin/yara"))):
    items = await db.yara_rules.find({}, {"_id": 0}).sort("name", 1).to_list(500)
    return {"items": items}


@router.post("/v1/admin/yara/rules/validate")
async def validate_rule(body: ValidateBody, user: dict = Depends(require_role("admin"))):
    from yara_scan import validate_rule_source
    return validate_rule_source(body.source)


@router.post("/v1/admin/yara/rules")
async def create_rule(body: RuleBody, user: dict = Depends(require_role("admin"))):
    from yara_scan import validate_rule_source
    check = validate_rule_source(body.source)
    doc = {
        "id": str(uuid.uuid4()), **body.model_dump(),
        "valid": check["ok"], "compile_error": check["error"],
        "created_at": now_iso(), "created_by": user["email"],
    }
    await db.yara_rules.insert_one(doc)
    return _clean(doc)


@router.put("/v1/admin/yara/rules/{rule_id}")
async def update_rule(rule_id: str, body: RuleBody, user: dict = Depends(require_role("admin"))):
    from yara_scan import validate_rule_source
    existing = await db.yara_rules.find_one({"id": rule_id}, {"_id": 0})
    if not existing:
        raise HTTPException(404, "Rule not found")
    check = validate_rule_source(body.source)
    update = {**body.model_dump(), "valid": check["ok"], "compile_error": check["error"], "updated_at": now_iso()}
    await db.yara_rules.update_one({"id": rule_id}, {"$set": update})
    return {**existing, **update}


@router.delete("/v1/admin/yara/rules/{rule_id}")
async def delete_rule(rule_id: str, user: dict = Depends(require_role("admin"))):
    await db.yara_rules.delete_one({"id": rule_id})
    return {"ok": True}


@router.post("/v1/admin/yara/scan")
async def scan_file(
    file: UploadFile = File(...),
    label: str = Form(""),
    asset_id: str = Form(""),
    user: dict = Depends(require_role("admin")),
):
    content = await file.read()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(400, f"File too large -- max {MAX_UPLOAD_BYTES // (1024*1024)}MB")
    from yara_scan import run_yara_scan
    try:
        return await run_yara_scan(db, filename=file.filename or "upload", content=content,
                                    label=label or None, asset_id=asset_id or None)
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.get("/v1/admin/yara/history")
async def scan_history(user: dict = Depends(get_current_user)):
    items = await db.yara_scan_history.find(
        {}, {"_id": 0, "matches.strings": 0}  # list view doesn't need per-string offsets, just counts
    ).sort("scanned_at", -1).to_list(100)
    return {"items": items}


@router.get("/v1/admin/yara/history/{scan_id}")
async def scan_detail(scan_id: str, user: dict = Depends(get_current_user)):
    doc = await db.yara_scan_history.find_one({"id": scan_id}, {"_id": 0})
    if not doc:
        raise HTTPException(404, "Scan not found")
    return doc
