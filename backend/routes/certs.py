"""TLS certificate expiry monitoring -- CRUD for watch targets + run-now + status list."""
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from db import db
from auth_utils import get_current_user, require_role
from routes.common import now_iso

router = APIRouter()


class CertTargetBody(BaseModel):
    hostname: str
    port: int = 443
    label: Optional[str] = None
    asset_id: Optional[str] = None
    enabled: bool = True


def _validate(body: CertTargetBody):
    host = (body.hostname or "").strip()
    if not host:
        raise HTTPException(400, "Hostname is required")
    if not (1 <= body.port <= 65535):
        raise HTTPException(400, "Port must be between 1 and 65535")


@router.get("/v1/admin/certs/targets")
async def list_cert_targets(user: dict = Depends(get_current_user)):
    targets = await db.cert_watch_targets.find({}, {"_id": 0}).sort("created_at", -1).to_list(500)
    keys = [f"{t['hostname']}:{t.get('port', 443)}" for t in targets]
    certs = await db.tls_certificates.find({"id": {"$in": keys}}, {"_id": 0}).to_list(500)
    cert_by_key = {c["id"]: c for c in certs}
    for t in targets:
        t["latest"] = cert_by_key.get(f"{t['hostname']}:{t.get('port', 443)}")
    return {"items": targets}


@router.post("/v1/admin/certs/targets")
async def create_cert_target(body: CertTargetBody, user: dict = Depends(require_role("admin"))):
    _validate(body)
    doc = {"id": str(uuid.uuid4()), **body.model_dump(), "created_at": now_iso(), "created_by": user["email"]}
    await db.cert_watch_targets.insert_one(doc)
    doc.pop("_id", None)
    return doc


@router.put("/v1/admin/certs/targets/{target_id}")
async def update_cert_target(target_id: str, body: CertTargetBody, user: dict = Depends(require_role("admin"))):
    _validate(body)
    existing = await db.cert_watch_targets.find_one({"id": target_id}, {"_id": 0})
    if not existing:
        raise HTTPException(404, "Watch target not found")
    update = body.model_dump()
    await db.cert_watch_targets.update_one({"id": target_id}, {"$set": update})
    return {**existing, **update}


@router.delete("/v1/admin/certs/targets/{target_id}")
async def delete_cert_target(target_id: str, user: dict = Depends(require_role("admin"))):
    await db.cert_watch_targets.delete_one({"id": target_id})
    return {"ok": True}


@router.post("/v1/admin/certs/targets/{target_id}/check-now")
async def check_cert_now(target_id: str, user: dict = Depends(require_role("admin"))):
    from cert_monitor import run_cert_check
    t = await db.cert_watch_targets.find_one({"id": target_id}, {"_id": 0})
    if not t:
        raise HTTPException(404, "Watch target not found")
    result = await run_cert_check(db, t["hostname"], t.get("port", 443), t.get("asset_id"), t.get("label"))
    return result


@router.post("/v1/admin/certs/check-all")
async def check_all_certs_now(user: dict = Depends(require_role("admin"))):
    from cert_monitor import run_all_cert_checks
    return await run_all_cert_checks(db)


@router.post("/v1/admin/certs/targets/import-internet-facing")
async def import_internet_facing_assets(user: dict = Depends(require_role("admin"))):
    """Bulk-adds a watch target (port 443) for every asset marked internet-facing/
    external that isn't already being watched -- saves clicking through them one by one."""
    assets = await db.assets.find(
        {"exposure": {"$in": ["internet", "external"]}}, {"_id": 0, "id": 1, "hostname": 1}
    ).to_list(1000)
    existing = await db.cert_watch_targets.find({}, {"_id": 0, "hostname": 1}).to_list(1000)
    existing_hosts = {e["hostname"] for e in existing}
    added = 0
    for a in assets:
        host = a.get("hostname")
        if not host or host in existing_hosts:
            continue
        await db.cert_watch_targets.insert_one({
            "id": str(uuid.uuid4()), "hostname": host, "port": 443, "label": None,
            "asset_id": a.get("id"), "enabled": True, "created_at": now_iso(), "created_by": user["email"],
        })
        existing_hosts.add(host)
        added += 1
    return {"added": added}
