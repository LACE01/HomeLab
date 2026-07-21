"""Email authentication (SPF/DKIM/DMARC) monitoring -- CRUD for watch targets +
run-now + status list. Mirrors routes/certs.py's structure."""
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from db import db
from rbac import require_module
from auth_utils import get_current_user, require_role
from routes.common import now_iso

router = APIRouter()


class DomainTargetBody(BaseModel):
    domain: str
    label: Optional[str] = None
    asset_id: Optional[str] = None
    enabled: bool = True


def _validate(body: DomainTargetBody):
    d = (body.domain or "").strip().lower()
    if not d or "." not in d or " " in d:
        raise HTTPException(400, "A valid domain (e.g. example.com) is required")


@router.get("/v1/admin/email-auth/targets")
async def list_domain_targets(user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/admin/email-auth"))):
    targets = await db.domain_watch_targets.find({}, {"_id": 0}).sort("created_at", -1).to_list(500)
    domains = [t["domain"] for t in targets]
    results = await db.domain_email_security.find({"domain": {"$in": domains}}, {"_id": 0}).to_list(500)
    result_by_domain = {r["domain"]: r for r in results}
    for t in targets:
        t["latest"] = result_by_domain.get(t["domain"])
    return {"items": targets}


@router.post("/v1/admin/email-auth/targets")
async def create_domain_target(body: DomainTargetBody, user: dict = Depends(require_role("admin"))):
    _validate(body)
    domain = body.domain.strip().lower()
    doc = {
        "id": str(uuid.uuid4()), "domain": domain, "label": body.label,
        "asset_id": body.asset_id, "enabled": body.enabled,
        "created_at": now_iso(), "created_by": user["email"],
    }
    await db.domain_watch_targets.insert_one(doc)
    doc.pop("_id", None)
    return doc


@router.put("/v1/admin/email-auth/targets/{target_id}")
async def update_domain_target(target_id: str, body: DomainTargetBody, user: dict = Depends(require_role("admin"))):
    _validate(body)
    existing = await db.domain_watch_targets.find_one({"id": target_id}, {"_id": 0})
    if not existing:
        raise HTTPException(404, "Watch target not found")
    update = body.model_dump()
    update["domain"] = body.domain.strip().lower()
    await db.domain_watch_targets.update_one({"id": target_id}, {"$set": update})
    return {**existing, **update}


@router.delete("/v1/admin/email-auth/targets/{target_id}")
async def delete_domain_target(target_id: str, user: dict = Depends(require_role("admin"))):
    await db.domain_watch_targets.delete_one({"id": target_id})
    return {"ok": True}


@router.post("/v1/admin/email-auth/targets/{target_id}/check-now")
async def check_domain_now(target_id: str, user: dict = Depends(require_role("admin"))):
    from domain_email_security import run_domain_check
    t = await db.domain_watch_targets.find_one({"id": target_id}, {"_id": 0})
    if not t:
        raise HTTPException(404, "Watch target not found")
    return await run_domain_check(db, t["domain"], t.get("asset_id"), t.get("label"))


@router.post("/v1/admin/email-auth/check-all")
async def check_all_domains_now(user: dict = Depends(require_role("admin"))):
    from domain_email_security import run_all_domain_checks
    return await run_all_domain_checks(db)
