"""EASM: watch-domain CRUD, scan-now, and the candidate review queue."""
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from db import db
from rbac import require_module
from auth_utils import get_current_user, require_role
from routes.common import now_iso

router = APIRouter()


class DomainBody(BaseModel):
    domain: str
    enabled: bool = True


class DismissBody(BaseModel):
    reason: Optional[str] = None


def _clean_domain(d: str) -> str:
    d = (d or "").strip().lower().lstrip(".")
    if not d or "." not in d or " " in d:
        raise HTTPException(400, "Enter a bare domain like 'example.com', not a URL")
    return d


@router.get("/v1/admin/easm/domains")
async def list_domains(user: dict = Depends(get_current_user)):
    items = await db.easm_domains.find({}, {"_id": 0}).sort("created_at", -1).to_list(200)
    return {"items": items}


@router.post("/v1/admin/easm/domains")
async def create_domain(body: DomainBody, user: dict = Depends(require_role("admin"))):
    domain = _clean_domain(body.domain)
    existing = await db.easm_domains.find_one({"domain": domain}, {"_id": 0})
    if existing:
        raise HTTPException(400, f"'{domain}' is already being watched")
    doc = {"id": str(uuid.uuid4()), "domain": domain, "enabled": body.enabled,
           "last_scanned_at": None, "last_result": None,
           "created_at": now_iso(), "created_by": user["email"]}
    await db.easm_domains.insert_one(doc)
    doc.pop("_id", None)
    return doc


@router.delete("/v1/admin/easm/domains/{domain_id}")
async def delete_domain(domain_id: str, user: dict = Depends(require_role("admin"))):
    await db.easm_domains.delete_one({"id": domain_id})
    return {"ok": True}


@router.post("/v1/admin/easm/domains/{domain_id}/scan-now")
async def scan_domain_now(domain_id: str, user: dict = Depends(require_role("admin"))):
    from easm import run_easm_scan
    from routes.common import record_engagement, now_iso
    d = await db.easm_domains.find_one({"id": domain_id}, {"_id": 0})
    if not d:
        raise HTTPException(404, "Watch domain not found")
    started = now_iso()
    try:
        result = await run_easm_scan(db, d["domain"])
        await record_engagement(
            db, name=f"EASM sweep — {d['domain']}", scanner="EASM (crt.sh)", scan_type="on_demand",
            scan_method="passive_discovery", status="completed",
            assets_scanned=result.get("hostnames_found", 0), findings_created=0,
            findings_updated=result.get("new_candidates", 0), started_at=started,
        )
        return result
    except ValueError as e:
        await record_engagement(db, name=f"EASM sweep — {d['domain']}", scanner="EASM (crt.sh)",
                                 scan_type="on_demand", scan_method="passive_discovery", status="failed",
                                 started_at=started, error=str(e))
        raise HTTPException(502, str(e))


@router.get("/v1/admin/easm/candidates")
async def list_candidates(status: Optional[str] = None, user: dict = Depends(get_current_user),
                           _rbac: dict = Depends(require_module("/easm"))):
    query = {"status": status} if status else {}
    items = await db.easm_candidates.find(query, {"_id": 0}).sort("first_seen_at", -1).to_list(2000)
    counts = {
        "new": await db.easm_candidates.count_documents({"status": "new"}),
        "promoted": await db.easm_candidates.count_documents({"status": "promoted"}),
        "dismissed": await db.easm_candidates.count_documents({"status": "dismissed"}),
    }
    return {"items": items, "counts": counts}


@router.post("/v1/admin/easm/candidates/{candidate_id}/promote")
async def promote(candidate_id: str, user: dict = Depends(require_role("admin"))):
    from easm import promote_candidate
    try:
        return await promote_candidate(db, candidate_id, user["email"])
    except ValueError as e:
        raise HTTPException(404, str(e))


@router.post("/v1/admin/easm/candidates/{candidate_id}/dismiss")
async def dismiss(candidate_id: str, body: DismissBody, user: dict = Depends(require_role("admin"))):
    from easm import dismiss_candidate
    await dismiss_candidate(db, candidate_id, body.reason)
    return {"ok": True}


@router.post("/v1/admin/exposure/resync")
async def resync_exposure(user: dict = Depends(require_role("admin"))):
    """Retroactively fixes findings.internet_facing to match each asset's current
    exposure. Needed for data that went stale BEFORE this reconciliation existed --
    e.g. an asset reclassified as internet-facing whose pre-existing findings never
    got the memo. New promotions/reclassifications stay in sync going forward on
    their own; this is a one-time catch-up tool for older/imported data."""
    from easm import sync_internet_facing_for_asset
    assets = await db.assets.find({}, {"_id": 0, "id": 1, "exposure": 1}).to_list(100000)
    updated_findings = 0
    assets_changed = 0
    for a in assets:
        n = await sync_internet_facing_for_asset(db, a["id"], a.get("exposure") or "unknown")
        if n:
            updated_findings += n
            assets_changed += 1
    return {"ok": True, "assets_checked": len(assets), "assets_with_changes": assets_changed, "findings_updated": updated_findings}
