"""Threat Intel Watchlist -- CRUD + bulk import + manual sync trigger for the
persistent IOC list in threat_intel_watchlist.py. See that module's docstring
for how matching/correlation works; this file is just the admin-facing API."""
import uuid
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from db import db
from rbac import require_module
from auth_utils import get_current_user
from routes.common import now_iso
from threat_intel_watchlist import add_ioc, IOC_TYPES, sync_threatfox_feed

router = APIRouter()


class IocBody(BaseModel):
    ioc_type: str
    value: str
    severity: str = "High"
    notes: Optional[str] = None


class BulkImportBody(BaseModel):
    ioc_type: str
    values: List[str]
    severity: str = "High"
    notes: Optional[str] = None


def _validate_type(ioc_type: str):
    if ioc_type not in IOC_TYPES:
        raise HTTPException(400, f"ioc_type must be one of {IOC_TYPES}")


@router.get("/v1/admin/threat-intel/watchlist")
async def list_watchlist(
    ioc_type: Optional[str] = None, source: Optional[str] = None, q: Optional[str] = None,
    limit: int = 100, offset: int = 0,
    user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/admin/threat-intel")),
):
    flt: dict = {}
    if ioc_type:
        flt["ioc_type"] = ioc_type
    if source:
        flt["source"] = source
    if q:
        flt["value"] = {"$regex": q, "$options": "i"}
    total = await db.ioc_watchlist.count_documents(flt)
    cursor = db.ioc_watchlist.find(flt, {"_id": 0}).sort("added_at", -1).skip(offset).limit(min(limit, 500))
    items = await cursor.to_list(length=None)
    return {"items": items, "total": total}


@router.post("/v1/admin/threat-intel/watchlist")
async def create_ioc(
    body: IocBody, user: dict = Depends(get_current_user),
    _rbac: dict = Depends(require_module("/admin/threat-intel", level="edit")),
):
    _validate_type(body.ioc_type)
    if not body.value.strip():
        raise HTTPException(400, "value is required")
    doc = await add_ioc(
        db, ioc_type=body.ioc_type, value=body.value, source="manual",
        severity=body.severity, notes=body.notes, added_by=user.get("email"),
    )
    return doc


@router.post("/v1/admin/threat-intel/watchlist/bulk-import")
async def bulk_import(
    body: BulkImportBody, user: dict = Depends(get_current_user),
    _rbac: dict = Depends(require_module("/admin/threat-intel", level="edit")),
):
    _validate_type(body.ioc_type)
    added, skipped = 0, 0
    for raw in body.values:
        value = raw.strip()
        if not value:
            continue
        existing = await db.ioc_watchlist.find_one({"value": value.lower()})
        if existing:
            skipped += 1
            continue
        await add_ioc(
            db, ioc_type=body.ioc_type, value=value, source="manual",
            severity=body.severity, notes=body.notes, added_by=user.get("email"),
        )
        added += 1
    return {"added": added, "skipped": skipped}


@router.delete("/v1/admin/threat-intel/watchlist/{ioc_id}")
async def delete_ioc(
    ioc_id: str, user: dict = Depends(get_current_user),
    _rbac: dict = Depends(require_module("/admin/threat-intel", level="edit")),
):
    result = await db.ioc_watchlist.delete_one({"id": ioc_id})
    if result.deleted_count == 0:
        raise HTTPException(404, "IOC not found")
    return {"ok": True}


@router.post("/v1/admin/threat-intel/sync-now")
async def sync_now(
    user: dict = Depends(get_current_user),
    _rbac: dict = Depends(require_module("/admin/threat-intel", level="edit")),
):
    try:
        result = await sync_threatfox_feed(db)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(502, f"ThreatFox sync failed: {e}")
    return result


@router.get("/v1/admin/threat-intel/stats")
async def stats(
    user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/admin/threat-intel")),
):
    total = await db.ioc_watchlist.count_documents({})
    by_type = {}
    for t in IOC_TYPES:
        by_type[t] = await db.ioc_watchlist.count_documents({"ioc_type": t})
    with_hits = await db.ioc_watchlist.count_documents({"hits": {"$gt": 0}})
    return {"total": total, "by_type": by_type, "with_hits": with_hits}


async def threat_intel_watchlist_sync_loop(db, interval_hours: float = 12):
    """Periodic bulk pull from ThreatFox, mirroring splunk_sync_loop/wazuh_sync_loop's
    pattern. Silently no-ops (just logs) if abuse.ch isn't configured -- this loop is
    always registered, configuring the integration is what turns it on."""
    import asyncio
    import logging
    logger = logging.getLogger("threat_intel_watchlist_sync_loop")
    await asyncio.sleep(90)  # stagger past Splunk/Wazuh's own startup staggers
    while True:
        try:
            result = await sync_threatfox_feed(db)
            logger.info(f"ThreatFox feed sync: {result}")
        except ValueError:
            pass  # not configured yet -- expected/quiet, not an error
        except Exception as e:
            logger.warning(f"ThreatFox feed sync failed: {e}")
        await asyncio.sleep(interval_hours * 3600)
