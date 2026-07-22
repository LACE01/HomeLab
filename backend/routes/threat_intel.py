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
from threat_intel_watchlist import (
    add_ioc, IOC_TYPES, sync_threatfox_feed, sync_opensourcemalware_feed,
    sync_opencti_feed, sync_otx_feed,
)

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


@router.get("/v1/admin/threat-intel/watchlist/{ioc_id}")
async def get_ioc(
    ioc_id: str, user: dict = Depends(get_current_user),
    _rbac: dict = Depends(require_module("/admin/threat-intel")),
):
    """Full detail for one IOC, including the `detail` dict of raw source fields
    (STIX pattern, OTX pulse, ThreatFox malware family, OSM advisory, etc.) that
    the watchlist list view doesn't need but the click-to-expand detail modal
    does -- kept as a separate GET so the list endpoint's payload stays light."""
    doc = await db.ioc_watchlist.find_one({"id": ioc_id}, {"_id": 0})
    if not doc:
        raise HTTPException(404, "IOC not found")
    return doc


@router.get("/v1/admin/threat-intel/watchlist/{ioc_id}/matches")
async def ioc_matches(
    ioc_id: str, user: dict = Depends(get_current_user),
    _rbac: dict = Depends(require_module("/admin/threat-intel")),
):
    """Recent security_events this IOC actually triggered (via check_and_emit's
    raw={"watchlist_id": ...}) -- the "where/when did this hit something in our
    environment" half of the detail modal, complementing get_ioc's "why is this
    considered malicious" half."""
    doc = await db.ioc_watchlist.find_one({"id": ioc_id}, {"_id": 0})
    if not doc:
        raise HTTPException(404, "IOC not found")
    cursor = db.security_events.find(
        {"raw.watchlist_id": ioc_id}, {"_id": 0},
    ).sort("last_seen_at", -1).limit(25)
    events = await cursor.to_list(length=None)
    return {"items": events, "total": len(events)}


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


@router.post("/v1/admin/threat-intel/sync-now/opensourcemalware")
async def sync_now_opensourcemalware(
    user: dict = Depends(get_current_user),
    _rbac: dict = Depends(require_module("/admin/threat-intel", level="edit")),
):
    try:
        result = await sync_opensourcemalware_feed(db)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(502, f"OpenSourceMalware sync failed: {e}")
    return result


@router.post("/v1/admin/threat-intel/sync-now/opencti")
async def sync_now_opencti(
    user: dict = Depends(get_current_user),
    _rbac: dict = Depends(require_module("/admin/threat-intel", level="edit")),
):
    try:
        result = await sync_opencti_feed(db)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(502, f"OpenCTI sync failed: {e}")
    return result


@router.post("/v1/admin/threat-intel/sync-now/otx")
async def sync_now_otx(
    user: dict = Depends(get_current_user),
    _rbac: dict = Depends(require_module("/admin/threat-intel", level="edit")),
):
    try:
        result = await sync_otx_feed(db)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(502, f"AlienVault OTX sync failed: {e}")
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
    """Periodic bulk pull from ThreatFox, OpenSourceMalware, OpenCTI, and
    AlienVault OTX, mirroring splunk_sync_loop/wazuh_sync_loop's pattern.
    Silently no-ops (just logs) for whichever feed isn't configured -- this loop
    is always registered, configuring any of the four integrations is what turns
    that quarter of it on."""
    import asyncio
    import logging
    logger = logging.getLogger("threat_intel_watchlist_sync_loop")
    await asyncio.sleep(90)  # stagger past Splunk/Wazuh's own startup staggers
    while True:
        for label, sync_fn in (
            ("ThreatFox", sync_threatfox_feed),
            ("OpenSourceMalware", sync_opensourcemalware_feed),
            ("OpenCTI", sync_opencti_feed),
            ("AlienVault OTX", sync_otx_feed),
        ):
            try:
                result = await sync_fn(db)
                logger.info(f"{label} feed sync: {result}")
            except ValueError:
                pass  # not configured yet -- expected/quiet, not an error
            except Exception as e:
                logger.warning(f"{label} feed sync failed: {e}")
        await asyncio.sleep(interval_hours * 3600)
