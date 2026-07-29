"""CTI / OSINT hub API -- see cti.py for what each source does and what it
reuses. Everything is gated on the existing /admin/recon-osint module so this
lands inside the Compromise Monitoring & OSINT area rather than as a separate
permission surface."""
import uuid
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from db import db
from rbac import require_module
from routes.common import now_iso
import cti

router = APIRouter()

MODULE_KEY = "/admin/recon-osint"


class FeedBody(BaseModel):
    name: str
    url: str
    enabled: bool = True


class KeywordBody(BaseModel):
    keyword: str


class InvestigateBody(BaseModel):
    value: str


class TyposquatBody(BaseModel):
    domain: str


class CtBody(BaseModel):
    domain: Optional[str] = None


class TyposquatStatusBody(BaseModel):
    status: str      # new | benign | malicious | monitoring


# --------------------------- overview ---------------------------

@router.get("/v1/cti/overview")
async def cti_overview(user: dict = Depends(require_module(MODULE_KEY))):
    """One call for the hub landing view: counts across every CTI source plus
    the owned-domain registry the sweeps run against."""
    domains = await cti.owned_domains(db)
    kev = await cti.kev_report(db)
    return {
        "owned_domains": domains,
        "feeds": await db.cti_feeds.count_documents({}),
        "articles_matched": await db.cti_articles.count_documents({"matches": {"$ne": []}}),
        "ransomware_victims_tracked": await db.cti_ransomware_victims.count_documents({}),
        "ransomware_matches": await db.cti_ransomware_victims.count_documents({"match": {"$ne": None}}),
        "kev_in_environment": kev["kev_in_environment"],
        "kev_past_due": kev["past_kev_due_date"],
        "certificates_tracked": await db.cti_certificates.count_documents({}),
        "certificates_new": await db.cti_certificates.count_documents({"newly_issued": True}),
        "typosquats_registered": await db.cti_typosquats.count_documents({"resolves": True}),
        "typosquats_unreviewed": await db.cti_typosquats.count_documents({"status": "new"}),
        "investigations": await db.cti_investigations.count_documents({}),
    }


# --------------------------- custom feeds ---------------------------

@router.get("/v1/cti/feeds")
async def list_feeds(user: dict = Depends(require_module(MODULE_KEY))):
    feeds = await db.cti_feeds.find({}, {"_id": 0}).sort("name", 1).to_list(200)
    keywords = await db.cti_keywords.find({}, {"_id": 0}).sort("keyword", 1).to_list(200)
    return {"feeds": feeds, "keywords": keywords}


@router.post("/v1/cti/feeds")
async def add_feed(body: FeedBody, user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    if not body.url.startswith(("http://", "https://")):
        raise HTTPException(400, "url must be an http(s) feed URL")
    existing = await db.cti_feeds.find_one({"url": body.url}, {"_id": 0, "id": 1})
    if existing:
        raise HTTPException(409, "That feed is already being monitored")
    doc = {"id": str(uuid.uuid4()), "name": body.name or body.url, "url": body.url,
           "enabled": body.enabled, "last_synced_at": None,
           "added_by": user.get("email"), "added_at": now_iso()}
    await db.cti_feeds.insert_one(dict(doc))
    return doc


@router.delete("/v1/cti/feeds/{feed_id}")
async def delete_feed(feed_id: str, user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    result = await db.cti_feeds.delete_one({"id": feed_id})
    if result.deleted_count == 0:
        raise HTTPException(404, "Feed not found")
    await db.cti_articles.delete_many({"feed_id": feed_id})
    return {"ok": True}


@router.post("/v1/cti/keywords")
async def add_keyword(body: KeywordBody, user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    kw = body.keyword.strip()
    if len(kw) < 3:
        raise HTTPException(400, "keyword must be at least 3 characters (shorter terms match everything)")
    if await db.cti_keywords.find_one({"keyword": kw}, {"_id": 0, "id": 1}):
        raise HTTPException(409, "Already watching that keyword")
    doc = {"id": str(uuid.uuid4()), "keyword": kw, "added_by": user.get("email"), "added_at": now_iso()}
    await db.cti_keywords.insert_one(dict(doc))
    return doc


@router.delete("/v1/cti/keywords/{keyword_id}")
async def delete_keyword(keyword_id: str, user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    result = await db.cti_keywords.delete_one({"id": keyword_id})
    if result.deleted_count == 0:
        raise HTTPException(404, "Keyword not found")
    return {"ok": True}


@router.post("/v1/cti/feeds/sync")
async def sync_feeds(user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    try:
        return await cti.sync_cti_feeds(db)
    except Exception as e:
        raise HTTPException(502, f"Feed sync failed: {e}")


@router.post("/v1/cti/opencti/sync")
async def sync_opencti(user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    """Pull OpenCTI Reports into the Threat News stream -- usually the richest
    source an org already has, since it aggregates every feed OpenCTI is
    connected to plus analyst-written intel."""
    try:
        return await cti.sync_opencti_reports(db)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(502, f"OpenCTI sync failed: {e}")


@router.get("/v1/cti/articles")
async def list_articles(matched_only: bool = False, limit: int = 100,
                         user: dict = Depends(require_module(MODULE_KEY))):
    flt = {"matches": {"$ne": []}} if matched_only else {}
    items = await db.cti_articles.find(flt, {"_id": 0}).sort("fetched_at", -1).to_list(min(limit, 500))
    return {"items": items}


# --------------------------- ransomware.live ---------------------------

@router.post("/v1/cti/ransomware/sync")
async def sync_ransomware(user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    try:
        return await cti.sync_ransomware_live(db)
    except Exception as e:
        raise HTTPException(502, f"ransomware.live sync failed: {e}")


@router.get("/v1/cti/ransomware")
async def list_ransomware(matched_only: bool = False, limit: int = 200,
                           user: dict = Depends(require_module(MODULE_KEY))):
    flt = {"match": {"$ne": None}} if matched_only else {}
    items = await db.cti_ransomware_victims.find(flt, {"_id": 0}).sort("fetched_at", -1).to_list(min(limit, 500))
    return {"items": items}


# --------------------------- CISA KEV reporting ---------------------------

@router.get("/v1/cti/kev-report")
async def get_kev_report(user: dict = Depends(require_module(MODULE_KEY))):
    return await cti.kev_report(db)


# --------------------------- certificate transparency ---------------------------

@router.post("/v1/cti/certificates/sync")
async def sync_certs(body: CtBody, user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    try:
        return await cti.sync_ct_logs(db, domain=body.domain)
    except Exception as e:
        raise HTTPException(502, f"Certificate transparency sync failed: {e}")


@router.get("/v1/cti/certificates")
async def list_certs(domain: Optional[str] = None, new_only: bool = False, limit: int = 200,
                      user: dict = Depends(require_module(MODULE_KEY))):
    flt: dict = {}
    if domain:
        flt["domain"] = domain.lower()
    if new_only:
        flt["newly_issued"] = True
    items = await db.cti_certificates.find(flt, {"_id": 0}).sort("first_seen_at", -1).to_list(min(limit, 500))
    return {"items": items}


# --------------------------- typosquats ---------------------------

@router.post("/v1/cti/typosquats/scan")
async def scan_typosquats_route(body: TyposquatBody,
                                 user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    domain = body.domain.strip().lower()
    if "." not in domain:
        raise HTTPException(400, "domain must look like example.com")
    try:
        return await cti.scan_typosquats(db, domain)
    except Exception as e:
        raise HTTPException(502, f"Typosquat scan failed: {e}")


@router.get("/v1/cti/typosquats")
async def list_typosquats(domain: Optional[str] = None,
                           user: dict = Depends(require_module(MODULE_KEY))):
    flt: dict = {"resolves": True}
    if domain:
        flt["domain"] = domain.lower()
    items = await db.cti_typosquats.find(flt, {"_id": 0}).sort("first_seen_at", -1).to_list(500)
    return {"items": items}


@router.patch("/v1/cti/typosquats/{squat_id}")
async def update_typosquat(squat_id: str, body: TyposquatStatusBody,
                            user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    if body.status not in ("new", "benign", "malicious", "monitoring"):
        raise HTTPException(400, "status must be new/benign/malicious/monitoring")
    result = await db.cti_typosquats.update_one({"id": squat_id}, {"$set": {
        "status": body.status, "reviewed_by": user.get("email"), "reviewed_at": now_iso()}})
    if result.matched_count == 0:
        raise HTTPException(404, "Not found")
    return await db.cti_typosquats.find_one({"id": squat_id}, {"_id": 0})


# --------------------------- ad-hoc investigation ---------------------------

@router.post("/v1/cti/investigate")
async def investigate_route(body: InvestigateBody,
                             user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    try:
        return await cti.investigate(db, body.value)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(502, f"Investigation failed: {e}")


@router.get("/v1/cti/investigations")
async def list_investigations(limit: int = 25, user: dict = Depends(require_module(MODULE_KEY))):
    items = await db.cti_investigations.find({}, {"_id": 0}).sort("ran_at", -1).to_list(min(limit, 100))
    return {"items": items}


# --------------------------- shodan rollup ---------------------------

@router.get("/v1/cti/shodan-exposure")
async def shodan_exposure(user: dict = Depends(require_module(MODULE_KEY))):
    return await cti.shodan_exposure_summary(db)
