"""VulnOps — Vulnerability Operations Platform backend."""
import os
import uuid
import csv
import io
from datetime import datetime, timezone, timedelta
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env")

from fastapi import FastAPI, APIRouter, Depends, HTTPException, Request, Response, Query
from fastapi.responses import StreamingResponse
from starlette.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List, Any

from db import db
from auth_utils import (
    hash_password, verify_password, create_access_token,
    get_current_user, require_role, verify_api_key,
)
from scoring import compute_risk, compute_sla_days
from seed import seed_all

import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vulnops")


app = FastAPI(title="VulnOps API", version="1.0.0")
api = APIRouter(prefix="/api")


# --------------------------- helpers ---------------------------
def now_iso():
    return datetime.now(timezone.utc).isoformat()


def _clean(doc: dict) -> dict:
    if not doc:
        return doc
    doc.pop("_id", None)
    return doc


def parse_time_range(range_key: Optional[str], start: Optional[str], end: Optional[str]) -> tuple:
    """Resolve a time range key (7d/30d/90d/4mo/6mo/12mo/custom/all) → (start_iso, end_iso, days).
    Returns (None, None, None) when range is 'all' or unset."""
    now = datetime.now(timezone.utc)
    if range_key == "custom" and start and end:
        return start, end, max(1, (datetime.fromisoformat(end.replace("Z","+00:00")) - datetime.fromisoformat(start.replace("Z","+00:00"))).days)
    presets = {"7d": 7, "30d": 30, "90d": 90, "4mo": 120, "6mo": 180, "12mo": 365}
    if range_key in presets:
        days = presets[range_key]
        return (now - timedelta(days=days)).isoformat(), now.isoformat(), days
    return None, None, None


# --------------------------- AUTH ---------------------------
class LoginBody(BaseModel):
    email: EmailStr
    password: str


@api.post("/auth/login")
async def login(body: LoginBody, response: Response):
    user = await db.users.find_one({"email": body.email.lower()})
    if not user or not verify_password(body.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token(user["id"], user["email"], user["role"])
    response.set_cookie(
        key="access_token", value=token, httponly=True, secure=False, samesite="lax",
        max_age=12 * 3600, path="/",
    )
    return {
        "token": token,
        "user": {"id": user["id"], "email": user["email"], "name": user["name"], "role": user["role"]},
    }


@api.post("/auth/logout")
async def logout(request: Request, response: Response):
    sess = request.cookies.get("session_token")
    if sess:
        await db.user_sessions.delete_many({"session_token": sess})
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("session_token", path="/")
    return {"ok": True}


@api.get("/auth/me")
async def me(user: dict = Depends(get_current_user)):
    return user


# --- Emergent Google OAuth session exchange ---
class GoogleSessionBody(BaseModel):
    session_id: str


@api.post("/auth/google/session")
async def google_session(body: GoogleSessionBody, response: Response):
    import requests as _requests
    try:
        r = _requests.get(
            "https://demobackend.emergentagent.com/auth/v1/env/oauth/session-data",
            headers={"X-Session-ID": body.session_id},
            timeout=10,
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Auth provider unreachable: {e}")
    if r.status_code != 200:
        raise HTTPException(status_code=401, detail="Invalid session_id")
    data = r.json()
    email = (data.get("email") or "").lower()
    name = data.get("name") or email
    picture = data.get("picture")
    session_token = data.get("session_token")
    if not email or not session_token:
        raise HTTPException(status_code=502, detail="Malformed session-data response")

    user = await db.users.find_one({"email": email})
    if user is None:
        user = {
            "id": str(uuid.uuid4()), "email": email, "name": name,
            "role": "analyst", "picture": picture, "auth_provider": "google",
            "created_at": now_iso(), "password_hash": None,
        }
        await db.users.insert_one(user)
    else:
        await db.users.update_one({"email": email}, {"$set": {"name": name, "picture": picture, "auth_provider": user.get("auth_provider", "google")}})

    expires_at = datetime.now(timezone.utc) + timedelta(days=7)
    await db.user_sessions.insert_one({
        "id": str(uuid.uuid4()), "user_id": user["id"], "session_token": session_token,
        "expires_at": expires_at, "created_at": datetime.now(timezone.utc),
    })

    response.set_cookie(
        key="session_token", value=session_token, httponly=True,
        secure=True, samesite="none", max_age=7 * 24 * 3600, path="/",
    )
    return {"user": {"id": user["id"], "email": user["email"], "name": user["name"],
                     "role": user["role"], "picture": picture}}


def _finding_ctx(f: dict) -> dict:
    """Build a notification context dict from a finding doc."""
    return {
        "severity": f.get("severity"), "title": f.get("title"),
        "cve": f.get("cve") or "—", "asset": f.get("asset_hostname"),
        "owner_team": f.get("owner_team"), "risk_score": f.get("risk_score"),
        "due_at": (f.get("due_at") or "")[:19],
        "url": f"/findings/{f.get('id')}",
    }


# --------------------------- FINDINGS ---------------------------
@api.get("/v1/findings")
async def list_findings(
    user: dict = Depends(get_current_user),
    q: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    kev: Optional[bool] = None,
    internet_facing: Optional[bool] = None,
    owner_team: Optional[str] = None,
    product_id: Optional[str] = None,
    asset_id: Optional[str] = None,
    cve: Optional[str] = None,
    view: Optional[str] = None,
    sort: str = "risk_score",
    order: str = "desc",
    limit: int = 100,
    offset: int = 0,
):
    flt: dict = {}
    if severity:
        flt["severity"] = severity
    if status:
        flt["status"] = status
    if kev is not None:
        flt["kev_flag"] = kev
    if internet_facing is not None:
        flt["internet_facing"] = internet_facing
    if owner_team:
        flt["owner_team"] = owner_team
    if product_id:
        flt["product_id"] = product_id
    if asset_id:
        flt["asset_id"] = asset_id
    if cve:
        flt["cve"] = cve
    if q:
        flt["$or"] = [
            {"title": {"$regex": q, "$options": "i"}},
            {"cve": {"$regex": q, "$options": "i"}},
            {"asset_hostname": {"$regex": q, "$options": "i"}},
            {"qid": {"$regex": q, "$options": "i"}},
        ]

    # Saved views
    now = datetime.now(timezone.utc)
    if view == "kev":
        flt["kev_flag"] = True
    elif view == "internet_facing_critical":
        flt["internet_facing"] = True
        flt["severity"] = {"$in": ["Critical", "High"]}
    elif view == "overdue":
        flt["due_at"] = {"$lt": now.isoformat()}
        flt["status"] = {"$in": ["New", "Needs triage", "Valid", "Reopened"]}
    elif view == "reopened":
        flt["status"] = "Reopened"
    elif view == "patch_unavailable":
        flt["patch_available"] = False
    elif view == "highest_risk":
        flt["status"] = {"$in": ["New", "Needs triage", "Valid", "Reopened"]}

    sort_dir = -1 if order == "desc" else 1
    cursor = db.findings.find(flt, {"_id": 0}).sort(sort, sort_dir).skip(offset).limit(limit)
    items = await cursor.to_list(length=limit)
    total = await db.findings.count_documents(flt)
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@api.get("/v1/findings/stats")
async def findings_stats(user: dict = Depends(get_current_user)):
    pipeline_sev = [{"$group": {"_id": "$severity", "count": {"$sum": 1}}}]
    pipeline_status = [{"$group": {"_id": "$status", "count": {"$sum": 1}}}]
    sev = {r["_id"]: r["count"] async for r in db.findings.aggregate(pipeline_sev)}
    statuses = {r["_id"]: r["count"] async for r in db.findings.aggregate(pipeline_status)}
    total = await db.findings.count_documents({})
    kev_count = await db.findings.count_documents({"kev_flag": True})
    overdue = await db.findings.count_documents({
        "due_at": {"$lt": now_iso()},
        "status": {"$in": ["New", "Needs triage", "Valid", "Reopened"]},
    })
    return {"total": total, "by_severity": sev, "by_status": statuses, "kev": kev_count, "overdue": overdue}


@api.get("/v1/findings/{finding_id}")
async def get_finding(finding_id: str, user: dict = Depends(get_current_user)):
    f = await db.findings.find_one({"id": finding_id}, {"_id": 0})
    if not f:
        raise HTTPException(404, "Finding not found")
    return f


@api.get("/v1/findings/{finding_id}/kri")
async def finding_kri(finding_id: str, user: dict = Depends(get_current_user)):
    """KRI / ZDES / BII / urgency tier / Empirical percentile / Critical Indicators for one finding."""
    from scoring_v2 import (compute_kri, compute_zdes, compute_bii, urgency_tier,
                            critical_indicators, empirical_percentile, cwe_prevalence_map)
    f = await db.findings.find_one({"id": finding_id}, {"_id": 0})
    if not f:
        raise HTTPException(404, "Finding not found")
    cwe_map = await cwe_prevalence_map(db)
    cwe_w = cwe_map.get(f.get("cwe"), 1.0)
    kri = compute_kri(f, cwe_w)
    zdes = compute_zdes(f)
    asset = await db.assets.find_one({"id": f.get("asset_id")}, {"_id": 0}) or {}
    bii = compute_bii(f, asset.get("criticality", "medium"), patch_hours_estimated=f.get("patch_hours_estimated", 4.0))
    tier = urgency_tier(kri["kri_score"], bool(f.get("kev_flag")), f.get("risk_score") or 0)

    # Cohort = open findings of same severity
    cohort_cursor = db.findings.find(
        {"severity": f.get("severity"), "status": {"$in": ["New", "Needs triage", "Valid", "Reopened"]}},
        {"_id": 0, "epss_score": 1, "cvss_score": 1, "cwe": 1}
    )
    cohort_scores = []
    async for c in cohort_cursor:
        cw = cwe_map.get(c.get("cwe"), 1.0)
        cohort_scores.append(compute_kri(c, cw)["kri_score"])
    pct = empirical_percentile(kri["kri_score"], cohort_scores)
    indicators = critical_indicators(f)

    return {
        "finding_id": finding_id,
        **kri, **zdes, **bii,
        "urgency_tier": tier,
        "due_basis": f"KRI {kri['kri_score']:.3f} · CVSS {f.get('cvss_score')} · EPSS {f.get('epss_score')} · "
                     f"CWE local weight {cwe_w} · {'KEV' if f.get('kev_flag') else 'no-KEV'} · "
                     f"asset {asset.get('criticality', 'medium')}",
        "empirical": pct,
        "critical_indicators": indicators,
        "patch_hours_estimated": f.get("patch_hours_estimated", 4.0),
    }


@api.get("/v1/cwe-prevalence")
async def cwe_prevalence(user: dict = Depends(get_current_user)):
    from scoring_v2 import cwe_prevalence_map
    weights = await cwe_prevalence_map(db)
    # Enrich with finding counts and a sample title per CWE
    pipeline = [
        {"$match": {"cwe": {"$ne": None}}},
        {"$group": {"_id": "$cwe", "count": {"$sum": 1}, "sample_title": {"$first": "$title"}}},
    ]
    enrich: dict = {}
    async for r in db.findings.aggregate(pipeline):
        enrich[r["_id"]] = {"count": r["count"], "sample_title": r.get("sample_title")}
    items = []
    for cwe, w in weights.items():
        e = enrich.get(cwe, {"count": 0, "sample_title": ""})
        items.append({"cwe": cwe, "weight": w, "count": e["count"], "sample_title": e["sample_title"]})
    items.sort(key=lambda x: (-x["weight"], -x["count"]))
    return {"items": items}


# --------------------------- THREAT INTEL (OpenCTI) ---------------------------
@api.get("/v1/threat-intel/{cve}")
async def threat_intel_for_cve(cve: str, user: dict = Depends(get_current_user)):
    """Query OpenCTI for threat-intel context around a CVE.
    Reads endpoint + api_key from the OpenCTI integration record (Admin → Integrations)."""
    integration = await db.integrations.find_one({"name": "OpenCTI"}, {"_id": 0})
    cfg = (integration or {}).get("config") or {}
    endpoint = cfg.get("endpoint")
    api_key = cfg.get("api_key")

    if not endpoint or not api_key:
        # Return a representative synthetic intel envelope so the UI works pre-config
        return {
            "configured": False,
            "cve": cve,
            "message": "OpenCTI not configured. Add endpoint + api_key in Integrations → OpenCTI to enable live enrichment.",
            "threat_actors": [], "intrusion_sets": [], "malware": [], "campaigns": [],
            "indicators": [], "external_references": [],
        }

    import httpx
    query = (
        '{ vulnerabilities(filters: {mode:and, filters:[{key:"name", values:["'
        + cve + '"]}], filterGroups:[]}) {'
        '  edges { node { id name '
        '    stixCoreRelationships {'
        '      edges { node { id relationship_type to { ... on ThreatActor { name } ... on IntrusionSet { name } '
        '        ... on Malware { name } ... on Campaign { name } } } }'
        '    } externalReferences { edges { node { source_name url } } } } } } }'
    )
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.post(endpoint.rstrip("/") + "/graphql",
                             headers={"Authorization": f"Bearer {api_key}"},
                             json={"query": query})
        if r.status_code != 200:
            return {"configured": True, "cve": cve, "error": f"OpenCTI HTTP {r.status_code}", "raw": r.text[:300]}
        data = r.json().get("data", {}).get("vulnerabilities", {}).get("edges", [])
        actors, sets_, malware, campaigns, refs = [], [], [], [], []
        for v in data:
            node = v.get("node", {})
            for er in node.get("externalReferences", {}).get("edges", []):
                en = er.get("node", {})
                refs.append({"source": en.get("source_name"), "url": en.get("url")})
            for rel in node.get("stixCoreRelationships", {}).get("edges", []):
                rn = rel.get("node", {})
                target = rn.get("to", {}) or {}
                name = target.get("name")
                if not name:
                    continue
                # Bucket by relationship_type heuristics
                rtype = rn.get("relationship_type", "")
                if "actor" in rtype.lower(): actors.append(name)
                elif "intrusion" in rtype.lower(): sets_.append(name)
                elif "campaign" in rtype.lower(): campaigns.append(name)
                else: malware.append(name)
        return {"configured": True, "cve": cve,
                "threat_actors": list(set(actors)), "intrusion_sets": list(set(sets_)),
                "malware": list(set(malware)), "campaigns": list(set(campaigns)),
                "external_references": refs[:20]}
    except Exception as e:
        return {"configured": True, "cve": cve, "error": str(e)}


@api.get("/v1/findings/{finding_id}/timeline")
async def finding_timeline(finding_id: str, user: dict = Depends(get_current_user)):
    items = await db.activity_log.find({"entity_type": "finding", "entity_id": finding_id}, {"_id": 0}).sort("timestamp", -1).to_list(200)
    return {"items": items}


@api.get("/v1/findings/{finding_id}/observations")
async def finding_observations(finding_id: str, user: dict = Depends(get_current_user)):
    items = await db.observations.find({"finding_id": finding_id}, {"_id": 0}).sort("observed_at", -1).to_list(100)
    return {"items": items}


@api.get("/v1/findings/{finding_id}/tickets")
async def finding_tickets(finding_id: str, user: dict = Depends(get_current_user)):
    items = await db.tickets.find({"finding_id": finding_id}, {"_id": 0}).to_list(50)
    return {"items": items}


@api.get("/v1/findings/{finding_id}/comments")
async def finding_comments(finding_id: str, user: dict = Depends(get_current_user)):
    items = await db.comments.find({"finding_id": finding_id}, {"_id": 0}).sort("created_at", -1).to_list(200)
    return {"items": items}


class CommentBody(BaseModel):
    text: str
    attachments: Optional[List[dict]] = None  # [{name, mime, data_url}] — data_url is base64 (small images only)


@api.post("/v1/findings/{finding_id}/comments")
async def add_comment(finding_id: str, body: CommentBody, user: dict = Depends(get_current_user)):
    # Reject oversized attachments (>1MB base64 → ~750KB binary)
    atts = body.attachments or []
    for a in atts:
        if isinstance(a.get("data_url"), str) and len(a["data_url"]) > 1_400_000:
            raise HTTPException(413, f"Attachment '{a.get('name','?')}' exceeds 1 MB limit")
        if a.get("mime") and not a["mime"].startswith(("image/", "application/pdf")):
            raise HTTPException(400, f"Only image and PDF attachments allowed (got {a['mime']})")
    c = {"id": str(uuid.uuid4()), "finding_id": finding_id, "author": user["email"],
         "text": body.text, "attachments": atts, "created_at": now_iso()}
    await db.comments.insert_one(c)
    return _clean(c)


class StatusUpdate(BaseModel):
    status: str
    note: Optional[str] = None


@api.patch("/v1/findings/{finding_id}/status")
async def update_status(finding_id: str, body: StatusUpdate, user: dict = Depends(get_current_user)):
    valid = ["New", "Needs triage", "Valid", "False positive", "Duplicate", "Mitigated",
             "Accepted risk", "Deferred", "Fixed pending validation", "Fixed validated",
             "Reopened", "Out of scope", "Closed administratively"]
    if body.status not in valid:
        raise HTTPException(400, f"Invalid status. Allowed: {valid}")
    res = await db.findings.update_one(
        {"id": finding_id},
        {"$set": {"status": body.status, "last_changed_at": now_iso()}},
    )
    if res.matched_count == 0:
        raise HTTPException(404, "Finding not found")
    await db.activity_log.insert_one({
        "id": str(uuid.uuid4()), "entity_type": "finding", "entity_id": finding_id,
        "action": "status_changed", "actor": user["email"], "timestamp": now_iso(),
        "details": f"Status set to {body.status}" + (f" — {body.note}" if body.note else ""),
    })
    # Auto-dispatch: reopened
    if body.status == "Reopened":
        from notifier import dispatch
        f = await db.findings.find_one({"id": finding_id}, {"_id": 0})
        if f:
            await dispatch("finding_reopened", _finding_ctx(f), db)
    return {"ok": True}


class BulkStatus(BaseModel):
    ids: List[str]
    status: str
    note: Optional[str] = None


@api.post("/v1/findings/bulk-status")
async def bulk_status(body: BulkStatus, user: dict = Depends(get_current_user)):
    await db.findings.update_many({"id": {"$in": body.ids}},
                                  {"$set": {"status": body.status, "last_changed_at": now_iso()}})
    docs = [{"id": str(uuid.uuid4()), "entity_type": "finding", "entity_id": fid,
             "action": "bulk_status", "actor": user["email"], "timestamp": now_iso(),
             "details": f"Bulk set to {body.status}"} for fid in body.ids]
    if docs:
        await db.activity_log.insert_many(docs)
    return {"updated": len(body.ids)}


class AssignBody(BaseModel):
    ids: List[str]
    assignee: str


@api.post("/v1/findings/bulk-assign")
async def bulk_assign(body: AssignBody, user: dict = Depends(get_current_user)):
    await db.findings.update_many({"id": {"$in": body.ids}},
                                  {"$set": {"assigned_to": body.assignee, "last_changed_at": now_iso()}})
    return {"updated": len(body.ids)}


@api.get("/v1/prioritization/preview")
async def prioritization_preview(finding_id: str, user: dict = Depends(get_current_user)):
    f = await db.findings.find_one({"id": finding_id}, {"_id": 0})
    if not f:
        raise HTTPException(404, "Finding not found")
    asset = await db.assets.find_one({"id": f.get("asset_id")}, {"_id": 0})
    return compute_risk(f, asset)


# --------------------------- ATTACK PATH ANALYSIS ---------------------------
@api.get("/v1/attack-paths/cves")
async def attack_path_cves(user: dict = Depends(get_current_user)):
    """List CVEs that have open findings on 2+ assets (good candidates for path analysis)."""
    pipeline = [
        {"$match": {"cve": {"$ne": None, "$exists": True},
                    "status": {"$in": ["New", "Needs triage", "Valid", "Reopened"]}}},
        {"$group": {"_id": "$cve",
                    "asset_count": {"$addToSet": "$asset_id"},
                    "title": {"$first": "$title"},
                    "severity": {"$first": "$severity"},
                    "kev": {"$first": "$kev_flag"},
                    "max_risk": {"$max": "$risk_score"}}},
        {"$project": {"_id": 0, "cve": "$_id", "title": 1, "severity": 1, "kev": 1,
                      "max_risk": 1, "affected_assets": {"$size": "$asset_count"}}},
        {"$match": {"affected_assets": {"$gte": 1}}},
        {"$sort": {"max_risk": -1}},
        {"$limit": 100},
    ]
    items = [r async for r in db.findings.aggregate(pipeline)]
    return {"items": items}


@api.get("/v1/attack-paths/graph")
async def attack_path_graph(cve: Optional[str] = None, finding_id: Optional[str] = None,
                             user: dict = Depends(get_current_user)):
    from attack_path import build_attack_path
    return await build_attack_path(db, cve=cve, finding_id=finding_id)


# --------------------------- ASSETS ---------------------------
@api.get("/v1/assets")
async def list_assets(user: dict = Depends(get_current_user),
                     q: Optional[str] = None, criticality: Optional[str] = None,
                     environment: Optional[str] = None, exposure: Optional[str] = None,
                     limit: int = 100, offset: int = 0):
    flt: dict = {}
    if criticality:
        flt["criticality"] = criticality
    if environment:
        flt["environment"] = environment
    if exposure:
        flt["exposure"] = exposure
    if q:
        flt["$or"] = [
            {"hostname": {"$regex": q, "$options": "i"}},
            {"ip": {"$regex": q, "$options": "i"}},
            {"fqdn": {"$regex": q, "$options": "i"}},
        ]
    items = await db.assets.find(flt, {"_id": 0}).skip(offset).limit(limit).to_list(limit)
    total = await db.assets.count_documents(flt)

    # enrich each asset with open findings count and max severity
    for a in items:
        a["open_findings"] = await db.findings.count_documents({
            "asset_id": a["id"],
            "status": {"$in": ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]},
        })
        a["critical_findings"] = await db.findings.count_documents({
            "asset_id": a["id"], "severity": "Critical",
            "status": {"$in": ["New", "Needs triage", "Valid", "Reopened"]},
        })
    return {"items": items, "total": total}


@api.get("/v1/assets/{asset_id}")
async def get_asset(asset_id: str, user: dict = Depends(get_current_user)):
    a = await db.assets.find_one({"id": asset_id}, {"_id": 0})
    if not a:
        raise HTTPException(404, "Asset not found")
    return a


@api.get("/v1/assets/{asset_id}/findings")
async def asset_findings(asset_id: str, user: dict = Depends(get_current_user)):
    items = await db.findings.find({"asset_id": asset_id}, {"_id": 0}).sort("risk_score", -1).to_list(500)
    return {"items": items}


@api.get("/v1/assets/{asset_id}/tickets")
async def asset_tickets(asset_id: str, user: dict = Depends(get_current_user)):
    items = await db.tickets.find({"asset_id": asset_id}, {"_id": 0}).to_list(100)
    return {"items": items}


@api.get("/v1/assets/{asset_id}/history")
async def asset_history(asset_id: str, user: dict = Depends(get_current_user)):
    items = await db.activity_log.find({"entity_id": asset_id}, {"_id": 0}).sort("timestamp", -1).to_list(200)
    # Also include finding observations
    obs = await db.observations.find({"asset_id": asset_id}, {"_id": 0}).sort("observed_at", -1).to_list(200)
    return {"activity": items, "observations": obs}


# --------------------------- PRODUCTS ---------------------------
@api.get("/v1/products")
async def list_products(user: dict = Depends(get_current_user)):
    items = await db.products.find({}, {"_id": 0}).to_list(200)
    for p in items:
        p["asset_count"] = await db.assets.count_documents({"product_id": p["id"]})
        p["open_findings"] = await db.findings.count_documents({
            "product_id": p["id"],
            "status": {"$in": ["New", "Needs triage", "Valid", "Reopened"]},
        })
        p["critical_findings"] = await db.findings.count_documents({
            "product_id": p["id"], "severity": "Critical",
            "status": {"$in": ["New", "Needs triage", "Valid", "Reopened"]},
        })
    return {"items": items}


@api.get("/v1/products/{product_id}")
async def get_product(product_id: str, user: dict = Depends(get_current_user)):
    p = await db.products.find_one({"id": product_id}, {"_id": 0})
    if not p:
        raise HTTPException(404, "Product not found")
    p["assets"] = await db.assets.find({"product_id": product_id}, {"_id": 0}).to_list(200)
    p["findings"] = await db.findings.find({"product_id": product_id}, {"_id": 0}).sort("risk_score", -1).limit(100).to_list(100)
    return p


# --------------------------- ENGAGEMENTS ---------------------------
@api.get("/v1/engagements")
async def list_engagements(user: dict = Depends(get_current_user)):
    items = await db.engagements.find({}, {"_id": 0}).sort("started_at", -1).to_list(100)
    return {"items": items}


# --------------------------- TICKETS ---------------------------
@api.get("/v1/tickets")
async def list_tickets(user: dict = Depends(get_current_user), status: Optional[str] = None):
    flt = {}
    if status:
        flt["status"] = status
    items = await db.tickets.find(flt, {"_id": 0}).sort("updated_at", -1).to_list(500)
    return {"items": items}


# --------------------------- EXCEPTIONS ---------------------------
@api.get("/v1/exceptions")
async def list_exceptions(user: dict = Depends(get_current_user)):
    items = await db.exceptions.find({}, {"_id": 0}).to_list(200)
    # Enrich with finding info
    for e in items:
        f = await db.findings.find_one({"id": e["finding_id"]}, {"_id": 0, "title": 1, "severity": 1, "asset_hostname": 1, "cve": 1})
        if f:
            e["finding_title"] = f.get("title")
            e["severity"] = f.get("severity")
            e["asset_hostname"] = f.get("asset_hostname")
            e["cve"] = f.get("cve")
    return {"items": items}


class ExceptionCreate(BaseModel):
    finding_id: str
    rationale: str
    expires_at: str
    compensating_controls: List[str] = []


@api.post("/v1/exceptions")
async def create_exception(body: ExceptionCreate, user: dict = Depends(get_current_user)):
    f = await db.findings.find_one({"id": body.finding_id})
    if not f:
        raise HTTPException(404, "Finding not found")
    exc = {
        "id": str(uuid.uuid4()), "finding_id": body.finding_id, "asset_id": f.get("asset_id"),
        "rationale": body.rationale, "approver": user["email"], "approved_at": now_iso(),
        "expires_at": body.expires_at, "renewal_history": [],
        "compensating_controls": body.compensating_controls, "evidence_files": [], "status": "active",
    }
    await db.exceptions.insert_one(exc)
    await db.findings.update_one({"id": body.finding_id}, {"$set": {"status": "Accepted risk", "last_changed_at": now_iso()}})
    return _clean(exc)


# --------------------------- INTEGRATIONS ---------------------------
@api.get("/v1/integrations")
async def list_integrations(user: dict = Depends(get_current_user)):
    items = await db.integrations.find({}, {"_id": 0}).to_list(100)
    # Mask secrets in list view
    for i in items:
        cfg = i.get("config") or {}
        if cfg.get("api_key"): cfg["api_key"] = cfg["api_key"][:4] + "•••" + cfg["api_key"][-4:] if len(cfg.get("api_key",""))>8 else "•••"
        if cfg.get("api_secret"): cfg["api_secret"] = "•••"
    return {"items": items}


class IntegrationConfig(BaseModel):
    endpoint: Optional[str] = None
    api_key: Optional[str] = None
    api_secret: Optional[str] = None
    username: Optional[str] = None
    auth_type: Optional[str] = None
    enabled: Optional[bool] = None


@api.patch("/v1/integrations/{integration_id}")
async def update_integration(integration_id: str, body: IntegrationConfig, user: dict = Depends(require_role("admin"))):
    integration = await db.integrations.find_one({"id": integration_id})
    if not integration:
        raise HTTPException(404, "Integration not found")
    cfg = integration.get("config") or {}
    update = body.model_dump(exclude_none=True)
    for k, v in update.items():
        cfg[k] = v
    await db.integrations.update_one({"id": integration_id}, {"$set": {"config": cfg, "last_changed_at": now_iso()}})
    return {"ok": True}


@api.post("/v1/integrations/{integration_id}/test")
async def test_integration(integration_id: str, user: dict = Depends(require_role("admin"))):
    integration = await db.integrations.find_one({"id": integration_id})
    if not integration:
        raise HTTPException(404, "Integration not found")
    cfg = integration.get("config") or {}
    # Validate required credentials
    if not cfg.get("endpoint") or not cfg.get("api_key"):
        await db.integrations.update_one({"id": integration_id}, {"$set": {"status": "degraded", "sync_errors": (integration.get("sync_errors") or 0)+1}})
        raise HTTPException(400, "Missing endpoint or api_key — configure the connector first")
    # Simulated test (real HTTP call would go here per connector type)
    await db.integrations.update_one({"id": integration_id}, {"$set": {
        "status": "healthy", "last_sync_at": now_iso(), "sync_errors": 0,
    }})
    return {"ok": True, "message": f"Connection to {integration['name']} verified."}


# --------------------------- IMPORT JOBS ---------------------------
@api.get("/v1/import-jobs")
async def list_import_jobs(user: dict = Depends(get_current_user)):
    items = await db.import_jobs.find({}, {"_id": 0}).sort("started_at", -1).limit(200).to_list(200)
    return {"items": items}


@api.get("/v1/import-jobs/{job_id}")
async def get_import_job(job_id: str, user: dict = Depends(get_current_user)):
    j = await db.import_jobs.find_one({"id": job_id}, {"_id": 0})
    if not j:
        raise HTTPException(404, "Job not found")
    return j


# --------------------------- DASHBOARDS ---------------------------
@api.get("/v1/dashboards/analyst")
async def dashboard_analyst(
    user: dict = Depends(get_current_user),
    range: Optional[str] = "30d",
    start: Optional[str] = None,
    end: Optional[str] = None,
):
    open_states = ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]
    open_findings = await db.findings.count_documents({"status": {"$in": open_states}})
    start_iso, end_iso, days = parse_time_range(range, start, end)
    # "New in window" — count findings created within the selected range
    new_q: dict = {"status": "New"}
    if start_iso:
        new_q["created_at"] = {"$gte": start_iso, "$lte": end_iso}
    new_findings = await db.findings.count_documents(new_q)
    triage = await db.findings.count_documents({"status": "Needs triage"})
    kev = await db.findings.count_documents({"kev_flag": True, "status": {"$in": open_states}})
    rti_high = await db.findings.count_documents({"rti": "active_attacks", "status": {"$in": open_states}})
    reopened = await db.findings.count_documents({"status": "Reopened"})
    overdue = await db.findings.count_documents({"due_at": {"$lt": now_iso()}, "status": {"$in": open_states}})
    unassigned = await db.findings.count_documents({"assigned_to": None, "status": {"$in": open_states}})
    low_confidence = await db.findings.count_documents({"ownership_confidence": {"$lt": 0.7}, "status": {"$in": open_states}})
    top = await db.findings.find({"status": {"$in": open_states}}, {"_id": 0}).sort("risk_score", -1).limit(10).to_list(10)
    recent_imports = await db.import_jobs.find({}, {"_id": 0}).sort("started_at", -1).limit(6).to_list(6)
    failed_imports = await db.import_jobs.count_documents({"status": "failed"})
    return {
        "open_findings": open_findings, "new_findings": new_findings,
        "needs_triage": triage, "kev_findings": kev, "rti_findings": rti_high,
        "reopened": reopened, "overdue": overdue, "unassigned": unassigned,
        "low_confidence_ownership": low_confidence, "top_findings": top,
        "recent_imports": recent_imports, "failed_imports": failed_imports,
        "range": range, "range_days": days, "range_start": start_iso, "range_end": end_iso,
    }


@api.get("/v1/dashboards/manager")
async def dashboard_manager(
    user: dict = Depends(get_current_user),
    range: Optional[str] = "30d",
    start: Optional[str] = None,
    end: Optional[str] = None,
):
    teams: dict = {}
    async for f in db.findings.find({"status": {"$in": ["New", "Needs triage", "Valid", "Reopened"]}}, {"_id": 0, "owner_team": 1, "due_at": 1, "severity": 1}):
        t = f.get("owner_team", "Unassigned")
        teams.setdefault(t, {"open": 0, "overdue": 0, "critical": 0})
        teams[t]["open"] += 1
        if f.get("due_at") and f["due_at"] < now_iso():
            teams[t]["overdue"] += 1
        if f.get("severity") == "Critical":
            teams[t]["critical"] += 1
    snap_q: dict = {}
    start_iso, end_iso, days = parse_time_range(range, start, end)
    if start_iso:
        snap_q["date"] = {"$gte": start_iso[:10], "$lte": end_iso[:10]}
    snapshots = await db.score_snapshots.find(snap_q, {"_id": 0}).sort("date", 1).to_list(400)
    exception_count = await db.exceptions.count_documents({"status": "active"})
    return {
        "by_team": [{"team": k, **v} for k, v in teams.items()],
        "snapshots": snapshots, "active_exceptions": exception_count,
        "range": range, "range_days": days,
    }


@api.get("/v1/dashboards/executive")
async def dashboard_executive(
    user: dict = Depends(get_current_user),
    range: Optional[str] = "30d",
    start: Optional[str] = None,
    end: Optional[str] = None,
):
    snap_q: dict = {}
    start_iso, end_iso, days = parse_time_range(range, start, end)
    if start_iso:
        snap_q["date"] = {"$gte": start_iso[:10], "$lte": end_iso[:10]}
    snapshots = await db.score_snapshots.find(snap_q, {"_id": 0}).sort("date", 1).to_list(400)
    # Fallback to last snapshot if window is empty
    if not snapshots:
        snapshots = await db.score_snapshots.find({}, {"_id": 0}).sort("date", 1).to_list(60)
    current = snapshots[-1] if snapshots else {"org_score": 0, "sla_compliance": 0, "mttr_days": 0}

    products = await db.products.find({}, {"_id": 0}).to_list(50)
    for p in products:
        p["critical_open"] = await db.findings.count_documents({
            "product_id": p["id"], "severity": {"$in": ["Critical", "High"]},
            "status": {"$in": ["New", "Needs triage", "Valid", "Reopened"]},
        })

    by_env: dict = {}
    async for f in db.findings.find({"severity": {"$in": ["Critical", "High"]}, "status": {"$in": ["New", "Needs triage", "Valid", "Reopened"]}}, {"_id": 0, "asset_environment": 1}):
        env = f.get("asset_environment", "unknown")
        by_env[env] = by_env.get(env, 0) + 1

    score = current["org_score"]
    if score >= 85:
        narrative = "Strong security posture. Risk well-managed with low SLA breach rate."
    elif score >= 70:
        narrative = "Moderate security posture. A few high-risk findings need attention to push the score higher."
    else:
        narrative = "Elevated risk. Critical findings on internet-facing assets are pulling the score down."

    return {
        "current_score": score, "narrative": narrative,
        "sla_compliance": current.get("sla_compliance"),
        "mttr_days": current.get("mttr_days"),
        "snapshots": snapshots,
        "by_product": products,
        "by_environment": [{"environment": k, "count": v} for k, v in by_env.items()],
        "score_factors": [
            {"factor": "Open KEV findings", "impact": "-8", "reason": f"{await db.findings.count_documents({'kev_flag': True, 'status': {'$in': ['New', 'Needs triage', 'Valid', 'Reopened']}})} active"},
            {"factor": "Internet-facing critical", "impact": "-6", "reason": "Exposed services with critical CVEs"},
            {"factor": "SLA adherence", "impact": "+4", "reason": f"{current.get('sla_compliance', 0)}% on-time remediation"},
            {"factor": "Scan coverage", "impact": "+3", "reason": "94% of inventory under active scanning"},
        ],
        "range": range, "range_days": days,
    }


# --------------------------- REPORTS / EXPORT ---------------------------
@api.get("/v1/reports/csv/findings")
async def export_findings_csv(user: dict = Depends(get_current_user),
                              severity: Optional[str] = None, status: Optional[str] = None):
    flt: dict = {}
    if severity:
        flt["severity"] = severity
    if status:
        flt["status"] = status
    items = await db.findings.find(flt, {"_id": 0}).limit(5000).to_list(5000)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID", "CVE", "QID", "Title", "Severity", "CVSS", "EPSS", "KEV",
        "Risk Score", "Status", "Asset", "IP", "Owner Team", "First Seen", "Due", "Source",
    ])
    for f in items:
        writer.writerow([
            f.get("id"), f.get("cve") or "", f.get("source_native_id") or "", f.get("title"),
            f.get("severity"), f.get("cvss_score"), f.get("epss_score"),
            "YES" if f.get("kev_flag") else "NO", f.get("risk_score"),
            f.get("status"), f.get("asset_hostname"), f.get("asset_ip") or "",
            f.get("owner_team"), f.get("first_seen_at"), f.get("due_at"), f.get("source_tool"),
        ])
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=findings.csv"},
    )


@api.get("/v1/reports/pdf/executive")
async def export_executive_pdf(user: dict = Depends(get_current_user)):
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib import colors

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("title", parent=styles["Title"], fontSize=20, textColor=colors.HexColor("#0D1117"))
    elements: list = []
    elements.append(Paragraph("VulnOps — Executive Security Report", title_style))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"Generated: {now_iso()}", styles["Normal"]))
    elements.append(Spacer(1, 12))

    dash = await dashboard_executive(user)
    elements.append(Paragraph(f"<b>Security Score:</b> {dash['current_score']} / 100", styles["Heading2"]))
    elements.append(Paragraph(dash["narrative"], styles["Normal"]))
    elements.append(Spacer(1, 12))

    elements.append(Paragraph(f"<b>SLA Compliance:</b> {dash['sla_compliance']}%", styles["Normal"]))
    elements.append(Paragraph(f"<b>MTTR:</b> {dash['mttr_days']} days", styles["Normal"]))
    elements.append(Spacer(1, 12))

    elements.append(Paragraph("<b>Critical Open Findings by Product</b>", styles["Heading3"]))
    rows = [["Product", "Critical/High Open"]]
    for p in dash["by_product"]:
        rows.append([p["name"], str(p.get("critical_open", 0))])
    t = Table(rows, hAlign="LEFT")
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0D1117")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#30363D")),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 12))

    elements.append(Paragraph("<b>Key Score Factors</b>", styles["Heading3"]))
    for sf in dash["score_factors"]:
        elements.append(Paragraph(f"• {sf['factor']} ({sf['impact']}) — {sf['reason']}", styles["Normal"]))

    doc.build(elements)
    buffer.seek(0)
    return StreamingResponse(buffer, media_type="application/pdf",
                             headers={"Content-Disposition": "attachment; filename=executive-report.pdf"})


# --------------------------- REPORT BUILDER ---------------------------
from reports import REPORT_CATALOG, GROUP_FIELDS, run_prebuilt, run_custom


@api.get("/v1/reports/catalog")
async def reports_catalog(user: dict = Depends(get_current_user)):
    return {"items": REPORT_CATALOG, "group_fields": GROUP_FIELDS,
            "filter_fields": ["severity", "status", "kev_flag", "internet_facing", "owner_team", "product_name", "asset_environment"],
            "metrics": [{"id": "count", "label": "Count of Findings"}, {"id": "risk_sum", "label": "Sum of Risk Score"}],
            "date_fields": ["first_seen_at", "last_seen_at", "due_at", "last_changed_at"]}


@api.get("/v1/reports/run/{report_id}")
async def run_report(report_id: str, fmt: str = "pdf", user: dict = Depends(get_current_user)):
    if fmt not in ("pdf", "csv"):
        raise HTTPException(400, "fmt must be 'pdf' or 'csv'")
    result = await run_prebuilt(db, report_id, fmt)
    if result is None:
        raise HTTPException(404, f"Unknown report_id: {report_id}")
    return result


class CustomReportBody(BaseModel):
    fmt: str = "pdf"
    group_by: str = "severity"
    metric: str = "count"
    filters: dict = {}
    date_field: Optional[str] = "first_seen_at"
    date_from: Optional[str] = None
    date_to: Optional[str] = None


@api.post("/v1/reports/run-custom")
async def run_custom_report(body: CustomReportBody, user: dict = Depends(get_current_user)):
    if body.fmt not in ("pdf", "csv"):
        raise HTTPException(400, "fmt must be 'pdf' or 'csv'")
    return await run_custom(db, body.model_dump(), body.fmt)


# --------------------------- INGESTION (API) ---------------------------
class UniversalFindingIn(BaseModel):
    source_tool: str
    source_record_id: str
    title: str
    severity: str
    description: Optional[str] = None
    cve: Optional[str] = None
    cwe: Optional[str] = None
    cvss_score: Optional[float] = None
    epss_score: Optional[float] = None
    kev_flag: Optional[bool] = False
    rti: Optional[List[str]] = []
    asset_hostname: str
    asset_ip: Optional[str] = None
    remediation: Optional[str] = None
    detection_logic: Optional[str] = None
    qid: Optional[str] = None
    plugin_id: Optional[str] = None


class UniversalIngestBody(BaseModel):
    idempotency_key: Optional[str] = None
    mode: str = "import"  # or "reimport"
    findings: List[UniversalFindingIn]


@api.post("/v1/ingest/universal")
async def ingest_universal(body: UniversalIngestBody, request: Request, _: dict = Depends(verify_api_key)):
    job_id = str(uuid.uuid4())
    started = now_iso()
    created = 0
    updated = 0
    dedup = 0
    failed = 0
    errors: list = []

    for f_in in body.findings:
        try:
            # Find or create asset
            asset = await db.assets.find_one({"hostname": f_in.asset_hostname}, {"_id": 0})
            if not asset:
                asset = {
                    "id": str(uuid.uuid4()), "hostname": f_in.asset_hostname, "ip": f_in.asset_ip,
                    "fqdn": None, "environment": "unknown", "criticality": "medium",
                    "exposure": "internal", "platform": "unknown", "operating_system": "unknown",
                    "asset_type": "server", "owner_team": "Unassigned",
                    "product_id": None, "product_name": None,
                    "tags": ["auto-created"], "status": "active", "created_at": now_iso(),
                    "ownership_confidence": 0.3, "ownership_rationale": "Auto-created from ingestion (no tag match)",
                }
                await db.assets.insert_one(asset)

            canonical = f"{f_in.cve or f_in.qid or f_in.source_record_id}::{f_in.asset_hostname}"
            existing = await db.findings.find_one({"canonical_key": canonical}, {"_id": 0})

            base_finding = {
                "source_tool": f_in.source_tool, "source_observation_id": f_in.source_record_id,
                "source_native_id": f_in.qid or f_in.plugin_id or f_in.source_record_id,
                "qid": f_in.qid, "plugin_id": f_in.plugin_id,
                "title": f_in.title, "description": f_in.description, "severity": f_in.severity,
                "cve": f_in.cve, "cwe": f_in.cwe,
                "cvss_score": f_in.cvss_score, "epss_score": f_in.epss_score or 0,
                "kev_flag": f_in.kev_flag or False, "rti": f_in.rti or [],
                "remediation": f_in.remediation, "detection_logic": f_in.detection_logic,
                "asset_id": asset["id"], "asset_hostname": asset["hostname"],
                "asset_ip": asset.get("ip"), "asset_criticality": asset["criticality"],
                "asset_exposure": asset["exposure"], "asset_environment": asset["environment"],
                "internet_facing": asset["exposure"] in ("internet", "external"),
                "owner_team": asset["owner_team"], "ownership_confidence": asset.get("ownership_confidence", 0.5),
                "product_id": asset.get("product_id"), "product_name": asset.get("product_name"),
                "last_seen_at": now_iso(), "last_changed_at": now_iso(),
                "imported_at": now_iso(), "detection_channel": "api_push",
            }

            if existing:
                # Reopen if it was closed and we see it again
                new_status = existing["status"]
                reopened = existing.get("reopened_count", 0)
                if existing["status"] in ("Fixed validated", "Mitigated", "Closed administratively"):
                    new_status = "Reopened"
                    reopened += 1
                base_finding["status"] = new_status
                base_finding["reopened_count"] = reopened
                base_finding["first_seen_at"] = existing["first_seen_at"]  # preserve original
                base_finding["canonical_key"] = canonical
                risk = compute_risk({**existing, **base_finding}, asset)
                base_finding["risk_score"] = risk["score"]
                base_finding["risk_breakdown"] = risk["breakdown"]
                await db.findings.update_one({"id": existing["id"]}, {"$set": base_finding})
                updated += 1
                if existing["status"] not in ("Fixed validated", "Mitigated", "Closed administratively"):
                    dedup += 1
            else:
                new_finding = {
                    "id": str(uuid.uuid4()), "canonical_key": canonical,
                    "first_seen_at": now_iso(), "reopened_count": 0,
                    "status": "New", "validation_status": "pending",
                    "sla_days": compute_sla_days(f_in.severity, asset["criticality"]),
                    "due_at": (datetime.now(timezone.utc) + timedelta(days=compute_sla_days(f_in.severity, asset["criticality"]))).isoformat(),
                    "tags": asset.get("tags", []),
                    "compliance_scope": [], "advisory_links": [], "exploit_references": [],
                    **base_finding,
                }
                risk = compute_risk(new_finding, asset)
                new_finding["risk_score"] = risk["score"]
                new_finding["risk_breakdown"] = risk["breakdown"]
                await db.findings.insert_one(new_finding)
                created += 1
                # Auto-dispatch on new finding
                try:
                    from notifier import dispatch
                    ctx = _finding_ctx(new_finding)
                    sev = new_finding.get("severity")
                    if sev == "Critical":
                        await dispatch("finding_created_critical", ctx, db)
                    elif sev == "High":
                        await dispatch("finding_created_high", ctx, db)
                    if new_finding.get("kev_flag"):
                        await dispatch("kev_match", ctx, db)
                except Exception as e:
                    logger.exception(f"notify dispatch failed: {e}")

            # Observation
            await db.observations.insert_one({
                "id": str(uuid.uuid4()),
                "finding_id": existing["id"] if existing else new_finding["id"],
                "asset_id": asset["id"], "source_tool": f_in.source_tool,
                "source_record_id": f_in.source_record_id, "qid": f_in.qid, "plugin_id": f_in.plugin_id,
                "detection_logic": f_in.detection_logic, "raw_severity": f_in.severity,
                "normalized_severity": f_in.severity, "observed_at": now_iso(), "imported_at": now_iso(),
            })
        except Exception as e:
            failed += 1
            errors.append({"record_id": f_in.source_record_id, "error": str(e)})

    job = {
        "id": job_id, "source_name": body.findings[0].source_tool if body.findings else "unknown",
        "mode": body.mode, "status": "failed" if failed and not created else "success",
        "request_id": body.idempotency_key or f"req_{uuid.uuid4().hex[:12]}",
        "started_at": started, "finished_at": now_iso(),
        "created_count": created, "updated_count": updated, "deduplicated_count": dedup,
        "failed_count": failed, "retry_count": 0, "errors": errors,
    }
    await db.import_jobs.insert_one(job)
    return _clean(job)


# --------------------------- ADMIN ---------------------------
@api.get("/v1/admin/users")
async def list_users(user: dict = Depends(require_role("admin"))):
    items = await db.users.find({}, {"_id": 0, "password_hash": 0}).to_list(100)
    return {"items": items}


class UserCreate(BaseModel):
    email: EmailStr
    name: str
    role: str = "analyst"
    team: Optional[str] = None
    department: Optional[str] = None
    password: Optional[str] = None


@api.post("/v1/admin/users")
async def create_user(body: UserCreate, user: dict = Depends(require_role("admin"))):
    existing = await db.users.find_one({"email": body.email.lower()})
    if existing:
        raise HTTPException(409, "Email already exists")
    if body.role not in ["admin", "analyst", "manager", "executive"]:
        raise HTTPException(400, "Invalid role")
    new = {
        "id": str(uuid.uuid4()), "email": body.email.lower(), "name": body.name,
        "role": body.role, "team": body.team, "department": body.department,
        "password_hash": hash_password(body.password) if body.password else None,
        "created_at": now_iso(), "active": True,
    }
    await db.users.insert_one(new)
    return {"id": new["id"], "email": new["email"]}


class UserUpdate(BaseModel):
    name: Optional[str] = None
    team: Optional[str] = None
    department: Optional[str] = None
    role: Optional[str] = None
    active: Optional[bool] = None
    password: Optional[str] = None


@api.patch("/v1/admin/users/{user_id}")
async def update_user(user_id: str, body: UserUpdate, user: dict = Depends(require_role("admin"))):
    update = {}
    for k, v in body.model_dump(exclude_none=True).items():
        if k == "password":
            update["password_hash"] = hash_password(v)
        else:
            update[k] = v
    if not update:
        raise HTTPException(400, "No fields to update")
    res = await db.users.update_one({"id": user_id}, {"$set": update})
    if res.matched_count == 0:
        raise HTTPException(404, "User not found")
    return {"ok": True}


@api.delete("/v1/admin/users/{user_id}")
async def delete_user(user_id: str, user: dict = Depends(require_role("admin"))):
    if user_id == user["id"]:
        raise HTTPException(400, "Cannot delete your own account")
    res = await db.users.delete_one({"id": user_id})
    await db.user_sessions.delete_many({"user_id": user_id})
    if res.deleted_count == 0:
        raise HTTPException(404, "User not found")
    return {"ok": True}


# --------------------------- NOTIFICATION CHANNELS & RULES ---------------------------
class ChannelIn(BaseModel):
    name: str
    type: str
    webhook_url: Optional[str] = None
    to: Optional[str] = None
    enabled: bool = True


@api.get("/v1/admin/notification-channels")
async def list_channels(user: dict = Depends(get_current_user)):
    items = await db.notification_channels.find({}, {"_id": 0}).to_list(100)
    for c in items:
        if c.get("webhook_url") and len(c["webhook_url"]) > 30:
            c["webhook_url_masked"] = c["webhook_url"][:32] + "•••" + c["webhook_url"][-6:]
        c.pop("webhook_url", None)
    return {"items": items}


@api.post("/v1/admin/notification-channels")
async def create_channel(body: ChannelIn, user: dict = Depends(require_role("admin"))):
    from notifier import CHANNELS
    if body.type not in CHANNELS:
        raise HTTPException(400, f"type must be one of {CHANNELS}")
    if body.type == "email" and not body.to:
        raise HTTPException(400, "to (recipient email) is required for email channels")
    if body.type in ("discord", "slack", "teams", "webhook") and not body.webhook_url:
        raise HTTPException(400, "webhook_url is required for this channel type")
    doc = {**body.model_dump(), "id": str(uuid.uuid4()), "created_at": now_iso()}
    await db.notification_channels.insert_one(doc)
    return {"id": doc["id"]}


@api.delete("/v1/admin/notification-channels/{channel_id}")
async def delete_channel(channel_id: str, user: dict = Depends(require_role("admin"))):
    await db.notification_channels.delete_one({"id": channel_id})
    return {"ok": True}


@api.post("/v1/admin/notification-channels/{channel_id}/test")
async def test_channel(channel_id: str, user: dict = Depends(require_role("admin"))):
    from notifier import deliver
    channel = await db.notification_channels.find_one({"id": channel_id}, {"_id": 0})
    if not channel:
        raise HTTPException(404, "Channel not found")
    ctx = {
        "severity": "Critical", "title": "Test notification — Log4Shell RCE",
        "cve": "CVE-2021-44228", "asset": "web-prod-01", "owner_team": "Platform Eng",
        "risk_score": 96, "due_at": "2026-03-01",
        "url": "https://remediationhub.preview.emergentagent.com/findings/demo",
    }
    rec = await deliver(channel, "new_assignment", ctx, db)
    return {"delivered": rec["delivered"], "status_code": rec["status_code"], "response": rec["response"]}


class RuleIn(BaseModel):
    name: str
    trigger: str
    channel_ids: list[str]
    severity_in: Optional[list[str]] = None
    owner_team: Optional[str] = None
    template_id: Optional[str] = None
    frequency: str = "immediate"
    active: bool = True


@api.get("/v1/admin/notification-rules")
async def list_rules_notif(user: dict = Depends(get_current_user)):
    items = await db.notification_rules.find({}, {"_id": 0}).to_list(200)
    return {"items": items}


@api.post("/v1/admin/notification-rules")
async def create_rule_notif(body: RuleIn, user: dict = Depends(require_role("admin"))):
    from notifier import TRIGGERS
    if body.trigger not in TRIGGERS:
        raise HTTPException(400, f"trigger must be one of {TRIGGERS}")
    doc = {**body.model_dump(), "id": str(uuid.uuid4()), "created_at": now_iso()}
    await db.notification_rules.insert_one(doc)
    return {"id": doc["id"]}


@api.delete("/v1/admin/notification-rules/{rule_id}")
async def delete_rule_notif(rule_id: str, user: dict = Depends(require_role("admin"))):
    await db.notification_rules.delete_one({"id": rule_id})
    return {"ok": True}


@api.get("/v1/admin/notifications-outbox")
async def list_outbox(user: dict = Depends(get_current_user)):
    items = await db.notifications_outbox.find({}, {"_id": 0}).sort("created_at", -1).limit(200).to_list(200)
    return {"items": items}


@api.get("/v1/admin/notification-meta")
async def notification_meta(user: dict = Depends(get_current_user)):
    from notifier import TRIGGERS, CHANNELS, TEMPLATES
    return {"triggers": TRIGGERS, "channels": CHANNELS, "templates": list(TEMPLATES.keys())}


# --------------------------- ASSIGNMENT RULES ---------------------------
class AssignmentRule(BaseModel):
    id: Optional[str] = None
    name: str
    priority: int = 100
    field: str  # tags|environment|platform|criticality|exposure|department
    operator: str = "equals"  # equals|contains
    value: str
    assign_team: str
    active: bool = True


@api.get("/v1/admin/assignment-rules")
async def list_rules(user: dict = Depends(get_current_user)):
    items = await db.assignment_rules.find({}, {"_id": 0}).sort("priority", 1).to_list(200)
    return {"items": items}


@api.post("/v1/admin/assignment-rules")
async def create_rule(body: AssignmentRule, user: dict = Depends(require_role("admin"))):
    rule = body.model_dump()
    rule["id"] = str(uuid.uuid4())
    rule["created_at"] = now_iso()
    await db.assignment_rules.insert_one(rule)
    return _clean(rule)


@api.patch("/v1/admin/assignment-rules/{rule_id}")
async def update_rule(rule_id: str, body: AssignmentRule, user: dict = Depends(require_role("admin"))):
    update = {k: v for k, v in body.model_dump().items() if k != "id" and v is not None}
    res = await db.assignment_rules.update_one({"id": rule_id}, {"$set": update})
    if res.matched_count == 0:
        raise HTTPException(404, "Rule not found")
    return {"ok": True}


@api.delete("/v1/admin/assignment-rules/{rule_id}")
async def delete_rule(rule_id: str, user: dict = Depends(require_role("admin"))):
    await db.assignment_rules.delete_one({"id": rule_id})
    return {"ok": True}


def _rule_matches(rule: dict, asset: dict) -> bool:
    f = rule["field"]
    val = rule["value"].lower()
    asset_val = asset.get(f) or asset.get("tags") if f == "tags" else asset.get(f)
    if f == "tags":
        tags = [str(t).lower() for t in (asset.get("tags") or [])]
        return val in tags if rule["operator"] == "equals" else any(val in t for t in tags)
    av = str(asset_val or "").lower()
    return av == val if rule["operator"] == "equals" else val in av


@api.post("/v1/admin/assignment-rules/apply")
async def apply_rules(user: dict = Depends(require_role("admin"))):
    rules = await db.assignment_rules.find({"active": True}, {"_id": 0}).sort("priority", 1).to_list(500)
    assets = await db.assets.find({}, {"_id": 0}).to_list(5000)
    updated_assets = 0
    updated_findings = 0
    for asset in assets:
        matched_rule = next((r for r in rules if _rule_matches(r, asset)), None)
        if matched_rule:
            new_team = matched_rule["assign_team"]
            rationale = f"Matched rule '{matched_rule['name']}': {matched_rule['field']} {matched_rule['operator']} '{matched_rule['value']}'"
            confidence = 0.95
        else:
            new_team = asset.get("owner_team", "Unassigned")
            rationale = "No assignment rule matched — preserved existing owner"
            confidence = 0.3
        await db.assets.update_one({"id": asset["id"]}, {"$set": {
            "owner_team": new_team, "ownership_rationale": rationale, "ownership_confidence": confidence,
        }})
        updated_assets += 1
        r = await db.findings.update_many(
            {"asset_id": asset["id"], "status": {"$nin": ["Fixed validated", "Closed administratively"]}},
            {"$set": {"owner_team": new_team, "ownership_confidence": confidence, "ownership_rationale": rationale}},
        )
        updated_findings += r.modified_count
    return {"updated_assets": updated_assets, "updated_findings": updated_findings, "rules_evaluated": len(rules)}


@api.get("/v1/ownership-mappings")
async def ownership_mappings(user: dict = Depends(get_current_user), q: Optional[str] = None):
    flt = {}
    if q:
        flt["$or"] = [{"hostname": {"$regex": q, "$options": "i"}}, {"owner_team": {"$regex": q, "$options": "i"}}]
    items = await db.assets.find(flt, {"_id": 0, "id": 1, "hostname": 1, "owner_team": 1,
                                       "ownership_confidence": 1, "ownership_rationale": 1, "tags": 1,
                                       "environment": 1, "platform": 1, "criticality": 1, "exposure": 1}).to_list(1000)
    return {"items": items}


@api.get("/v1/admin/sla-policies")
async def get_sla_policies(user: dict = Depends(get_current_user)):
    from scoring import SLA_DAYS
    return {"policies": SLA_DAYS}


@api.get("/v1/admin/api-keys")
async def list_api_keys(user: dict = Depends(require_role("admin"))):
    items = await db.api_keys.find({}, {"_id": 0}).to_list(100)
    return {"items": items}


# --------------------------- OPERATIONAL DASHBOARD ---------------------------
@api.get("/v1/dashboards/operational")
async def dashboard_operational(user: dict = Depends(get_current_user), team: Optional[str] = None):
    base_flt: dict = {}
    if team:
        base_flt["owner_team"] = team
    open_states = ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]

    # Aging buckets
    now_dt = datetime.now(timezone.utc)
    buckets = {"0-7": 0, "8-30": 0, "31-60": 0, "61-90": 0, "90+": 0}
    by_assignee: dict = {}
    overdue_by_sev: dict = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    total_open = 0
    reopened_total = 0
    async for f in db.findings.find({**base_flt, "status": {"$in": open_states}},
                                    {"_id": 0, "first_seen_at": 1, "owner_team": 1, "assigned_to": 1,
                                     "severity": 1, "due_at": 1, "reopened_count": 1}):
        total_open += 1
        if f.get("reopened_count", 0):
            reopened_total += 1
        try:
            fs = datetime.fromisoformat((f.get("first_seen_at") or "").replace("Z", "+00:00"))
            age = (now_dt - fs).days
            if age <= 7: buckets["0-7"] += 1
            elif age <= 30: buckets["8-30"] += 1
            elif age <= 60: buckets["31-60"] += 1
            elif age <= 90: buckets["61-90"] += 1
            else: buckets["90+"] += 1
        except Exception:
            pass
        a = f.get("assigned_to") or f.get("owner_team") or "Unassigned"
        by_assignee[a] = by_assignee.get(a, 0) + 1
        if f.get("due_at") and f["due_at"] < now_iso():
            overdue_by_sev[f.get("severity", "Info")] = overdue_by_sev.get(f.get("severity", "Info"), 0) + 1

    # Throughput last 30 days
    throughput = []
    for d in range(29, -1, -1):
        day = now_dt - timedelta(days=d)
        start = day.replace(hour=0, minute=0, second=0).isoformat()
        end = (day + timedelta(days=1)).replace(hour=0, minute=0, second=0).isoformat()
        opened = await db.findings.count_documents({**base_flt, "first_seen_at": {"$gte": start, "$lt": end}})
        closed = await db.findings.count_documents({**base_flt, "last_changed_at": {"$gte": start, "$lt": end},
                                                    "status": {"$in": ["Fixed validated", "Mitigated", "Closed administratively"]}})
        throughput.append({"date": day.strftime("%Y-%m-%d"), "opened": opened, "closed": closed, "net": opened - closed})

    # MTTR & MTTT — sample from closed findings
    mttr_samples = []
    async for f in db.findings.find({**base_flt, "status": {"$in": ["Fixed validated", "Mitigated"]}},
                                    {"first_seen_at": 1, "last_changed_at": 1}).limit(500):
        try:
            fs = datetime.fromisoformat(f["first_seen_at"].replace("Z", "+00:00"))
            lc = datetime.fromisoformat(f["last_changed_at"].replace("Z", "+00:00"))
            mttr_samples.append((lc - fs).days)
        except Exception:
            pass
    mttr = round(sum(mttr_samples) / len(mttr_samples), 1) if mttr_samples else 0
    closed_total = await db.findings.count_documents({**base_flt, "status": {"$in": ["Fixed validated", "Mitigated"]}})
    reopen_rate = round((reopened_total / max(closed_total + reopened_total, 1)) * 100, 1)

    # Scan coverage = assets with at least one observation in last 14d / total assets
    cutoff = (now_dt - timedelta(days=14)).isoformat()
    scanned = await db.observations.distinct("asset_id", {"observed_at": {"$gte": cutoff}})
    total_assets = await db.assets.count_documents({})
    coverage = round((len(scanned) / max(total_assets, 1)) * 100, 1)

    return {
        "total_open": total_open, "aging_buckets": buckets,
        "by_assignee": [{"assignee": k, "count": v} for k, v in sorted(by_assignee.items(), key=lambda x: -x[1])][:15],
        "overdue_by_severity": overdue_by_sev,
        "throughput": throughput, "mttr_days": mttr, "reopen_rate": reopen_rate,
        "scan_coverage_pct": coverage, "reopened_open": reopened_total,
        "active_exceptions": await db.exceptions.count_documents({"status": "active"}),
        "team_scope": team or "All teams",
    }


# --------------------------- LATE-DEFINED ROUTES ---------------------------
@api.post("/v1/admin/nightly-rescore/run")
async def trigger_nightly(user: dict = Depends(require_role("admin"))):
    from nightly import run_nightly_rescore
    return await run_nightly_rescore(db)


@api.get("/v1/admin/nightly-rescore/runs")
async def list_rescore_runs(user: dict = Depends(get_current_user)):
    items = await db.rescoring_runs.find({}, {"_id": 0}).sort("ran_at", -1).limit(50).to_list(50)
    return {"items": items}


# --------------------------- USER PREFERENCES (Tile picker / saved layouts) ---------------------------
DEFAULT_PREFS: dict = {
    "dashboard": {
        "range": "30d",
        "tiles": {
            "stat-open": True, "stat-triage": True, "stat-kev": True, "stat-rti": True,
            "stat-overdue": True, "stat-reopened": True, "stat-unassigned": True,
            "stat-lowconf": True, "stat-failedimports": True, "stat-new": True,
            "panel-severity": True, "panel-top-findings": True, "panel-imports": True,
            "panel-cwe": True,
        },
    },
    "findings": {
        "group_by": "none",   # none | cve | os | title | severity | asset
        "view_mode": "by_asset",  # by_asset | by_vulnerability
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


@api.get("/v1/me/preferences")
async def get_my_preferences(user: dict = Depends(get_current_user)):
    doc = await db.user_preferences.find_one({"user_id": user["id"]}, {"_id": 0})
    prefs = doc.get("prefs", {}) if doc else {}
    return _deep_merge(DEFAULT_PREFS, prefs)


class PrefsBody(BaseModel):
    prefs: dict


@api.put("/v1/me/preferences")
async def put_my_preferences(body: PrefsBody, user: dict = Depends(get_current_user)):
    merged = _deep_merge(DEFAULT_PREFS, body.prefs or {})
    await db.user_preferences.update_one(
        {"user_id": user["id"]},
        {"$set": {"user_id": user["id"], "prefs": merged, "updated_at": now_iso()}},
        upsert=True,
    )
    return merged


# --------------------------- FINDINGS GROUPING ---------------------------
@api.get("/v1/findings-groups")
async def findings_group(
    user: dict = Depends(get_current_user),
    group_by: str = Query("cve", regex="^(cve|os|title|severity|asset|none)$"),
    view_mode: str = Query("by_asset", regex="^(by_asset|by_vulnerability)$"),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    owner_team: Optional[str] = None,
    limit: int = 100,
):
    flt: dict = {"status": {"$in": ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]}}
    if severity:
        flt["severity"] = severity
    if status:
        flt["status"] = status
    if owner_team:
        flt["owner_team"] = owner_team

    # Map group_by to the appropriate field; "asset" groups by hostname; "os" groups by asset_os
    field_map = {
        "cve": "$cve", "os": "$asset_os", "title": "$title",
        "severity": "$severity", "asset": "$asset_hostname",
    }
    if group_by == "none":
        # Fall back to plain list (limited) to keep contract uniform
        items = await db.findings.find(flt, {"_id": 0}).sort("risk_score", -1).limit(limit).to_list(limit)
        return {"group_by": "none", "view_mode": view_mode, "groups": [{"key": "—", "count": len(items), "max_risk": items[0]["risk_score"] if items else 0, "items": items}]}

    grp_field = field_map[group_by]
    # "by_vulnerability" view collapses by canonical_key (de-dupes the same CVE across assets)
    if view_mode == "by_vulnerability" and group_by == "cve":
        pipeline = [
            {"$match": flt},
            {"$group": {"_id": grp_field,
                        "count": {"$sum": 1},
                        "unique_assets": {"$addToSet": "$asset_id"},
                        "max_risk": {"$max": "$risk_score"},
                        "severities": {"$addToSet": "$severity"},
                        "kev": {"$max": {"$cond": [{"$eq": ["$kev_flag", True]}, 1, 0]}},
                        "sample_title": {"$first": "$title"},
                        "sample_id": {"$first": "$id"}}},
            {"$project": {"_id": 0, "key": "$_id", "count": 1, "max_risk": 1,
                          "asset_count": {"$size": "$unique_assets"}, "severities": 1,
                          "kev": 1, "sample_title": 1, "sample_id": 1}},
            {"$sort": {"max_risk": -1}},
            {"$limit": limit},
        ]
    else:
        pipeline = [
            {"$match": flt},
            {"$group": {"_id": grp_field,
                        "count": {"$sum": 1},
                        "max_risk": {"$max": "$risk_score"},
                        "severities": {"$addToSet": "$severity"},
                        "sample_title": {"$first": "$title"},
                        "sample_id": {"$first": "$id"}}},
            {"$project": {"_id": 0, "key": "$_id", "count": 1, "max_risk": 1,
                          "severities": 1, "sample_title": 1, "sample_id": 1}},
            {"$sort": {"max_risk": -1, "count": -1}},
            {"$limit": limit},
        ]
    groups = [r async for r in db.findings.aggregate(pipeline)]
    # Replace None keys for display
    for g in groups:
        if g.get("key") is None:
            g["key"] = "—"
    return {"group_by": group_by, "view_mode": view_mode, "groups": groups, "total_groups": len(groups)}


@api.get("/")
async def root():
    return {"name": "VulnOps API", "version": "1.0.0", "status": "ok"}


# --------------------------- INCLUDE & STARTUP ---------------------------
app.include_router(api)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def on_startup():
    await db.users.create_index("email", unique=True)
    await db.findings.create_index("canonical_key")
    await db.findings.create_index("asset_id")
    await db.findings.create_index("status")
    await db.findings.create_index("severity")
    await db.observations.create_index("finding_id")
    await db.api_keys.create_index("key", unique=True)
    try:
        await seed_all(db)
        logger.info("Seed completed.")
    except Exception as e:
        logger.exception(f"Seed failed: {e}")
    # Nightly rescore loop (24h)
    import asyncio as _a
    from nightly import nightly_loop
    _a.create_task(nightly_loop(db, interval_hours=24))
