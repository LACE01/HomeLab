"""Findings routes: list, stats, detail, KRI, comments, status updates, bulk ops,
prioritization preview, attack-paths, CWE prevalence, threat-intel, findings-groups."""
import uuid
from datetime import datetime, timezone
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from db import db
from auth_utils import get_current_user
from scoring import compute_risk
from routes.common import now_iso, _clean, finding_ctx

router = APIRouter()


# --------------------------- FINDINGS LIST + STATS ---------------------------
@router.get("/v1/findings")
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


@router.get("/v1/findings/stats")
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


# --------------------------- FINDINGS-GROUPS (literal path before {finding_id}) ---------------------------
@router.get("/v1/findings-groups")
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

    field_map = {
        "cve": "$cve", "os": "$asset_os", "title": "$title",
        "severity": "$severity", "asset": "$asset_hostname",
    }
    if group_by == "none":
        items = await db.findings.find(flt, {"_id": 0}).sort("risk_score", -1).limit(limit).to_list(limit)
        return {"group_by": "none", "view_mode": view_mode, "groups": [{"key": "—", "count": len(items), "max_risk": items[0]["risk_score"] if items else 0, "items": items}]}

    grp_field = field_map[group_by]
    if view_mode == "by_vulnerability" and group_by == "cve":
        pipeline = [
            {"$match": flt},
            {"$sort": {"risk_score": -1}},
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
            {"$sort": {"risk_score": -1}},
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
    for g in groups:
        if g.get("key") is None:
            g["key"] = "—"
    return {"group_by": group_by, "view_mode": view_mode, "groups": groups, "total_groups": len(groups)}


# --------------------------- CWE PREVALENCE ---------------------------
@router.get("/v1/cwe-prevalence")
async def cwe_prevalence(user: dict = Depends(get_current_user)):
    from scoring_v2 import cwe_prevalence_map
    weights = await cwe_prevalence_map(db)
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
@router.get("/v1/threat-intel/{cve}")
async def threat_intel_for_cve(cve: str, user: dict = Depends(get_current_user)):
    integration = await db.integrations.find_one({"name": "OpenCTI"}, {"_id": 0})
    cfg = (integration or {}).get("config") or {}
    endpoint = cfg.get("endpoint")
    api_key = cfg.get("api_key")

    if not endpoint or not api_key:
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
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as c:
            r = await c.post(endpoint.rstrip("/") + "/graphql",
                             headers={"Authorization": f"Bearer {api_key}",
                                      "Content-Type": "application/json"},
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
                rtype = rn.get("relationship_type", "")
                if "actor" in rtype.lower():
                    actors.append(name)
                elif "intrusion" in rtype.lower():
                    sets_.append(name)
                elif "campaign" in rtype.lower():
                    campaigns.append(name)
                else:
                    malware.append(name)
        return {"configured": True, "cve": cve,
                "threat_actors": list(set(actors)), "intrusion_sets": list(set(sets_)),
                "malware": list(set(malware)), "campaigns": list(set(campaigns)),
                "external_references": refs[:20]}
    except Exception as e:
        return {"configured": True, "cve": cve, "error": str(e)}


# --------------------------- ATTACK PATH ---------------------------
@router.get("/v1/attack-paths/cves")
async def attack_path_cves(user: dict = Depends(get_current_user)):
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


@router.get("/v1/attack-paths/graph")
async def attack_path_graph(cve: Optional[str] = None, finding_id: Optional[str] = None,
                             user: dict = Depends(get_current_user)):
    from attack_path import build_attack_path
    return await build_attack_path(db, cve=cve, finding_id=finding_id)


# --------------------------- PARAMETERIZED ROUTES (must come AFTER literal /v1/findings-groups etc) ---------------------------
@router.get("/v1/findings/{finding_id}")
async def get_finding(finding_id: str, user: dict = Depends(get_current_user)):
    f = await db.findings.find_one({"id": finding_id}, {"_id": 0})
    if not f:
        raise HTTPException(404, "Finding not found")
    return f


@router.get("/v1/findings/{finding_id}/kri")
async def finding_kri(finding_id: str, user: dict = Depends(get_current_user)):
    """KRI / ZDES / BII / urgency tier / Empirical percentile / Critical Indicators for one finding."""
    from scoring_v2 import (compute_kri, compute_zdes, compute_bii, urgency_tier,
                            empirical_percentile, critical_indicators, cwe_prevalence_map)
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


@router.get("/v1/findings/{finding_id}/timeline")
async def finding_timeline(finding_id: str, user: dict = Depends(get_current_user)):
    items = await db.activity_log.find({"entity_type": "finding", "entity_id": finding_id}, {"_id": 0}).sort("timestamp", -1).to_list(200)
    return {"items": items}


@router.get("/v1/findings/{finding_id}/observations")
async def finding_observations(finding_id: str, user: dict = Depends(get_current_user)):
    items = await db.observations.find({"finding_id": finding_id}, {"_id": 0}).sort("observed_at", -1).to_list(100)
    return {"items": items}


@router.get("/v1/findings/{finding_id}/tickets")
async def finding_tickets(finding_id: str, user: dict = Depends(get_current_user)):
    items = await db.tickets.find({"finding_id": finding_id}, {"_id": 0}).to_list(50)
    return {"items": items}


@router.get("/v1/findings/{finding_id}/comments")
async def finding_comments(finding_id: str, user: dict = Depends(get_current_user)):
    items = await db.comments.find({"finding_id": finding_id}, {"_id": 0}).sort("created_at", -1).to_list(200)
    return {"items": items}


class CommentBody(BaseModel):
    text: str
    attachments: Optional[List[dict]] = None  # [{name, mime, data_url}] — data_url is base64 (small images only)


@router.post("/v1/findings/{finding_id}/comments")
async def add_comment(finding_id: str, body: CommentBody, user: dict = Depends(get_current_user)):
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


@router.patch("/v1/findings/{finding_id}/status")
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
    if body.status == "Reopened":
        from notifier import dispatch
        f = await db.findings.find_one({"id": finding_id}, {"_id": 0})
        if f:
            await dispatch("finding_reopened", finding_ctx(f), db)
    return {"ok": True}


class BulkStatus(BaseModel):
    ids: List[str]
    status: str
    note: Optional[str] = None


@router.post("/v1/findings/bulk-status")
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


@router.post("/v1/findings/bulk-assign")
async def bulk_assign(body: AssignBody, user: dict = Depends(get_current_user)):
    await db.findings.update_many({"id": {"$in": body.ids}},
                                  {"$set": {"assigned_to": body.assignee, "last_changed_at": now_iso()}})
    return {"updated": len(body.ids)}


class OwnerTeamBody(BaseModel):
    ids: List[str]
    owner_team: str


@router.post("/v1/findings/bulk-owner")
async def bulk_owner(body: OwnerTeamBody, user: dict = Depends(get_current_user)):
    """Bulk-update owner_team for selected findings. Sets ownership_confidence to 1.0
    because a human explicitly assigned them."""
    await db.findings.update_many(
        {"id": {"$in": body.ids}},
        {"$set": {
            "owner_team": body.owner_team,
            "ownership_confidence": 1.0,
            "ownership_rationale": f"Manually assigned to {body.owner_team} by {user['email']}",
            "last_changed_at": now_iso(),
        }},
    )
    docs = [{"id": str(uuid.uuid4()), "entity_type": "finding", "entity_id": fid,
             "action": "bulk_owner", "actor": user["email"], "timestamp": now_iso(),
             "details": f"Owner team set to {body.owner_team}"} for fid in body.ids]
    if docs:
        await db.activity_log.insert_many(docs)
    return {"updated": len(body.ids), "owner_team": body.owner_team}


@router.get("/v1/prioritization/preview")
async def prioritization_preview(finding_id: str, user: dict = Depends(get_current_user)):
    f = await db.findings.find_one({"id": finding_id}, {"_id": 0})
    if not f:
        raise HTTPException(404, "Finding not found")
    asset = await db.assets.find_one({"id": f.get("asset_id")}, {"_id": 0})
    return compute_risk(f, asset)
