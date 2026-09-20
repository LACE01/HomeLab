"""Findings routes: list, stats, detail, KRI, comments, status updates, bulk ops,
prioritization preview, attack-paths, CWE prevalence, threat-intel, findings-groups."""
import re
import csv
import io
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from db import db
from rbac import require_module
from auth_utils import get_current_user, require_role
from scoring import compute_risk
from routes.common import now_iso, _clean, finding_ctx, team_scope_filter, OPEN_STATUSES, RESOLVED_STATUSES

router = APIRouter()


def _parse_search_operators(q: str):
    """Pull field-scoped operators out of the search box (#58): qid:, cve:, owner:,
    source:, entity:. Returns (free_text, extra_filter_clauses). Whatever isn't an
    operator stays as free text for the normal title/CVE/hostname/QID search."""
    if not q:
        return "", []
    extra, free = [], []
    for tok in q.split():
        if ":" in tok:
            field, _, val = tok.partition(":")
            field, val = field.lower().strip(), val.strip()
            if not val:
                continue
            if field == "qid":
                ors = [{"qid": {"$regex": val, "$options": "i"}}]
                if val.isdigit():
                    ors += [{"qid": int(val)}, {"qid": val}]
                extra.append({"$or": ors})
                continue
            if field == "cve":
                extra.append({"cve": {"$regex": val, "$options": "i"}}); continue
            if field in ("owner", "team"):
                extra.append({"owner_team": {"$regex": val, "$options": "i"}}); continue
            if field == "source":
                extra.append({"source_tool": {"$regex": val, "$options": "i"}}); continue
            if field == "entity":
                extra.append({"entity_name": {"$regex": val, "$options": "i"}}); continue
        free.append(tok)
    return " ".join(free), extra


def _q_or_clauses(q: str) -> list:
    """Free-text search across title/CVE/hostname/QID. QID is stored as a string
    by some scanners and as an int by others, and a $regex never matches a numeric
    field -- which is exactly why searching a QID looked wired but returned nothing.
    So for an all-digits query we also match the QID (and plugin_id) as a number."""
    ql = (q or "").strip()
    ors = [
        {"title": {"$regex": ql, "$options": "i"}},
        {"cve": {"$regex": ql, "$options": "i"}},
        {"asset_hostname": {"$regex": ql, "$options": "i"}},
        {"qid": {"$regex": ql, "$options": "i"}},
    ]
    if ql.isdigit():
        ors.append({"qid": int(ql)})
        ors.append({"qid": ql})
        ors.append({"plugin_id": ql})
        ors.append({"plugin_id": int(ql)})
    return ors


# --------------------------- FINDINGS LIST + STATS ---------------------------
async def _build_findings_filter(
    user, *, q=None, severity=None, status=None, kev=None, internet_facing=None,
    owner_team=None, product_id=None, asset_id=None, tags=None, asset_type=None,
    exploitability=None, include_resolved=False, cve=None, cwe=None, view=None,
    platform=None, min_risk_score=None, source_tool=None,
    sla=None, age_days=None, entity=None, confidence=None,
    qid=None, hostname=None, title=None,
) -> dict:
    """Shared filter builder for the findings list AND the CSV export, so an export
    reflects exactly the same filters (and team scoping, and hide-resolved default)
    as what's on screen."""
    flt: dict = {}
    # Team scoping: analyst/executive users only see their team(s)' findings --
    # a user can now belong to more than one team, so this is an $in over every
    # team they're on, not an exact match against a single string. admin + manager
    # see everything (team_scope_filter returns {} for those roles).
    flt.update(team_scope_filter(user))
    and_clauses: list = []
    if severity:
        flt["severity"] = {"$in": severity}
    if status:
        flt["status"] = {"$in": status}
    if kev is not None:
        flt["kev_flag"] = kev
    if internet_facing is not None:
        flt["internet_facing"] = internet_facing
    if owner_team:
        flt["owner_team"] = owner_team
    if product_id:
        flt["product_id"] = product_id

    # Asset attribute filters (tags / asset_type) live on the ASSET, so resolve
    # them to a set of asset ids and intersect with any explicit asset_id filter.
    asset_conds: dict = {}
    if tags:
        asset_conds["tags"] = {"$in": tags}
    if asset_type:
        asset_conds["asset_type"] = {"$in": asset_type}
    if asset_conds:
        matched_ids = [a["id"] for a in await db.assets.find(
            asset_conds, {"_id": 0, "id": 1}).to_list(50000)]
        if asset_id:
            matched_ids = [i for i in matched_ids if i in set(asset_id)]
        # a filter that matches no asset must return nothing, not everything
        and_clauses.append({"asset_id": {"$in": matched_ids or ["__no_match__"]}})
    elif asset_id:
        and_clauses.append({"asset_id": {"$in": asset_id}})

    # Ease-of-exploitability: any of the selected signals (OR within the facet).
    if exploitability:
        exploit_map = {
            "kev": {"kev_flag": True},
            "active_attacks": {"rti": "active_attacks"},
            "public_exploit": {"rti": "public_exploit"},
            "epss_high": {"epss_score": {"$gte": 0.5}},
        }
        or_conds = [exploit_map[e] for e in exploitability if e in exploit_map]
        if or_conds:
            and_clauses.append({"$or": or_conds})
    if cve:
        flt["cve"] = {"$in": cve} if isinstance(cve, list) else cve
    if qid:
        ql = qid if isinstance(qid, list) else [qid]
        qor = [{"qid": {"$in": ql}}]
        ints = [int(x) for x in ql if str(x).isdigit()]
        if ints:
            qor.append({"qid": {"$in": ints}})
        and_clauses.append({"$or": qor})
    if hostname:
        hl = hostname if isinstance(hostname, list) else [hostname]
        and_clauses.append({"asset_hostname": {"$in": hl}})
    if title:
        tl = title if isinstance(title, list) else [title]
        and_clauses.append({"title": {"$in": tl}})
    if cwe:
        flt["cwe"] = cwe
    if platform:
        flt["asset_os"] = {"$regex": platform, "$options": "i"}
    if min_risk_score is not None:
        flt["risk_score"] = {"$gte": min_risk_score}
    if source_tool:
        # Exact-ish match rather than a bare $eq -- YARA/SBOM "view what this scan
        # created" deep links pass this, and a case-sensitive exact match is brittle
        # against minor naming drift ("SBOM / OSV.dev" vs "SBOM/OSV.dev" etc).
        flt["source_tool"] = {"$regex": f"^{re.escape(source_tool)}$", "$options": "i"}
    # #58 field-scoped operators (qid:/cve:/owner:/source:/entity:) + free text
    free_text, op_clauses = _parse_search_operators(q)
    and_clauses.extend(op_clauses)
    if free_text:
        and_clauses.append({"$or": _q_or_clauses(free_text)})

    # #58 additional filters
    if sla == "overdue":
        and_clauses.append({"due_at": {"$lt": datetime.now(timezone.utc).isoformat()}})
    elif sla == "within":
        and_clauses.append({"due_at": {"$gte": datetime.now(timezone.utc).isoformat()}})
    if age_days is not None:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=int(age_days))).isoformat()
        and_clauses.append({"first_seen_at": {"$lte": cutoff}})
    if entity:
        flt["entity_name"] = {"$regex": entity, "$options": "i"}
    if confidence == "low":
        and_clauses.append({"$or": [{"ownership_confidence": {"$lt": 0.5}},
                                    {"ownership_confidence": {"$exists": False}}]})
    elif confidence == "high":
        and_clauses.append({"ownership_confidence": {"$gte": 0.5}})

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
    elif view == "active_attacks":
        flt["rti"] = "active_attacks"
        flt["status"] = {"$in": ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]}
    elif view == "unassigned":
        flt["assigned_to"] = None
        flt["status"] = {"$in": ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]}

    # #60: by default the list shows only OPEN findings. Resolved/fixed items were
    # appearing in the default (unfiltered) list and being counted as active, which
    # inflated the numbers. If the user explicitly picks statuses, or a view sets
    # one, or asks to include resolved, we respect that.
    if not include_resolved and not status and not view and "status" not in flt:
        flt["status"] = {"$in": OPEN_STATUSES}

    if and_clauses:
        flt["$and"] = flt.get("$and", []) + and_clauses
    return flt



@router.get("/v1/findings")
async def list_findings(
    user: dict = Depends(get_current_user),
    q: Optional[str] = None,
    severity: Optional[List[str]] = Query(None),
    status: Optional[List[str]] = Query(None),
    kev: Optional[bool] = None,
    internet_facing: Optional[bool] = None,
    owner_team: Optional[str] = None,
    product_id: Optional[str] = None,
    asset_id: Optional[List[str]] = Query(None),
    tags: Optional[List[str]] = Query(None),
    asset_type: Optional[List[str]] = Query(None),
    exploitability: Optional[List[str]] = Query(None),
    include_resolved: bool = False,
    cve: Optional[str] = None,
    cwe: Optional[str] = None,
    view: Optional[str] = None,
    platform: Optional[str] = None,
    min_risk_score: Optional[int] = None,
    source_tool: Optional[str] = None,
    sla: Optional[str] = None,
    age_days: Optional[int] = None,
    entity: Optional[str] = None,
    confidence: Optional[str] = None,
    sort: str = "risk_score",
    order: str = "desc",
    limit: int = 100,
    offset: int = 0,
    _rbac: dict = Depends(require_module("/findings")),
):
    flt = await _build_findings_filter(
        user, q=q, severity=severity, status=status, kev=kev, internet_facing=internet_facing,
        owner_team=owner_team, product_id=product_id, asset_id=asset_id, tags=tags,
        asset_type=asset_type, exploitability=exploitability, include_resolved=include_resolved,
        cve=cve, cwe=cwe, view=view, platform=platform, min_risk_score=min_risk_score,
        source_tool=source_tool, sla=sla, age_days=age_days, entity=entity, confidence=confidence,
    )

    sort_dir = -1 if order == "desc" else 1
    cursor = db.findings.find(flt, {"_id": 0}).sort(sort, sort_dir).skip(offset).limit(limit)
    items = await cursor.to_list(length=limit)
    total = await db.findings.count_documents(flt)
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/v1/findings/suggest")
async def findings_suggest(field: str, q: str = "", limit: int = 15,
                           user: dict = Depends(get_current_user),
                           _rbac: dict = Depends(require_module("/findings"))):
    """Autocomplete for the campaign scope picker (and anywhere else): distinct
    values of a field matching q, so users pick real values instead of having to
    type an exact string. field: cve | qid | title | hostname."""
    col = {"cve": "cve", "qid": "qid", "title": "title", "hostname": "asset_hostname"}.get(field)
    if not col:
        raise HTTPException(400, "field must be one of cve, qid, title, hostname")
    ql = (q or "").strip()
    query = {col: {"$regex": re.escape(ql), "$options": "i"}} if ql else {col: {"$ne": None}}
    try:
        vals = await db.findings.distinct(col, query)
    except Exception:
        vals = []
    # qid can be stored as int -> stringify + also match numeric prefix
    out = sorted({str(v) for v in vals if v not in (None, "")},
                 key=lambda x: (not x.lower().startswith(ql.lower()), x))
    return {"items": out[:limit]}


@router.get("/v1/findings/stats")
async def findings_stats(user: dict = Depends(get_current_user)):
    # #60: severity/KEV headline counts are OPEN-scoped so resolved findings don't
    # inflate the dashboard. by_status still spans every status (that's its job),
    # and by_severity_all keeps the all-inclusive breakdown for anyone who wants it.
    pipeline_sev = [{"$match": {"status": {"$in": OPEN_STATUSES}}},
                    {"$group": {"_id": "$severity", "count": {"$sum": 1}}}]
    pipeline_sev_all = [{"$group": {"_id": "$severity", "count": {"$sum": 1}}}]
    pipeline_status = [{"$group": {"_id": "$status", "count": {"$sum": 1}}}]
    sev = {r["_id"]: r["count"] async for r in db.findings.aggregate(pipeline_sev)}
    sev_all = {r["_id"]: r["count"] async for r in db.findings.aggregate(pipeline_sev_all)}
    statuses = {r["_id"]: r["count"] async for r in db.findings.aggregate(pipeline_status)}
    total = await db.findings.count_documents({})
    open_total = await db.findings.count_documents({"status": {"$in": OPEN_STATUSES}})
    kev_count = await db.findings.count_documents({"kev_flag": True, "status": {"$in": OPEN_STATUSES}})
    overdue = await db.findings.count_documents({
        "due_at": {"$lt": now_iso()},
        "status": {"$in": ["New", "Needs triage", "Valid", "Reopened"]},
    })
    # Facet option lists for the Findings filter UI. Tags and device type live on
    # the asset, so pull the distinct values from there.
    try:
        tags = sorted([t for t in await db.assets.distinct("tags") if t])[:200]
    except Exception:
        tags = []
    try:
        asset_types = sorted([t for t in await db.assets.distinct("asset_type") if t])
    except Exception:
        asset_types = []
    return {"total": total, "open_total": open_total, "by_severity": sev,
            "by_severity_all": sev_all, "by_status": statuses, "kev": kev_count,
            "overdue": overdue, "available_tags": tags, "available_asset_types": asset_types,
            "resolved_statuses": RESOLVED_STATUSES}


# Column catalogue for the flexible CSV export (#59). label -> how to read it off a
# finding doc. The frontend column picker offers exactly these.
EXPORT_COLUMNS = {
    "id": ("ID", lambda f: f.get("id")),
    "cve": ("CVE", lambda f: f.get("cve") or ""),
    "qid": ("QID", lambda f: f.get("qid") or f.get("source_native_id") or ""),
    "title": ("Title", lambda f: f.get("title") or ""),
    "severity": ("Severity", lambda f: f.get("severity") or ""),
    "cvss": ("CVSS", lambda f: f.get("cvss_score")),
    "epss": ("EPSS", lambda f: f.get("epss_score")),
    "kev": ("KEV", lambda f: "YES" if f.get("kev_flag") else "NO"),
    "risk_score": ("Risk Score", lambda f: f.get("risk_score")),
    "status": ("Status", lambda f: f.get("status") or ""),
    "asset": ("Asset", lambda f: f.get("asset_hostname") or ""),
    "ip": ("IP", lambda f: f.get("asset_ip") or ""),
    "owner_team": ("Owner Team", lambda f: f.get("owner_team") or ""),
    "assigned_to": ("Assigned To", lambda f: f.get("assigned_to") or ""),
    "internet_facing": ("Internet Facing", lambda f: "YES" if f.get("internet_facing") else "NO"),
    "first_seen": ("First Seen", lambda f: f.get("first_seen_at") or ""),
    "due": ("Due", lambda f: f.get("due_at") or ""),
    "source": ("Source", lambda f: f.get("source_tool") or ""),
    "entity": ("Entity", lambda f: f.get("entity_name") or ""),
}
DEFAULT_EXPORT_COLUMNS = ["cve", "qid", "title", "severity", "kev", "risk_score",
                          "status", "asset", "ip", "owner_team", "due", "source"]


@router.get("/v1/findings/export")
async def export_findings(
    user: dict = Depends(get_current_user),
    _rbac: dict = Depends(require_module("/findings")),
    # same filter surface as the list, so the export respects what's on screen
    q: Optional[str] = None,
    severity: Optional[List[str]] = Query(None),
    status: Optional[List[str]] = Query(None),
    kev: Optional[bool] = None,
    internet_facing: Optional[bool] = None,
    owner_team: Optional[str] = None,
    asset_id: Optional[List[str]] = Query(None),
    tags: Optional[List[str]] = Query(None),
    asset_type: Optional[List[str]] = Query(None),
    exploitability: Optional[List[str]] = Query(None),
    include_resolved: bool = False,
    cve: Optional[str] = None,
    cwe: Optional[str] = None,
    view: Optional[str] = None,
    platform: Optional[str] = None,
    min_risk_score: Optional[int] = None,
    source_tool: Optional[str] = None,
    sla: Optional[str] = None,
    age_days: Optional[int] = None,
    entity: Optional[str] = None,
    confidence: Optional[str] = None,
    sort: str = "risk_score",
    order: str = "desc",
    # #59: choose columns and scope
    columns: Optional[List[str]] = Query(None),
    scope: str = "filtered",              # filtered | selected | all
    ids: Optional[List[str]] = Query(None),
    limit: int = 100000,
):
    """Flexible, team-scoped CSV export (#57 + #59).

    scope=filtered -> everything matching the current filters (team scoping always
    applies); scope=selected -> just the ids passed; scope=all -> every finding the
    user may see, ignoring the on-screen filters. Columns are user-chosen."""
    if scope == "selected":
        flt = {}
        flt.update(team_scope_filter(user))
        flt["id"] = {"$in": ids or ["__none__"]}
    elif scope == "all":
        flt = {}
        flt.update(team_scope_filter(user))
    else:
        flt = await _build_findings_filter(
            user, q=q, severity=severity, status=status, kev=kev, internet_facing=internet_facing,
            owner_team=owner_team, asset_id=asset_id, tags=tags, asset_type=asset_type,
            exploitability=exploitability, include_resolved=include_resolved, cve=cve, cwe=cwe,
            view=view, platform=platform, min_risk_score=min_risk_score, source_tool=source_tool,
            sla=sla, age_days=age_days, entity=entity, confidence=confidence,
        )

    cols = [c for c in (columns or DEFAULT_EXPORT_COLUMNS) if c in EXPORT_COLUMNS] or DEFAULT_EXPORT_COLUMNS
    sort_dir = -1 if order == "desc" else 1
    rows = await db.findings.find(flt, {"_id": 0}).sort(sort, sort_dir).limit(limit).to_list(limit)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([EXPORT_COLUMNS[c][0] for c in cols])
    for f in rows:
        writer.writerow([EXPORT_COLUMNS[c][1](f) for c in cols])
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=findings-export.csv",
                 "X-Export-Rows": str(len(rows))},
    )


@router.get("/v1/findings/export-columns")
async def export_columns(user: dict = Depends(get_current_user)):
    """The column catalogue + the default selection, for the export column picker."""
    return {"columns": [{"key": k, "label": v[0]} for k, v in EXPORT_COLUMNS.items()],
            "default": DEFAULT_EXPORT_COLUMNS}


# ------------------------ #58: per-user saved views ------------------------
class SavedViewBody(BaseModel):
    name: str
    # the filter state to restore, stored verbatim (a small dict of the UI's filters)
    filters: dict = {}


@router.get("/v1/findings/views")
async def list_saved_views(user: dict = Depends(get_current_user),
                           _rbac: dict = Depends(require_module("/findings"))):
    """This user's saved Findings views."""
    owner = user.get("email") or user.get("id")
    items = await db.saved_findings_views.find({"owner": owner}, {"_id": 0})         .sort("name", 1).to_list(200)
    return {"items": items}


@router.post("/v1/findings/views")
async def save_view(body: SavedViewBody, user: dict = Depends(get_current_user),
                    _rbac: dict = Depends(require_module("/findings"))):
    name = (body.name or "").strip()
    if not name:
        raise HTTPException(400, "A view name is required")
    owner = user.get("email") or user.get("id")
    doc = {"owner": owner, "name": name, "filters": body.filters or {}, "updated_at": now_iso()}
    existing = await db.saved_findings_views.find_one({"owner": owner, "name": name}, {"_id": 0})
    if existing:
        doc["id"] = existing["id"]
        await db.saved_findings_views.update_one({"owner": owner, "name": name}, {"$set": doc})
    else:
        doc["id"] = str(uuid.uuid4())
        await db.saved_findings_views.insert_one(dict(doc))
    return {"ok": True, "id": doc["id"], "name": name}


@router.delete("/v1/findings/views/{view_id}")
async def delete_saved_view(view_id: str, user: dict = Depends(get_current_user),
                            _rbac: dict = Depends(require_module("/findings"))):
    owner = user.get("email") or user.get("id")
    await db.saved_findings_views.delete_one({"owner": owner, "id": view_id})
    return {"ok": True}


class ViewAlertBody(BaseModel):
    enabled: bool


@router.patch("/v1/findings/views/{view_id}/alert")
async def toggle_view_alert(view_id: str, body: ViewAlertBody,
                            user: dict = Depends(get_current_user),
                            _rbac: dict = Depends(require_module("/findings"))):
    """Turn a saved view into a standing alert (or off). Enabling baselines the
    checkpoint to now, so it only fires on findings that appear AFTER you enable it,
    never on the backlog the view already matches."""
    owner = user.get("email") or user.get("id")
    v = await db.saved_findings_views.find_one({"owner": owner, "id": view_id}, {"_id": 0})
    if not v:
        raise HTTPException(404, "View not found")
    upd = {"alert_enabled": bool(body.enabled)}
    if body.enabled:
        upd["alert_enabled_at"] = now_iso()
        upd["alert_last_checked_at"] = now_iso()
    await db.saved_findings_views.update_one({"owner": owner, "id": view_id}, {"$set": upd})
    return {"ok": True, "alert_enabled": bool(body.enabled)}


# --------------------------- FINDINGS-GROUPS (literal path before {finding_id}) ---------------------------
@router.get("/v1/findings-groups")
async def findings_group(
    user: dict = Depends(get_current_user),
    group_by: str = Query("cve", pattern="^(cve|os|title|severity|asset|none)$"),
    view_mode: str = Query("by_asset", pattern="^(by_asset|by_vulnerability)$"),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    owner_team: Optional[str] = None,
    q: Optional[str] = None,
    limit: int = 100,
):
    flt: dict = {"status": {"$in": ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]}}
    flt.update(team_scope_filter(user))
    if severity:
        flt["severity"] = severity
    if status:
        flt["status"] = status
    if owner_team:
        flt["owner_team"] = owner_team
    if q:
        # Same search fields as the flat /v1/findings list -- previously the grouped
        # (default) Findings view silently ignored the search box entirely, so
        # searching a QID/CVE/hostname only worked with grouping turned off.
        flt["$or"] = _q_or_clauses(q)

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
def _opencti_graphql_url(endpoint: str) -> str:
    """Kept as a thin alias: the real logic now lives in opencti_client so the
    three sync paths cannot append "/graphql" to an endpoint that already names
    it. See opencti_client.graphql_url for why that mattered."""
    import opencti_client
    return opencti_client.graphql_url(endpoint)


async def opencti_ping(cfg: dict) -> dict:
    """Lightweight live connectivity check against OpenCTI's GraphQL endpoint, sharing
    the same Cloudflare Access redirect-detection as threat_intel_for_cve below so
    "Test Connection" on the Integrations page tells the truth instead of just
    confirming the endpoint/api_key fields are non-empty. Returns {"ok": bool, "message": str}."""
    import httpx
    endpoint = cfg.get("endpoint")
    api_key = cfg.get("api_key")
    if not endpoint or not api_key:
        return {"ok": False, "message": "Missing endpoint or api_key."}
    cf_client_id = cfg.get("cf_access_client_id")
    cf_client_secret = cfg.get("cf_access_client_secret")
    cf_headers_sent = bool(cf_client_id) and bool(cf_client_secret)
    from cf_diagnostics import classify_response, classify_exception, LAYER_EDGE
    import opencti_client
    headers = opencti_client.headers(cfg)
    # The exact URL matters: a Cloudflare WAF "Skip" rule is usually written
    # against one specific path, so if this ping goes to a different path than
    # the operator's rule matches, the rule quietly doesn't apply. Report the URL
    # so it can be compared against the Path column in Security Events.
    target_url = opencti_client.graphql_url(endpoint)
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=False) as c:
            r = await c.post(target_url, headers=headers,
                              json={"query": "{ about { version } }"})
        # A Cloudflare browser challenge ("Just a moment...") is served at the CDN
        # edge BEFORE Access runs, so it needs its own verdict -- telling someone
        # to fix their service token when the request never reached Access is how
        # an afternoon gets lost.
        verdict = classify_response(r, service_name="OpenCTI", token_sent=cf_headers_sent,
                                     client_id=cf_client_id)
        verdict["evidence"]["request_url"] = target_url
        if verdict["layer"] == LAYER_EDGE:
            return {"ok": False, "message": f"{verdict['title']}. {verdict['message']}",
                    "diagnostic": verdict}
        if r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("location", "")
            cf_login = "cloudflareaccess.com" in loc or "/cdn-cgi/access/login" in loc
            if cf_login and cf_headers_sent:
                id_hint = f"...{cf_client_id[-10:]}" if len(cf_client_id) > 10 else cf_client_id
                return {"ok": False, "message": (
                    f"Still redirecting to Cloudflare Access login even though a service token "
                    f"(client ID ending '{id_hint}') was sent on this request -- this is a Cloudflare-side "
                    "policy gap, not a VulnOps config issue. In CF Zero Trust → Access → Applications → "
                    "your OpenCTI app → Policies, the policy needs an Include rule of type 'Service Auth' "
                    "that selects this token. The token existing under Access → Service Auth alone isn't enough.")}
            if cf_login:
                return {"ok": False, "message": (
                    "Redirecting to Cloudflare Access login, and no CF-Access service token is saved here -- "
                    "add cf_access_client_id + cf_access_client_secret and Save, then test again.")}
            return {"ok": False, "message": f"Unexpected redirect to {loc[:120]}"}
        if r.status_code != 200:
            return {"ok": False, "message": f"{verdict['title']}. {verdict['message']}",
                    "diagnostic": verdict}
        ctype = (r.headers.get("content-type") or "").lower()
        if "application/json" not in ctype:
            return {"ok": False, "message": f"OpenCTI returned non-JSON ({ctype or 'no content-type'}) -- endpoint may be wrong or still behind an interstitial page."}
        data = r.json()
        if data.get("errors"):
            return {"ok": False, "message": f"OpenCTI GraphQL error: {data['errors'][0].get('message', data['errors'])}"}
        version = (data.get("data") or {}).get("about", {}).get("version", "unknown")
        return {"ok": True,
                "message": f"Connected — OpenCTI version {version} at {target_url}."}
    except httpx.TimeoutException as e:
        v = classify_exception(e, service_name="OpenCTI")
        return {"ok": False, "message": "Connection timed out — check the endpoint URL and that the server "
                                         "is reachable from this host.", "diagnostic": v}
    except httpx.ConnectError as e:
        v = classify_exception(e, service_name="OpenCTI")
        return {"ok": False, "message": f"Could not connect: {e}", "diagnostic": v}
    except Exception as e:
        return {"ok": False, "message": f"Unexpected error: {e}"}


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
    cf_client_id = cfg.get("cf_access_client_id")
    cf_client_secret = cfg.get("cf_access_client_secret")
    cf_headers_sent = bool(cf_client_id) and bool(cf_client_secret)

    try:
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        # Optional Cloudflare Access service-token headers — needed when the
        # OpenCTI tenant sits behind Cloudflare Zero Trust Access. These must be
        # sent as-is and NOT lost across redirects, so we disable redirect-follow
        # for the initial POST.
        if cf_client_id:
            headers["CF-Access-Client-Id"] = cf_client_id
        if cf_client_secret:
            headers["CF-Access-Client-Secret"] = cf_client_secret
        async with httpx.AsyncClient(timeout=15, follow_redirects=False) as c:
            r = await c.post(_opencti_graphql_url(endpoint),
                             headers=headers, json={"query": query})
        if r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("location", "")
            cf_login = "cloudflareaccess.com" in loc or "/cdn-cgi/access/login" in loc
            if cf_login and cf_headers_sent:
                # The token IS configured and WAS attached to this exact request, and
                # Cloudflare still bounced it to the login page -- that only happens
                # when the Access Application's policy doesn't have an Include rule
                # for this specific service token. Creating the token under
                # Access -> Service Auth is not enough by itself; it must also be
                # referenced by a policy on the Application, or CF ignores it.
                id_hint = f"...{cf_client_id[-10:]}" if len(cf_client_id) > 10 else cf_client_id
                msg = (f"OpenCTI is redirecting to Cloudflare Access login even though a service token "
                       f"(client ID ending '{id_hint}') is configured and was sent on this exact request "
                       "-- so this isn't a VulnOps config problem, it's on the Cloudflare side. In CF Zero "
                       "Trust → Access → Applications → open.smrtlab.net → Policies, edit (or add) a policy "
                       "with an Include rule of type 'Service Auth' that selects this token by name. Having "
                       "the token exist under Access → Service Auth isn't enough on its own -- it must also "
                       "be attached to the Application's policy, or Cloudflare keeps showing the login page.")
            elif cf_login and not cf_headers_sent:
                msg = ("OpenCTI is redirecting to Cloudflare Access login, and no CF-Access service token "
                       "is saved for this integration yet -- add BOTH cf_access_client_id and "
                       "cf_access_client_secret under Integrations → OpenCTI → Configure, then Save. "
                       "(Saving preserves whichever of the two you leave blank on a later edit, so you "
                       "don't need to re-paste both every time -- but the first save needs both together.)")
            else:
                msg = f"Unexpected redirect to {loc[:120]}"
            return {"configured": True, "cve": cve, "error": msg, "cf_headers_sent": cf_headers_sent,
                    "threat_actors": [], "intrusion_sets": [], "malware": [], "campaigns": [],
                    "indicators": [], "external_references": []}
        if r.status_code != 200:
            # Try to extract a friendly Cloudflare error message if present.
            friendly = None
            try:
                err_json = r.json()
                if isinstance(err_json, dict) and err_json.get("cloudflare_error"):
                    friendly = (f"OpenCTI origin returned {r.status_code}: {err_json.get('title')}. "
                                f"{err_json.get('what_you_should_do', '')}").strip()
            except Exception:
                pass
            return {"configured": True, "cve": cve,
                    "error": friendly or f"OpenCTI HTTP {r.status_code}",
                    "raw": r.text[:300],
                    "threat_actors": [], "intrusion_sets": [], "malware": [], "campaigns": [],
                    "indicators": [], "external_references": []}
        ctype = (r.headers.get("content-type") or "").lower()
        if "application/json" not in ctype:
            # Likely an interstitial (e.g. Cloudflare Access login page).
            cf_access = "cloudflare access" in r.text.lower() or "cf-access" in r.text.lower()
            msg = ("OpenCTI endpoint is behind Cloudflare Access — add a service "
                   "token to the OpenCTI integration config "
                   "(cf_access_client_id + cf_access_client_secret) or disable "
                   "Cloudflare Access on the /graphql route.") if cf_access else (
                   f"OpenCTI returned non-JSON ({ctype or 'no content-type'}) — "
                   "verify the endpoint is the GraphQL URL and the API key is valid.")
            return {"configured": True, "cve": cve, "error": msg,
                    "threat_actors": [], "intrusion_sets": [], "malware": [], "campaigns": [],
                    "indicators": [], "external_references": []}
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
@router.get("/v1/findings/nl-search")
async def nl_search(q: str, user: dict = Depends(get_current_user)):
    """Free-text search that understands common phrasing (severity, KEV, platform, owner
    team, CVE/CWE, risk thresholds, overdue/unassigned/internet-facing) without calling
    out to an LLM -- see nl_query.py for why."""
    from nl_query import parse_nl_query
    teams = [t for t in await db.assets.distinct("owner_team") if t and t != "Unassigned"]
    parsed = parse_nl_query(q, teams)
    f = parsed["filters"]
    result = await list_findings(
        user=user, q=f.get("q"), severity=f.get("severity"), status=f.get("status"),
        kev=f.get("kev"), internet_facing=f.get("internet_facing"), owner_team=f.get("owner_team"),
        cve=f.get("cve"), cwe=f.get("cwe"), view=f.get("view"), platform=f.get("platform"),
        min_risk_score=f.get("min_risk_score"), limit=100,
    )
    return {**result, "interpreted": parsed["interpreted"], "query": q}


@router.get("/v1/mitre/coverage")
async def mitre_coverage(refresh: bool = False, user: dict = Depends(get_current_user)):
    """Item 33's mapping-coverage indicator: how much of the open backlog we can
    actually map to ATT&CK, and which unmapped CWEs would buy the most coverage
    if added to the table."""
    # CACHED, and computed off the event loop.
    #
    # This resolves every open finding through the ATT&CK layers -- 44 regexes
    # against title + description + consequence + remediation each. On a 7,500
    # finding backlog that measured 5.5 SECONDS of synchronous CPU, and it was
    # running on every Finding Detail page view. In a single-process asyncio app
    # that means 5.5s during which the API answers nothing, and requests queue,
    # so a handful of concurrent page loads took the product down with 504s.
    #
    # It is a property of the whole backlog, not of the finding being viewed, so
    # recomputing it per request was never right regardless of speed.
    # See aggregate_cache.py.
    from mitre_mapping import coverage_from_findings
    from aggregate_cache import get_or_compute
    OPEN = ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]

    async def _compute():
        rows = await db.findings.find(
            {"status": {"$in": OPEN}},
            {"_id": 0, "id": 1, "title": 1, "description": 1, "consequence": 1,
             "remediation": 1, "business_impact": 1, "cwe": 1, "cwes": 1,
             "detection_logic": 1, "severity": 1, "internet_facing": 1, "kev_flag": 1,
             "mitre_technique_id": 1, "mitre_tactic": 1, "mitre_technique": 1,
             "mitre_mapping_source": 1},
        ).to_list(50000)
        return coverage_from_findings(rows)

    if refresh:
        # An explicit way to force a recompute. Without one, the only options
        # after a big sync are "wait out the TTL" or "restart the backend",
        # and people reach for the second.
        from aggregate_cache import invalidate
        await invalidate(db, "mitre_coverage")
    return await get_or_compute(db, "mitre_coverage", _compute, cpu_bound=True,
                                 is_empty=lambda v: not v.get("findings_total"))


@router.post("/v1/mitre/backfill-cwe")
async def mitre_backfill_cwe(user: dict = Depends(require_role("admin"))):
    """One-shot repair for findings already stored with a non-canonical CWE
    (Qualys' bare "89" etc). Rewrites them to canonical form so the ATT&CK
    mapping resolves. Idempotent -- already-canonical values are untouched."""
    from mitre_mapping import normalize_cwe
    updated = 0
    cursor = db.findings.find({"cwe": {"$nin": [None, ""]}}, {"_id": 0, "id": 1, "cwe": 1})
    async for f in cursor:
        canonical = normalize_cwe(f.get("cwe"))
        if canonical and canonical != f.get("cwe"):
            await db.findings.update_one({"id": f["id"]}, {"$set": {"cwe": canonical}})
            updated += 1
        elif not canonical and f.get("cwe"):
            # placeholder values like NVD-CWE-noinfo aren't real CWEs
            await db.findings.update_one({"id": f["id"]}, {"$set": {"cwe": None}})
            updated += 1
    return {"ok": True, "updated": updated}


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
        # Multi-asset CVEs make for a much more legible attack-path story (an actual
        # lateral-movement chain instead of a single floating node), so surface those
        # first; risk is the tiebreaker within that.
        {"$sort": {"affected_assets": -1, "max_risk": -1}},
        {"$limit": 100},
    ]
    items = [r async for r in db.findings.aggregate(pipeline)]
    return {"items": items}


@router.get("/v1/attack-paths/cve-graph")
async def attack_path_cve_graph(cve: Optional[str] = None, finding_id: Optional[str] = None,
                                 user: dict = Depends(get_current_user),
                                 _rbac: dict = Depends(require_module("/attack-paths"))):
    """LEGACY blast-radius view: given one CVE, fan out across every affected host.

    Superseded by the path-enumeration engine (routes/attack_paths.py), which
    answers the more useful question -- "what are the routes from the internet to
    something valuable, and which single fix breaks the most of them" -- rather
    than "who else has this bug". Kept and RENAMED (it used to squat on
    /v1/attack-paths/graph and shadow the new full-graph endpoint) because the
    per-CVE blast radius is still a legitimate thing to want to look at."""
    from attack_path import build_attack_path
    return await build_attack_path(db, cve=cve, finding_id=finding_id)


# --------------------------- PARAMETERIZED ROUTES (must come AFTER literal /v1/findings-groups etc) ---------------------------
@router.get("/v1/findings/{finding_id}")
async def get_finding(finding_id: str, user: dict = Depends(get_current_user)):
    from mitre_mapping import apply_mitre_mapping
    f = await db.findings.find_one({"id": finding_id}, {"_id": 0})
    if not f:
        raise HTTPException(404, "Finding not found")
    return apply_mitre_mapping(f)


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


VERIFICATION_WINDOW_DAYS = 3


@router.patch("/v1/findings/{finding_id}/status")
async def update_status(finding_id: str, body: StatusUpdate, user: dict = Depends(get_current_user)):
    valid = ["New", "Needs triage", "Valid", "False positive", "Duplicate", "Mitigated",
             "Accepted risk", "Deferred", "Fixed pending validation", "Fixed validated",
             "Reopened", "Out of scope", "Closed administratively"]
    if body.status not in valid:
        raise HTTPException(400, f"Invalid status. Allowed: {valid}")

    existing = await db.findings.find_one({"id": finding_id}, {"_id": 0})
    if not existing:
        raise HTTPException(404, "Finding not found")

    update = {"status": body.status, "last_changed_at": now_iso()}
    # Verification loop bookkeeping -- see routes/findings.py:verify_finding and
    # nightly.run_verification_sweep for how "pending" gets resolved.
    if body.status == "Fixed pending validation":
        due = (datetime.now(timezone.utc) + timedelta(days=VERIFICATION_WINDOW_DAYS)).isoformat()
        update.update({"verification_status": "pending", "verification_due_at": due,
                       "fixed_marked_at": now_iso(), "verification_note": None})
    elif body.status == "Fixed validated":
        update.update({"verification_status": "passed",
                       "verification_note": f"Manually verified by {user['email']}."})
    elif body.status == "Reopened" and existing.get("verification_status") == "pending":
        update.update({"verification_status": "failed",
                       "verification_note": "Regressed during the verification window."})

    res = await db.findings.update_one({"id": finding_id}, {"$set": update})
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


@router.get("/v1/findings/{finding_id}/patch-group")
async def patch_group(finding_id: str, user: dict = Depends(get_current_user)):
    """Findings sharing the same title on the same asset are, in practice, almost always
    fixed by the same underlying vendor update (e.g. a monthly cumulative security
    bulletin covering many CVEs at once) -- so applying one patch clears out the whole
    group instead of remediating CVE-by-CVE."""
    f = await db.findings.find_one({"id": finding_id}, {"_id": 0})
    if not f:
        raise HTTPException(404, "Finding not found")
    siblings = []
    if f.get("asset_id") and f.get("title"):
        siblings = await db.findings.find({
            "asset_id": f["asset_id"], "title": f["title"], "id": {"$ne": finding_id},
            "status": {"$in": ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]},
        }, {"_id": 0, "id": 1, "cve": 1, "severity": 1, "title": 1}).to_list(100)
    return {"siblings": siblings, "patch_available": f.get("patch_available"), "shared_title": f.get("title")}


@router.get("/v1/assets/{asset_id}/patch-groups")
async def asset_patch_groups(asset_id: str, user: dict = Depends(get_current_user)):
    """All open findings on this asset, grouped by shared patch title -- 'fix this one
    update, clear N findings' view for a single host."""
    pipeline = [
        {"$match": {"asset_id": asset_id,
                    "status": {"$in": ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]}}},
        {"$group": {"_id": "$title", "count": {"$sum": 1},
                    "cves": {"$addToSet": "$cve"}, "max_severity_rank": {"$max": {
                        "$switch": {"branches": [
                            {"case": {"$eq": ["$severity", "Critical"]}, "then": 5},
                            {"case": {"$eq": ["$severity", "High"]}, "then": 4},
                            {"case": {"$eq": ["$severity", "Medium"]}, "then": 3},
                            {"case": {"$eq": ["$severity", "Low"]}, "then": 2},
                        ], "default": 1}}},
                    "patch_available": {"$max": {"$cond": ["$patch_available", 1, 0]}},
                    "finding_ids": {"$push": "$id"}}},
        {"$sort": {"count": -1}},
    ]
    groups = [g async for g in db.findings.aggregate(pipeline)]
    sev_labels = {5: "Critical", 4: "High", 3: "Medium", 2: "Low", 1: "Info"}
    return {"groups": [{
        "title": g["_id"] or "(untitled)", "count": g["count"],
        "cves": [c for c in g["cves"] if c],
        "top_severity": sev_labels.get(g["max_severity_rank"], "Info"),
        "patch_available": bool(g["patch_available"]),
        "finding_ids": g["finding_ids"],
    } for g in groups]}


@router.post("/v1/findings/{finding_id}/verify")
async def verify_finding(finding_id: str, user: dict = Depends(get_current_user)):
    """Manual 'Verify now' -- same check the nightly sweep runs, on demand for one finding.
    Promotes to Fixed validated only if a successful import from the finding's own source
    has run since it was marked fixed (real confirmation the host was rescanned), otherwise
    reports what it's still waiting on."""
    from nightly import check_single_verification
    f = await db.findings.find_one({"id": finding_id}, {"_id": 0})
    if not f:
        raise HTTPException(404, "Finding not found")
    if f.get("status") != "Fixed pending validation":
        raise HTTPException(400, "Finding is not awaiting verification")
    return await check_single_verification(db, f)


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
async def bulk_owner(body: OwnerTeamBody, user: dict = Depends(require_role("admin", "manager")),
                      _rbac: dict = Depends(require_module("/findings", level="edit"))):
    """Bulk-update owner_team for selected findings. Sets ownership_confidence to 1.0
    because a human explicitly assigned them."""
    await db.findings.update_many(
        {"id": {"$in": body.ids}},
        {"$set": {
            "owner_team": body.owner_team,
            "ownership_confidence": 1.0,
            "ownership_confirmed_at": now_iso(),
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
