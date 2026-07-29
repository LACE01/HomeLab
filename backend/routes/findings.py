"""Findings routes: list, stats, detail, KRI, comments, status updates, bulk ops,
prioritization preview, attack-paths, CWE prevalence, threat-intel, findings-groups."""
import re
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from db import db
from rbac import require_module
from auth_utils import get_current_user, require_role
from scoring import compute_risk
from routes.common import now_iso, _clean, finding_ctx, team_scope_filter

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
    cwe: Optional[str] = None,
    view: Optional[str] = None,
    platform: Optional[str] = None,
    min_risk_score: Optional[int] = None,
    source_tool: Optional[str] = None,
    sort: str = "risk_score",
    order: str = "desc",
    limit: int = 100,
    offset: int = 0,
    _rbac: dict = Depends(require_module("/findings")),
):
    flt: dict = {}
    # Team scoping: analyst/executive users only see their team(s)' findings --
    # a user can now belong to more than one team, so this is an $in over every
    # team they're on, not an exact match against a single string. admin + manager
    # see everything (team_scope_filter returns {} for those roles).
    flt.update(team_scope_filter(user))
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
    elif view == "active_attacks":
        flt["rti"] = "active_attacks"
        flt["status"] = {"$in": ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]}
    elif view == "unassigned":
        flt["assigned_to"] = None
        flt["status"] = {"$in": ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]}

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
        flt["$or"] = [
            {"title": {"$regex": q, "$options": "i"}},
            {"cve": {"$regex": q, "$options": "i"}},
            {"asset_hostname": {"$regex": q, "$options": "i"}},
            {"qid": {"$regex": q, "$options": "i"}},
        ]

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
    """OpenCTI's GraphQL route is /graphql by default, but a lot of real deployments
    sit behind a reverse proxy / Cloudflare Tunnel that only forwards a specific,
    non-default path (e.g. a "/public/graphql" route carved out specifically so it
    can be exposed differently from the rest of the app -- this is exactly what one
    user's setup turned out to be, confirmed from their own browser hitting
    `open.smrtlab.net/public/graphql` and landing on OpenCTI's GraphQL playground).
    Previously this always blindly appended "/graphql" to whatever endpoint was
    configured, which silently mangled a fully-specified endpoint like
    "https://host/public/graphql" into "https://host/public/graphql/graphql" -- a
    request to a path that simply doesn't exist, no matter how correct the
    Cloudflare Access headers are. If the endpoint already ends in "/graphql",
    use it as-is; only append the default suffix when it doesn't."""
    endpoint = (endpoint or "").rstrip("/")
    if endpoint.endswith("/graphql"):
        return endpoint
    return endpoint + "/graphql"


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
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    if cf_client_id:
        headers["CF-Access-Client-Id"] = cf_client_id
    if cf_client_secret:
        headers["CF-Access-Client-Secret"] = cf_client_secret
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=False) as c:
            r = await c.post(_opencti_graphql_url(endpoint), headers=headers,
                              json={"query": "{ about { version } }"})
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
            return {"ok": False, "message": f"OpenCTI HTTP {r.status_code}: {r.text[:200]}"}
        ctype = (r.headers.get("content-type") or "").lower()
        if "application/json" not in ctype:
            return {"ok": False, "message": f"OpenCTI returned non-JSON ({ctype or 'no content-type'}) -- endpoint may be wrong or still behind an interstitial page."}
        data = r.json()
        if data.get("errors"):
            return {"ok": False, "message": f"OpenCTI GraphQL error: {data['errors'][0].get('message', data['errors'])}"}
        version = (data.get("data") or {}).get("about", {}).get("version", "unknown")
        return {"ok": True, "message": f"Connected — OpenCTI version {version}."}
    except httpx.TimeoutException:
        return {"ok": False, "message": "Connection timed out — check the endpoint URL and that the server is reachable from this host."}
    except httpx.ConnectError as e:
        return {"ok": False, "message": f"Could not connect: {e}"}
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
async def mitre_coverage(user: dict = Depends(get_current_user)):
    """Item 33's mapping-coverage indicator: how much of the open backlog we can
    actually map to ATT&CK, and which unmapped CWEs would buy the most coverage
    if added to the table."""
    from mitre_mapping import mapping_coverage
    OPEN = ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]
    counts: dict = {}
    async for row in db.findings.aggregate([
        {"$match": {"status": {"$in": OPEN}}},
        {"$group": {"_id": "$cwe", "count": {"$sum": 1}}},
    ]):
        counts[row["_id"]] = row["count"]
    return mapping_coverage(counts)


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


@router.get("/v1/attack-paths/graph")
async def attack_path_graph(cve: Optional[str] = None, finding_id: Optional[str] = None,
                             user: dict = Depends(get_current_user),
                             _rbac: dict = Depends(require_module("/attack-paths"))):
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
