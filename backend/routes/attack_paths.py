"""Attack Path Analysis API -- see attack_path_engine.py for the model.

Exposes paths as first-class, triageable records (list + detail + status), the
choke-point analysis that ranks remediations by how many paths each one breaks,
and the crown-jewel definition that gives paths somewhere meaningful to end.
"""
import uuid
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from db import db
from rbac import require_module
from routes.common import now_iso
import attack_path_engine as ape

router = APIRouter()

MODULE_KEY = "/attack-paths"


class AnalyzeBody(BaseModel):
    max_hops: int = 4
    max_paths: int = 200


class PathStatusBody(BaseModel):
    status: Optional[str] = None       # open | investigating | mitigating | accepted | resolved
    analyst_note: Optional[str] = None


class CrownJewelBody(BaseModel):
    """Attack paths are only meaningful if they END somewhere that matters, so
    the environment needs crown jewels defined. Same flexible selection the
    Security Reviews asset picker uses."""
    asset_ids: List[str] = []
    teams: List[str] = []
    tags: List[str] = []
    reason: str = ""
    unset: bool = False


@router.post("/v1/attack-paths/analyze")
async def analyze(body: AnalyzeBody, user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    """Rebuild the environment graph and re-enumerate every internet-to-crown-jewel
    path. Triage state on existing paths is preserved; paths that no longer exist
    are marked resolved rather than deleted."""
    if not 1 <= body.max_hops <= 8:
        raise HTTPException(400, "max_hops must be between 1 and 8")
    result = await ape.run_attack_path_analysis(db, max_hops=body.max_hops,
                                                 max_paths=min(body.max_paths, 500))
    return result


@router.get("/v1/attack-paths/summary")
async def summary(user: dict = Depends(require_module(MODULE_KEY))):
    """Headline numbers plus the last run's context, so the page can render
    without recomputing the whole graph on every visit."""
    last = await db.attack_path_runs.find({}, {"_id": 0}).sort("generated_at", -1).to_list(1)
    open_paths = await db.attack_paths.find(
        {"status": {"$nin": ["resolved", "accepted"]}}, {"_id": 0}).to_list(2000)
    crown_defined = await db.assets.count_documents({"criticality": {"$in": ["crown_jewel", "critical"]}})
    by_severity: dict = {}
    for p in open_paths:
        by_severity[p["severity"]] = by_severity.get(p["severity"], 0) + 1
    return {
        "last_run": last[0] if last else None,
        "open_paths": len(open_paths),
        "by_severity": by_severity,
        "critical_paths": by_severity.get("Critical", 0),
        "kev_paths": len([p for p in open_paths if p.get("uses_kev")]),
        "confirmed_paths": len([p for p in open_paths if not p.get("speculative")]),
        "crown_jewels_reachable": len({p["target_node_id"] for p in open_paths}),
        "entry_points": len({p["entry_node_id"] for p in open_paths}),
        "crown_jewels_defined": crown_defined,
        # The single most important honest signal: with no crown jewels defined,
        # the analysis cannot produce anything meaningful.
        "needs_crown_jewels": crown_defined == 0,
    }


@router.get("/v1/attack-paths/choke-points")
async def get_choke_points(user: dict = Depends(require_module(MODULE_KEY))):
    """Remediations ranked by how many enumerated paths each one BREAKS -- the
    "if you only do one thing" answer. Recomputed from stored open paths so it
    reflects triage decisions (an accepted path stops counting)."""
    paths = await db.attack_paths.find(
        {"status": {"$nin": ["resolved", "accepted"]}}, {"_id": 0}).to_list(2000)
    if not paths:
        return {"items": [], "total_paths": 0}
    graph = await ape.build_environment_graph(db)
    return {"items": ape.choke_points(paths, graph), "total_paths": len(paths)}


@router.get("/v1/attack-paths/graph")
async def full_graph(limit_nodes: int = 400, user: dict = Depends(require_module(MODULE_KEY))):
    """The whole environment graph for the 'see full graph' view -- every node
    and evidenced edge, with the ones that participate in a path flagged so the
    UI can dim the rest."""
    graph = await ape.build_environment_graph(db)
    paths = await db.attack_paths.find(
        {"status": {"$nin": ["resolved"]}}, {"_id": 0, "nodes": 1, "edges": 1}).to_list(2000)
    on_path_nodes = {n["id"] for p in paths for n in (p.get("nodes") or [])}
    on_path_edges = {e["id"] for p in paths for e in (p.get("edges") or [])}
    nodes = list(graph["nodes"].values())
    # keep path participants first so a cap never hides the interesting part
    nodes.sort(key=lambda n: (n["id"] not in on_path_nodes, -(n.get("critical_high") or 0)))
    nodes = nodes[:limit_nodes]
    keep = {n["id"] for n in nodes}
    edges = [e for e in graph["edges"] if e["from"] in keep and e["to"] in keep and e["from"] != e["to"]]
    for n in nodes:
        n["on_attack_path"] = n["id"] in on_path_nodes
    for e in edges:
        e["on_attack_path"] = e["id"] in on_path_edges
    return {"nodes": nodes, "edges": edges,
            "truncated": len(graph["nodes"]) > len(nodes),
            "total_nodes": len(graph["nodes"]), "total_edges": len(graph["edges"])}


@router.get("/v1/attack-paths/crown-jewels")
async def list_crown_jewels(user: dict = Depends(require_module(MODULE_KEY))):
    assets = await db.assets.find(
        {"$or": [{"criticality": {"$in": ["crown_jewel", "critical"]}},
                  {"tags": {"$in": list(ape.CROWN_TAGS)}}]},
        {"_id": 0, "id": 1, "hostname": 1, "ip": 1, "criticality": 1, "tags": 1,
         "owner_team": 1, "crown_jewel_reason": 1}).sort("hostname", 1).to_list(1000)
    for a in assets:
        a["reason"] = ape.crown_jewel_reason(a)
    return {"items": assets, "total": len(assets),
            "recognized_tags": sorted(ape.CROWN_TAGS)}


@router.post("/v1/attack-paths/crown-jewels")
async def set_crown_jewels(body: CrownJewelBody,
                            user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    """Mark assets as crown jewels individually, by team, or by tag. Without
    these the engine has no meaningful destination and deliberately returns
    nothing rather than inventing a target."""
    ids: set = set(body.asset_ids or [])
    for team in body.teams or []:
        ids.update(a["id"] for a in await db.assets.find(
            {"owner_team": team}, {"_id": 0, "id": 1}).to_list(5000))
    for tag in body.tags or []:
        ids.update(a["id"] for a in await db.assets.find(
            {"tags": tag}, {"_id": 0, "id": 1}).to_list(5000))
    if not ids:
        raise HTTPException(400, "Nothing matched -- provide asset_ids, teams, or tags that exist")

    if body.unset:
        result = await db.assets.update_many(
            {"id": {"$in": list(ids)}, "criticality": "crown_jewel"},
            {"$set": {"criticality": "high"}, "$unset": {"crown_jewel_reason": ""}})
        return {"ok": True, "unset": result.modified_count}

    result = await db.assets.update_many({"id": {"$in": list(ids)}}, {"$set": {
        "criticality": "crown_jewel",
        "crown_jewel_reason": body.reason or "Designated a crown jewel",
        "crown_jewel_set_by": user.get("email"), "crown_jewel_set_at": now_iso()}})
    return {"ok": True, "updated": result.modified_count, "matched": len(ids)}


@router.get("/v1/attack-paths")
async def list_paths(
    status: Optional[str] = None, severity: Optional[str] = None,
    confirmed_only: bool = False, kev_only: bool = False,
    target: Optional[str] = None, entry: Optional[str] = None,
    limit: int = 200, user: dict = Depends(require_module(MODULE_KEY)),
):
    flt: dict = {}
    if status:
        flt["status"] = status
    else:
        flt["status"] = {"$ne": "resolved"}
    if severity:
        flt["severity"] = severity
    if confirmed_only:
        flt["speculative"] = False
    if kev_only:
        flt["uses_kev"] = True
    if target:
        flt["target_label"] = {"$regex": target, "$options": "i"}
    if entry:
        flt["entry_label"] = {"$regex": entry, "$options": "i"}
    items = await db.attack_paths.find(flt, {"_id": 0}).sort("risk_score", -1).to_list(min(limit, 1000))
    return {"items": items, "total": len(items)}


@router.get("/v1/attack-paths/{path_id}")
async def get_path(path_id: str, user: dict = Depends(require_module(MODULE_KEY))):
    """Full detail for one path, with the live findings behind each exploited
    hop so an analyst can jump straight to the thing they'd fix."""
    p = await db.attack_paths.find_one({"id": path_id}, {"_id": 0})
    if not p:
        raise HTTPException(404, "Attack path not found")
    finding_ids = [e.get("finding_id") for e in (p.get("exploits") or []) if e.get("finding_id")]
    if finding_ids:
        p["findings"] = await db.findings.find(
            {"id": {"$in": finding_ids}},
            {"_id": 0, "id": 1, "title": 1, "severity": 1, "cve": 1, "status": 1,
             "asset_hostname": 1, "kev_flag": 1, "cvss_score": 1, "epss_score": 1,
             "remediation": 1, "due_at": 1}).to_list(50)
    graph_paths = await db.attack_paths.find(
        {"status": {"$nin": ["resolved", "accepted"]}}, {"_id": 0}).to_list(2000)
    graph = await ape.build_environment_graph(db)
    all_chokes = ape.choke_points(graph_paths, graph)
    # only the remediations that break THIS path, still showing their global reach
    p["remediation_options"] = [c for c in all_chokes if path_id in (c.get("path_ids") or [])][:10]
    return p


@router.patch("/v1/attack-paths/{path_id}")
async def update_path(path_id: str, body: PathStatusBody,
                       user: dict = Depends(require_module(MODULE_KEY, level="edit"))):
    p = await db.attack_paths.find_one({"id": path_id}, {"_id": 0})
    if not p:
        raise HTTPException(404, "Attack path not found")
    changes: dict = {}
    if body.status:
        if body.status not in ("open", "investigating", "mitigating", "accepted", "resolved"):
            raise HTTPException(400, "status must be open/investigating/mitigating/accepted/resolved")
        changes["status"] = body.status
        changes["status_set_by"] = user.get("email")
        changes["status_set_at"] = now_iso()
    if body.analyst_note is not None:
        changes["analyst_note"] = body.analyst_note
    if changes:
        await db.attack_paths.update_one({"id": path_id}, {"$set": changes})
    return await db.attack_paths.find_one({"id": path_id}, {"_id": 0})
