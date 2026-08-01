"""Asset identity: what we know about who a machine is, and repairing duplicates.

Entity resolution runs automatically on ingest, but two things must be visible
and human-controllable:

  * the duplicates ALREADY created by years of hostname-string matching, which
    resolution alone doesn't retroactively fix;
  * any low-confidence link the resolver made, because a weak-key match is a
    judgement call and the person who knows the environment should get the final
    say.

An automated identity system that offers neither is one you have to trust
blindly. This module is what makes trusting it optional.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from db import db
from auth_utils import get_current_user, require_role
import entity_resolution as er

router = APIRouter()


@router.get("/v1/assets/{asset_id}/identity")
async def asset_identity(asset_id: str, user: dict = Depends(get_current_user)):
    """Every identifier this asset is known by, and which systems have seen it.

    The `sources` list doubles as a control-coverage answer: an asset with no
    Defender identifier has no EDR on it, and an asset with no Intune identifier
    is unmanaged. That is a finding, not a display gap -- see `coverage_gaps`.
    """
    asset = await db.assets.find_one({"id": asset_id}, {"_id": 0})
    if not asset:
        raise HTTPException(404, "No such asset")
    identity = await er.identity_of(db, asset_id)

    expected = {
        "qualys": "vulnerability scanning",
        "defender": "endpoint detection & response",
        "intune": "device management / patch compliance",
    }
    seen = set(identity["sources"])
    identity["coverage_gaps"] = [
        {"source": s, "means": f"No {label} data has ever been seen for this asset."}
        for s, label in expected.items() if s not in seen
    ]
    identity["hostname"] = asset.get("hostname")
    identity["merged_into"] = asset.get("merged_into")
    return identity


@router.get("/v1/assets/duplicates")
async def duplicate_candidates(limit: int = 100, user: dict = Depends(get_current_user)):
    """Assets that share an identifier and are therefore probably one machine.

    Ordered strongest-evidence first: two assets sharing a hardware serial are
    near-certainly the same machine, while two sharing a short hostname might
    genuinely be two different servers both called SERVER1 -- so the list leads
    with the ones safe to merge.
    """
    candidates = await er.find_duplicate_candidates(db, limit=limit)
    out = []
    for c in candidates:
        assets = await db.assets.find(
            {"id": {"$in": c["asset_ids"]}, "status": {"$ne": "merged"}},
            {"_id": 0, "id": 1, "hostname": 1, "ip": 1, "operating_system": 1,
             "owner_team": 1, "criticality": 1, "created_at": 1}).to_list(20)
        if len(assets) < 2:
            continue  # already merged, or a tombstone
        for a in assets:
            a["open_findings"] = await db.findings.count_documents({
                "asset_id": a["id"],
                "status": {"$in": ["New", "Needs triage", "Valid", "Reopened"]}})
        out.append({**c, "assets": assets,
                     "safe_to_automerge": c["strength"] == er.STRONG})
    return {"items": out, "count": len(out),
             "note": ("Assets sharing a STRONG identifier (serial, device GUID) are the same "
                       "machine. Assets sharing only a short hostname or IP may not be -- two "
                       "servers can legitimately be named the same in different domains.")}


class MergeBody(BaseModel):
    keep_id: str
    absorb_id: str
    reason: str = ""


@router.post("/v1/assets/merge")
async def merge(body: MergeBody, user: dict = Depends(require_role("admin"))):
    """Fold one asset into another. Reversible -- see /v1/assets/merges."""
    try:
        record = await er.merge_assets(db, body.keep_id, body.absorb_id,
                                        actor=user.get("email") or user.get("id"),
                                        reason=body.reason)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return record


@router.get("/v1/assets/merges")
async def merge_history(limit: int = 50, user: dict = Depends(get_current_user)):
    """Merge history, so a wrong merge can be found and undone rather than
    discovered months later as a confusing asset record."""
    rows = await db.asset_merges.find(
        {}, {"_id": 0, "absorbed_snapshot": 0}).sort("at", -1).to_list(limit)
    return {"items": rows}


@router.post("/v1/assets/merges/{merge_id}/undo")
async def undo(merge_id: str, user: dict = Depends(require_role("admin"))):
    try:
        return await er.undo_merge(db, merge_id, actor=user.get("email") or user.get("id"))
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.get("/v1/assets/identity-links/uncertain")
async def uncertain_links(user: dict = Depends(get_current_user)):
    """Links the resolver made on weak evidence, for review.

    Surfacing these is what makes weak-key matching acceptable: the alternative
    is either refusing to match at all (losing most of the joins) or matching
    silently (and being wrong invisibly).
    """
    rows = await db.asset_identity_links.find(
        {"reviewed": {"$ne": True}}, {"_id": 0}).sort("created_at", -1).to_list(200)
    for r in rows:
        asset = await db.assets.find_one({"id": r["asset_id"]},
                                          {"_id": 0, "hostname": 1, "ip": 1})
        r["asset"] = asset
    return {"items": rows, "count": len(rows)}


class ReviewBody(BaseModel):
    accept: bool = True
    note: str = ""


@router.post("/v1/assets/identity-links/{link_id}/review")
async def review_link(link_id: str, body: ReviewBody,
                       user: dict = Depends(get_current_user)):
    """Confirm or reject a low-confidence link.

    Rejecting removes the identifiers that source contributed, so the bad join
    stops influencing every downstream answer -- which is the point of reviewing
    it at all.
    """
    link = await db.asset_identity_links.find_one({"id": link_id}, {"_id": 0})
    if not link:
        raise HTTPException(404, "No such link")
    await db.asset_identity_links.update_one({"id": link_id}, {"$set": {
        "reviewed": True, "accepted": body.accept, "note": body.note,
        "reviewed_by": user.get("email") or user.get("id"),
        "reviewed_at": er._now_iso()}})
    removed = 0
    if not body.accept:
        res = await db.asset_identifiers.delete_many({
            "asset_id": link["asset_id"], "source": link["source"]})
        removed = res.deleted_count
    return {"reviewed": True, "accepted": body.accept, "identifiers_removed": removed}


@router.post("/v1/assets/backfill-identity")
async def backfill_identity(user: dict = Depends(require_role("admin"))):
    """Derive identifiers from assets that predate this system.

    Existing asset documents already carry hostname, ip, qualys_host_id,
    defender_device_id and intune_device_id from the old string-matching era.
    Reading those into the identifier collection turns years of accumulated data
    into resolvable identity immediately, instead of waiting for each connector
    to see each machine again. Idempotent.
    """
    await er.ensure_indexes(db)
    assets = await db.assets.find(
        {"status": {"$ne": "merged"}},
        {"_id": 0, "id": 1, "hostname": 1, "fqdn": 1, "ip": 1, "mac": 1, "serial": 1,
         "qualys_host_id": 1, "defender_device_id": 1, "intune_device_id": 1,
         "aad_device_id": 1, "cloud_instance_id": 1}).to_list(None)
    written = 0
    for a in assets:
        # Attribute each identifier to the connector it must have come from. A
        # qualys_host_id proves Qualys has seen this machine; recording that as a
        # generic "backfill" source would make the EDR/patch coverage answer wrong
        # for every asset that predates identity resolution.
        for source, idents in er.attribute_sources(a).items():
            written += await er.record_identifiers(db, a["id"], idents, source)
    dupes = await er.find_duplicate_candidates(db, limit=500)
    return {
        "assets_scanned": len(assets),
        "identifiers_written": written,
        "duplicate_candidates_found": len(dupes),
        "strong_duplicates": len([d for d in dupes if d["strength"] == er.STRONG]),
        "note": ("Duplicates are reported, never merged automatically. Review them at "
                  "/v1/assets/duplicates -- an automatic merge on weak evidence is exactly "
                  "the failure this system exists to prevent."),
    }
