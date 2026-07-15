"""Routes for the Microsoft Entra ID directory sync (entra_sync.py) -- users, groups,
and stale-account detection."""
from fastapi import APIRouter, Depends

from db import db
from rbac import require_module
from auth_utils import get_current_user

router = APIRouter()


@router.get("/v1/directory/users")
async def list_directory_users(
    stale_only: bool = False, disabled_only: bool = False, q: str | None = None,
    page: int = 1, page_size: int = 50,
    user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/directory")),
):
    query: dict = {}
    if stale_only:
        query["is_stale"] = True
    if disabled_only:
        query["enabled"] = False
    if q:
        query["$or"] = [
            {"display_name": {"$regex": q, "$options": "i"}},
            {"upn": {"$regex": q, "$options": "i"}},
            {"email": {"$regex": q, "$options": "i"}},
        ]
    total = await db.directory_users.count_documents(query)
    items = await db.directory_users.find(query, {"_id": 0}).sort("display_name", 1) \
        .skip(max(0, (page - 1) * page_size)).limit(page_size).to_list(page_size)
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.get("/v1/directory/groups")
async def list_directory_groups(q: str | None = None, user: dict = Depends(get_current_user),
                                 _rbac: dict = Depends(require_module("/directory"))):
    query: dict = {}
    if q:
        query["display_name"] = {"$regex": q, "$options": "i"}
    items = await db.directory_groups.find(query, {"_id": 0}).sort("display_name", 1).to_list(2000)
    return {"items": items, "total": len(items)}


@router.get("/v1/directory/stats")
async def directory_stats(user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/directory"))):
    total_users = await db.directory_users.count_documents({})
    stale = await db.directory_users.count_documents({"is_stale": True})
    disabled = await db.directory_users.count_documents({"enabled": False})
    total_groups = await db.directory_groups.count_documents({})
    last_synced = await db.directory_users.find({}, {"_id": 0, "synced_at": 1}).sort("synced_at", -1).limit(1).to_list(1)
    return {
        "total_users": total_users, "stale_users": stale, "disabled_users": disabled,
        "total_groups": total_groups,
        "last_synced_at": last_synced[0]["synced_at"] if last_synced else None,
    }
