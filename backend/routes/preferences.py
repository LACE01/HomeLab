"""User preferences routes — tile picker / saved dashboard layouts per user."""
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from db import db
from auth_utils import get_current_user
from routes.common import now_iso, deep_merge

router = APIRouter()


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
        "group_by": "none",
        "view_mode": "by_asset",
    },
}


@router.get("/v1/me/preferences")
async def get_my_preferences(user: dict = Depends(get_current_user)):
    doc = await db.user_preferences.find_one({"user_id": user["id"]}, {"_id": 0})
    prefs = doc.get("prefs", {}) if doc else {}
    return deep_merge(DEFAULT_PREFS, prefs)


class PrefsBody(BaseModel):
    prefs: dict


@router.put("/v1/me/preferences")
async def put_my_preferences(body: PrefsBody, user: dict = Depends(get_current_user)):
    merged = deep_merge(DEFAULT_PREFS, body.prefs or {})
    await db.user_preferences.update_one(
        {"user_id": user["id"]},
        {"$set": {"user_id": user["id"], "prefs": merged, "updated_at": now_iso()}},
        upsert=True,
    )
    return merged
