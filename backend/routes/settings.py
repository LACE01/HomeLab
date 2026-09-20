"""Routes for feature_flags.py -- lets an admin view/toggle optional platform
behaviors from a Settings page."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from db import db
from auth_utils import require_role
from feature_flags import get_all_flags, set_flag
from app_settings import get_all_settings, set_setting

router = APIRouter()


@router.get("/v1/settings/feature-flags")
async def list_feature_flags(user: dict = Depends(require_role("admin"))):
    return {"items": await get_all_flags(db)}


class FlagUpdate(BaseModel):
    enabled: bool


@router.patch("/v1/settings/feature-flags/{key}")
async def update_feature_flag(key: str, body: FlagUpdate, user: dict = Depends(require_role("admin"))):
    try:
        result = await set_flag(db, key, body.enabled, user["email"])
    except ValueError as e:
        raise HTTPException(404, str(e))
    return result


@router.get("/v1/settings/tunables")
async def list_tunables(user: dict = Depends(require_role("admin"))):
    return {"items": await get_all_settings(db)}


class TunableUpdate(BaseModel):
    value: int


@router.patch("/v1/settings/tunables/{key}")
async def update_tunable(key: str, body: TunableUpdate, user: dict = Depends(require_role("admin"))):
    try:
        return await set_setting(db, key, body.value, user.get("email") or user.get("id"))
    except ValueError as e:
        raise HTTPException(400, str(e))
