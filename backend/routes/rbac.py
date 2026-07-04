"""Routes for role-based module access control -- see backend/rbac.py for the module
registry, defaults, and the require_module() enforcement dependency used across the
other route files."""
from typing import Dict, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from db import db
from auth_utils import get_current_user, require_role
from routes.common import now_iso

router = APIRouter()


@router.get("/v1/me/module-access")
async def my_module_access(user: dict = Depends(get_current_user)):
    """Every logged-in user's frontend calls this once after login to know which nav
    items/routes to show -- separate from the admin-only config endpoints below."""
    from rbac import MODULE_KEYS, allowed_modules_for_role
    if user.get("role") == "admin":
        return {"role": user.get("role"), "modules": MODULE_KEYS}
    modules = await allowed_modules_for_role(db, user.get("role"))
    return {"role": user.get("role"), "modules": modules}


@router.get("/v1/admin/rbac-config")
async def get_rbac_config(user: dict = Depends(require_role("admin"))):
    from rbac import MODULE_REGISTRY, CONFIGURABLE_ROLES, get_access_config
    access = await get_access_config(db)
    return {"modules": MODULE_REGISTRY, "roles": CONFIGURABLE_ROLES, "access": access}


class RbacConfigBody(BaseModel):
    access: Dict[str, List[str]]


@router.put("/v1/admin/rbac-config")
async def set_rbac_config(body: RbacConfigBody, user: dict = Depends(require_role("admin"))):
    from rbac import MODULE_KEYS, CONFIGURABLE_ROLES
    for role, keys in body.access.items():
        if role not in CONFIGURABLE_ROLES:
            raise HTTPException(400, f"Unknown or non-configurable role '{role}' (admin always has full access and isn't editable here)")
        unknown = [k for k in keys if k not in MODULE_KEYS]
        if unknown:
            raise HTTPException(400, f"Unknown module key(s): {', '.join(unknown)}")
    await db.rbac_config.update_one({}, {"$set": {"access": body.access, "updated_at": now_iso()}}, upsert=True)
    return {"ok": True}


@router.post("/v1/admin/rbac-config/reset-defaults")
async def reset_rbac_defaults(user: dict = Depends(require_role("admin"))):
    from rbac import _default_access
    defaults = _default_access()
    await db.rbac_config.update_one({}, {"$set": {"access": defaults, "updated_at": now_iso()}}, upsert=True)
    return {"access": defaults}
