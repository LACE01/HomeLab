"""Routes for role-based module access control -- see backend/rbac.py for the module
registry, defaults, and the require_module() enforcement dependency used across the
other route files."""
import uuid
from typing import Dict

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from db import db
from auth_utils import get_current_user, require_role
from routes.common import now_iso

router = APIRouter()


@router.get("/v1/me/module-access")
async def my_module_access(user: dict = Depends(get_current_user)):
    """Every logged-in user's frontend calls this once after login to know which nav
    items/routes to show, and which of those it can also edit -- separate from the
    admin-only config endpoints below."""
    from rbac import MODULE_KEYS, access_map_for_role
    if user.get("role") == "admin":
        return {"role": user.get("role"), "access": {k: "edit" for k in MODULE_KEYS}}
    access = await access_map_for_role(db, user.get("role"))
    return {"role": user.get("role"), "access": access}


@router.get("/v1/admin/rbac-config")
async def get_rbac_config(user: dict = Depends(require_role("admin"))):
    from rbac import MODULE_REGISTRY, CONFIGURABLE_ROLES, LEVELS, get_access_config
    access = await get_access_config(db)
    return {"modules": MODULE_REGISTRY, "roles": CONFIGURABLE_ROLES, "levels": LEVELS, "access": access}


class RbacConfigBody(BaseModel):
    access: Dict[str, Dict[str, str]]  # role -> {module_key: "view"|"edit"}


def _diff_access(old: dict, new: dict) -> str:
    """Human-readable summary of what changed, for the audit log entry -- e.g.
    "analyst: +edit /findings, -/admin/backups" rather than just "config updated"."""
    lines = []
    for role in sorted(set(old) | set(new)):
        before, after = old.get(role, {}), new.get(role, {})
        added = [f"{k} ({after[k]})" for k in after if k not in before]
        removed = [k for k in before if k not in after]
        changed = [f"{k} ({before[k]}→{after[k]})" for k in after if k in before and before[k] != after[k]]
        parts = []
        if added:
            parts.append(f"+{', '.join(added)}")
        if removed:
            parts.append(f"-{', '.join(removed)}")
        if changed:
            parts.append(f"~{', '.join(changed)}")
        if parts:
            lines.append(f"{role}: {'; '.join(parts)}")
    return "; ".join(lines) if lines else "no effective change"


@router.put("/v1/admin/rbac-config")
async def set_rbac_config(body: RbacConfigBody, user: dict = Depends(require_role("admin"))):
    from rbac import MODULE_KEYS, CONFIGURABLE_ROLES, LEVELS, get_access_config
    for role, levels_by_key in body.access.items():
        if role not in CONFIGURABLE_ROLES:
            raise HTTPException(400, f"Unknown or non-configurable role '{role}' (admin always has full access and isn't editable here)")
        for key, level in levels_by_key.items():
            if key not in MODULE_KEYS:
                raise HTTPException(400, f"Unknown module key '{key}'")
            if level not in LEVELS:
                raise HTTPException(400, f"Unknown access level '{level}' for '{key}' -- must be one of {LEVELS}")

    before = await get_access_config(db)
    await db.rbac_config.update_one({}, {"$set": {"access": body.access, "updated_at": now_iso()}}, upsert=True)
    await db.activity_log.insert_one({
        "id": str(uuid.uuid4()), "entity_type": "rbac_config", "entity_id": "global",
        "action": "rbac_access_updated", "actor": user["email"], "timestamp": now_iso(),
        "details": _diff_access(before, body.access),
    })
    return {"ok": True}


@router.post("/v1/admin/rbac-config/reset-defaults")
async def reset_rbac_defaults(user: dict = Depends(require_role("admin"))):
    from rbac import _default_access, get_access_config
    before = await get_access_config(db)
    defaults = _default_access()
    await db.rbac_config.update_one({}, {"$set": {"access": defaults, "updated_at": now_iso()}}, upsert=True)
    await db.activity_log.insert_one({
        "id": str(uuid.uuid4()), "entity_type": "rbac_config", "entity_id": "global",
        "action": "rbac_reset_defaults", "actor": user["email"], "timestamp": now_iso(),
        "details": _diff_access(before, defaults),
    })
    return {"access": defaults}
