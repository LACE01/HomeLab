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
    from rbac import MODULE_REGISTRY, LEVELS, get_access_config, configurable_roles, custom_roles
    access = await get_access_config(db)
    roles = await configurable_roles(db)
    custom = await custom_roles(db)
    return {"modules": MODULE_REGISTRY, "roles": roles, "custom_roles": custom, "levels": LEVELS, "access": access}


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
    from rbac import MODULE_KEYS, LEVELS, get_access_config, configurable_roles
    configurable = await configurable_roles(db)
    for role, levels_by_key in body.access.items():
        if role not in configurable:
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


# --------------------------- ROLES (create/rename/delete) ---------------------------
# The 4 roles this app ships with (BUILTIN_ROLES in backend/rbac.py) aren't stored
# here -- they're implicit and can't be renamed or deleted (too much of the app
# hardcodes `require_role("admin", ...)` checks against those exact strings for that
# to be safe). A custom role created here is just a name; what it can actually see
# and do is still decided entirely by the Role Access grid above, same as any
# built-in non-admin role.

class RoleCreateBody(BaseModel):
    name: str


@router.get("/v1/admin/roles")
async def list_roles(user: dict = Depends(require_role("admin"))):
    from rbac import BUILTIN_ROLES, all_roles
    docs = await db.roles.find({}, {"_id": 0}).to_list(None)
    custom_by_name = {d["name"]: d for d in docs}
    roles = await all_roles(db)
    return {"roles": [
        {"name": r, "is_builtin": r in BUILTIN_ROLES, "id": custom_by_name.get(r, {}).get("id")}
        for r in roles
    ]}


@router.post("/v1/admin/roles")
async def create_role(body: RoleCreateBody, user: dict = Depends(require_role("admin"))):
    from rbac import all_roles
    name = (body.name or "").strip()
    if not name:
        raise HTTPException(400, "Role name is required")
    if len(name) > 40:
        raise HTTPException(400, "Role name is too long (max 40 characters)")
    existing = await all_roles(db)
    if name.lower() in [r.lower() for r in existing]:
        raise HTTPException(409, f"A role named '{name}' already exists")
    new_role = {"id": str(uuid.uuid4()), "name": name, "created_at": now_iso(), "created_by": user["email"]}
    await db.roles.insert_one(new_role)
    await db.activity_log.insert_one({
        "id": str(uuid.uuid4()), "entity_type": "role", "entity_id": new_role["id"],
        "action": "role_created", "actor": user["email"], "timestamp": now_iso(),
        "details": f"Created role '{name}'",
    })
    return {"id": new_role["id"], "name": name}


class RoleRenameBody(BaseModel):
    name: str


@router.patch("/v1/admin/roles/{role_id}")
async def rename_role(role_id: str, body: RoleRenameBody, user: dict = Depends(require_role("admin"))):
    from rbac import all_roles
    role = await db.roles.find_one({"id": role_id}, {"_id": 0})
    if not role:
        raise HTTPException(404, "Custom role not found (built-in roles can't be renamed here)")
    new_name = (body.name or "").strip()
    if not new_name:
        raise HTTPException(400, "Role name is required")
    if len(new_name) > 40:
        raise HTTPException(400, "Role name is too long (max 40 characters)")
    old_name = role["name"]
    if new_name.lower() != old_name.lower():
        existing = await all_roles(db)
        if new_name.lower() in [r.lower() for r in existing]:
            raise HTTPException(409, f"A role named '{new_name}' already exists")

    await db.roles.update_one({"id": role_id}, {"$set": {"name": new_name}})
    if new_name != old_name:
        # Keep every user currently in this role, and any rbac_config access entry
        # keyed by its old name, pointed at the new name -- a rename shouldn't
        # silently strip people's role or their configured module access.
        cursor = db.users.find({"role": old_name}, {"_id": 0, "id": 1})
        async for u in cursor:
            await db.users.update_one({"id": u["id"]}, {"$set": {"role": new_name}})
        cfg_doc = await db.rbac_config.find_one({}, {"_id": 0}) or {}
        access = cfg_doc.get("access") or {}
        if old_name in access:
            access[new_name] = access.pop(old_name)
            await db.rbac_config.update_one({}, {"$set": {"access": access, "updated_at": now_iso()}}, upsert=True)

    await db.activity_log.insert_one({
        "id": str(uuid.uuid4()), "entity_type": "role", "entity_id": role_id,
        "action": "role_renamed", "actor": user["email"], "timestamp": now_iso(),
        "details": f"Renamed role '{old_name}' -> '{new_name}'",
    })
    return {"id": role_id, "name": new_name}


@router.delete("/v1/admin/roles/{role_id}")
async def delete_role(role_id: str, user: dict = Depends(require_role("admin"))):
    role = await db.roles.find_one({"id": role_id}, {"_id": 0})
    if not role:
        raise HTTPException(404, "Custom role not found (built-in roles can't be deleted)")
    role_name = role["name"]
    in_use = await db.users.count_documents({"role": role_name})
    if in_use:
        raise HTTPException(409, f"{in_use} user(s) still have this role -- reassign them before deleting it")
    await db.roles.delete_one({"id": role_id})
    cfg_doc = await db.rbac_config.find_one({}, {"_id": 0}) or {}
    access = cfg_doc.get("access") or {}
    if role_name in access:
        del access[role_name]
        await db.rbac_config.update_one({}, {"$set": {"access": access, "updated_at": now_iso()}}, upsert=True)
    await db.activity_log.insert_one({
        "id": str(uuid.uuid4()), "entity_type": "role", "entity_id": role_id,
        "action": "role_deleted", "actor": user["email"], "timestamp": now_iso(),
        "details": f"Deleted role '{role_name}'",
    })
    return {"ok": True}
