"""Idempotent one-time setup that runs at every boot, so a deploy needs no manual
follow-up steps (no .env edits, no Role Access clicks, no "Repair" button).

Each step is safe to run repeatedly: it either checks a marker or only acts when
the state it fixes is actually present.
"""
import logging
import uuid
from datetime import datetime, timezone

logger = logging.getLogger("vulnops")

# Modules added AFTER Role Access configs started being saved. On the first boot
# that runs grant_new_modules, these are the only keys treated as "new" -- every
# other key missing from a role was deliberately removed by an admin and stays
# removed. From then on, rbac_config.known_modules records what admins have seen.
NEW_MODULES_BOOTSTRAP = {"/wstg"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


async def grant_new_modules(db) -> dict:
    """A newly shipped page gets its default Role Access grants automatically.

    Without this, a saved Role Access config (which every install that has ever
    clicked Save has) silently hides every new page from non-admin roles until an
    admin notices and ticks it. New keys get the same defaults a fresh install
    would; keys an admin removed are never re-added."""
    from rbac import MODULE_KEYS, _default_access, _normalize_access
    doc = await db.rbac_config.find_one({}, {"_id": 0})
    if not doc or not doc.get("access"):
        return {"granted": {}, "note": "no saved config -- defaults already include every module"}
    access = _normalize_access(doc["access"])
    known = doc.get("known_modules")
    if known is None:
        known = [k for k in MODULE_KEYS if k not in NEW_MODULES_BOOTSTRAP]
    new_keys = [k for k in MODULE_KEYS if k not in set(known)]
    defaults = _default_access()
    granted: dict = {}
    for key in new_keys:
        for role, levels in defaults.items():
            if key in levels and role in access and key not in access[role]:
                access[role][key] = levels[key]
                granted.setdefault(role, []).append(key)
    await db.rbac_config.update_one({}, {"$set": {
        "access": access, "known_modules": list(MODULE_KEYS)}}, upsert=True)
    if granted:
        await db.activity_log.insert_one({
            "id": str(uuid.uuid4()), "entity_type": "rbac_config", "entity_id": "global",
            "action": "rbac_new_modules_granted", "actor": "system", "timestamp": _now(),
            "details": "; ".join(f"{r}: {', '.join(ks)}" for r, ks in granted.items())})
    return {"granted": granted}


async def bootstrap_super_admin(db) -> dict:
    """Item 73: deleting a campaign needs a super-admin. If nobody holds the flag
    (and SUPER_ADMIN_EMAILS isn't set), give it to the longest-standing active
    admin so the capability exists out of the box. That admin can then grant or
    revoke it for others in User Management. Never runs once anyone holds it."""
    import os
    if os.environ.get("SUPER_ADMIN_EMAILS", "").strip():
        return {"promoted": None, "note": "SUPER_ADMIN_EMAILS set"}
    if await db.users.count_documents({"super_admin": True}):
        return {"promoted": None}
    admins = await db.users.find(
        {"role": "admin", "active": {"$ne": False}}, {"_id": 0, "id": 1, "email": 1, "created_at": 1}
    ).to_list(500)
    if not admins:
        return {"promoted": None, "note": "no active admin"}
    admins.sort(key=lambda u: str(u.get("created_at") or ""))
    first = admins[0]
    await db.users.update_one({"id": first["id"]}, {"$set": {"super_admin": True}})
    await db.activity_log.insert_one({
        "id": str(uuid.uuid4()), "entity_type": "user", "entity_id": first["id"],
        "action": "super_admin_bootstrapped", "actor": "system", "timestamp": _now(),
        "details": f"{first.get('email')} made super-admin (no super-admin existed)"})
    return {"promoted": first.get("email")}


async def repair_cwes_once(db) -> dict:
    """Run the CWE repair (normalize + propagate by CVE) exactly once after the
    rescan-wipe fix shipped, instead of asking an admin to click "Repair CWEs"."""
    marker = "cwe_repair_v1"
    if await db.migrations.find_one({"id": marker}):
        return {"skipped": True}
    from cwe_repair import repair_cwes
    result = await repair_cwes(db)
    await db.migrations.insert_one({"id": marker, "at": _now(), "result": result})
    return result


async def run_all(db) -> None:
    for name, step in (("grant_new_modules", grant_new_modules),
                       ("bootstrap_super_admin", bootstrap_super_admin),
                       ("repair_cwes_once", repair_cwes_once)):
        try:
            res = await step(db)
            logger.info("startup migration %s: %s", name, res)
        except Exception as e:   # one failing step must never block boot
            logger.exception("startup migration %s failed: %s", name, e)
