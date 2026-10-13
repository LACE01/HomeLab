"""Boot-time migrations replace the manual post-deploy steps: new modules get
default Role Access grants (without resurrecting admin removals), a super-admin
is bootstrapped when none exists, and the CWE repair runs exactly once."""
import asyncio, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("MONGO_URL", "x"); os.environ.setdefault("DB_NAME", "t"); os.environ.setdefault("JWT_SECRET", "x")
os.environ["SUPER_ADMIN_EMAILS"] = ""
from mongomock_motor import AsyncMongoMockClient
import aggregate_cache
import startup_migrations as sm
from rbac import MODULE_KEYS, _default_access

async def _noop(*a, **k): return None
aggregate_cache.invalidate = _noop

async def main():
    db = AsyncMongoMockClient()["t"]
    # a saved config from before /wstg existed; admin deliberately removed /vendors from analyst
    access = _default_access()
    for r in access.values():
        r.pop("/wstg", None)
    access["analyst"].pop("/vendors")
    await db.rbac_config.insert_one({"access": access})
    r = await sm.grant_new_modules(db)
    cfg = (await db.rbac_config.find_one({}))
    assert cfg["access"]["manager"]["/wstg"] == "edit" and cfg["access"]["analyst"]["/wstg"] == "edit", r
    assert "/wstg" not in cfg["access"]["executive"]
    assert "/vendors" not in cfg["access"]["analyst"], "an admin's removal must not be undone"
    assert set(cfg["known_modules"]) == set(MODULE_KEYS)
    # an admin then removes /wstg from analyst -- a reboot must not re-add it
    await db.rbac_config.update_one({}, {"$unset": {"access.analyst./wstg": ""}})
    await sm.grant_new_modules(db)
    assert "/wstg" not in (await db.rbac_config.find_one({}))["access"]["analyst"]
    assert await db.activity_log.count_documents({"action": "rbac_new_modules_granted"}) == 1
    print("PASS: new modules auto-granted with defaults once; admin removals respected")

    await db.users.insert_many([
        {"id": "a2", "email": "late@x", "role": "admin", "created_at": "2026-05-01"},
        {"id": "a1", "email": "first@x", "role": "admin", "created_at": "2026-01-01"},
        {"id": "a0", "email": "gone@x", "role": "admin", "created_at": "2025-01-01", "active": False},
        {"id": "m1", "email": "mgr@x", "role": "manager", "created_at": "2024-01-01"},
    ])
    r = await sm.bootstrap_super_admin(db)
    assert r["promoted"] == "first@x", r
    r2 = await sm.bootstrap_super_admin(db)
    assert r2["promoted"] is None and await db.users.count_documents({"super_admin": True}) == 1
    print("PASS: longest-standing active admin becomes super-admin only when none exists")

    await db.findings.insert_many([
        {"id": "1", "cve": "CVE-1", "cwe": "89"}, {"id": "2", "cve": "CVE-1", "cwe": None}])
    r = await sm.repair_cwes_once(db)
    assert r["updated"] == 1 and r["propagated_by_cve"] == 1, r
    assert (await db.findings.find_one({"id": "2"}))["cwe"] == "CWE-89"
    assert (await sm.repair_cwes_once(db)) == {"skipped": True}
    await sm.run_all(db)   # whole sequence is safe to re-run
    print("PASS: CWE repair runs once at boot and is marked done")

asyncio.run(main())
