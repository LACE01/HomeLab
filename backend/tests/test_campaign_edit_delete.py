"""#73 -- edit a campaign after creation (logged, baseline recalculated) and
super-admin-only delete that archives the wrapper and never touches findings."""
import asyncio, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("MONGO_URL", "x"); os.environ.setdefault("DB_NAME", "t"); os.environ.setdefault("JWT_SECRET", "x")
from fastapi import HTTPException
from mongomock_motor import AsyncMongoMockClient
import routes.remediation_campaigns as rr
import remediation_campaigns as rc
from auth_utils import is_super_admin

ADMIN = {"id": "u1", "email": "admin@x", "role": "admin"}
SUPER = {"id": "u2", "email": "boss@x", "role": "admin", "super_admin": True}

assert not is_super_admin(ADMIN) and is_super_admin(SUPER)
assert not is_super_admin({"role": "manager", "super_admin": True}), "flag alone without admin role is not enough"
os.environ["SUPER_ADMIN_EMAILS"] = "Admin@X"
assert is_super_admin(ADMIN)
os.environ["SUPER_ADMIN_EMAILS"] = ""
print("PASS: super-admin = admin role + per-user flag or SUPER_ADMIN_EMAILS")

async def main():
    db = AsyncMongoMockClient()["t"]
    rr.db = db; rc_db = db
    await db.users.insert_many([dict(ADMIN), dict(SUPER)])
    await db.findings.insert_many([
        {"id": f"f{i}", "status": "New" if i < 4 else "Fixed validated", "severity": "High",
         "title": f"t{i}", "asset_id": "a"} for i in range(6)])
    await db.remediation_campaigns.insert_one({
        "id": "c1", "name": "Old", "status": "active", "finding_ids": ["f0", "f1", "f2"],
        "baseline_open_ids": ["f0", "f1", "f2"], "assignees": []})

    body = rr.CampaignPatch(name="New name", due_date="2026-12-01", remove_finding_ids=["f2"],
                            add_finding_ids=["f3", "f4", "f0"])
    out = await rr.update_campaign("c1", body, user=ADMIN)
    camp = await db.remediation_campaigns.find_one({"id": "c1"})
    assert camp["name"] == "New name" and camp["updated_by"] == "admin@x"
    assert sorted(camp["finding_ids"]) == ["f0", "f1", "f3", "f4"], camp["finding_ids"]
    # f2 removed from baseline; f3 open added; f4 resolved not added; f0 not double-counted
    assert sorted(camp["baseline_open_ids"]) == ["f0", "f1", "f3"], camp["baseline_open_ids"]
    acts = {a["action"]: a for a in await db.remediation_campaign_activity.find({"campaign_id": "c1"}).to_list(50)}
    assert {"edited", "scope_changed", "added_findings", "removed_findings"} <= set(acts), set(acts)
    assert "name: Old → New name" in acts["edited"]["detail"], acts["edited"]["detail"]
    assert "3 → 3" in acts["scope_changed"]["detail"], acts["scope_changed"]["detail"]
    assert out["viewer_can_delete"] is False and out["viewer_can_edit"] is True
    print("PASS: edits logged before→after; scope edits recalc baseline (removed leave, resolved adds don't count)")

    # no-op edit logs nothing
    n = await db.remediation_campaign_activity.count_documents({})
    await rr.update_campaign("c1", rr.CampaignPatch(name="New name"), user=ADMIN)
    assert await db.remediation_campaign_activity.count_documents({}) == n

    try:
        await rr.delete_campaign("c1", user=ADMIN); raise AssertionError("plain admin deleted")
    except HTTPException as e:
        assert e.status_code == 403
    before = await db.findings.find({}, {"_id": 0}).to_list(100)
    r = await rr.delete_campaign("c1", user=SUPER)
    assert r["ok"] and r["findings_untouched"] == 4
    assert await db.remediation_campaigns.count_documents({"id": "c1"}) == 0
    arch = await db.remediation_campaigns_deleted.find_one({"id": "c1"})
    assert arch["deleted_by"] == "boss@x" and len(arch["activity"]) >= 4
    assert await db.findings.find({}, {"_id": 0}).to_list(100) == before, "findings must be untouched"
    assert await db.activity_log.count_documents({"action": "campaign_deleted", "entity_id": "c1"}) == 1
    print("PASS: delete is super-admin only, archives wrapper+timeline, audit-logs, findings untouched")

asyncio.run(main())
