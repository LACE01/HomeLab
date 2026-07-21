import os, sys
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_vendor_gaps"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_vendor_gaps"]

import server
import auth_utils
from routes import vendors as vendors_route
vendors_route.db = db_module.db

import vendor_management as vm
import reconng

from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock
import asyncio
from datetime import datetime, timezone, timedelta

admin_user = {"id": "u1", "email": "admin@x.com", "role": "admin", "name": "Admin", "teams": []}
app = server.app
app.dependency_overrides[auth_utils.get_current_user] = lambda: admin_user
client = TestClient(app)

db = db_module.db

def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)

def days_from_now(n):
    return (datetime.now(timezone.utc) + timedelta(days=n)).date().isoformat()

# ============================================================
# Gap 1: contract/SLA/DPA tracking + renewal reminders
# ============================================================

r = client.post("/api/v1/vendors", json={"name": "Adobe", "category": "Software", "org_criticality": 4})
assert r.status_code == 200, r.text
adobe = r.json()
assert adobe["dpa_status"] == "not_required"
assert adobe["security_questionnaire_status"] == "not_started"
assert adobe["renewal_reminder_sent"] is False
print("PASS: new vendor defaults dpa_status/security_questionnaire_status/renewal_reminder_sent")

r = client.post("/api/v1/vendors", json={"name": "BadDPA", "dpa_status": "not_a_real_status"})
assert r.status_code == 400
r = client.post("/api/v1/vendors", json={"name": "BadQ", "security_questionnaire_status": "nonsense"})
assert r.status_code == 400
print("PASS: dpa_status/security_questionnaire_status validation on create")

r = client.patch(f"/api/v1/vendors/{adobe['id']}", json={
    "contract_start_date": "2025-01-01", "contract_end_date": "2027-01-01",
    "renewal_date": days_from_now(10), "contract_owner": "Jane Procurement",
    "dpa_status": "signed", "security_questionnaire_status": "completed",
})
assert r.status_code == 200, r.text
assert r.json()["dpa_status"] == "signed"
assert r.json()["renewal_reminder_sent"] is False  # first time setting renewal_date -> re-armed
print("PASS: update vendor contract fields + renewal_date first-set keeps reminder unarmed")

r = client.patch(f"/api/v1/vendors/{adobe['id']}", json={"dpa_status": "bogus"})
assert r.status_code == 400
print("PASS: dpa_status validation on update")

# --- renewals list endpoint ---
r = client.get("/api/v1/vendors/renewals")
assert r.status_code == 200, r.text
items = r.json()["items"]
assert len(items) == 1 and items[0]["name"] == "Adobe"
assert items[0]["overdue"] is False
print("PASS: GET /v1/vendors/renewals lists upcoming renewal")

# vendor with an overdue renewal date
r = client.post("/api/v1/vendors", json={"name": "OverdueCo", "category": "Software"})
overdue_id = r.json()["id"]
run(db.vendors.update_one({"id": overdue_id}, {"$set": {"renewal_date": days_from_now(-5)}}))
r = client.get("/api/v1/vendors/renewals")
names = {i["name"]: i for i in r.json()["items"]}
assert names["OverdueCo"]["overdue"] is True
print("PASS: overdue renewal flagged correctly")

# vendor with a renewal far in the future should NOT show up (default 30-day window)
r = client.post("/api/v1/vendors", json={"name": "FarFuture", "category": "Software"})
far_id = r.json()["id"]
run(db.vendors.update_one({"id": far_id}, {"$set": {"renewal_date": days_from_now(200)}}))
r = client.get("/api/v1/vendors/renewals")
names = {i["name"] for i in r.json()["items"]}
assert "FarFuture" not in names
print("PASS: renewals outside the warn window excluded")

# --- nightly sweep: check_vendor_renewals dispatches + marks reminded, no dupes ---
with patch("notifier.dispatch", new=AsyncMock(return_value=1)) as mock_dispatch:
    result = run(vm.check_vendor_renewals(db))
    assert result["reminded"] == 2  # Adobe + OverdueCo (FarFuture excluded by warn window)
    assert mock_dispatch.call_count == 2
    call_triggers = [c.args[0] for c in mock_dispatch.call_args_list]
    assert all(t == "vendor_contract_renewal_due" for t in call_triggers)
    adobe_call = next(c for c in mock_dispatch.call_args_list if c.args[1]["vendor_name"] == "Adobe")
    assert adobe_call.args[1]["contract_owner"] == "Jane Procurement"
    assert adobe_call.args[1]["dpa_status"] == "signed"
print("PASS: check_vendor_renewals dispatches vendor_contract_renewal_due for due vendors")

adobe_after = run(db.vendors.find_one({"id": adobe["id"]}, {"_id": 0}))
assert adobe_after["renewal_reminder_sent"] is True
print("PASS: renewal_reminder_sent marked True after reminder")

with patch("notifier.dispatch", new=AsyncMock(return_value=1)) as mock_dispatch2:
    result2 = run(vm.check_vendor_renewals(db))
    assert result2["reminded"] == 0
    assert mock_dispatch2.call_count == 0
print("PASS: re-running the sweep does not re-remind already-reminded vendors")

# pushing renewal_date out re-arms the reminder
r = client.patch(f"/api/v1/vendors/{adobe['id']}", json={"renewal_date": days_from_now(15)})
assert r.json()["renewal_reminder_sent"] is False
with patch("notifier.dispatch", new=AsyncMock(return_value=1)) as mock_dispatch3:
    result3 = run(vm.check_vendor_renewals(db))
    assert result3["reminded"] >= 1
print("PASS: editing renewal_date re-arms the reminder sweep")

logs = run(db.activity_log.find({"entity_type": "vendor", "action": "vendor_renewal_reminder_sent"}).to_list(100))
assert len(logs) >= 2
print(f"PASS: audit log entries for renewal reminders ({len(logs)})")

# ============================================================
# Gap 2: risk score trend over time
# ============================================================

run(db.assets.insert_many([
    {"id": "ga1", "hostname": "gap-ws-01", "hardware_info": "HP EliteDesk", "os": "Windows 10"},
]))
run(db.findings.insert_many([
    {"id": "gf1", "asset_id": "ga1", "title": "Windows Critical RCE", "severity": "Critical", "status": "New", "kev_flag": True},
]))
r = client.post("/api/v1/vendors", json={"name": "Microsoft", "category": "Software", "match_terms": ["Windows"], "org_criticality": 5})
ms_id = r.json()["id"]

snap1 = run(vm.snapshot_vendor_risk_history(db))
assert snap1["snapshots_written"] == 4  # Adobe, OverdueCo, FarFuture, Microsoft
print("PASS: snapshot_vendor_risk_history writes one row per vendor")

r = client.get(f"/api/v1/vendors/{ms_id}/risk-history")
assert r.status_code == 200, r.text
hist = r.json()["items"]
assert len(hist) == 1
assert hist[0]["risk_band"] in ("Critical", "High", "Medium", "Low")
assert hist[0]["asset_count"] == 1 and hist[0]["finding_count"] == 1
print("PASS: GET /v1/vendors/{id}/risk-history returns today's snapshot")

# re-running same day upserts, not duplicates
snap2 = run(vm.snapshot_vendor_risk_history(db))
r = client.get(f"/api/v1/vendors/{ms_id}/risk-history")
assert len(r.json()["items"]) == 1
print("PASS: same-day re-snapshot does not duplicate history rows")

# simulate a prior day's snapshot to verify multi-point history + days filter
yesterday = (datetime.now(timezone.utc).date() - timedelta(days=1)).isoformat()
run(db.vendor_risk_history.insert_one({
    "id": "manual1", "vendor_id": ms_id, "date": yesterday, "risk_score": 5, "risk_band": "Medium",
    "asset_count": 0, "finding_count": 0, "recorded_at": vm._now_iso(),
}))
r = client.get(f"/api/v1/vendors/{ms_id}/risk-history")
assert len(r.json()["items"]) == 2
assert r.json()["items"][0]["date"] == yesterday  # sorted ascending
print("PASS: risk-history returns multiple points sorted ascending by date")

r = client.get(f"/api/v1/vendors/{ms_id}/risk-history", params={"days": 0})
# days=0 -> since = today, yesterday's point excluded
assert all(i["date"] >= datetime.now(timezone.utc).date().isoformat() for i in r.json()["items"])
print("PASS: risk-history days window filter works")

r = client.get("/api/v1/vendors/doesnotexist/risk-history")
assert r.status_code == 404
print("PASS: risk-history 404s for unknown vendor")

# ============================================================
# Gap 3: SBOM component_name linkage
# ============================================================

run(db.findings.insert_one({
    "id": "sbom-f1", "asset_id": None, "title": "log4j-core@2.14.0 — GHSA-jfh8-c2jp-5v3q",
    "component_name": "log4j-core", "component_ecosystem": "Maven", "severity": "High", "status": "New",
}))
r = client.post("/api/v1/vendors", json={"name": "Apache", "category": "Software", "match_terms": ["log4j-core"]})
apache = r.json()
apache_full = client.get(f"/api/v1/vendors/{apache['id']}").json()
assert apache_full["finding_count"] == 1
assert apache_full["findings"][0]["id"] == "sbom-f1"
print("PASS: vendor links to SBOM finding via component_name match (not just title)")

# a vendor whose match_term only appears in component_name, not in the title text, still links
run(db.findings.insert_one({
    "id": "sbom-f2", "asset_id": None, "title": "Some Generic Package Vulnerability",
    "component_name": "requests-oauthlib", "component_ecosystem": "PyPI", "severity": "Medium", "status": "New",
}))
r = client.post("/api/v1/vendors", json={"name": "OAuthLibCo", "category": "Software", "match_terms": ["requests-oauthlib"]})
oauth_full = client.get(f"/api/v1/vendors/{r.json()['id']}").json()
assert oauth_full["finding_count"] == 1 and oauth_full["findings"][0]["id"] == "sbom-f2"
print("PASS: component_name-only match works even when title doesn't contain the term")

# ============================================================
# Gap 4: dedicated vendor compromise notification trigger
# ============================================================

r = client.post("/api/v1/vendors", json={"name": "TrackedVendor", "category": "Cloud Service / SaaS", "domain": "trackedvendor.example.com"})
tracked = r.json()

mod = reconng.MODULE_BY_ID["otx_domain"]
rows = [{"name": "IOC hit", "resource": "malware-c2", "detail": "Known bad indicator"}]

with patch("notifier.dispatch", new=AsyncMock(return_value=1)) as mock_dispatch:
    created = run(reconng._ingest_osint_rows(db, mod, "trackedvendor.example.com", rows))
    assert created == 1
    triggers_fired = [c.args[0] for c in mock_dispatch.call_args_list]
    assert "vendor_compromise_found" in triggers_fired
    vendor_call = next(c for c in mock_dispatch.call_args_list if c.args[0] == "vendor_compromise_found")
    assert vendor_call.args[1]["vendor_name"] == "TrackedVendor"
    assert vendor_call.args[1]["vendor_id"] == tracked["id"]
    assert vendor_call.args[1]["url"] == f"/vendors/{tracked['id']}"
print("PASS: _ingest_osint_rows fires vendor_compromise_found for a tracked vendor's domain")

# domain NOT tracked as a vendor should not fire the vendor-specific trigger
with patch("notifier.dispatch", new=AsyncMock(return_value=1)) as mock_dispatch2:
    run(reconng._ingest_osint_rows(db, mod, "untracked-domain.example.com", [
        {"name": "Other hit", "resource": "x", "detail": "y"}
    ]))
    triggers_fired2 = [c.args[0] for c in mock_dispatch2.call_args_list]
    assert "vendor_compromise_found" not in triggers_fired2
print("PASS: untracked domain does not fire vendor_compromise_found")

# re-ingesting the same row (dedup key) does not re-fire either trigger
with patch("notifier.dispatch", new=AsyncMock(return_value=1)) as mock_dispatch3:
    created2 = run(reconng._ingest_osint_rows(db, mod, "trackedvendor.example.com", rows))
    assert created2 == 0
    assert mock_dispatch3.call_count == 0
print("PASS: duplicate OSINT row does not re-fire notifications")

# trigger + template registered
import notifier
assert "vendor_compromise_found" in notifier.TRIGGERS
assert "vendor_contract_renewal_due" in notifier.TRIGGERS
assert "vendor_compromise_found" in notifier.TEMPLATES
assert "vendor_contract_renewal_due" in notifier.TEMPLATES
rendered = notifier.render("vendor_compromise_found", {
    "vendor_name": "Adobe", "module": "OTX", "target": "adobe.com", "label": "hit", "detail": "d", "url": "/vendors/x",
})
assert "Adobe" in rendered["subject"]
print("PASS: notifier TRIGGERS/TEMPLATES registered and render correctly")

print("\nALL VENDOR GAP TESTS PASSED")
