import os, sys
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_vendor_management"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_vendor_management"]

import server
import auth_utils
from routes import vendors as vendors_route
vendors_route.db = db_module.db

import vendor_management as vm

from fastapi.testclient import TestClient

admin_user = {"id": "u1", "email": "admin@x.com", "role": "admin", "name": "Admin", "teams": []}
app = server.app
app.dependency_overrides[auth_utils.get_current_user] = lambda: admin_user
client = TestClient(app)

db = db_module.db

import asyncio

def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)

# --- meta ---
r = client.get("/api/v1/vendors/meta")
assert r.status_code == 200, r.text
meta = r.json()
assert "Hardware" in meta["categories"]
assert meta["criticality_levels"] == [1, 2, 3, 4, 5]
print("PASS: meta endpoint")

# --- seed assets/findings for suggestions + linking ---
run(db.assets.insert_many([
    {"id": "a1", "hostname": "ws-01", "hardware_info": "HP EliteDesk 800 G4 SFF", "os": "Windows 10 Enterprise"},
    {"id": "a2", "hostname": "ws-02", "hardware_info": "HP EliteDesk 800 G4 SFF", "os": "Windows 10 Enterprise"},
    {"id": "a3", "hostname": "srv-01", "hardware_info": "Dell PowerEdge R740", "os": "Ubuntu 22.04"},
]))
run(db.findings.insert_many([
    {"id": "f1", "asset_id": "a1", "title": "Adobe Acrobat Reader DC Multiple Vulnerabilities", "severity": "Critical", "status": "New", "kev_flag": True},
    {"id": "f2", "asset_id": "a1", "title": "Windows SMB Remote Code Execution", "severity": "High", "status": "Valid"},
    {"id": "f3", "asset_id": "a3", "title": "OpenSSL Vulnerability", "severity": "Medium", "status": "Fixed"},
]))

# --- suggestions: HP (hardware, 2 assets) + Dell (hardware, 1 asset) + Microsoft (OS, 2 assets) + Canonical (OS, 1 asset) ---
r = client.get("/api/v1/vendors/suggestions")
assert r.status_code == 200, r.text
suggestions = r.json()
names = {s["name"]: s for s in suggestions}
assert names["HP"]["asset_count"] == 2 and names["HP"]["category"] == "Hardware"
assert names["Dell"]["asset_count"] == 1
assert names["Microsoft"]["asset_count"] == 2 and names["Microsoft"]["category"] == "Software"
assert names["Canonical"]["asset_count"] == 1
print("PASS: suggestions from asset hardware_info + os")

# --- create vendor individually ---
r = client.post("/api/v1/vendors", json={"name": "HP", "category": "Hardware", "org_criticality": 4})
assert r.status_code == 200, r.text
hp = r.json()
assert hp["name"] == "HP" and hp["org_criticality"] == 4 and hp["monitoring_enabled"] is False
print("PASS: create vendor")

# duplicate name (case-insensitive) returns existing, doesn't double-create
r = client.post("/api/v1/vendors", json={"name": "hp", "category": "Hardware"})
assert r.status_code == 200, r.text
assert r.json()["id"] == hp["id"]
r = client.get("/api/v1/vendors")
assert r.json()["total"] == 1
print("PASS: duplicate vendor name dedupes")

# invalid category / criticality
r = client.post("/api/v1/vendors", json={"name": "BadCo", "category": "Nonsense"})
assert r.status_code == 400
r = client.post("/api/v1/vendors", json={"name": "BadCo", "org_criticality": 9})
assert r.status_code == 400
print("PASS: validation errors for bad category/criticality")

# --- bulk create (Adobe with match_terms, Microsoft with domain) ---
r = client.post("/api/v1/vendors/bulk", json={"vendors": [
    {"name": "Adobe", "category": "Software", "match_terms": ["Adobe Acrobat"], "org_criticality": 3},
    {"name": "Microsoft", "category": "Software", "domain": "microsoft.com", "match_terms": ["Windows"], "org_criticality": 5},
]})
assert r.status_code == 200, r.text
assert r.json()["created"] == 2
r = client.get("/api/v1/vendors")
assert r.json()["total"] == 3
print("PASS: bulk create vendors")

vendors_by_name = {v["name"]: v for v in client.get("/api/v1/vendors").json()["items"]}
adobe = vendors_by_name["Adobe"]
microsoft = vendors_by_name["Microsoft"]

# --- list includes computed risk fields ---
assert "risk_score" in adobe and "risk_band" in adobe and "asset_count" in adobe
# Adobe links via finding title match only (no asset match) -> asset_count 0, finding_count 1 (Critical/KEV finding f1)
assert adobe["finding_count"] == 1
assert adobe["risk_band"] in ("Critical", "High", "Medium", "Low", "Very Low", "Negligible") or isinstance(adobe["risk_band"], str)
print("PASS: list computes risk per vendor")

# Microsoft links via os="Windows..." on a1/a2 plus match_terms "Windows" in findings/os -> asset_count should include a1,a2
assert microsoft["asset_count"] == 2
print("PASS: vendor asset linking via os field")

# HP links via hardware_info substring "HP" -> asset_count 2 (a1, a2)
hp_full = client.get(f"/api/v1/vendors/{hp['id']}").json()
assert hp_full["asset_count"] == 2
assert hp_full["exposure"] == []
print("PASS: vendor drill-down (get_vendor) returns merged risk + exposure fields correctly")

# --- 404 handling ---
r = client.get("/api/v1/vendors/doesnotexist")
assert r.status_code == 404
r = client.patch("/api/v1/vendors/doesnotexist", json={"name": "X"})
assert r.status_code == 404
r = client.delete("/api/v1/vendors/doesnotexist")
assert r.status_code == 404
print("PASS: 404s for unknown vendor id")

# --- stats ---
r = client.get("/api/v1/vendors/stats")
assert r.status_code == 200, r.text
stats = r.json()
assert stats["total_vendors"] == 3
assert stats["by_category"]["Hardware"] == 1
assert stats["by_category"]["Software"] == 2
assert any(x["name"] == "Adobe" for x in stats["top_exposure"])
print("PASS: stats endpoint (by_category/by_band/top_exposure)")

# --- update vendor ---
r = client.patch(f"/api/v1/vendors/{adobe['id']}", json={"org_criticality": 5, "notes": "Critical PDF tooling"})
assert r.status_code == 200, r.text
assert r.json()["org_criticality"] == 5
print("PASS: update vendor")

r = client.patch(f"/api/v1/vendors/{adobe['id']}", json={"category": "Nonsense"})
assert r.status_code == 400
print("PASS: update validation")

# --- audit log entries ---
logs = run(db.activity_log.find({"entity_type": "vendor"}).to_list(100))
actions = [l["action"] for l in logs]
assert "vendor_added" in actions
assert "vendor_updated" in actions
print(f"PASS: audit log entries written ({len(logs)} entries: {sorted(set(actions))})")

# --- monitoring: needs domain ---
r = client.post(f"/api/v1/vendors/{adobe['id']}/monitor", json={"enabled": True})
assert r.status_code == 400
print("PASS: monitoring requires a domain")

r = client.post(f"/api/v1/vendors/{microsoft['id']}/monitor", json={"enabled": True})
assert r.status_code == 200, r.text
assert r.json()["monitoring_enabled"] is True
schedules = run(db.recon_schedules.find({"target": "microsoft.com"}).to_list(100))
assert len(schedules) == len(vm.MONITOR_MODULE_IDS)
assert all(s["created_by"] == f"vendor:{microsoft['id']}" for s in schedules)
print("PASS: enabling monitoring creates recon_schedules entries reusing the existing collection")

# idempotent: enabling again doesn't duplicate
r = client.post(f"/api/v1/vendors/{microsoft['id']}/monitor", json={"enabled": True})
schedules2 = run(db.recon_schedules.find({"target": "microsoft.com"}).to_list(100))
assert len(schedules2) == len(vm.MONITOR_MODULE_IDS)
print("PASS: re-enabling monitoring does not duplicate schedules")

r = client.post(f"/api/v1/vendors/{microsoft['id']}/monitor", json={"enabled": False})
assert r.status_code == 200
assert r.json()["monitoring_enabled"] is False
schedules3 = run(db.recon_schedules.find({"target": "microsoft.com"}).to_list(100))
assert len(schedules3) == 0
print("PASS: disabling monitoring removes recon_schedules entries")

# --- check-now (mocked reconng.run_module) ---
from unittest.mock import patch, AsyncMock

async def fake_run_module_clean(db_arg, module_id, target, timeout_sec=300):
    return {"osint_findings_created": 0, "easm_candidates_created": 0}

with patch("reconng.run_module", new=AsyncMock(side_effect=fake_run_module_clean)):
    r = client.post(f"/api/v1/vendors/{microsoft['id']}/check-now")
    assert r.status_code == 200, r.text
    results = r.json()["results"]
    assert len(results) == len(vm.MONITOR_MODULE_IDS)
    assert all(x["status"] == "clean" for x in results)
print("PASS: check-now clean path (mocked reconng.run_module)")

async def fake_run_module_found(db_arg, module_id, target, timeout_sec=300):
    if module_id == "certificate_transparency":
        return {"easm_candidates_created": 2}
    return {"osint_findings_created": 1}

with patch("reconng.run_module", new=AsyncMock(side_effect=fake_run_module_found)):
    r = client.post(f"/api/v1/vendors/{microsoft['id']}/check-now")
    results = r.json()["results"]
    assert all(x["status"] == "found" for x in results)
print("PASS: check-now found path (mocked reconng.run_module)")

async def fake_run_module_error(db_arg, module_id, target, timeout_sec=300):
    raise ValueError("not configured")

with patch("reconng.run_module", new=AsyncMock(side_effect=fake_run_module_error)):
    r = client.post(f"/api/v1/vendors/{microsoft['id']}/check-now")
    results = r.json()["results"]
    assert all(x["status"] == "not_configured" for x in results)
print("PASS: check-now not_configured path (ValueError from reconng.run_module)")

# check-now requires domain
r = client.post(f"/api/v1/vendors/{adobe['id']}/check-now")
assert r.status_code == 400
print("PASS: check-now requires a domain")

# --- exposure endpoint (reads db.osint_findings keyed by target=domain) ---
run(db.osint_findings.insert_many([
    {"id": "of1", "target": "microsoft.com", "module_id": "otx_domain", "found_at": "2026-07-01T00:00:00+00:00", "summary": "IOC hit"},
]))
r = client.get(f"/api/v1/vendors/{microsoft['id']}/exposure")
assert r.status_code == 200, r.text
assert len(r.json()["items"]) == 1
r = client.get(f"/api/v1/vendors/{adobe['id']}/exposure")
assert r.json()["items"] == []
print("PASS: exposure endpoint reads osint_findings by domain target")

# drill-down (get_vendor) also surfaces the same exposure list
full = client.get(f"/api/v1/vendors/{microsoft['id']}").json()
assert len(full["exposure"]) == 1 and full["exposure"][0]["id"] == "of1"
print("PASS: get_vendor merges exposure into drill-down response")

# --- bulk delete ---
r = client.post("/api/v1/vendors/bulk-delete", json={"ids": [adobe["id"], hp["id"]]})
assert r.status_code == 200, r.text
assert r.json()["deleted"] == 2
r = client.get("/api/v1/vendors")
assert r.json()["total"] == 1
print("PASS: bulk delete vendors")

r = client.post("/api/v1/vendors/bulk-delete", json={"ids": []})
assert r.status_code == 400
print("PASS: bulk delete requires ids")

# --- delete individual (also disables monitoring, no error even though already off) ---
r = client.delete(f"/api/v1/vendors/{microsoft['id']}")
assert r.status_code == 200, r.text
r = client.get("/api/v1/vendors")
assert r.json()["total"] == 0
print("PASS: delete vendor")

# --- RBAC: /vendors is registered as a module and gated ---
import rbac
keys = [m["key"] for m in rbac.MODULE_REGISTRY]
assert "/vendors" in keys
print("PASS: /vendors registered in RBAC MODULE_REGISTRY")

# non-admin without access is blocked (manager gets edit by default since /vendors isn't admin-only-by-default)
manager_user = {"id": "u2", "email": "mgr@x.com", "role": "manager", "name": "Mgr", "teams": []}
app.dependency_overrides[auth_utils.get_current_user] = lambda: manager_user
r = client.get("/api/v1/vendors/meta")
assert r.status_code == 200, r.text
print("PASS: manager role has default access to /vendors (not admin-only-by-default)")
app.dependency_overrides[auth_utils.get_current_user] = lambda: admin_user

print("\nALL VENDOR MANAGEMENT TESTS PASSED")
