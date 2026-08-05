import os, sys, asyncio
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_feature_flags"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_feature_flags"]

import server
import auth_utils
from routes import settings as settings_route
settings_route.db = db_module.db

from fastapi.testclient import TestClient

admin_user = {"id": "u1", "email": "admin@x.com", "role": "admin", "name": "Admin", "teams": []}
analyst_user = {"id": "u2", "email": "analyst@x.com", "role": "analyst", "name": "Analyst", "teams": []}
app = server.app
client = TestClient(app)

db = db_module.db


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


import feature_flags

# --- default state: everything on, no doc in db yet ---
enabled = run(feature_flags.is_enabled(db, "vendor_detect_findings"))
assert enabled is True
print("PASS: unset flag defaults to enabled")

unknown = run(feature_flags.is_enabled(db, "totally_made_up_key"))
assert unknown is True
print("PASS: unknown flag key fails open (enabled), doesn't silently disable")

all_flags = run(feature_flags.get_all_flags(db))
assert len(all_flags) == len(feature_flags.FLAG_REGISTRY)
# Each flag reflects its OWN registry default. Most default True; the
# active-validation kill switch defaults False on purpose, so a blanket
# "all enabled" assertion is wrong now.
defaults = {f["key"]: f.get("default", True) for f in feature_flags.FLAG_REGISTRY}
assert all(f["enabled"] is defaults[f["key"]] for f in all_flags)
assert any(f["key"] == "active_validation_enabled" and f["enabled"] is False for f in all_flags), \
    "the active-validation capability must default to OFF"
print("PASS: get_all_flags returns the full registry with each flag at its own default — and the "
      "active-validation kill switch defaults OFF")

# --- set_flag ---
result = run(feature_flags.set_flag(db, "vendor_detect_findings", False, "admin@x.com"))
assert result["enabled"] is False
disabled_now = run(feature_flags.is_enabled(db, "vendor_detect_findings"))
assert disabled_now is False
print("PASS: set_flag persists and is_enabled reflects it")

try:
    run(feature_flags.set_flag(db, "not_a_real_flag", True, "admin@x.com"))
    assert False
except ValueError:
    pass
print("PASS: set_flag rejects an unknown key")

# --- routes ---
app.dependency_overrides[auth_utils.get_current_user] = lambda: admin_user
r = client.get("/api/v1/settings/feature-flags")
assert r.status_code == 200, r.text
items = r.json()["items"]
vf = next(f for f in items if f["key"] == "vendor_detect_findings")
assert vf["enabled"] is False and vf["updated_by"] == "admin@x.com"
print("PASS: GET /v1/settings/feature-flags reflects the override")

r = client.patch("/api/v1/settings/feature-flags/vendor_detect_findings", json={"enabled": True})
assert r.status_code == 200, r.text
r2 = client.get("/api/v1/settings/feature-flags")
vf2 = next(f for f in r2.json()["items"] if f["key"] == "vendor_detect_findings")
assert vf2["enabled"] is True
print("PASS: PATCH toggles a flag back on")

r = client.patch("/api/v1/settings/feature-flags/not_a_real_flag", json={"enabled": True})
assert r.status_code == 404
print("PASS: PATCH on unknown key 404s")

app.dependency_overrides[auth_utils.get_current_user] = lambda: analyst_user
r = client.get("/api/v1/settings/feature-flags")
assert r.status_code == 403
print("PASS: non-admin forbidden from settings")

app.dependency_overrides[auth_utils.get_current_user] = lambda: admin_user

# --- actually gates suggest_vendors() ---
from routes import vendors as vendors_route
vendors_route.db = db
run(db.assets.insert_one({"id": "a1", "hostname": "ws-01"}))
run(db.findings.insert_one({"id": "f1", "title": "Adobe Acrobat Reader DC Multiple Vulnerabilities", "asset_id": "a1"}))

import vendor_management
suggestions = run(vendor_management.suggest_vendors(db))
assert any(s["name"] == "Adobe" for s in suggestions)
print("PASS: with flag enabled, Adobe is suggested from finding titles")

run(feature_flags.set_flag(db, "vendor_detect_findings", False, "admin@x.com"))
suggestions2 = run(vendor_management.suggest_vendors(db))
assert not any(s["name"] == "Adobe" for s in suggestions2)
print("PASS: disabling vendor_detect_findings removes finding-based suggestions")

run(feature_flags.set_flag(db, "vendor_detect_findings", True, "admin@x.com"))
run(feature_flags.set_flag(db, "vendor_detect_hardware", False, "admin@x.com"))
run(feature_flags.set_flag(db, "vendor_detect_os", False, "admin@x.com"))
run(db.assets.update_one({"id": "a1"}, {"$set": {"hardware_info": "Dell OptiPlex", "os": "Windows 11"}}))
suggestions3 = run(vendor_management.suggest_vendors(db))
names3 = {s["name"] for s in suggestions3}
assert "Dell" not in names3 and "Microsoft" not in names3
assert "Adobe" in names3  # findings-based detection still runs independently
print("PASS: disabling hardware/os detection independently suppresses only those sources")

print("\nALL FEATURE FLAG TESTS PASSED")
