import os, sys, asyncio
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_vendor_finding_detection"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_vendor_finding_detection"]

import server
import auth_utils
from routes import vendors as vendors_route
vendors_route.db = db_module.db

from fastapi.testclient import TestClient

admin_user = {"id": "u1", "email": "admin@x.com", "role": "admin", "name": "Admin", "teams": []}
app = server.app
app.dependency_overrides[auth_utils.get_current_user] = lambda: admin_user
client = TestClient(app)

db = db_module.db


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# No hardware/OS data at all -- only vulnerability findings, mimicking a real
# deployment where Qualys/Nessus-style findings are the actual data source and
# nothing about asset.hardware_info/os happens to mention a software vendor.
run(db.assets.insert_many([
    {"id": "a1", "hostname": "ws-01"},
    {"id": "a2", "hostname": "ws-02"},
    {"id": "a3", "hostname": "srv-01"},
]))
run(db.findings.insert_many([
    {"id": "f1", "title": "Adobe Acrobat Reader DC Multiple Vulnerabilities", "asset_id": "a1"},
    {"id": "f2", "title": "Adobe Acrobat Reader DC Multiple Vulnerabilities", "asset_id": "a2"},
    {"id": "f3", "title": "Oracle Java SE Multiple Vulnerabilities", "asset_id": "a1"},
    {"id": "f4", "title": "Remote Code Execution via unpatched OS component", "asset_id": "a3"},  # no vendor keyword
    # SBOM-sourced finding: vendor should be picked up via component_name too
    {"id": "f5", "title": "log4j-core@2.14.1 -- CVE-2021-44228", "component_name": "log4j-core", "asset_id": "a3"},
]))

import vendor_management

suggestions = run(vendor_management.suggest_vendors(db))
by_name = {s["name"]: s for s in suggestions}

assert "Adobe" in by_name, suggestions
assert by_name["Adobe"]["asset_count"] == 2  # a1 + a2, not double-counted despite 2 matching findings on a1... wait a1 has both f1(Adobe) and f3(Oracle)
assert by_name["Adobe"]["category"] == "Software"
assert by_name["Adobe"]["source"] == "finding_title"
print("PASS: Adobe surfaced from finding titles alone (no hardware_info/os signal at all)")

assert "Oracle" in by_name
assert by_name["Oracle"]["asset_count"] == 1  # only a1
print("PASS: Oracle surfaced from a separate finding title, correct distinct asset_count")

assert "srv-01" not in str(by_name)  # sanity: no bogus vendor from the CWE-style title
generic_titles = [s for s in suggestions if s["name"] in ("Remote", "Code", "Execution")]
assert generic_titles == []
print("PASS: a generic CWE-style finding title with no real vendor keyword doesn't produce a bogus suggestion")

# Approve Adobe through the real API end-to-end
r = client.post("/api/v1/vendors/candidates/scan")
assert r.status_code == 200, r.text
r = client.get("/api/v1/vendors/candidates")
pending = r.json()["items"]
adobe = next(c for c in pending if c["name"] == "Adobe")
assert adobe["asset_count"] == 2
r = client.post(f"/api/v1/vendors/candidates/{adobe['id']}/approve")
assert r.status_code == 200, r.text
vendor = r.json()["vendor"]
assert vendor["name"] == "Adobe"
print("PASS: Adobe candidate (detected purely from vulnerability data) approves into a real tracked vendor")

r = client.get(f"/api/v1/vendors/{vendor['id']}")
full = r.json()
assert full["asset_count"] == 2
assert any(f["title"].startswith("Adobe") for f in full.get("linked_findings", full.get("findings", [])) or [])
print("PASS: approved vendor's drill-down shows the real linked findings/assets that drove detection")

# A vendor that shows up via BOTH an OS match AND a finding title should merge into
# ONE candidate with a correctly unioned (not double-counted or duplicated) asset_count.
run(db.assets.insert_one({"id": "a4", "hostname": "ws-04", "os": "Windows 11 Enterprise"}))
run(db.findings.insert_one({"id": "f6", "title": "Microsoft Outlook Remote Code Execution", "asset_id": "a4"}))
suggestions2 = run(vendor_management.suggest_vendors(db))
ms = next((s for s in suggestions2 if s["name"] == "Microsoft"), None)
assert ms is not None
assert ms["asset_count"] == 1  # a4 counted once, not twice, despite matching both asset_os AND finding_title
assert "asset_os" in ms["source"] and "finding_title" in ms["source"]
print("PASS: a vendor detected via multiple sources on the same asset merges into one candidate, not duplicates")

print("\nALL VENDOR FINDING-DETECTION TESTS PASSED")
