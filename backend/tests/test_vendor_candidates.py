import os, sys, asyncio
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_vendor_candidates"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_vendor_candidates"]

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

# seed assets so suggest_vendors() has something real to detect
run(db.assets.insert_many([
    {"id": "a1", "hostname": "ws-01", "hardware_info": "HP EliteDesk 800 G4 SFF", "os": "Windows 10 Enterprise"},
    {"id": "a2", "hostname": "ws-02", "hardware_info": "HP EliteDesk 800 G4 SFF", "os": "Windows 10 Enterprise"},
    {"id": "a3", "hostname": "srv-01", "hardware_info": "Dell PowerEdge R740", "os": "Ubuntu 22.04"},
]))

# --- scan populates the candidate queue ---
r = client.post("/api/v1/vendors/candidates/scan")
assert r.status_code == 200, r.text
scan1 = r.json()
print("scan1:", scan1)
assert scan1["created"] >= 3  # HP, Dell, Microsoft (Canonical too, but at least these 3)
assert scan1["refreshed"] == 0
print("PASS: scan populates candidate queue from detected assets")

r = client.get("/api/v1/vendors/candidates")
assert r.status_code == 200, r.text
pending = r.json()["items"]
names = {c["name"] for c in pending}
assert "HP" in names and "Dell" in names and "Microsoft" in names
hp = next(c for c in pending if c["name"] == "HP")
assert hp["status"] == "pending" and hp["asset_count"] == 2
print("PASS: GET candidates lists pending detections with correct asset_count")

# --- re-scanning refreshes existing pending candidates instead of duplicating ---
r = client.post("/api/v1/vendors/candidates/scan")
scan2 = r.json()
assert scan2["created"] == 0
assert scan2["refreshed"] >= 3
r = client.get("/api/v1/vendors/candidates")
assert len(r.json()["items"]) == len(pending)  # no duplicates
print("PASS: re-scanning refreshes pending candidates, doesn't duplicate")

# --- approve HP: creates a real, active vendor with a risk profile ---
r = client.post(f"/api/v1/vendors/candidates/{hp['id']}/approve")
assert r.status_code == 200, r.text
approved = r.json()
vendor = approved["vendor"]
assert vendor["name"] == "HP" and vendor["category"] == "Hardware"
print("PASS: approving a candidate creates a real vendor")

r = client.get(f"/api/v1/vendors/{vendor['id']}")
assert r.status_code == 200, r.text
full = r.json()
assert "risk_score" in full and "risk_band" in full and full["asset_count"] == 2
print("PASS: approved vendor immediately has a computed risk profile (assets/findings/score)")

# candidate is now marked approved, not pending, and doesn't reappear in pending list
r = client.get("/api/v1/vendors/candidates")
pending_names_after = {c["name"] for c in r.json()["items"]}
assert "HP" not in pending_names_after
r2 = client.get("/api/v1/vendors/candidates", params={"status": "approved"})
assert any(c["name"] == "HP" for c in r2.json()["items"])
print("PASS: approved candidate leaves the pending queue")

# double-approve is rejected
r = client.post(f"/api/v1/vendors/candidates/{hp['id']}/approve")
assert r.status_code == 400
print("PASS: approving an already-decided candidate is rejected")

# re-scanning doesn't re-suggest HP now that it's an active vendor (suggest_vendors
# already excludes existing vendor names/match_terms)
r = client.post("/api/v1/vendors/candidates/scan")
r2 = client.get("/api/v1/vendors/candidates")
assert "HP" not in {c["name"] for c in r2.json()["items"]}
print("PASS: an approved-and-created vendor doesn't get re-suggested as a candidate")

# --- deny Dell: goes to denied status, does NOT create a vendor ---
dell = next(c for c in pending if c["name"] == "Dell")
r = client.post(f"/api/v1/vendors/candidates/{dell['id']}/deny")
assert r.status_code == 200, r.text
r = client.get("/api/v1/vendors")
assert not any(v["name"] == "Dell" for v in r.json()["items"])
print("PASS: denying a candidate does not create a vendor")

# denial is remembered across future scans -- Dell must not resurface
r = client.post("/api/v1/vendors/candidates/scan")
r2 = client.get("/api/v1/vendors/candidates")
assert "Dell" not in {c["name"] for c in r2.json()["items"]}
r3 = client.get("/api/v1/vendors/candidates", params={"status": "denied"})
assert any(c["name"] == "Dell" for c in r3.json()["items"])
print("PASS: denial is remembered -- denied candidate never resurfaces on rescan")

# unknown candidate id
r = client.post("/api/v1/vendors/candidates/doesnotexist/approve")
assert r.status_code == 404
r = client.post("/api/v1/vendors/candidates/doesnotexist/deny")
assert r.status_code == 404
print("PASS: 404s for unknown candidate id")

# --- bulk approve / bulk deny ---
r = client.get("/api/v1/vendors/candidates")
remaining = r.json()["items"]
ms = next(c for c in remaining if c["name"] == "Microsoft")
others = [c for c in remaining if c["name"] != "Microsoft"]

r = client.post("/api/v1/vendors/candidates/bulk-approve", json={"ids": [ms["id"]]})
assert r.status_code == 200, r.text
bulk_result = r.json()
assert bulk_result["approved"] == 1
assert bulk_result["vendors"][0]["name"] == "Microsoft"
print("PASS: bulk-approve creates vendors for each id")

if others:
    r = client.post("/api/v1/vendors/candidates/bulk-deny", json={"ids": [c["id"] for c in others]})
    assert r.status_code == 200, r.text
    assert r.json()["denied"] == len(others)
    print("PASS: bulk-deny marks each id denied")

r = client.get("/api/v1/vendors/candidates")
assert r.json()["total"] == 0
print("PASS: pending queue empty after processing all candidates")

# --- audit log entries for candidate decisions ---
logs = run(db.activity_log.find({"entity_type": "vendor", "action": {"$in": ["vendor_candidate_approved", "vendor_candidate_denied"]}}).to_list(100))
assert len(logs) >= 3
print(f"PASS: audit log entries for candidate approve/deny ({len(logs)} entries)")

print("\nALL VENDOR CANDIDATE QUEUE TESTS PASSED")
