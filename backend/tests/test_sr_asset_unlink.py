"""#53 In-Scope Assets: removing an asset UNLINKS it from this review's scope
ONLY -- it never deletes the underlying host or its findings from inventory.

This is the guardrail that made the ticket worth being careful about: a trash
icon wired to delete the asset itself (and its findings history) would be
dangerous. These tests prove the unlink route touches only the review's
linked_asset_ids, and that per-row and bulk removal both work.
"""
import os, sys, asyncio
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_sr_asset_unlink"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_sr_asset_unlink"]

import server, auth_utils
from routes import security_reviews as sr_route
sr_route.db = db_module.db
from fastapi.testclient import TestClient

admin = {"id": "u1", "email": "admin@x.com", "role": "admin", "name": "Admin", "teams": [], "team": "SecOps"}
server.app.dependency_overrides[auth_utils.get_current_user] = lambda: admin
server.app.dependency_overrides[auth_utils.get_current_user_optional] = lambda: admin
client = TestClient(server.app)
db = db_module.db
run = lambda c: asyncio.get_event_loop().run_until_complete(c)
def a(c, m=""): assert c, m


# seed three assets, each with an open finding
run(db.assets.insert_many([
    {"id": "asset-1", "hostname": "web-1", "ip": "10.0.0.1", "status": "active"},
    {"id": "asset-2", "hostname": "web-2", "ip": "10.0.0.2", "status": "active"},
    {"id": "asset-3", "hostname": "db-1", "ip": "10.0.0.3", "status": "active"},
]))
run(db.findings.insert_many([
    {"id": "f1", "asset_id": "asset-1", "status": "New", "severity": "High"},
    {"id": "f2", "asset_id": "asset-2", "status": "New", "severity": "Critical"},
    {"id": "f3", "asset_id": "asset-3", "status": "New", "severity": "Low"},
]))

review = client.post("/api/v1/security-reviews", json={
    "title": "Scope test", "review_type": "New software purchase (SaaS / COTS / on-prem)",
    "entity_name": "Acme", "entity_domain": "acme.com", "data_classifications": ["PII (Colorado)"],
}).json()
rid = review["id"]

# link all three
r = client.post(f"/api/v1/security-reviews/{rid}/assets", json={"asset_ids": ["asset-1", "asset-2", "asset-3"]})
a(r.status_code == 200 and r.json()["linked_total"] == 3, r.text)
print("PASS: three assets linked into the review's scope")


# ============ per-row remove: unlinks ONE, leaves host + finding intact ============

r = client.post(f"/api/v1/security-reviews/{rid}/assets/unlink", json={"asset_ids": ["asset-1"]})
a(r.status_code == 200 and r.json()["linked_total"] == 2, r.text)
scope = client.get(f"/api/v1/security-reviews/{rid}/assets").json()
a({i["id"] for i in scope["items"]} == {"asset-2", "asset-3"}, "asset-1 was not removed from scope")
# THE guardrail: the host and its finding are STILL in inventory
a(run(db.assets.count_documents({"id": "asset-1"})) == 1, "unlink DELETED the host from inventory!")
a(run(db.findings.count_documents({"id": "f1"})) == 1, "unlink DELETED the host's finding history!")
print("PASS: per-row remove unlinks the asset from THIS review only — the host and its finding remain "
      "in inventory (the trash icon is not a destructive delete)")


# ============ bulk remove: unlinks several at once, inventory untouched ============

r = client.post(f"/api/v1/security-reviews/{rid}/assets/unlink", json={"asset_ids": ["asset-2", "asset-3"]})
a(r.status_code == 200 and r.json()["linked_total"] == 0, r.text)
scope = client.get(f"/api/v1/security-reviews/{rid}/assets").json()
a(scope["items"] == [], "bulk remove left assets in scope")
a(run(db.assets.count_documents({})) == 3, "bulk remove deleted hosts from inventory!")
a(run(db.findings.count_documents({})) == 3, "bulk remove deleted findings from inventory!")
print("PASS: bulk remove unlinks multiple assets in one call and inventory (all 3 hosts + 3 findings) "
      "is completely untouched")


# ============ the review row itself only stores the id list ============

doc = run(db.security_reviews.find_one({"id": rid}, {"_id": 0}))
a(doc["linked_asset_ids"] == [], "the review still references removed assets")
print("PASS: removal edits only the review's linked_asset_ids — scope membership, nothing else")

server.app.dependency_overrides.clear()
print("\nALL IN-SCOPE ASSET UNLINK TESTS PASSED")
