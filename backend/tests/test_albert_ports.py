import os, sys, asyncio
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_albert_ports"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_albert_ports"]

import server
import auth_utils
from routes import albert as albert_route
albert_route.db = db_module.db

from fastapi.testclient import TestClient

admin_user = {"id": "u1", "email": "admin@x.com", "role": "admin", "name": "Admin", "teams": []}
app = server.app
app.dependency_overrides[auth_utils.get_current_user] = lambda: admin_user
client = TestClient(app)

db = db_module.db


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


import albert_ingest

# Real-world-shaped rows: mixed int/float/str port representations, the way
# different Excel cell formats and openpyxl can hand them back.
run(db.albert_alerts.insert_many([
    {"id": "a1", "time_gmt": "2026-07-20T00:00:00+00:00", "device": "s1", "severity": "High",
     "category": "Lateral Movement", "source_ip": "10.0.0.5", "destination_ip": "10.0.0.9",
     "source_port": 58357, "destination_port": 445, "suppressed": False},
    {"id": "a2", "time_gmt": "2026-07-20T00:01:00+00:00", "device": "s1", "severity": "High",
     "category": "Lateral Movement", "source_ip": "10.0.0.6", "destination_ip": "10.0.0.9",
     "source_port": 57968, "destination_port": 445, "suppressed": False},
    {"id": "a3", "time_gmt": "2026-07-20T00:02:00+00:00", "device": "s1", "severity": "Low",
     "category": "External IP Lookup", "source_ip": "10.0.0.6", "destination_ip": "8.8.8.8",
     "source_port": 51000.0, "destination_port": "443", "suppressed": False},
    {"id": "a4", "time_gmt": "2026-07-20T00:03:00+00:00", "device": "s2", "severity": "Low",
     "category": "External IP Lookup", "source_ip": "10.0.0.7", "destination_ip": "8.8.4.4",
     "source_port": None, "destination_port": 443, "suppressed": False},
]))

stats = run(albert_ingest.compute_albert_stats(db, days=30))
top_src = {p["value"]: p["count"] for p in stats["top_source_ports"]}
top_dst = {p["value"]: p["count"] for p in stats["top_destination_ports"]}

assert top_dst.get("445") == 2, stats["top_destination_ports"]
assert top_dst.get("443") == 2, stats["top_destination_ports"]  # int 443 + str "443" merge into one key
print("PASS: top_destination_ports aggregates correctly, merging int/str representations of the same port")

assert top_src.get("58357") == 1 and top_src.get("57968") == 1 and top_src.get("51000") == 1
print("PASS: top_source_ports aggregates correctly, normalizing a float port (51000.0) to '51000'")

assert sum(top_src.values()) == 3  # a4's None source_port correctly excluded
print("PASS: a null/missing port doesn't get counted as a bogus entry")

# --- route-level exact port filtering (not the old regex-substring q param) ---
r = client.get("/api/v1/admin/albert/alerts", params={"destination_port": 445})
assert r.status_code == 200, r.text
body = r.json()
assert body["total"] == 2 and {a["id"] for a in body["items"]} == {"a1", "a2"}
print("PASS: GET /v1/admin/albert/alerts?destination_port=445 returns exact matches only")

r2 = client.get("/api/v1/admin/albert/alerts", params={"destination_port": "443"})
assert r2.status_code == 200, r2.text
body2 = r2.json()
assert body2["total"] == 2 and {a["id"] for a in body2["items"]} == {"a3", "a4"}
print("PASS: destination_port filter matches regardless of whether the port is stored as int or str")

r3 = client.get("/api/v1/admin/albert/alerts", params={"source_port": 58357})
assert r3.status_code == 200, r3.text
body3 = r3.json()
assert body3["total"] == 1 and body3["items"][0]["id"] == "a1"
print("PASS: source_port filter narrows to the exact port, not a substring/regex match")

# Note: the original version of this test also re-verified port aggregation against
# a real user-uploaded Albert export file. That's an ad-hoc local artifact (a specific
# user's upload from a specific session), not something that exists in the repo or a
# CI runner, so it's intentionally left out of the persisted/CI version of this test --
# the synthetic-data assertions above already cover the same aggregation logic.

print("\nALL ALBERT PORT STATS TESTS PASSED")
