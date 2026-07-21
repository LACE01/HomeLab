import os, sys, asyncio
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_asset_albert_link"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_asset_albert_link"]

import server
import auth_utils
from routes import inventory as inv_route
inv_route.db = db_module.db

from fastapi.testclient import TestClient
admin_user = {"id": "u1", "email": "admin@x.com", "role": "admin", "name": "Admin", "teams": []}
app = server.app
app.dependency_overrides[auth_utils.get_current_user] = lambda: admin_user
client = TestClient(app)

db = db_module.db

def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)

run(db.assets.insert_many([
    {"id": "a1", "hostname": "ws-01", "ip": "10.0.0.5", "criticality": "medium"},
    {"id": "a2", "hostname": "ws-02", "ip": "10.0.0.9", "criticality": "medium"},
]))
run(db.albert_alerts.insert_many([
    {"id": "al1", "time_gmt": "2026-07-14T00:00:00+00:00", "device": "s1", "alert_message": "x",
     "severity": "High", "category": "Lateral Movement", "source_ip": "10.0.0.5", "destination_ip": "10.0.0.9",
     "source_asset_id_override": None, "destination_asset_id_override": None},
    {"id": "al2", "time_gmt": "2026-07-13T00:00:00+00:00", "device": "s1", "alert_message": "y",
     "severity": "Low", "category": "Other", "source_ip": "9.9.9.9", "destination_ip": "10.0.0.5",
     "source_asset_id_override": None, "destination_asset_id_override": None},
    # override says this belongs to a2 even though its source_ip matches a1's ip --
    # proves override precedence beats IP matching, same as routes/albert.py's
    # single-alert view.
    {"id": "al3", "time_gmt": "2026-07-12T00:00:00+00:00", "device": "s1", "alert_message": "z",
     "severity": "Medium", "category": "Other", "source_ip": "10.0.0.5", "destination_ip": "1.2.3.4",
     "source_asset_id_override": "a2", "destination_asset_id_override": None},
]))

r = client.get("/api/v1/assets/a1/albert-alerts")
assert r.status_code == 200, r.text
data = r.json()
assert data["total"] == 2
assert {i["id"] for i in data["items"]} == {"al1", "al2"}
assert data["severity_counts"] == {"High": 1, "Low": 1}
assert len(data["daily_trend"]) == 2
print("PASS: asset a1 resolves al1 (source match) + al2 (dest match), excludes al3 (overridden away)")

r2 = client.get("/api/v1/assets/a2/albert-alerts")
data2 = r2.json()
assert data2["total"] == 2
assert {i["id"] for i in data2["items"]} == {"al1", "al3"}
print("PASS: asset a2 resolves al1 (dest ip match) + al3 (override), confirming override precedence")

r3 = client.get("/api/v1/assets/doesnotexist/albert-alerts")
assert r3.status_code == 200
assert r3.json()["total"] == 0
print("PASS: unknown asset id returns empty result, not an error")

print("\nALL ASSET-ALBERT-LINK TESTS PASSED")
