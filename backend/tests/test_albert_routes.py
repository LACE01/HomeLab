# NOTE: this test depends on a real Albert (CIS/MS-ISAC) export file from a
# specific local session upload, which is intentionally NOT committed to the repo
# (it's a real org's exported network telemetry, not synthetic fixture data).
# It will fail with FileNotFoundError in a clean checkout / CI -- kept here for
# local reference only. The same ingestion/dedup/severity/stats logic is covered
# with synthetic data by test_albert_gaps2.py, test_albert_ports.py, and
# test_asset_albert_link.py, which ARE part of the CI suite.
import os, sys, io
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_albert_routes"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_albert_routes"]

import server
import auth_utils
from routes import albert as albert_route
albert_route.db = db_module.db

from fastapi.testclient import TestClient

admin_user = {"id": "u1", "email": "admin@x.com", "role": "admin", "name": "Admin", "teams": []}
app = server.app
app.dependency_overrides[auth_utils.get_current_user] = lambda: admin_user
client = TestClient(app)

with open("/sessions/youthful-dazzling-pasteur/mnt/uploads/EagleCo_Albert_Allowlist_Alert_Report-2026-07-14T13_02_35 (1).xlsx", "rb") as f:
    content = f.read()

# non-xlsx rejected
r = client.post("/api/v1/admin/albert/upload", files={"file": ("test.txt", b"hello", "text/plain")})
assert r.status_code == 400, r.text
print("PASS: rejects non-xlsx")

# real upload
r = client.post("/api/v1/admin/albert/upload", files={"file": ("EagleCo_Albert_Allowlist_Alert_Report.xlsx", content, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")})
assert r.status_code == 200, r.text
data = r.json()
print("upload result:", data)
assert data["rows_parsed"] == 588
assert data["duplicates_merged"] == 366

r = client.get("/api/v1/admin/albert/imports")
assert r.status_code == 200
assert len(r.json()) == 1
print("PASS: imports list")

r = client.get("/api/v1/admin/albert/stats", params={"days": 30})
assert r.status_code == 200
stats = r.json()
assert stats["total_alerts"] == 588
print("PASS: stats endpoint", {k: stats[k] for k in ("total_alerts", "severity_counts")})

r = client.get("/api/v1/admin/albert/alerts", params={"q": "PowerShell", "page_size": 5})
assert r.status_code == 200
alerts = r.json()
assert alerts["total"] > 0
print("PASS: alerts search, total=", alerts["total"])

alert_id = alerts["items"][0]["id"]
r = client.get(f"/api/v1/admin/albert/alerts/{alert_id}")
assert r.status_code == 200
assert r.json()["id"] == alert_id
print("PASS: alert detail")

r = client.get("/api/v1/admin/albert/alerts/nonexistent-id")
assert r.status_code == 404
print("PASS: 404 on unknown alert id")

# RBAC: analyst without module access should be blocked
analyst_user = {"id": "u2", "email": "analyst@x.com", "role": "analyst", "name": "Analyst", "teams": []}
app.dependency_overrides[auth_utils.get_current_user] = lambda: analyst_user
r = client.get("/api/v1/admin/albert/stats")
print("analyst stats status:", r.status_code, r.json())
# analyst default access is "edit" on everything not admin-only (per rbac.py _default_access),
# and /admin/albert isn't in _ADMIN_ONLY_BY_DEFAULT, so this should actually succeed
assert r.status_code == 200, r.text
print("PASS: analyst has default access (module not admin-only-by-default)")

print("ALL ALBERT ROUTE TESTS PASSED")

app.dependency_overrides[auth_utils.get_current_user] = lambda: admin_user
r = client.get("/api/v1/admin/albert/signatures", params={"days": 90})
assert r.status_code == 200, r.text
sigs = r.json()
print("signatures count:", len(sigs))
for s in sigs:
    print(" -", s["severity"], s["category"], s["count"], "|", s["alert_message"][:60])
assert len(sigs) == 8, len(sigs)
assert sigs[0]["severity"] in ("Critical", "High")
print("PASS: signatures endpoint")
print("ALL EXTENDED ALBERT TESTS PASSED")

# exact alert_message filter (drill-down from signature card)
r = client.get("/api/v1/admin/albert/alerts", params={"alert_message": "Unsupported/Fake FireFox Version 1."})
assert r.status_code == 200, r.text
exact = r.json()
print("exact alert_message filter total:", exact["total"])
assert exact["total"] == 36
assert all(a["alert_message"] == "Unsupported/Fake FireFox Version 1." for a in exact["items"])
print("PASS: exact alert_message filter")
