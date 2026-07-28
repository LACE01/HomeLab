"""Regression tests for the July-2026 UI/bug-fix batch:
- Findings grouped view: the search box (q) now filters grouped results too,
  including QID lookups (previously silently ignored in grouped mode).
- Findings grouped view: honors owner_team deep links (Team Dashboard drills).
- Charts timeseries: an OPEN finding whose last_seen_at is stale (one-shot
  import sources never refresh it) still counts as present today, instead of
  silently vanishing from the per-host chart while the findings table shows it.
"""
import os, sys, asyncio, uuid
from datetime import datetime, timezone, timedelta
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_batch_ui_fixes"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_batch_ui_fixes"]

import server
import auth_utils
from routes import findings as findings_route
from routes import charts as charts_route
findings_route.db = db_module.db
charts_route.db = db_module.db

from fastapi.testclient import TestClient

admin_user = {"id": "u1", "email": "admin@x.com", "role": "admin", "name": "Admin", "teams": []}
app = server.app
app.dependency_overrides[auth_utils.get_current_user] = lambda: admin_user
client = TestClient(app)

db = db_module.db


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _now():
    return datetime.now(timezone.utc)


def _iso(dt):
    return dt.isoformat()


def _mk_finding(**over):
    doc = {
        "id": str(uuid.uuid4()), "title": "Test finding", "severity": "High", "status": "New",
        "cve": None, "qid": None, "cwe": None, "asset_id": None, "asset_hostname": "host-x",
        "asset_os": "Linux", "owner_team": None, "risk_score": 50, "source_tool": "Qualys",
        "first_seen_at": _iso(_now() - timedelta(days=10)),
        "last_seen_at": _iso(_now() - timedelta(days=1)),
        "detection_channel": "test",
    }
    doc.update(over)
    run(db.findings.insert_one(doc))
    return doc


# ============ grouped findings view: q + owner_team filters ============

run(db.findings.delete_many({}))
_mk_finding(title="OpenSSL vuln", qid="110123", cve="CVE-2023-1111", owner_team="NetOps")
_mk_finding(title="Apache vuln", qid="87654", cve="CVE-2023-2222", owner_team="AppSec")
_mk_finding(title="Kernel vuln", qid="110999", cve="CVE-2023-3333", owner_team="NetOps")

r = client.get("/api/v1/findings-groups", params={"group_by": "cve", "q": "110123"})
assert r.status_code == 200
groups = r.json()["groups"]
all_cves = {g["key"] for g in groups}
assert all_cves == {"CVE-2023-1111"}, f"QID search in grouped view should narrow to the one matching finding, got {all_cves}"
print("PASS: grouped Findings view now applies the q search (QID lookup narrows groups)")

r = client.get("/api/v1/findings-groups", params={"group_by": "cve", "q": "apache"})
assert {g["key"] for g in r.json()["groups"]} == {"CVE-2023-2222"}
print("PASS: grouped view q also matches title text, same fields as the flat list search")

r = client.get("/api/v1/findings-groups", params={"group_by": "cve", "owner_team": "NetOps"})
keys = {g["key"] for g in r.json()["groups"]}
assert keys == {"CVE-2023-1111", "CVE-2023-3333"}, keys
print("PASS: grouped view honors owner_team (Team Dashboard deep links no longer dropped)")

# ============ charts: open finding with stale last_seen_at still shows today ============

run(db.findings.delete_many({}))
# Open finding, one-shot import: first/last seen 200 days ago, never refreshed, still "New".
_mk_finding(
    title="Stale-but-open nmap finding", asset_id="asset-stale", source_tool="Nmap",
    first_seen_at=_iso(_now() - timedelta(days=200)),
    last_seen_at=_iso(_now() - timedelta(days=200)),
    status="New",
)
# Closed finding with the same stale window -- must NOT be resurrected to today.
_mk_finding(
    title="Old fixed finding", asset_id="asset-stale", source_tool="Nmap",
    first_seen_at=_iso(_now() - timedelta(days=200)),
    last_seen_at=_iso(_now() - timedelta(days=190)),
    status="Fixed validated",
)

r = client.get("/api/v1/charts/findings-timeseries", params={"days": 90, "group_by": "status", "asset_id": "asset-stale"})
assert r.status_code == 200
data = r.json()
assert data["total"] >= 1, "open finding with stale last_seen_at must still appear in the 90-day window"
today = _now().date().isoformat()
today_point = next((p for p in data["series"] if p["date"] == today), None)
assert today_point is not None
assert today_point.get("New", 0) == 1, f"open finding should count as present today, got {today_point}"
assert today_point.get("Fixed validated", 0) == 0, f"closed finding must keep its historical window, got {today_point}"
print("PASS: charts timeseries counts stale-last_seen OPEN findings as present today, without resurrecting closed ones")
