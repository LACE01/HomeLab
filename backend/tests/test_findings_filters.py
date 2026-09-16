"""Findings multi-select filtering: combine several facets and several values per
facet, filter by asset tags / device type / ease-of-exploitability, and page
through >100 results.

AND across facets, OR within a facet. Tags and device type resolve through the
asset. Pagination returns total so the UI can show 'page X of Y'.
"""
import os, sys, asyncio
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_findings_filters"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_findings_filters"]
db = db_module.db

import server, auth_utils
from routes import findings as findings_route
findings_route.db = db
from fastapi.testclient import TestClient
admin = {"id": "u1", "email": "a@x.com", "role": "admin", "name": "A", "teams": [], "team": None}
server.app.dependency_overrides[auth_utils.get_current_user] = lambda: admin
client = TestClient(server.app)
run = lambda c: asyncio.get_event_loop().run_until_complete(c)
def a(c, m=""): assert c, m


# assets: a server (tagged pci) and a workstation (tagged corp)
run(db.assets.insert_many([
    {"id": "srv1", "hostname": "srv1", "asset_type": "server", "tags": ["pci", "prod"]},
    {"id": "ws1", "hostname": "ws1", "asset_type": "workstation", "tags": ["corp"]},
]))
# findings
run(db.findings.insert_many([
    {"id": "f1", "title": "OpenSSL RCE", "severity": "Critical", "status": "New", "asset_id": "srv1",
     "kev_flag": True, "internet_facing": True, "rti": ["public_exploit"], "epss_score": 0.9, "risk_score": 90},
    {"id": "f2", "title": "Apache path", "severity": "High", "status": "New", "asset_id": "srv1",
     "kev_flag": False, "internet_facing": True, "rti": [], "epss_score": 0.1, "risk_score": 70},
    {"id": "f3", "title": "Local priv-esc", "severity": "Critical", "status": "New", "asset_id": "ws1",
     "kev_flag": False, "internet_facing": False, "rti": ["active_attacks"], "epss_score": 0.2, "risk_score": 60},
    {"id": "f4", "title": "Info leak", "severity": "Low", "status": "Fixed validated", "asset_id": "ws1",
     "kev_flag": False, "internet_facing": False, "rti": [], "epss_score": 0.0, "risk_score": 10},
]))


def ids(params):
    r = client.get("/api/v1/findings", params=params)
    a(r.status_code == 200, r.text)
    return {i["id"] for i in r.json()["items"]}, r.json()["total"]


# ---- multiple severities (OR within the facet) ----
got, total = ids([("severity", "Critical"), ("severity", "High")])
a(got == {"f1", "f2", "f3"} and total == 3, got)
print("PASS: multi-select severity (Critical OR High) returns all matching findings")

# ---- severity AND internet_facing (AND across facets) ----
got, _ = ids([("severity", "Critical"), ("internet_facing", "true")])
a(got == {"f1"}, got)
print("PASS: facets combine with AND — Critical AND internet-facing narrows to one")

# ---- filter by asset tag (resolved via the asset) ----
got, _ = ids([("tags", "pci")])
a(got == {"f1", "f2"}, got)
print("PASS: filtering by asset tag 'pci' returns only findings on the pci-tagged asset")

# ---- filter by device type = server ----
got, _ = ids([("asset_type", "server")])
a(got == {"f1", "f2"}, got)
print("PASS: filtering by device type 'server' returns only findings on servers")

# ---- ease of exploitability: KEV OR active_attacks OR public_exploit ----
got, _ = ids([("exploitability", "kev"), ("exploitability", "active_attacks")])
a(got == {"f1", "f3"}, got)
print("PASS: exploitability facet ORs its signals (KEV f1 + active_attacks f3)")

got, _ = ids([("exploitability", "epss_high")])
a(got == {"f1"}, got)
print("PASS: exploitability 'epss_high' selects findings with EPSS ≥ 0.5")

# ---- the big combo the user described: KEV + internet-facing + server + pci tag ----
got, _ = ids([("exploitability", "kev"), ("internet_facing", "true"),
              ("asset_type", "server"), ("tags", "pci")])
a(got == {"f1"}, got)
print("PASS: many facets at once (KEV + internet-facing + server + pci) narrow to exactly one finding")

# ---- a filter matching no asset returns nothing (not everything) ----
got, total = ids([("tags", "does-not-exist")])
a(got == set() and total == 0, (got, total))
print("PASS: a tag that matches no asset returns zero findings, not the whole list")

# ---- pagination: >100 results page through with a correct total ----
run(db.findings.insert_many([
    {"id": f"p{i}", "title": f"pad {i}", "severity": "Medium", "status": "New",
     "asset_id": "srv1", "risk_score": 50} for i in range(130)]))
r1 = client.get("/api/v1/findings", params={"severity": "Medium", "limit": 100, "offset": 0}).json()
r2 = client.get("/api/v1/findings", params={"severity": "Medium", "limit": 100, "offset": 100}).json()
a(r1["total"] == 130 and len(r1["items"]) == 100 and len(r2["items"]) == 30, (r1["total"], len(r2["items"])))
a({i["id"] for i in r1["items"]}.isdisjoint({i["id"] for i in r2["items"]}), "pages must not overlap")
print("PASS: 130 results page cleanly (100 + 30) with total=130 for 'page X of Y'")

# ---- facet option lists for the UI ----
stats = client.get("/api/v1/findings/stats").json()
a("pci" in stats["available_tags"] and "server" in stats["available_asset_types"])
print("PASS: /findings/stats exposes available_tags + available_asset_types for the filter dropdowns")

server.app.dependency_overrides.clear()
print("\nALL FINDINGS FILTER TESTS PASSED")
