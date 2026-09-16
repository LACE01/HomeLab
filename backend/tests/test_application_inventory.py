"""#54 Software/SaaS Application Inventory.

Auto-populated from EDR/Qualys installed software, SBOM components, and completed
Security Reviews. The headline inference is shadow IT: something DISCOVERED on
endpoints that never went through a Security Review. These tests cover the
aggregation, the review-matching (by name and by vendor), the shadow-IT flag, and
that SBOM libraries don't get mis-flagged as shadow IT.
"""
import os, sys, asyncio
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_app_inventory"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_app_inventory"]
db = db_module.db

import application_inventory as ai
run = lambda c: asyncio.get_event_loop().run_until_complete(c)
def a(c, m=""): assert c, m


# ---- sources ----
# EDR installed software across two hosts (Chrome on both; a rogue app on one)
run(db.software_inventory.insert_many([
    {"source": "defender_device", "asset_id": "h1", "vendor": "Google", "name": "Google Chrome", "version": "120"},
    {"source": "defender_device", "asset_id": "h2", "vendor": "Google", "name": "Google Chrome", "version": "121"},
    {"source": "qualys_device", "asset_id": "h3", "vendor": "Rogue Ltd", "name": "uTorrent", "version": "3.5"},
    {"source": "defender_org", "asset_id": None, "vendor": "Acme", "name": "Acme SaaS Agent"},
]))
# a completed Security Review created a reviewed entity for Acme (matches by name)
# and one for the vendor "Google" (matches Chrome by vendor)
run(db.reviewed_entities.insert_many([
    {"id": "e1", "name": "Acme SaaS Agent", "type": "saas", "current_rating": "Medium", "last_review_id": "SR-1"},
    {"id": "e2", "name": "Google", "type": "vendor", "current_rating": "Low", "last_review_id": "SR-2"},
]))
# an SBOM dependency (a library) -- must NOT be shadow IT
run(db.findings.insert_one({
    "id": "f1", "source_tool_type": "Software Composition Analysis",
    "component_name": "log4j-core", "component_ecosystem": "maven", "component_version": "2.14.1"}))

res = run(ai.rebuild_inventory(db))
a(res["applications"] >= 4, res)
print(f"PASS: inventory rebuilt from EDR + SBOM + reviews ({res['applications']} apps, "
      f"sources {res['by_source']})")


def _get(name):
    return run(db.application_inventory.find_one({"key": name.lower()}, {"_id": 0}))


# ---- install_count aggregates distinct hosts ----
chrome = _get("Google Chrome")
a(chrome["install_count"] == 2 and set(chrome["hosts"]) == {"h1", "h2"}, chrome)
a("120" in chrome["versions"] and "121" in chrome["versions"])
print("PASS: an app seen on multiple hosts aggregates to one entry with install_count = distinct hosts")


# ---- review matching: by name (Acme) and by vendor (Chrome via 'Google') ----
acme = _get("Acme SaaS Agent")
a(acme["reviewed"] is True and acme["review_rating"] == "Medium" and acme["shadow_it"] is False)
a(chrome["reviewed"] is True and chrome["review_rating"] == "Low",
  "Chrome should match the reviewed VENDOR 'Google'")
a(chrome["shadow_it"] is False, "a reviewed app is not shadow IT")
print("PASS: discovered apps are linked to a completed review by name (Acme) or by vendor (Chrome→Google) "
      "and are not shadow IT")


# ---- shadow IT: uTorrent is on an endpoint but never reviewed ----
ut = _get("uTorrent")
a(ut["shadow_it"] is True and ut["reviewed"] is False, ut)
a(ut["category"] == "installed_software")
print("PASS: uTorrent — discovered on an endpoint, never reviewed — is flagged as shadow IT")


# ---- SBOM dependency is NOT shadow IT (it's a library, not installed app/SaaS) ----
log4j = _get("log4j-core")
a(log4j["category"] == "dependency" and log4j["shadow_it"] is False,
  "an SBOM library must not be flagged shadow IT")
a("sbom" in log4j["sources"])
print("PASS: SBOM dependencies are inventoried as libraries and never mis-flagged as shadow IT")


# ---- Google Workspace is a pluggable, not-configured source (no fabricated data) ----
a(res["google_workspace"]["configured"] is False)
print("PASS: Google Workspace is reported as a not-configured pluggable source — no fabricated apps")


# ---- rebuild is idempotent (re-run doesn't duplicate) ----
res2 = run(ai.rebuild_inventory(db))
a(res2["applications"] == res["applications"], "rebuild must be idempotent, not additive")
print("PASS: rebuild replaces the inventory rather than duplicating it")


# ---- stats + route-level list/detail ----
st = run(ai.stats(db))
a(st["total"] == res["applications"] and st["shadow_it"] >= 1)
import server, auth_utils
from routes import application_inventory as ai_route
ai_route.db = db
from fastapi.testclient import TestClient
admin = {"id": "u1", "email": "a@x.com", "role": "admin", "name": "A", "teams": []}
server.app.dependency_overrides[auth_utils.get_current_user] = lambda: admin
client = TestClient(server.app)

r = client.get("/api/v1/app-inventory", params={"shadow_it": "true"})
a(r.status_code == 200, r.text)
a(any(i["name"] == "uTorrent" for i in r.json()["items"]), "shadow_it filter should return uTorrent")
print("PASS: GET /v1/app-inventory?shadow_it=true returns the unsanctioned apps")

run(db.assets.insert_one({"id": "h1", "hostname": "ws-1", "ip": "10.0.0.1"}))
detail = client.get(f"/api/v1/app-inventory/{chrome['id']}").json()
a(any(h["hostname"] == "ws-1" for h in detail.get("host_details", [])),
  "detail should hydrate host hostnames for the IR 'which hosts run this' use-case")
print("PASS: the detail endpoint hydrates host hostnames — answering 'which hosts run this app' for IR")

server.app.dependency_overrides.clear()
print("\nALL APPLICATION INVENTORY TESTS PASSED")
