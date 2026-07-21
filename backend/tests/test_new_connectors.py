import os, sys, asyncio
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_new_connectors"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_new_connectors"]

import server
import auth_utils
from routes import integrations as integrations_route
from routes import directory as directory_route
from routes import inventory as inventory_route
integrations_route.db = db_module.db
directory_route.db = db_module.db
inventory_route.db = db_module.db

from fastapi.testclient import TestClient
import httpx

admin_user = {"id": "u1", "email": "admin@x.com", "role": "admin", "name": "Admin", "teams": []}
app = server.app
app.dependency_overrides[auth_utils.get_current_user] = lambda: admin_user
client = TestClient(app)

db = db_module.db


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ---------------- Fake httpx.AsyncClient (queue-based) ----------------
class FakeResponse:
    def __init__(self, status_code, json_data=None, text=""):
        self.status_code = status_code
        self._json = json_data if json_data is not None else {}
        self.text = text if text else str(json_data or "")

    def json(self):
        return self._json


class FakeAsyncClient:
    queue = []  # list of FakeResponse, consumed in call order (get or post)

    def __init__(self, *a, **kw):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url, **kw):
        assert FakeAsyncClient.queue, f"FakeAsyncClient.queue exhausted on GET {url}"
        return FakeAsyncClient.queue.pop(0)

    async def post(self, url, **kw):
        assert FakeAsyncClient.queue, f"FakeAsyncClient.queue exhausted on POST {url}"
        return FakeAsyncClient.queue.pop(0)


_real_async_client = httpx.AsyncClient
httpx.AsyncClient = FakeAsyncClient


def seed_queue(*responses):
    FakeAsyncClient.queue = list(responses)


# =====================================================================
# 1) VirusTotal
# =====================================================================
run(db.integrations.insert_one({
    "id": "vt1", "name": "VirusTotal", "type": "threat_intel", "status": "healthy",
    "config": {"endpoint": "https://www.virustotal.com/api/v3", "api_key": "vtkey"},
}))

import reconng

seed_queue(FakeResponse(200, {"data": {"attributes": {
    "meaningful_name": "evil.example", "reputation": -12,
    "last_analysis_stats": {"malicious": 5, "suspicious": 2, "harmless": 60, "undetected": 10},
}}}))
rows = run(reconng.run_virustotal_lookup("evil.example", "domain"))
assert len(rows) == 1 and "5 malicious" in rows[0]["name"], rows
print("PASS: VirusTotal domain lookup with detections returns a row")

seed_queue(FakeResponse(200, {"data": {"attributes": {
    "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 5},
}}}))
rows = run(reconng.run_virustotal_lookup("clean.example", "domain"))
assert rows == []
print("PASS: VirusTotal clean result returns no rows (doesn't manufacture noise)")

seed_queue(FakeResponse(401, text="bad key"))
try:
    run(reconng.run_virustotal_lookup("x.example", "domain"))
    assert False, "expected RuntimeError"
except RuntimeError as e:
    assert "rejected" in str(e)
print("PASS: VirusTotal 401 raises a clear RuntimeError")

# via run_module dispatch end-to-end (checks MODULE_CATALOG wiring + osint ingestion)
seed_queue(FakeResponse(200, {"data": {"attributes": {
    "meaningful_name": "bad-ip", "last_analysis_stats": {"malicious": 3, "suspicious": 0, "harmless": 50, "undetected": 5},
}}}))
result = run(reconng.run_module(db, "vt_ip", "6.6.6.6"))
assert result["osint_findings_created"] == 1, result
found = run(db.osint_findings.find_one({"target": "6.6.6.6"}))
assert found and "VirusTotal" in found["label"]
print("PASS: vt_ip module dispatch ingests into osint_findings")


# =====================================================================
# 2) HaveIBeenPwned -- per-email lookup (reconng) + domain-wide sync (hibp_domain)
# =====================================================================
run(db.integrations.insert_one({
    "id": "hibp1", "name": "HaveIBeenPwned", "type": "threat_intel", "status": "healthy",
    "config": {"endpoint": "https://haveibeenpwned.com/api/v3", "api_key": "hibpkey", "domain": "example.com"},
}))

seed_queue(FakeResponse(200, [{"Name": "Adobe"}, {"Name": "Gawker"}]))
rows = run(reconng.run_hibp_lookup("alice@example.com", "breach"))
assert len(rows) == 1 and "Adobe" in rows[0]["detail"]
print("PASS: HIBP per-email breach lookup returns a row with breach names")

seed_queue(FakeResponse(404))
rows = run(reconng.run_hibp_lookup("clean@example.com", "breach"))
assert rows == []
print("PASS: HIBP per-email 404 (not found) returns no rows, not an error")

import hibp_domain

seed_queue(FakeResponse(200, {"alice": ["Adobe"], "bob": ["Adobe", "Gawker"]}))
result = run(hibp_domain.sync_hibp_domain_breaches(db))
assert result["breached_accounts_found"] == 2
assert result["osint_findings_created"] == 2, result
print("PASS: HIBP domain-wide sync ingests every breached alias as an osint finding")

# re-running with the SAME data should not re-create findings (label-based dedup key
# stable when the breach set for an alias hasn't changed)
seed_queue(FakeResponse(200, {"alice": ["Adobe"], "bob": ["Adobe", "Gawker"]}))
result2 = run(hibp_domain.sync_hibp_domain_breaches(db))
assert result2["osint_findings_created"] == 0, result2
print("PASS: HIBP domain-wide sync dedups unchanged breach sets on re-run")

# bob shows up in a NEW breach -- should be treated as a new, separately-alertable finding
seed_queue(FakeResponse(200, {"alice": ["Adobe"], "bob": ["Adobe", "Gawker", "Collection1"]}))
result3 = run(hibp_domain.sync_hibp_domain_breaches(db))
assert result3["osint_findings_created"] == 1, result3
print("PASS: a NEW breach for an already-seen alias is treated as a new finding")

seed_queue(FakeResponse(403, text="domain not verified"))
try:
    run(hibp_domain.sync_hibp_domain_breaches(db))
    assert False
except RuntimeError as e:
    assert "hasn't been verified" in str(e)
print("PASS: HIBP domain sync 403 gives a clear domain-verification error message")

run(db.integrations.update_one({"id": "hibp1"}, {"$set": {"config.domain": ""}}))
try:
    run(hibp_domain.sync_hibp_domain_breaches(db))
    assert False
except RuntimeError as e:
    assert "No domain set" in str(e)
print("PASS: HIBP domain sync with no domain configured gives a clear error")
run(db.integrations.update_one({"id": "hibp1"}, {"$set": {"config.domain": "example.com"}}))


# =====================================================================
# 3) msgraph.py -- token fetch, caching, pagination
# =====================================================================
run(db.integrations.insert_one({
    "id": "msgraph-probe", "name": "__msgraph_probe__", "type": "identity", "status": "not_configured",
    # Deliberately a DIFFERENT tenant/client than section 4's real "Microsoft Entra ID"
    # fixture below -- msgraph._TOKEN_CACHE is keyed by (tenant_id, client_id, scope),
    # so reusing the same tenant/client here would let this section's cached token
    # silently satisfy section 4's token fetch too, consuming one fewer queued fake
    # HTTP response than section 4 expects and shifting every subsequent queued
    # response by one (caught by an assertion failure the first time this test was
    # run against the real code, not a hypothetical -- keeping tenants distinct per
    # section avoids the whole class of bug).
    "config": {"endpoint": "https://graph.microsoft.com/v1.0", "tenant_id": "tenant-msgraph-probe",
               "client_id": "client-msgraph-probe", "client_secret": "secret-msgraph-probe"},
}))

import msgraph

seed_queue(FakeResponse(200, {"access_token": "tok-abc", "expires_in": 3600}))
tok = run(msgraph.get_client_credentials_token(db, "__msgraph_probe__", "https://graph.microsoft.com/.default"))
assert tok == "tok-abc"
print("PASS: msgraph token fetch returns access_token")

# second call within the queue being empty proves the cache was used, not a fresh POST
tok2 = run(msgraph.get_client_credentials_token(db, "__msgraph_probe__", "https://graph.microsoft.com/.default"))
assert tok2 == "tok-abc"
print("PASS: msgraph token is cached (no extra HTTP call needed)")

seed_queue(FakeResponse(200, {"access_token": "tok-refreshed", "expires_in": 3600}))
tok3 = run(msgraph.get_client_credentials_token(db, "__msgraph_probe__", "https://graph.microsoft.com/.default", force_refresh=True))
assert tok3 == "tok-refreshed"
print("PASS: force_refresh bypasses the cache and gets a new token")

no_creds_integration_name = "Microsoft Intune"
run(db.integrations.insert_one({"id": "intune-noconf", "name": no_creds_integration_name, "config": {}}))
try:
    run(msgraph.get_client_credentials_token(db, no_creds_integration_name, "https://graph.microsoft.com/.default"))
    assert False
except ValueError as e:
    assert "isn't configured" in str(e)
print("PASS: missing tenant/client credentials raises a clear ValueError")
run(db.integrations.delete_one({"id": "intune-noconf"}))

run(db.integrations.insert_one({
    "id": "defbad", "name": "__aadsts_test__",
    "config": {"tenant_id": "t", "client_id": "c", "client_secret": "bad"},
}))
seed_queue(FakeResponse(400, {"error": "invalid_client", "error_description": "AADSTS7000215: Invalid client secret"}))
try:
    run(msgraph.get_client_credentials_token(db, "__aadsts_test__", "https://graph.microsoft.com/.default"))
    assert False
except RuntimeError as e:
    assert "AADSTS7000215" in str(e)
print("PASS: Azure AD token rejection surfaces the real AADSTS error_description")
run(db.integrations.delete_one({"id": "defbad"}))

seed_queue(
    FakeResponse(200, {"value": [{"id": 1}, {"id": 2}], "@odata.nextLink": "https://graph.microsoft.com/v1.0/next"}),
    FakeResponse(200, {"value": [{"id": 3}]}),
)
items = run(msgraph.graph_get_paginated("tok-abc", "https://graph.microsoft.com/v1.0/users"))
assert [i["id"] for i in items] == [1, 2, 3]
print("PASS: graph_get_paginated follows @odata.nextLink across pages")


# =====================================================================
# 4) Entra ID directory sync
# =====================================================================
run(db.integrations.insert_one({
    "id": "entra1", "name": "Microsoft Entra ID", "type": "identity", "status": "not_configured",
    "config": {"endpoint": "https://graph.microsoft.com/v1.0", "tenant_id": "tenant-entra",
               "client_id": "client-entra", "client_secret": "secret-entra"},
}))

import entra_sync

seed_queue(
    FakeResponse(200, {"access_token": "tok-entra", "expires_in": 3600}),
    FakeResponse(200, {"value": [
        {"id": "u-active", "displayName": "Active User", "userPrincipalName": "active@example.com",
         "accountEnabled": True, "createdDateTime": "2020-01-01T00:00:00Z",
         "signInActivity": {"lastSignInDateTime": "2026-07-10T00:00:00Z"}},
        {"id": "u-stale", "displayName": "Stale User", "userPrincipalName": "stale@example.com",
         "accountEnabled": True, "createdDateTime": "2020-01-01T00:00:00Z",
         "signInActivity": {"lastSignInDateTime": "2020-02-01T00:00:00Z"}},
        {"id": "u-disabled", "displayName": "Disabled User", "userPrincipalName": "gone@example.com",
         "accountEnabled": False, "createdDateTime": "2019-01-01T00:00:00Z", "signInActivity": {}},
    ]}),
    FakeResponse(200, {"value": [
        {"id": "g1", "displayName": "IT Admins", "securityEnabled": True, "mailEnabled": False, "groupTypes": []},
    ]}),
)
result = run(entra_sync.sync_entra_directory(db))
assert result["users_synced"] == 3
assert result["stale_accounts"] == 1
assert result["disabled_accounts"] == 1
assert result["groups_synced"] == 1
print("PASS: Entra ID sync populates directory_users/directory_groups with correct stale/disabled counts")

stale_doc = run(db.directory_users.find_one({"id": "u-stale"}))
assert stale_doc["is_stale"] is True
active_doc = run(db.directory_users.find_one({"id": "u-active"}))
assert active_doc["is_stale"] is False
print("PASS: stale flag correctly distinguishes recently-signed-in vs. dormant accounts")


# =====================================================================
# 5) Defender for Endpoint sync -- devices + software inventory + vendor linkage
# =====================================================================
run(db.integrations.insert_one({
    "id": "defender1", "name": "Microsoft Defender for Endpoint", "type": "endpoint", "status": "not_configured",
    "config": {"endpoint": "https://api.security.microsoft.com", "tenant_id": "tenant-defender",
               "client_id": "client-defender", "client_secret": "secret-defender"},
}))
run(db.assets.insert_many([
    {"id": "a-ws01", "hostname": "ws-01.corp.local", "criticality": "medium"},
    {"id": "a-ws02", "hostname": "ws-02", "criticality": "low"},
]))

import defender_sync

seed_queue(
    FakeResponse(200, {"access_token": "tok-defender", "expires_in": 3600}),
    FakeResponse(200, {"value": [
        {"id": "dev-1", "computerDnsName": "ws-01.corp.local", "riskScore": "High", "exposureLevel": "Medium",
         "healthStatus": "Active", "osPlatform": "Windows10", "agentVersion": "1.2.3", "lastSeen": "2026-07-14T00:00:00Z"},
        {"id": "dev-2", "computerDnsName": "unmatched-host", "riskScore": "High", "exposureLevel": "High",
         "healthStatus": "Active", "osPlatform": "Windows11", "agentVersion": "1.2.3", "lastSeen": "2026-07-14T00:00:00Z"},
    ]}),
    FakeResponse(200, {"value": [
        {"id": "sw1", "vendor": "Adobe Inc.", "name": "Acrobat Reader DC", "exposedMachines": 5, "weaknesses": 2},
    ]}),
    FakeResponse(200, {"value": [
        {"id": "dev-1", "softwareVendor": "Adobe Inc.", "softwareName": "Acrobat Reader DC", "softwareVersion": "23.1"},
    ]}),
)
result = run(defender_sync.sync_defender(db))
assert result["devices_seen"] == 2
assert result["devices_matched_to_assets"] == 1
assert result["high_risk_devices"] == 2  # both dev-1 and dev-2 are High risk, matched or not
assert result["org_software_products_synced"] == 1
assert result["per_device_software_links_synced"] == 1
print("PASS: Defender sync matches devices by hostname and counts org-wide high-risk devices")

ws01 = run(db.assets.find_one({"id": "a-ws01"}))
assert ws01["defender_device_id"] == "dev-1"
assert ws01["defender_risk_score"] == "High"
print("PASS: matched asset gets Defender risk/exposure fields stamped on it")

org_sw = run(db.software_inventory.find_one({"source": "defender_org", "vendor": "Adobe Inc."}))
assert org_sw is not None
device_sw = run(db.software_inventory.find_one({"source": "defender_device", "asset_id": "a-ws01"}))
assert device_sw is not None and device_sw["name"] == "Acrobat Reader DC"
print("PASS: org-wide and per-device software_inventory rows are both persisted")

# vendor_management now sees a REAL software vendor, not just hardware/OS guesses
import vendor_management

suggestions = run(vendor_management.suggest_vendors(db))
edr_suggestion = next((s for s in suggestions if s["name"] == "Adobe Inc."), None)
assert edr_suggestion is not None, suggestions
assert edr_suggestion["source"] == "edr_software_inventory"
assert edr_suggestion["asset_count"] == 1
print("PASS: suggest_vendors() surfaces a real EDR-detected software vendor with correct asset_count")

fake_vendor = {"name": "Adobe Inc.", "match_terms": []}
linked, structural_ids = run(vendor_management._linked_assets(db, fake_vendor))
assert any(a["id"] == "a-ws01" for a in linked), linked
assert "a-ws01" in structural_ids  # EDR software linkage IS structural (whole asset runs it)
print("PASS: _linked_assets() picks up an asset via real software linkage, not just substring match")


# =====================================================================
# 6) Intune sync -- compliance/patch state + summary
# =====================================================================
run(db.integrations.insert_one({
    "id": "intune1", "name": "Microsoft Intune", "type": "mdm", "status": "not_configured",
    "config": {"endpoint": "https://graph.microsoft.com/v1.0", "tenant_id": "tenant-intune",
               "client_id": "client-intune", "client_secret": "secret-intune"},
}))

import intune_sync

seed_queue(
    FakeResponse(200, {"access_token": "tok-intune", "expires_in": 3600}),
    FakeResponse(200, {"value": [
        {"id": "idev-1", "deviceName": "ws-01", "operatingSystem": "Windows", "osVersion": "10.0.19045",
         "complianceState": "noncompliant", "managementState": "managed", "lastSyncDateTime": "2026-07-14T00:00:00Z",
         "isEncrypted": True, "userPrincipalName": "active@example.com"},
    ]}),
)
result = run(intune_sync.sync_intune(db))
assert result["devices_matched_to_assets"] == 1
assert result["noncompliant_devices"] == 1
print("PASS: Intune sync matches device by hostname and flags noncompliant state")

ws01_after = run(db.assets.find_one({"id": "a-ws01"}))
assert ws01_after["intune_compliance_state"] == "noncompliant"
print("PASS: matched asset gets Intune compliance fields stamped on it")

summary = run(intune_sync.get_patch_compliance_summary(db))
assert summary["total_managed"] == 1
assert summary["by_compliance_state"].get("noncompliant") == 1
assert summary["unmanaged"] == 1  # a-ws02 was never matched by either connector
print("PASS: patch compliance summary aggregates managed vs unmanaged assets correctly")


# =====================================================================
# 7) Routes: directory, patch-compliance, asset software, integrations masking/test
# =====================================================================
r = client.get("/api/v1/directory/users")
assert r.status_code == 200, r.text
data = r.json()
assert data["total"] == 3
print("PASS: GET /v1/directory/users")

r = client.get("/api/v1/directory/users", params={"stale_only": True})
assert r.json()["total"] == 1
print("PASS: GET /v1/directory/users?stale_only=true filters correctly")

r = client.get("/api/v1/directory/groups")
assert r.status_code == 200 and r.json()["total"] == 1
print("PASS: GET /v1/directory/groups")

r = client.get("/api/v1/directory/stats")
assert r.status_code == 200
stats = r.json()
assert stats["total_users"] == 3 and stats["stale_users"] == 1 and stats["disabled_users"] == 1
print("PASS: GET /v1/directory/stats")

r = client.get("/api/v1/patch-compliance/summary")
assert r.status_code == 200
assert r.json()["total_managed"] == 1
print("PASS: GET /v1/patch-compliance/summary")

r = client.get("/api/v1/assets/a-ws01/software")
assert r.status_code == 200
items = r.json()["items"]
assert len(items) == 1 and items[0]["vendor"] == "Adobe Inc."
print("PASS: GET /v1/assets/{id}/software returns per-device software inventory")

# integrations PATCH masking for the new fields (client_secret / tenant_id / domain)
r = client.patch("/api/v1/integrations/entra1", json={
    "tenant_id": "new-tenant", "client_id": "new-client", "client_secret": "super-secret-value",
})
assert r.status_code == 200, r.text
r2 = client.get("/api/v1/integrations")
item = next(i for i in r2.json()["items"] if i["id"] == "entra1")
assert item["config"]["tenant_id"] == "new-tenant"
assert item["config"]["client_secret"] == "•••"
print("PASS: PATCH persists tenant_id/client_id, masks client_secret in list responses")

# integrations Test endpoint for an MS Graph connector -- real token-fetch based check
seed_queue(FakeResponse(200, {"access_token": "tok-test", "expires_in": 3600}))
r = client.post("/api/v1/integrations/entra1/test")
assert r.status_code == 200, r.text
assert "authenticated successfully" in r.json()["message"]
print("PASS: Test endpoint for Microsoft Entra ID does a real token fetch, not just a reachability probe")

# Test endpoint with missing creds -> 400 (not the generic "missing endpoint/api_key" 400)
run(db.integrations.insert_one({"id": "intune-empty", "name": "Microsoft Intune", "config": {}}))
r = client.post("/api/v1/integrations/intune-empty/test")
assert r.status_code == 400
assert "tenant ID" in r.json()["detail"]
print("PASS: Test endpoint for an unconfigured MS Graph connector gives a tenant/client-specific 400")

# sync dispatch routing for HaveIBeenPwned via the generic /sync endpoint
seed_queue(FakeResponse(200, {"alice": ["Adobe"]}))
# alice/Adobe already exists from earlier in this test (unchanged), so this exercises
# the dedup path end-to-end through the actual HTTP route, not just the function.
r = client.post("/api/v1/integrations/hibp1/sync")
assert r.status_code == 200, r.text
print("PASS: POST /v1/integrations/{id}/sync correctly dispatches to HaveIBeenPwned's sync job")

httpx.AsyncClient = _real_async_client
print("\nALL NEW CONNECTOR TESTS PASSED")
