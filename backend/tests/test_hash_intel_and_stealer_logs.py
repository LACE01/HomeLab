import os, sys, asyncio, json
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_hash_intel"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_hash_intel"]

import server
import auth_utils
from routes import admin as admin_route
admin_route.db = db_module.db
from routes import yara as yara_route
yara_route.db = db_module.db

from fastapi.testclient import TestClient
import httpx

admin_user = {"id": "u1", "email": "admin@x.com", "role": "admin", "name": "Admin", "teams": []}
app = server.app
app.dependency_overrides[auth_utils.get_current_user] = lambda: admin_user
client = TestClient(app)

db = db_module.db


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


class FakeResponse:
    def __init__(self, status_code, json_data=None, text=""):
        self.status_code = status_code
        self._json = json_data or {}
        self.text = text

    def json(self):
        return self._json


class FakeAsyncClient:
    # queue of responses popped in call order, keyed loosely by call count
    queue = []

    def __init__(self, *a, **kw):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url, **kw):
        return FakeAsyncClient.queue.pop(0)

    async def post(self, url, **kw):
        return FakeAsyncClient.queue.pop(0)


_real = httpx.AsyncClient
httpx.AsyncClient = FakeAsyncClient

# ============ hash_intel.py ============
run(db.integrations.insert_one({"id": "vt1", "name": "VirusTotal", "config": {"api_key": "vt-key"}}))

import hash_intel

# --- malicious hit ---
FakeAsyncClient.queue = [FakeResponse(200, {
    "data": {"attributes": {"last_analysis_stats": {"malicious": 12, "suspicious": 2, "harmless": 40, "undetected": 5},
                             "meaningful_name": "evil.exe"}}
})]
doc = run(hash_intel.check_hash_virustotal(db, "a" * 64, entity_type="file", entity_id="f1", entity_label="evil.exe"))
assert doc["status"] == "malicious", doc
print("PASS: check_hash_virustotal records a malicious VT hit")

watch = run(db.ioc_watchlist.find_one({"value": "a" * 64}, {"_id": 0}))
assert watch is not None and watch["source"] == "virustotal_auto" and watch["ioc_type"] == "hash"
print("PASS: a malicious hit is auto-added to the IOC watchlist so future encounters are caught locally")

events = run(db.security_events.find({"event_type": "hash_reputation_hit"}, {"_id": 0}).to_list(10))
assert len(events) == 1
print("PASS: a security event is emitted for the malicious hash hit")

# --- clean hit (no rows) ---
FakeAsyncClient.queue = [FakeResponse(200, {
    "data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 60, "undetected": 3}}}
})]
doc2 = run(hash_intel.check_hash_virustotal(db, "b" * 64))
assert doc2["status"] == "clean"
print("PASS: a clean VT result is recorded as clean, no watchlist entry created")

clean_watch = run(db.ioc_watchlist.find_one({"value": "b" * 64}))
assert clean_watch is None
print("PASS: a clean hash does NOT get added to the watchlist")

# --- not configured ---
run(db.integrations.delete_many({"name": "VirusTotal"}))
doc3 = run(hash_intel.check_hash_virustotal(db, "c" * 64))
assert doc3["status"] == "not_configured"
print("PASS: check_hash_virustotal degrades to 'not_configured' instead of raising when VT isn't set up")

run(db.integrations.insert_one({"id": "vt1", "name": "VirusTotal", "config": {"api_key": "vt-key"}}))

# --- get_hash_check ---
fetched = run(hash_intel.get_hash_check(db, "a" * 64))
assert fetched is not None and fetched["status"] == "malicious"
print("PASS: get_hash_check retrieves a stored result")

# --- auto_check_hash_backlog ---
run(db.yara_scan_history.insert_many([
    {"filename": "one.exe", "sha256": "d" * 64, "asset_id": None, "asset_hostname": None, "scanned_at": "2026-07-20T00:00:00+00:00"},
    {"filename": "two.exe", "sha256": "e" * 64, "asset_id": None, "asset_hostname": None, "scanned_at": "2026-07-19T00:00:00+00:00"},
    {"filename": "already-done.exe", "sha256": "a" * 64, "asset_id": None, "asset_hostname": None, "scanned_at": "2026-07-18T00:00:00+00:00"},
]))
FakeAsyncClient.queue = [
    FakeResponse(200, {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0}}}}),
    FakeResponse(200, {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0}}}}),
]
import time
t0 = time.time()
backlog = run(hash_intel.auto_check_hash_backlog(db, max_checks=5))
elapsed = time.time() - t0
assert backlog["checked"] == 2  # d... and e... are new; a... already has a hash_intel_checks doc
print(f"PASS: auto_check_hash_backlog only checks hashes without an existing result ({backlog['checked']} checked, 'a...' correctly skipped)")

# ============ hibp_domain.py stealer logs ============
run(db.integrations.update_one({"name": "HaveIBeenPwned"}, {"$set": {
    "name": "HaveIBeenPwned", "config": {"api_key": "hibp-key", "domain": "eaglecounty-example.gov"}
}}, upsert=True))

import hibp_domain

FakeAsyncClient.queue = [FakeResponse(200, {"jsmith": ["netflix.com", "spotify.com"], "abrown": ["linkedin.com"]})]
result = run(hibp_domain.sync_hibp_stealer_logs(db))
assert result["stealer_log_accounts_found"] == 2, result
assert result["domain"] == "eaglecounty-example.gov"
print("PASS: sync_hibp_stealer_logs parses a real hit response and reports account count")

findings = run(db.osint_findings.find({"module": "hibp_stealer_logs"}, {"_id": 0}).to_list(10))
assert len(findings) == 2
assert any("netflix.com" in f["detail"] for f in findings)
print("PASS: stealer log hits are ingested as osint_findings with the affected sites in the detail")

# --- 404 = no hits (not an error) ---
FakeAsyncClient.queue = [FakeResponse(404)]
result2 = run(hibp_domain.sync_hibp_stealer_logs(db))
assert result2["stealer_log_accounts_found"] == 0
print("PASS: a 404 (zero stealer-log hits) is treated as a clean result, not an error")

# --- 403 = not verified / subscription tier doesn't include stealer logs ---
FakeAsyncClient.queue = [FakeResponse(403, text="Forbidden")]
try:
    run(hibp_domain.sync_hibp_stealer_logs(db))
    assert False, "should have raised"
except RuntimeError as e:
    assert "subscription tier" in str(e) or "verified" in str(e)
print("PASS: a 403 raises a clear, actionable error distinguishing verification vs. subscription tier")

# --- not configured ---
run(db.integrations.delete_many({"name": "HaveIBeenPwned"}))
try:
    run(hibp_domain.sync_hibp_stealer_logs(db))
    assert False, "should have raised"
except RuntimeError as e:
    assert "isn't configured" in str(e)
print("PASS: sync_hibp_stealer_logs raises a clear error when HaveIBeenPwned isn't configured")

# ============ admin routes ============
run(db.integrations.insert_one({"id": "vt2", "name": "VirusTotal", "config": {"api_key": "vt-key"}}))
r = client.get("/api/v1/admin/hash-intel/status")
assert r.status_code == 200, r.text
body = r.json()
assert body["hashes_checked"] >= 4 and body["malicious_hits"] == 1
print("PASS: GET /v1/admin/hash-intel/status reports aggregate counts")

httpx.AsyncClient = _real
print("\nALL HASH INTEL + STEALER LOG TESTS PASSED")
