import os, sys, asyncio, uuid
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_tenable_sync"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_tenable_sync"]

import server
import auth_utils
from routes import admin as admin_route
admin_route.db = db_module.db

from fastapi.testclient import TestClient

admin_user = {"id": "u1", "email": "admin@x.com", "role": "admin", "name": "Admin", "teams": []}
app = server.app
app.dependency_overrides[auth_utils.get_current_user] = lambda: admin_user
client = TestClient(app)

db = db_module.db


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


import tenable_sync as ts

ENDPOINT = "https://nessus.local:8834"

SCANS_RESPONSE = {
    "scans": [
        {"id": 10, "name": "Internal Network Scan", "status": "completed"},
        {"id": 11, "name": "Still Running Scan", "status": "running"},
    ]
}

SCAN_10_DETAILS = {
    "info": {"name": "Internal Network Scan"},
    "hosts": [{"host_id": 1, "hostname": "10.0.0.5"}],
}

HOST_1_VULNS = {
    "vulnerabilities": [
        {"plugin_id": 12345, "plugin_name": "OpenSSL Vuln (fallback name)", "plugin_family": "General", "severity": 3, "count": 1},
        {"plugin_id": 99999, "plugin_name": "Nessus Scan Information", "plugin_family": "Settings", "severity": 0, "count": 1},
    ]
}

PLUGIN_12345 = {
    "id": 12345, "name": "OpenSSL Multiple Vulnerabilities", "family_name": "General",
    "attributes": [
        {"attribute_name": "synopsis", "attribute_value": "The remote host has an outdated OpenSSL."},
        {"attribute_name": "description", "attribute_value": "A detailed description of the OpenSSL issue."},
        {"attribute_name": "solution", "attribute_value": "Upgrade to the latest OpenSSL version."},
        {"attribute_name": "cve", "attribute_value": "CVE-2023-1234"},
        {"attribute_name": "cvss3_base_score", "attribute_value": "7.5"},
        {"attribute_name": "cvss3_vector", "attribute_value": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    ],
}

PLUGIN_99999 = {
    "id": 99999, "name": "Nessus Scan Information", "family_name": "Settings",
    "attributes": [
        {"attribute_name": "synopsis", "attribute_value": "This plugin displays information about the scan."},
    ],
}


class FakeResponse:
    def __init__(self, json_data, status_code=200):
        self._json = json_data
        self.status_code = status_code
        self.text = str(json_data)[:200]

    def json(self):
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            import httpx
            raise httpx.HTTPStatusError("error", request=None, response=self)


class FakeAsyncClient:
    """Fakes every httpx call this module (and the KEV/EPSS enrichers it calls
    in its post-pass) makes. Dispatches by URL substring so one class covers the
    Nessus API calls and the CISA/FIRST.org enrichment calls -- same
    single-fake-seam convention as test_container_scan.py's FakeOsvAsyncClient.
    `get_override` is a hook tests can set to intercept/extend specific URLs
    without needing a whole new class per test."""
    calls = []
    get_override = None

    def __init__(self, *a, **kw):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, url, **kw):
        FakeAsyncClient.calls.append(("POST", url))
        if url.endswith("/session"):
            return FakeResponse({"token": "fake-session-token-abc"})
        return FakeResponse({})

    async def get(self, url, **kw):
        FakeAsyncClient.calls.append(("GET", url))
        if FakeAsyncClient.get_override:
            override = FakeAsyncClient.get_override(url)
            if override is not None:
                return override
        if url == ENDPOINT + "/scans":
            return FakeResponse(SCANS_RESPONSE)
        if url == ENDPOINT + "/scans/10":
            return FakeResponse(SCAN_10_DETAILS)
        if url == ENDPOINT + "/scans/10/hosts/1":
            return FakeResponse(HOST_1_VULNS)
        if url == ENDPOINT + "/plugins/plugin/12345":
            return FakeResponse(PLUGIN_12345)
        if url == ENDPOINT + "/plugins/plugin/99999":
            return FakeResponse(PLUGIN_99999)
        if "cisa.gov" in url:
            return FakeResponse({"vulnerabilities": []})
        if "api.first.org" in url:
            return FakeResponse({"data": []})
        raise AssertionError(f"Unexpected GET {url}")


import httpx
_real_httpx_async_client = httpx.AsyncClient
httpx.AsyncClient = FakeAsyncClient


def _reset():
    run(db.integrations.delete_many({}))
    run(db.assets.delete_many({}))
    run(db.findings.delete_many({}))
    run(db.tenable_sync_runs.delete_many({}))
    run(db.import_jobs.delete_many({}))
    FakeAsyncClient.calls = []
    FakeAsyncClient.get_override = None


def _seed_integration(auth_type="api_key"):
    cfg = {"endpoint": ENDPOINT, "auth_type": auth_type}
    if auth_type == "basic":
        cfg.update({"username": "admin", "api_key": "adminpass123"})
    else:
        cfg.update({"api_key": "accessKey123", "api_secret": "secretKey456"})
    doc = {"id": str(uuid.uuid4()), "name": "Tenable Nessus", "type": "infrastructure",
           "status": "not_configured", "config": cfg, "sync_errors": 0}
    run(db.integrations.insert_one(doc))
    return doc


# ============ severity mapping / small helpers ============

assert ts._norm_severity(4) == "Critical"
assert ts._norm_severity(3) == "High"
assert ts._norm_severity(2) == "Medium"
assert ts._norm_severity(1) == "Low"
assert ts._norm_severity(0) == "Info"
assert ts._norm_severity(None) == "Medium"
assert ts._norm_severity("not-a-number") == "Medium"
print("PASS: Nessus severity ints (0-4) map to our normalized severity strings")

assert ts._looks_like_ip("10.0.0.5") is True
assert ts._looks_like_ip("web01.corp.local") is False
assert ts._looks_like_ip("") is False
print("PASS: _looks_like_ip distinguishes IPs from hostnames")

_attrs = ts._parse_plugin_attributes({"attributes": [
    {"attribute_name": "cve", "attribute_value": "CVE-2023-0001"},
    {"attribute_name": "cve", "attribute_value": "CVE-2023-0002"},
    {"attribute_name": "solution", "attribute_value": "Patch it"},
]})
assert _attrs["cve"] == ["CVE-2023-0001", "CVE-2023-0002"]
assert _attrs["solution"] == "Patch it"
print("PASS: _parse_plugin_attributes collects repeated attribute names (multi-CVE plugins) into a list")

# ============ auth ============

_reset()
headers = run(ts._auth_headers(ENDPOINT, {"auth_type": "api_key", "api_key": "AK", "api_secret": "SK"}))
assert headers == {"X-ApiKeys": "accessKey=AK; secretKey=SK"}
assert FakeAsyncClient.calls == []  # API-key mode needs no network round-trip
print("PASS: API-key auth mode builds the X-ApiKeys header with no network call")

_reset()
headers = run(ts._auth_headers(ENDPOINT, {"auth_type": "basic", "username": "admin", "api_key": "pw123"}))
assert headers == {"X-Cookie": "token=fake-session-token-abc"}
assert ("POST", ENDPOINT + "/session") in FakeAsyncClient.calls
print("PASS: basic auth mode trades username/password for a session token via POST /session")

_reset()
try:
    run(ts._auth_headers(ENDPOINT, {"auth_type": "api_key", "api_key": "AK"}))
    assert False, "should have raised"
except RuntimeError as e:
    assert "api_key/api_secret" in str(e)
print("PASS: missing secret_key raises a clear error instead of sending a malformed header")

# ============ full sync ============

_reset()
_seed_integration()
result = run(ts.run_tenable_sync(db))
assert result["status"] == "success"
summary = result["summary"]
assert summary["scans_found"] == 1  # the "running" scan is excluded up front
assert summary["scans_processed"] == 1
assert summary["created"] == 2  # one High/CVE finding + one Info/no-CVE finding
print("PASS: run_tenable_sync() only processes completed scans and creates one finding per plugin hit")

findings = run(db.findings.find({}, {"_id": 0}).to_list(10))
# The key is now (CVE, RESOLVED ASSET ID) rather than (CVE, hostname string).
# Building it from a name meant Qualys and Nessus reporting the same CVE on the
# same machine either collided and overwrote each other's source_tool, or missed
# and duplicated -- decided by nothing but how each tool spelled the host.
# See corroboration.py.
_asset = run(db.assets.find_one({"hostname": "10.0.0.5"}, {"_id": 0}))
by_key = {f["canonical_key"]: f for f in findings}
assert f"CVE-2023-1234::{_asset['id']}" in by_key, by_key.keys()
assert any(k.startswith("tenable-nessus:99999::") for k in by_key), by_key.keys()
print("PASS: canonical_key is keyed on the resolved asset id, using the CVE when present and the "
      "tool's own plugin id otherwise (two tools' proprietary ids are not the same finding)")

high = by_key[f"CVE-2023-1234::{_asset['id']}"]
assert high["severity"] == "High"
assert high["cvss_score"] == 7.5
assert high["remediation"] == "Upgrade to the latest OpenSSL version."
assert high["title"] == "OpenSSL Multiple Vulnerabilities"
assert high["source_tool"] == "Tenable Nessus"
# and the finding now carries a sources[] array, so a second scanner reporting the
# same CVE corroborates it instead of overwriting source_tool
assert high["source_count"] == 1
assert high["sources"][0]["tool"] == "Tenable Nessus"
assert high["sources"][0]["native_id"] == "12345"
assert high["detection_channel"] == "tenable_api"
assert high["cve_list"] == ["CVE-2023-1234"]
print("PASS: finding fields (severity/cvss/remediation/title) are populated from the plugin-detail lookup")

info = by_key[next(k for k in by_key if k.startswith("tenable-nessus:99999::"))]
assert info["severity"] == "Info"
assert info["cve"] is None
print("PASS: an Info-severity, no-CVE plugin hit still becomes its own finding (no severity filtering)")

asset = run(db.assets.find_one({"hostname": "10.0.0.5"}, {"_id": 0}))
assert asset is not None
assert asset["ip"] == "10.0.0.5"
assert "tenable" in asset["tags"]
print("PASS: a new asset is auto-created from the scan's host, tagged 'tenable', IP inferred when the hostname is an IP")

runs = run(db.tenable_sync_runs.find({}, {"_id": 0}).to_list(10))
assert len(runs) == 1
jobs = run(db.import_jobs.find({"source_name": "Tenable Nessus"}, {"_id": 0}).to_list(10))
assert len(jobs) == 1 and jobs[0]["created_count"] == 2
print("PASS: a run record + mirrored import_jobs entry are written for the dashboard")

# ============ plugin-detail caching across hosts in the same run ============

_reset()
_seed_integration()


def _second_host_override(url):
    if url == ENDPOINT + "/scans/10":
        return FakeResponse({"info": {}, "hosts": [
            {"host_id": 1, "hostname": "10.0.0.5"},
            {"host_id": 2, "hostname": "10.0.0.6"},
        ]})
    if url == ENDPOINT + "/scans/10/hosts/2":
        return FakeResponse({"vulnerabilities": [
            {"plugin_id": 12345, "plugin_name": "OpenSSL Vuln", "plugin_family": "General", "severity": 3, "count": 1},
        ]})
    return None


FakeAsyncClient.get_override = _second_host_override
result = run(ts.run_tenable_sync(db))
FakeAsyncClient.get_override = None

assert result["summary"]["created"] == 3  # 2 findings on host 1 + 1 on host 2
plugin_calls = [c for c in FakeAsyncClient.calls if c[1] == ENDPOINT + "/plugins/plugin/12345"]
assert len(plugin_calls) == 1, "plugin 12345 detail should be fetched once per run, not once per host"
print("PASS: plugin-detail lookups are cached per plugin_id within a single sync run")

# ============ auto-resolve of stale findings, scoped per host ============

_reset()
_seed_integration()
stale = {
    "id": str(uuid.uuid4()), "canonical_key": "CVE-OLD-9999::10.0.0.5",
    "detection_channel": "tenable_api", "asset_hostname": "10.0.0.5",
    "status": "New", "first_seen_at": "2020-01-01T00:00:00+00:00",
    "severity": "Medium", "title": "Old since-fixed vuln",
}
run(db.findings.insert_one(stale))

result = run(ts.run_tenable_sync(db))
assert result["summary"]["auto_closed"] == 1
updated = run(db.findings.find_one({"canonical_key": "CVE-OLD-9999::10.0.0.5"}, {"_id": 0}))
assert updated["status"] == "Fixed validated"
assert "auto-closed" in updated["verification_note"]
print("PASS: a previously-open finding no longer reported on re-scan of the same host is auto-closed")

# ============ reopen semantics ============

_reset()
_seed_integration()
run(ts.run_tenable_sync(db))
_a = run(db.assets.find_one({"hostname": "10.0.0.5"}, {"_id": 0}))
_key = f"CVE-2023-1234::{_a['id']}"
closed = run(db.findings.find_one({"canonical_key": _key}, {"_id": 0}))
run(db.findings.update_one({"id": closed["id"]}, {"$set": {"status": "Fixed validated"}}))

result = run(ts.run_tenable_sync(db))
reopened = run(db.findings.find_one({"canonical_key": _key}, {"_id": 0}))
assert reopened["status"] == "Reopened"
assert reopened["reopened_count"] == 1
assert result["summary"]["updated"] >= 1
print("PASS: a finding seen again after being marked Fixed validated is reopened, not silently left closed")

# ============ clean failure modes ============

_reset()
doc = {"id": str(uuid.uuid4()), "name": "Tenable Nessus", "type": "infrastructure",
       "status": "not_configured", "config": {}, "sync_errors": 0}
run(db.integrations.insert_one(doc))
try:
    run(ts.run_tenable_sync(db))
    assert False, "should have raised"
except RuntimeError as e:
    assert "missing endpoint" in str(e)
print("PASS: a missing endpoint raises a clear, readable error (same convention as qualys_sync.py)")

_reset()
try:
    run(ts.run_tenable_sync(db))
    assert False, "should have raised"
except RuntimeError as e:
    assert "not found" in str(e)
print("PASS: syncing with no Tenable Nessus integration configured at all raises clearly")

# ============ routes ============

_reset()
_seed_integration()
r = client.post("/api/v1/admin/tenable/sync/run")
assert r.status_code == 200, r.text
assert r.json()["status"] == "running"
print("PASS: POST /v1/admin/tenable/sync/run starts a background sync and returns immediately")


async def _wait_for_run():
    for _ in range(50):
        await asyncio.sleep(0.05)
        doc = await db.tenable_sync_runs.find_one({}, {"_id": 0})
        if doc and doc.get("status") != "running":
            return doc
    return await db.tenable_sync_runs.find_one({}, {"_id": 0})


final = run(_wait_for_run())
assert final is not None and final["status"] == "success"
print("PASS: the background sync job completes and replaces the 'running' placeholder row")

r2 = client.get("/api/v1/admin/tenable/sync/runs")
assert r2.status_code == 200
assert len(r2.json()["items"]) >= 1
print("PASS: GET /v1/admin/tenable/sync/runs lists past run history")

run(db.tenable_sync_runs.insert_one({"id": "already-running-1", "status": "running", "ran_at": ts._now_iso(), "summary": {}, "errors": []}))
r3 = client.post("/api/v1/admin/tenable/sync/run")
assert r3.status_code == 200
assert r3.json()["id"] == "already-running-1"
assert r3.json()["message"] == "Sync already in progress"
run(db.tenable_sync_runs.delete_one({"id": "already-running-1"}))
print("PASS: triggering sync while one is already running returns the in-progress job instead of starting a duplicate")

# ============ feature flag + seed wiring ============

import feature_flags
assert "tenable_nightly_sync" in feature_flags.FLAG_KEYS
print("PASS: tenable_nightly_sync is registered in the feature flag registry")

import seed
assert any(s["name"] == "Tenable Nessus" for s in seed.SCANNERS)
print("PASS: 'Tenable Nessus' integration card is seeded")

httpx.AsyncClient = _real_httpx_async_client

print("\nALL TENABLE NESSUS CONNECTOR TESTS PASSED")
