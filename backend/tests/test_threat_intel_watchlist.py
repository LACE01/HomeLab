import os, sys, asyncio, uuid
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_threat_intel_watchlist"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_threat_intel_watchlist"]

import server
import auth_utils
from routes import threat_intel as ti_route
ti_route.db = db_module.db

from fastapi.testclient import TestClient

admin_user = {"id": "u1", "email": "admin@x.com", "role": "admin", "name": "Admin", "teams": []}
app = server.app
app.dependency_overrides[auth_utils.get_current_user] = lambda: admin_user
client = TestClient(app)

db = db_module.db


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


import threat_intel_watchlist as tiw

# ============ pure helpers ============

assert tiw._normalize("1.2.3.4:8080") == "1.2.3.4"
assert tiw._normalize("  EVIL.example.COM  ") == "evil.example.com"
print("PASS: _normalize lowercases/trims and strips ThreatFox's ip:port suffix")

assert tiw._parse_stix_pattern("[ipv4-addr:value = '1.2.3.4']") == ("ip", "1.2.3.4")
assert tiw._parse_stix_pattern("[domain-name:value = 'evil.example.com']") == ("domain", "evil.example.com")
assert tiw._parse_stix_pattern("[url:value = 'http://evil.example.com/payload']") == ("url", "http://evil.example.com/payload")
assert tiw._parse_stix_pattern("[file:hashes.'SHA-256' = 'abc123']") == ("hash", "abc123")
assert tiw._parse_stix_pattern("[mac-addr:value = 'aa:bb:cc:dd:ee:ff']") == (None, None)  # unmapped STIX type
assert tiw._parse_stix_pattern("") == (None, None)
assert tiw._parse_stix_pattern(None) == (None, None)
print("PASS: _parse_stix_pattern extracts (ioc_type, value) from simple STIX indicator patterns, skips unmapped/empty ones")


def _reset():
    run(db.integrations.delete_many({}))
    run(db.ioc_watchlist.delete_many({}))
    run(db.security_events.delete_many({}))


# ============ add_ioc carries an optional `detail` dict ============

_reset()
doc = run(tiw.add_ioc(db, ioc_type="ip", value="9.9.9.9", source="manual", severity="High",
                       notes="test note", detail=None))
assert doc["detail"] is None
doc2 = run(tiw.add_ioc(db, ioc_type="domain", value="evil.example.com", source="opencti_feed",
                        severity="Critical", notes="OpenCTI indicator", detail={"pattern": "[domain-name:value = 'evil.example.com']"}))
assert doc2["detail"]["pattern"] == "[domain-name:value = 'evil.example.com']"
print("PASS: add_ioc stores an optional detail dict (None for manual entries, populated for feed-sourced ones)")

# ============ ThreatFox / OpenSourceMalware feed syncs populate `detail` ============

_reset()


class FakeResponse:
    """Faithful stand-in for an httpx response: real JSON in .text and a
    content-type header. The previous version had no headers at all and put a
    Python repr in .text, which meant anything inspecting the response shape
    (like the Cloudflare-vs-Access-vs-origin diagnostic) saw a malformed reply."""

    def __init__(self, json_data, status_code=200, headers=None, text=None):
        import json as _json
        self._json = json_data
        self.status_code = status_code
        self.text = text if text is not None else _json.dumps(json_data)
        self.headers = headers or {"Content-Type": "application/json"}

    def json(self):
        return self._json

    def raise_for_status(self):
        pass


class FakeAsyncClient:
    """Single fake covering every httpx call this module's four sync_*_feed
    functions make -- dispatches by URL/method, same one-fake-per-test-file
    convention as test_tenable_sync.py's FakeAsyncClient."""
    def __init__(self, *a, **kw):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, url, **kw):
        if "threatfox-api.abuse.ch" in url:
            return FakeResponse({
                "query_status": "ok",
                "data": [
                    {"ioc_type": "domain", "ioc": "bad-domain.example", "malware_printable": "Emotet",
                     "malware_alias": "Heodo", "threat_type": "botnet_cc", "confidence_level": 90,
                     "first_seen": "2026-01-01", "last_seen": "2026-01-05", "reference": "https://threatfox.abuse.ch/ioc/1/",
                     "reporter": "someone", "tags": ["emotet"], "id": "1"},
                ],
            })
        if "/graphql" in url:
            return FakeResponse({
                "data": {
                    "indicators": {
                        "edges": [
                            {"node": {"id": "ind-1", "name": "Known C2 IP", "pattern": "[ipv4-addr:value = '5.5.5.5']",
                                      "description": "C2 for FooMalware", "valid_until": "2027-01-01",
                                      "x_opencti_score": 85, "objectLabel": [{"value": "c2"}, {"value": "foomalware"}]}},
                            {"node": {"id": "ind-2", "name": "Known bad domain", "pattern": "[domain-name:value = 'bad2.example']",
                                      "description": "phishing domain", "valid_until": None,
                                      "x_opencti_score": 40, "objectLabel": []}},
                            {"node": {"id": "ind-3", "name": "Unmapped observable", "pattern": "[mac-addr:value = 'aa:bb:cc:dd:ee:ff']",
                                      "description": "not a type we track", "valid_until": None,
                                      "x_opencti_score": None, "objectLabel": []}},
                            {"node": {"id": "ind-4", "name": "Already-known IP", "pattern": "[ipv4-addr:value = '9.9.9.9']",
                                      "description": "dup", "valid_until": None, "x_opencti_score": None, "objectLabel": []}},
                        ]
                    }
                }
            })
        return FakeResponse({})

    async def get(self, url, **kw):
        if "api.opensourcemalware.com" in url:
            eco = kw.get("params", {}).get("ecosystem")
            if eco == "npm":
                return FakeResponse({"threats": [
                    {"package_name": "evil-pkg", "severity_level": "critical",
                     "tags": ["backdoor"], "threat_description": "Exfiltrates env vars",
                     "discovered_date": "2026-02-01", "advisory_url": "https://opensourcemalware.com/advisories/1"},
                ]})
            return FakeResponse({"threats": []})
        if "/pulses/subscribed" in url:
            return FakeResponse({
                "results": [
                    {"id": "pulse-1", "name": "Weekly malware roundup", "description": "community pulse",
                     "author_name": "researcher1", "tags": ["malware"], "references": ["https://example.com/report"],
                     "indicators": [
                         {"type": "IPv4", "indicator": "6.6.6.6", "description": "C2 node", "created": "2026-01-10"},
                         {"type": "domain", "indicator": "bad3.example", "description": "phishing", "created": "2026-01-11"},
                         {"type": "FileHash-SHA256", "indicator": "deadbeef" * 8, "description": "dropper", "created": "2026-01-12"},
                         {"type": "CIDR", "indicator": "10.0.0.0/8", "description": "not trackable as a single value", "created": "2026-01-12"},
                         {"type": "IPv4", "indicator": "9.9.9.9", "description": "already known", "created": "2026-01-13"},
                     ]},
                ]
            })
        return FakeResponse({})


import httpx
_real_httpx_async_client = httpx.AsyncClient
httpx.AsyncClient = FakeAsyncClient


def _seed_integration(name, cfg):
    run(db.integrations.insert_one({"id": str(uuid.uuid4()), "name": name, "type": "threat_intel",
                                     "status": "not_configured", "config": cfg, "sync_errors": 0}))


_reset()
_seed_integration("abuse.ch (ThreatFox)", {"api_key": "authkey123"})
result = run(tiw.sync_threatfox_feed(db))
assert result["added"] == 1
doc = run(db.ioc_watchlist.find_one({"value": "bad-domain.example"}, {"_id": 0}))
assert doc["detail"]["malware"] == "Emotet"
assert doc["detail"]["threatfox_ioc_id"] == "1"
assert doc["detail"]["reference"] == "https://threatfox.abuse.ch/ioc/1/"
print("PASS: sync_threatfox_feed stores a `detail` dict (malware family, confidence, reference, reporter, tags) for the drill-down view")

_reset()
_seed_integration("OpenSourceMalware", {"api_key": "osm_token123"})
result = run(tiw.sync_opensourcemalware_feed(db, ecosystems=["npm"]))
assert result["added"] == 1
doc = run(db.ioc_watchlist.find_one({"value": "npm:evil-pkg"}, {"_id": 0}))
assert doc["detail"]["ecosystem"] == "npm"
assert doc["detail"]["advisory_url"] == "https://opensourcemalware.com/advisories/1"
print("PASS: sync_opensourcemalware_feed stores a `detail` dict (ecosystem, package name, advisory URL) for the drill-down view")

# ============ new: sync_opencti_feed ============

_reset()
run(tiw.add_ioc(db, ioc_type="ip", value="9.9.9.9", source="manual", severity="High"))  # pre-existing, should be skipped as a dup

try:
    run(tiw.sync_opencti_feed(db))
    raise AssertionError("expected ValueError for unconfigured OpenCTI")
except ValueError as e:
    assert "OpenCTI isn't configured" in str(e)
print("PASS: sync_opencti_feed raises ValueError with a clear message when OpenCTI isn't configured")

_seed_integration("OpenCTI", {"endpoint": "https://opencti.example.internal", "api_key": "opencti-token"})
result = run(tiw.sync_opencti_feed(db))
assert result["added"] == 2, f"expected 2 new IOCs (5.5.5.5 ip, bad2.example domain), got {result}"
assert result["skipped_unparsed"] == 1  # the mac-addr indicator
ip_doc = run(db.ioc_watchlist.find_one({"value": "5.5.5.5"}, {"_id": 0}))
assert ip_doc["source"] == "opencti_feed"
assert ip_doc["severity"] == "Critical"  # score 85 >= 80
assert ip_doc["detail"]["labels"] == ["c2", "foomalware"]
assert ip_doc["detail"]["opencti_indicator_id"] == "ind-1"
domain_doc = run(db.ioc_watchlist.find_one({"value": "bad2.example"}, {"_id": 0}))
assert domain_doc["severity"] == "Medium"  # score 40 < 50
dup_count = run(db.ioc_watchlist.count_documents({"value": "9.9.9.9"}))
assert dup_count == 1  # not duplicated, the manual entry wins
print("PASS: sync_opencti_feed pulls OpenCTI's recent Indicators, resolves STIX patterns to IOC values, "
      "maps score->severity, skips unmapped patterns and already-watchlisted values, and preserves detail for drill-down")

# ============ new: sync_otx_feed ============

_reset()
run(tiw.add_ioc(db, ioc_type="ip", value="9.9.9.9", source="manual", severity="High"))

try:
    run(tiw.sync_otx_feed(db))
    raise AssertionError("expected ValueError for unconfigured OTX")
except ValueError as e:
    assert "AlienVault OTX isn't configured" in str(e)
print("PASS: sync_otx_feed raises ValueError with a clear message when AlienVault OTX isn't configured")

_seed_integration("AlienVault OTX", {"api_key": "otx-token"})
result = run(tiw.sync_otx_feed(db))
assert result["added"] == 3, f"expected 3 new IOCs (ip/domain/hash), got {result}"
assert result["pulses_checked"] == 1
ip_doc = run(db.ioc_watchlist.find_one({"value": "6.6.6.6"}, {"_id": 0}))
assert ip_doc["source"] == "otx_feed"
assert ip_doc["detail"]["pulse_name"] == "Weekly malware roundup"
assert ip_doc["detail"]["indicator_type"] == "IPv4"
hash_doc = run(db.ioc_watchlist.find_one({"value": "deadbeef" * 8}, {"_id": 0}))
assert hash_doc["ioc_type"] == "hash"
cidr_count = run(db.ioc_watchlist.count_documents({"value": "10.0.0.0/8"}))
assert cidr_count == 0  # CIDR isn't in _OTX_TYPE_MAP, correctly skipped
dup_count = run(db.ioc_watchlist.count_documents({"value": "9.9.9.9"}))
assert dup_count == 1
print("PASS: sync_otx_feed pulls subscribed pulses' indicators, maps supported OTX types to our IOC buckets, "
      "skips unsupported types (CIDR) and already-watchlisted values, and preserves pulse detail for drill-down")

httpx.AsyncClient = _real_httpx_async_client

# ============ routes: get_ioc / matches drill-down / new sync-now endpoints ============

_reset()
ioc = run(tiw.add_ioc(db, ioc_type="ip", value="7.7.7.7", source="opencti_feed", severity="Critical",
                       notes="Known C2 IP", detail={"opencti_indicator_id": "ind-9"}))

r = client.get(f"/api/v1/admin/threat-intel/watchlist/{ioc['id']}")
assert r.status_code == 200
assert r.json()["detail"]["opencti_indicator_id"] == "ind-9"
print("PASS: GET /v1/admin/threat-intel/watchlist/{id} returns the full doc including `detail` for the click-to-expand modal")

r = client.get("/api/v1/admin/threat-intel/watchlist/does-not-exist")
assert r.status_code == 404
print("PASS: GET .../watchlist/{id} 404s for an unknown IOC id")

# seed a match via check_and_emit, same as qualys_sync.py/yara_scan.py/sbom.py do
run(tiw.check_and_emit(db, "7.7.7.7", entity_type="asset", entity_id="asset-1", entity_label="web01.corp.local"))
r = client.get(f"/api/v1/admin/threat-intel/watchlist/{ioc['id']}/matches")
assert r.status_code == 200
body = r.json()
assert body["total"] == 1
assert body["items"][0]["entity_label"] == "web01.corp.local"
print("PASS: GET .../watchlist/{id}/matches surfaces the security_events this IOC actually triggered in this environment")

r = client.get(f"/api/v1/admin/threat-intel/watchlist/{ioc['id']}/matches")
# an IOC that has never matched anything returns an empty (not error) list
_reset()
ioc2 = run(tiw.add_ioc(db, ioc_type="domain", value="never-matched.example", source="manual", severity="Low"))
r = client.get(f"/api/v1/admin/threat-intel/watchlist/{ioc2['id']}/matches")
assert r.status_code == 200 and r.json() == {"items": [], "total": 0}
print("PASS: .../matches returns an empty list (not an error) for an IOC with no recorded hits")

# sync-now/opencti and sync-now/otx endpoints: 400 when unconfigured, 200 + summary when configured
_reset()
r = client.post("/api/v1/admin/threat-intel/sync-now/opencti")
assert r.status_code == 400
r = client.post("/api/v1/admin/threat-intel/sync-now/otx")
assert r.status_code == 400
print("PASS: POST sync-now/opencti and sync-now/otx return 400 with a clear message when those integrations aren't configured")

httpx.AsyncClient = FakeAsyncClient
_seed_integration("OpenCTI", {"endpoint": "https://opencti.example.internal", "api_key": "tok"})
_seed_integration("AlienVault OTX", {"api_key": "tok"})
r = client.post("/api/v1/admin/threat-intel/sync-now/opencti")
assert r.status_code == 200 and r.json()["added"] == 3  # 5.5.5.5, bad2.example, 9.9.9.9 -- nothing pre-seeded this time
r = client.post("/api/v1/admin/threat-intel/sync-now/otx")
# 9.9.9.9 was just added a line above by the OpenCTI sync, so OTX's own "already known" 9.9.9.9
# indicator is now correctly skipped as a dup -- only 6.6.6.6/bad3.example/the sha256 hash are new.
assert r.status_code == 200 and r.json()["added"] == 3, r.json()
httpx.AsyncClient = _real_httpx_async_client
print("PASS: POST sync-now/opencti and sync-now/otx return 200 + a summary once each integration is configured")
