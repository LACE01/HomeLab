import os, sys, asyncio
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_yara_vt_wiring"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_yara_vt_wiring"]

import server
import auth_utils
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
    def __init__(self, status_code, json_data=None):
        self.status_code = status_code
        self._json = json_data or {}
        self.text = ""

    def json(self):
        return self._json


class FakeAsyncClient:
    queue = []

    def __init__(self, *a, **kw):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url, **kw):
        return FakeAsyncClient.queue.pop(0)


_real = httpx.AsyncClient
httpx.AsyncClient = FakeAsyncClient

run(db.integrations.insert_one({"id": "vt1", "name": "VirusTotal", "config": {"api_key": "vt-key"}}))
run(db.yara_rules.insert_one({
    "id": "r1", "name": "test-rule", "enabled": True,
    "source": 'rule test_rule { strings: $a = "evil-marker" condition: $a }',
}))

FakeAsyncClient.queue = [FakeResponse(200, {
    "data": {"attributes": {"last_analysis_stats": {"malicious": 5, "suspicious": 1}}}
})]

r = client.post(
    "/api/v1/admin/yara/scan",
    files={"file": ("sample.txt", b"this file contains an evil-marker inside it", "text/plain")},
    data={"label": "", "asset_id": ""},
)
assert r.status_code == 200, r.text
body = r.json()
assert body["matched_rule_count"] == 1, body
assert body["virustotal"] is not None and body["virustotal"]["status"] == "malicious"
print("PASS: POST /v1/admin/yara/scan automatically checks the file hash against VirusTotal and returns the result inline")

watch = run(db.ioc_watchlist.find_one({"value": body["sha256"]}, {"_id": 0}))
assert watch is not None
print("PASS: the malicious hash from a YARA scan gets auto-added to the IOC watchlist")

# --- disabling the feature flag should skip the VT check entirely ---
import feature_flags
run(feature_flags.set_flag(db, "auto_hash_virustotal_check", False, "admin@x.com"))
FakeAsyncClient.queue = []  # if this gets consumed, the flag didn't actually gate the call
r2 = client.post(
    "/api/v1/admin/yara/scan",
    files={"file": ("sample2.txt", b"a totally clean file", "text/plain")},
    data={"label": "", "asset_id": ""},
)
assert r2.status_code == 200, r2.text
assert r2.json()["virustotal"] is None
print("PASS: disabling auto_hash_virustotal_check skips the VT call entirely (no queued response consumed)")

httpx.AsyncClient = _real
print("\nALL YARA <-> VIRUSTOTAL WIRING TESTS PASSED")
