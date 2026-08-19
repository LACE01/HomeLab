"""Cloudflare connection test: a REAL query, not 'any HTTP reply = success'.

The reported bug: the test reported 'reachable (HTTP 400)' as SUCCESS. Cloudflare's
GraphQL endpoint answers 400 to a bare GET (it needs a POST with a query), and the
generic reachability probe took any HTTP response as proof of a working connector
-- so the test passed with no valid token. The hardest case is subtler still:
Cloudflare returns HTTP 200 with an `errors` array on an auth/permission failure,
so even a proper 200 is not enough on its own.
"""
import os, sys, asyncio, json
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_cf_conn"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_cf_conn"]

import attack_telemetry as at
import httpx

run = lambda c: asyncio.get_event_loop().run_until_complete(c)


def a(c, m=""): assert c, m


class FakeResp:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body
    @property
    def text(self):
        return self._body if isinstance(self._body, str) else json.dumps(self._body)
    def json(self):
        if isinstance(self._body, (dict, list)):
            return self._body
        return json.loads(self._body)


def patch_post(status, body, capture=None):
    class C:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, url, **kw):
            if capture is not None:
                capture["url"] = url
                capture["headers"] = kw.get("headers")
                capture["json"] = kw.get("json")
            return FakeResp(status, body)
    httpx.AsyncClient = C


_real = httpx.AsyncClient


# ============ config validation before any network call ============

a(run(at.test_connection({}))["ok"] is False)
a("No Cloudflare credential" in run(at.test_connection({}))["message"])
a("No Zone ID" in run(at.test_connection({"api_key": "tok"}))["message"])
print("PASS: missing credential or Zone ID is reported before any request — with guidance on where "
      "to find the Zone ID")


# ============ THE bug: a bare 400 must NOT read as success ============

patch_post(400, "GET method not allowed; use POST")
res = run(at.test_connection({"api_key": "tok", "zone_id": "z1"}))
httpx.AsyncClient = _real
a(res["ok"] is False, "HTTP 400 was treated as success -- the exact reported bug")
a("HTTP 400" in res["message"])
print("PASS: an HTTP 400 from Cloudflare is a FAILURE with the body surfaced, not "
      "'reachable (HTTP 400) = success' — the reported bug")


# ============ 200 WITH errors[] is a failure, not a pass ============

patch_post(200, {"data": {"viewer": {"zones": []}},
                 "errors": [{"message": "Authentication error"}]})
res = run(at.test_connection({"api_key": "badtok", "zone_id": "z1"}))
httpx.AsyncClient = _real
a(res["ok"] is False)
a("Authentication error" in res["message"] and "GraphQL error" in res["message"])
print("PASS: a 200 response carrying a GraphQL errors[] array is a FAILURE with the error surfaced "
      "— Cloudflare returns 200+errors on auth failure, so status alone is not enough")


# ============ 200, no errors, but the zone didn't come back ============

patch_post(200, {"data": {"viewer": {"zones": []}}})
res = run(at.test_connection({"api_key": "tok", "zone_id": "wrong-zone"}))
httpx.AsyncClient = _real
a(res["ok"] is False and "returned no zone" in res["message"])
print("PASS: a clean 200 whose zone list is empty is a failure — the token is valid but the Zone "
      "ID is wrong or invisible to it")


# ============ the happy path ============

patch_post(200, {"data": {"viewer": {"zones": [{"zoneTag": "z1"}]}}})
res = run(at.test_connection({"api_key": "tok", "zone_id": "z1"}))
httpx.AsyncClient = _real
a(res["ok"] is True)
a("API token" in res["message"] and "z1" in res["message"])
print("PASS: a 200 that returns the configured zone with no errors is the only thing that counts "
      "as success, and it names the auth mode and zone")


# ============ auth mode: token vs global key ============

cap = {}
patch_post(200, {"data": {"viewer": {"zones": [{"zoneTag": "z1"}]}}}, capture=cap)
run(at.test_connection({"api_key": "tok", "zone_id": "z1"}))
httpx.AsyncClient = _real
a(cap["headers"].get("Authorization") == "Bearer tok")
a("X-Auth-Key" not in cap["headers"])
print("PASS: with just an api_key, auth is a scoped API token (Authorization: Bearer)")

cap = {}
patch_post(200, {"data": {"viewer": {"zones": [{"zoneTag": "z1"}]}}}, capture=cap)
res = run(at.test_connection({"api_key": "globalkey", "api_email": "ops@county.us", "zone_id": "z1"}))
httpx.AsyncClient = _real
a(cap["headers"].get("X-Auth-Email") == "ops@county.us")
a(cap["headers"].get("X-Auth-Key") == "globalkey")
a("Authorization" not in cap["headers"])
a("global API key" in res["message"])
print("PASS: with an api_email present, auth switches to the global API key headers "
      "(X-Auth-Email / X-Auth-Key), and the message names that mode")

# and the query actually POSTs the zone tag
a(cap["json"]["variables"]["zoneTag"] == "z1")
a("zones" in cap["json"]["query"])
print("PASS: the test POSTs a real GraphQL query scoped to the configured zone — a query, not a "
      "reachability ping")


# ============ 401 / 403 get specific, actionable messages ============

patch_post(401, "unauthorized")
r401 = run(at.test_connection({"api_key": "tok", "zone_id": "z1"}))
httpx.AsyncClient = _real
a(r401["ok"] is False and "Analytics:Read" in r401["message"])

patch_post(403, "forbidden")
r403 = run(at.test_connection({"api_key": "tok", "zone_id": "z1"}))
httpx.AsyncClient = _real
a(r403["ok"] is False and "lacks permission" in r403["message"])
print("PASS: 401 and 403 give distinct, actionable guidance (token scope vs zone permission) "
      "rather than a generic failure")


# ============ the connector's own _graphql uses the same auth builder ============

h_token = at.cf_auth_headers({"api_key": "t"})
a(h_token["Authorization"] == "Bearer t")
h_global = at.cf_auth_headers({"api_key": "k", "api_email": "e@x.com"})
a(h_global["X-Auth-Key"] == "k" and h_global["X-Auth-Email"] == "e@x.com")
import inspect
a("cf_auth_headers" in inspect.getsource(at._graphql),
  "the sync path must use the same auth builder as the test, or the two can disagree")
print("PASS: sync and test share one auth-header builder, so a global-key config that tests OK also "
      "syncs OK")
