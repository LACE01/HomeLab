"""Every OpenCTI caller must build the SAME URL.

Found from a real Cloudflare Security Events log: the operator's endpoint is
"https://open.smrtlab.net/public/graphql" (their proxy exposes a non-default
route). Test Connection honoured that path. The three sync paths appended
"/graphql" to it regardless, so they were calling "/public/graphql/graphql".

That is the nastiest shape a bug can take: the diagnostic tool says "Connected"
and everything that does real work fails, so the operator goes hunting through
Cloudflare Access instead of looking at the path. These tests pin the URL
construction and assert that all four callers go through one code path.
"""
import os, sys, asyncio, json
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_opencti_client"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_opencti_client"]

import httpx
import opencti_client as oc

run = lambda c: asyncio.get_event_loop().run_until_complete(c)


# ============ URL construction ============

# a bare base URL gets the default route appended
assert oc.graphql_url("https://opencti.example.net") == "https://opencti.example.net/graphql"
assert oc.graphql_url("https://opencti.example.net/") == "https://opencti.example.net/graphql"
print("PASS: a bare base URL gets OpenCTI's default /graphql route appended")

# THE BUG: an endpoint that already names the GraphQL path must be left alone
assert oc.graphql_url("https://open.smrtlab.net/public/graphql") == \
    "https://open.smrtlab.net/public/graphql", "must not double-append"
assert oc.graphql_url("https://open.smrtlab.net/public/graphql/") == \
    "https://open.smrtlab.net/public/graphql"
assert oc.graphql_url("https://h/graphql") == "https://h/graphql"
assert oc.graphql_url("https://h/graphql/") == "https://h/graphql"
assert "graphql/graphql" not in oc.graphql_url("https://h/public/graphql")
print("PASS: an endpoint that already names the GraphQL path is used as-is — never turned into "
      "/public/graphql/graphql, which is a path that does not exist")

assert oc.graphql_url("") == "" and oc.graphql_url(None) == ""
print("PASS: an empty endpoint yields an empty URL rather than a bare '/graphql'")


# ============ headers ============

h = oc.headers({"api_key": "tok"})
assert h["Authorization"] == "Bearer tok"
assert h["User-Agent"].startswith("Nightwatch-VulnMgmt/"), \
    "httpx's default UA is exactly what 'definitely automated' bot rules match"
assert "CF-Access-Client-Id" not in h, "no half-configured Access headers"
print("PASS: headers carry the API key and a descriptive User-Agent, and omit Access headers when none configured")

h = oc.headers({"api_key": "tok", "cf_access_client_id": "abc.access",
                "cf_access_client_secret": "s3cret"})
assert h["CF-Access-Client-Id"] == "abc.access" and h["CF-Access-Client-Secret"] == "s3cret"
print("PASS: a configured service token is attached as both CF-Access headers")

# a half-configured token is NOT a token: reporting one would send the operator
# to inspect Access policies for something Cloudflare never received
assert oc.token_sent({"cf_access_client_id": "abc.access"}) is False
assert oc.token_sent({"cf_access_client_secret": "s3cret"}) is False
assert oc.token_sent({"cf_access_client_id": "a", "cf_access_client_secret": "b"}) is True
print("PASS: only a COMPLETE id+secret pair counts as 'a service token was sent'")


# ============ every caller actually uses it ============

for module in ("cti.py", "reconng.py", "threat_intel_watchlist.py", "routes/findings.py"):
    src = open(module).read()
    assert "opencti_client" in src, f"{module} does not use the shared client"
    assert 'rstrip("/") + "/graphql"' not in src, \
        f"{module} still hand-builds the URL and will double-append /graphql"
print("PASS: all four OpenCTI callers build their URL through the shared client — no hand-rolled "
      "string concatenation left to drift")


# ============ end-to-end: the real sync honours the configured path ============

called = {}


class RecordingClient:
    def __init__(self, *a, **kw): pass
    async def __aenter__(self): return self
    async def __aexit__(self, *a): return False

    async def post(self, url, **kw):
        called["url"] = url
        called["headers"] = kw.get("headers") or {}

        class R:
            status_code = 200
            headers = {"Content-Type": "application/json"}
            text = json.dumps({"data": {"reports": {"edges": []}}})

            def json(self): return json.loads(self.text)
        return R()


_real = httpx.AsyncClient
httpx.AsyncClient = RecordingClient
db = db_module.db
run(db.integrations.insert_one({
    "id": "octi", "name": "OpenCTI", "type": "threat_intel",
    "config": {"endpoint": "https://open.smrtlab.net/public/graphql", "api_key": "tok",
               "cf_access_client_id": "abcd.access", "cf_access_client_secret": "s3cret"}}))

import cti
run(cti.sync_opencti_reports(db))
assert called["url"] == "https://open.smrtlab.net/public/graphql", called["url"]
assert called["headers"]["CF-Access-Client-Id"] == "abcd.access"
assert called["headers"]["User-Agent"].startswith("Nightwatch-VulnMgmt/")
print("PASS: the CTI reports sync POSTs to the configured /public/graphql path (not "
      "/public/graphql/graphql) and sends the Access token plus the descriptive User-Agent")

called.clear()
import threat_intel_watchlist as wl
run(wl.sync_opencti_feed(db, limit=5))
assert called["url"] == "https://open.smrtlab.net/public/graphql", called["url"]
assert called["headers"]["CF-Access-Client-Id"] == "abcd.access"
print("PASS: the watchlist indicator feed uses the configured path too")

called.clear()
import reconng
run(reconng.run_opencti_lookup("1.2.3.4"))
assert called["url"] == "https://open.smrtlab.net/public/graphql", called["url"]
print("PASS: the recon per-target lookup uses the configured path too — all three sync paths agree "
      "with what Test Connection reports")

httpx.AsyncClient = _real


# ============ Test Connection reports the URL it used ============

import inspect
from routes import findings as findings_route
src = inspect.getsource(findings_route.opencti_ping)
assert "target_url" in src and "request_url" in src, \
    "Test Connection must report WHICH url it called, so it can be matched against the Path " \
    "column in Cloudflare Security Events"
assert findings_route._opencti_graphql_url("https://h/public/graphql") == "https://h/public/graphql"
print("PASS: Test Connection reports the exact URL it called — the detail that makes a WAF Skip-rule "
      "path mismatch findable instead of invisible")


# ============ the diagnostic names the path-mismatch trap ============

import cf_diagnostics as cfd
v = cfd.classify_response(
    type("R", (), {"status_code": 403,
                    "text": "<html><head><title>Just a moment...</title></head></html>",
                    "headers": {"Server": "cloudflare", "CF-RAY": "abc-DEN"}})(),
    service_name="OpenCTI", token_sent=True, client_id="abcd1234ef.access")
joined = " ".join(v["remediation"])
assert "/public/graphql" in joined and "does not cover" in joined, \
    "the remediation must warn that an existing Skip rule on one path does not cover another"
assert "user agent" in joined.lower()
print("PASS: the edge verdict warns that an existing Skip rule may be scoped to a different path or "
      "user agent than the request being blocked")
