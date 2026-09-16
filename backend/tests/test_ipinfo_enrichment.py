"""#55 IPinfo enrichment (Lite tier).

IPinfo adds IP context -- country + ASN/org -- to pipelines that had none: the
Albert/CTI IP-enrichment path and attack-telemetry attribution. These tests cover
the client (normalization, private-IP skip, not-configured vs error, caching) and
that it actually feeds both pipelines without ever blocking them."""
import os, sys, asyncio, json
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_ipinfo"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_ipinfo"]
db = db_module.db

import ipinfo, httpx
run = lambda c: asyncio.get_event_loop().run_until_complete(c)
def a(c, m=""): assert c, m

LITE = {"ip": "8.8.8.8", "asn": "AS15169", "as_name": "Google LLC", "as_domain": "google.com",
        "country_code": "US", "country": "United States", "continent": "North America"}


class FakeResp:
    def __init__(self, status, body): self.status_code = status; self._b = body
    @property
    def text(self): return json.dumps(self._b) if isinstance(self._b, dict) else self._b
    def json(self): return self._b


def patch_get(status, body, capture=None):
    class C:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def get(self, url, **kw):
            if capture is not None:
                capture["url"] = url; capture["params"] = kw.get("params")
            return FakeResp(status, body)
    ipinfo.httpx.AsyncClient = C


_real = httpx.AsyncClient


# ============ private / invalid IPs are skipped (nothing to geolocate) ============

a(ipinfo.is_public_ip("8.8.8.8") is True)
for bad in ("10.0.0.5", "192.168.1.1", "127.0.0.1", "::1", "not-an-ip", ""):
    a(ipinfo.is_public_ip(bad) is False, f"{bad} should not be treated as public")
a(run(ipinfo.lookup_ip(db, "10.0.0.5")) is None, "a private IP returns None, not an error")
print("PASS: private/loopback/invalid IPs are skipped (returned as None), only public IPs are looked up")


# ============ not configured is distinct from an error ============

try:
    run(ipinfo.lookup_ip(db, "8.8.8.8"))
    a(False, "expected not-configured to raise ValueError")
except ValueError as e:
    a("isn't configured" in str(e))
print("PASS: with no token, lookup raises a clear 'not configured' ValueError (not a generic error)")

# configure it
run(db.integrations.insert_one({"name": "IPinfo", "config": {"api_key": "tok", "endpoint": "https://api.ipinfo.io"}}))


# ============ a real lookup normalizes + caches, and uses the Lite endpoint + token ============

cap = {}
patch_get(200, LITE, capture=cap)
out = run(ipinfo.lookup_ip(db, "8.8.8.8"))
ipinfo.httpx.AsyncClient = _real
a(out["country"] == "United States" and out["asn"] == "AS15169" and out["as_name"] == "Google LLC")
a(out["org"] == "AS15169 Google LLC")
a("/lite/8.8.8.8" in cap["url"] and cap["params"]["token"] == "tok",
  "must call the Lite endpoint with the token as a query param")
print("PASS: a lookup hits the Lite endpoint with the token and normalizes country + ASN/org")

# second call is served from cache -- no HTTP (patch to error to prove it isn't called)
patch_get(500, "should not be called")
out2 = run(ipinfo.lookup_ip(db, "8.8.8.8"))
ipinfo.httpx.AsyncClient = _real
a(out2["asn"] == "AS15169", "cache should have served the second lookup without an HTTP call")
a(run(db.ipinfo_cache.count_documents({"ip": "8.8.8.8"})) == 1)
print("PASS: results are cached (a repeated lookup does not re-call the API)")


# ============ enrich_quietly never raises, even when IPinfo errors ============

patch_get(429, "rate limited")
a(run(ipinfo.enrich_quietly(db, "1.1.1.1")) is None, "enrich_quietly must swallow errors")
ipinfo.httpx.AsyncClient = _real
print("PASS: enrich_quietly returns None instead of raising, so it can't block a pipeline it enriches")


# ============ feeds the CTI/Albert pipeline: enrich_ip gets a geo field ============

import albert_enrichment
# stub the threat-intel lookups so the test is about IPinfo, not those
import reconng
async def _empty(*a, **k): return []
reconng.run_opencti_lookup = _empty
reconng.run_greynoise_lookup = _empty
reconng.run_otx_lookup = _empty
reconng.run_abusech_lookup = _empty
patch_get(200, {**LITE, "ip": "9.9.9.9"})
doc = run(albert_enrichment.enrich_ip(db, "9.9.9.9"))
ipinfo.httpx.AsyncClient = _real
a(doc.get("geo") and doc["geo"]["country"] == "United States", "enrich_ip must attach IPinfo geo")
a(any(r["source"] == "IPinfo" and r["status"] == "found" for r in doc["results"]),
  "IPinfo appears as a context source in the enrichment results")
# context geo is NOT mirrored into osint_findings (it isn't a threat verdict)
a(run(db.osint_findings.count_documents({"target": "9.9.9.9"})) == 0,
  "IPinfo geo context must not be written as a threat finding")
print("PASS: enrich_ip (Albert/CTI pipeline) now carries IPinfo geo/ASN as context — and context is "
      "never mis-filed as a threat finding")

print("\nALL IPINFO ENRICHMENT TESTS PASSED")
