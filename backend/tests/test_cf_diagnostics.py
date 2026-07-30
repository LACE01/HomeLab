"""Which layer refused the request? Cloudflare edge challenge vs Cloudflare
Access vs the origin app all look like "an HTTP error with an HTML body", and
telling them apart is the difference between a five-minute fix and changing the
wrong setting all afternoon."""
import os, sys, asyncio
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_cf_diag"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_cf_diag"]

import cf_diagnostics as cfd


class Resp:
    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


# The exact page the user was seeing.
JUST_A_MOMENT = (
    '<!DOCTYPE html><html lang="en-US"><head><title>Just a moment...</title>'
    '<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">'
    '<meta http-equiv="X-UA-Compatible" content="IE=Edge"><meta name="robots" content="noindex,nofollow">'
    '<script src="/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1"></script></head></html>'
)

CF_HEADERS = {"Server": "cloudflare", "CF-RAY": "9a1b2c3d4e5f6789-DEN",
              "Content-Type": "text/html; charset=UTF-8"}


# ============ the reported failure ============

v = cfd.classify_response(Resp(403, JUST_A_MOMENT, CF_HEADERS),
                           service_name="OpenCTI", token_sent=True, client_id="abcd1234ef.access")
assert v["layer"] == cfd.LAYER_EDGE
assert v["ok"] is False
assert "bot protection" in v["title"].lower()
assert "before" in v["message"].lower() and "access" in v["message"].lower()
# it must actively tell the operator their Access config is NOT the problem
assert "not the problem" in v["message"].lower()
# and it must acknowledge the token was sent but is irrelevant here
assert "can't help here" in v["message"]
assert any("Super Bot Fight Mode" in r for r in v["remediation"])
assert any("IP Access Rules" in r for r in v["remediation"])
assert any("curl" in r for r in v["remediation"])
assert v["evidence"]["cf_ray"] == "9a1b2c3d4e5f6789-DEN"
print("PASS: a 403 'Just a moment...' page is identified as CDN-edge bot protection, states plainly that Access "
      "is NOT the cause, and points at Super Bot Fight Mode / IP Access Rules")

# the old behaviour, for contrast: raw HTML in the message told you nothing
line = cfd.summary_line(v)
assert "<!DOCTYPE" not in line and "<html" not in line, "the HTML page must never reach the error message"
assert len(line) > 80 and "Start here:" in line
print("PASS: the one-line error carries the actionable summary instead of the raw HTML page")

# detection also works from the cf-mitigated header alone (no body)
v2 = cfd.classify_response(Resp(403, "", {"cf-mitigated": "challenge", "Server": "cloudflare"}),
                            service_name="OpenCTI")
assert v2["layer"] == cfd.LAYER_EDGE
print("PASS: the cf-mitigated: challenge header alone is enough to identify an edge challenge")

# other challenge wordings
for title in ("Attention Required! | Cloudflare", "Checking your browser before accessing",
               "Please wait... | Cloudflare"):
    page = f"<html><head><title>{title}</title></head></html>"
    assert cfd.classify_response(Resp(503, page, CF_HEADERS))["layer"] == cfd.LAYER_EDGE, title
print("PASS: the other Cloudflare interstitial wordings are recognized too")


# ============ Access, which is a different fix ============

v = cfd.classify_response(Resp(302, "", {"Location": "https://myteam.cloudflareaccess.com/cdn-cgi/access/login/x"}),
                           service_name="OpenCTI", token_sent=True, client_id="abcd1234ef.access")
assert v["layer"] == cfd.LAYER_ACCESS
assert "service token" in v["title"].lower()
# the specific misconfiguration that bites people: policy ACTION must be Service Auth
assert any("action must be" in r.lower() and "service auth" in r.lower() for r in v["remediation"])
assert any("not 'Allow'" in r for r in v["remediation"])
print("PASS: an Access login redirect WITH a token is diagnosed as a policy problem, naming the "
      "action-must-be-Service-Auth trap rather than blaming the token")

v = cfd.classify_response(Resp(302, "", {"Location": "https://t.cloudflareaccess.com/cdn-cgi/access/login"}),
                           service_name="OpenCTI", token_sent=False)
assert v["layer"] == cfd.LAYER_ACCESS
assert "no service token" in v["title"].lower()
assert any("Service Auth" in r for r in v["remediation"])
print("PASS: an Access redirect with NO token saved says to create one, rather than sending you to bot settings")

# a 403 whose body mentions Access is Access, not the edge
v = cfd.classify_response(Resp(403, "<html>redirecting to cloudflareaccess.com</html>",
                                {"Server": "cloudflare"}), token_sent=True, client_id="x")
assert v["layer"] == cfd.LAYER_ACCESS
print("PASS: a 403 mentioning Access is attributed to Access, not to bot protection")


# ============ the origin app, which is a third fix ============

v = cfd.classify_response(Resp(401, '{"errors":[{"message":"invalid token"}]}',
                                {"Content-Type": "application/json"}), service_name="OpenCTI")
assert v["layer"] == cfd.LAYER_ORIGIN
assert "itself rejected" in v["title"]
assert "Cloudflare let it through" in v["message"]
assert any("API key" in r for r in v["remediation"])
print("PASS: a JSON 401 is attributed to OpenCTI's own auth — explicitly noting Cloudflare let it through")

v = cfd.classify_response(Resp(502, "bad gateway", {"Server": "cloudflare"}), service_name="OpenCTI")
assert v["layer"] == cfd.LAYER_ORIGIN and "unreachable or unhealthy" in v["title"]
assert any("tunnel" in r.lower() for r in v["remediation"])
print("PASS: 502/503/504 is attributed to the origin being down, with the tunnel called out")

# HTML with a 200 -- a challenge or login page served with a success code
v = cfd.classify_response(Resp(200, "<html>login</html>", {"Content-Type": "text/html", "Server": "cloudflare"}),
                           service_name="OpenCTI")
assert v["ok"] is False and "HTML where JSON was expected" in v["title"]
print("PASS: HTML served with a 200 is caught rather than blowing up in a JSON parse later")

# the happy path
v = cfd.classify_response(Resp(200, '{"data":{"about":{"version":"6.2.0"}}}',
                                {"Content-Type": "application/json"}), service_name="OpenCTI")
assert v["ok"] is True and v["layer"] == cfd.LAYER_OK
print("PASS: a normal JSON 200 is reported as reachable")

# transport failures
import httpx
v = cfd.classify_exception(httpx.ConnectError("nodename nor servname provided"), service_name="OpenCTI")
assert v["layer"] == cfd.LAYER_TRANSPORT and "ConnectError" in v["message"]
assert any("tunnel" in r.lower() for r in v["remediation"])
print("PASS: DNS/connect failures are separated from anything Cloudflare or the app did")


# ============ outbound requests identify themselves ============

h = cfd.api_headers({"Authorization": "Bearer x"})
assert h["User-Agent"].startswith("Nightwatch-VulnMgmt/")
assert h["Authorization"] == "Bearer x" and h["Accept"] == "application/json"
print("PASS: outbound calls send a descriptive User-Agent instead of httpx's default "
      "(which is exactly what bot rules key on)")


# ============ the real call sites use it ============

for module, needle in (("cti.py", "classify_response"), ("reconng.py", "classify_response"),
                        ("threat_intel_watchlist.py", "classify_response"),
                        ("routes/findings.py", "classify_response")):
    src = open(module).read()
    assert needle in src, f"{module} still swallows the raw response"
    assert "cf_diagnostics" in src
print("PASS: every OpenCTI call site (CTI hub sync, recon lookup, watchlist feed, Test Connection) "
      "routes failures through the shared diagnostic")

for module in ("cti.py", "reconng.py", "threat_intel_watchlist.py", "routes/findings.py"):
    src = open(module).read()
    assert 'f"OpenCTI HTTP {r.status_code}: {r.text' not in src, \
        f"{module} still pastes the raw response body into the error"
print("PASS: no OpenCTI call site pastes a raw HTML body into the error message any more")


# ============ end-to-end through the real sync function ============

import cti


class FakeChallengeClient:
    def __init__(self, *a, **kw): pass
    async def __aenter__(self): return self
    async def __aexit__(self, *a): return False
    async def post(self, url, **kw):
        return Resp(403, JUST_A_MOMENT, CF_HEADERS)


_real = httpx.AsyncClient
httpx.AsyncClient = FakeChallengeClient
db = db_module.db
run = lambda c: asyncio.get_event_loop().run_until_complete(c)
run(db.integrations.insert_one({"id": "octi", "name": "OpenCTI", "type": "threat_intel",
                                 "config": {"endpoint": "https://open.example.net", "api_key": "tok",
                                             "cf_access_client_id": "abcd1234ef.access",
                                             "cf_access_client_secret": "s3cret"}}))
try:
    run(cti.sync_opencti_reports(db))
    raise AssertionError("expected a RuntimeError")
except RuntimeError as e:
    msg = str(e)
    assert "<!DOCTYPE" not in msg and "<html" not in msg
    assert "bot protection" in msg.lower()
    assert "Super Bot Fight Mode" in msg
httpx.AsyncClient = _real
print("PASS: the OpenCTI reports sync now fails with 'blocked by Cloudflare's bot protection … "
      "Start here: Super Bot Fight Mode', not a wall of HTML")
