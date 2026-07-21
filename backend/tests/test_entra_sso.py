import os, sys, asyncio
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_entra_sso"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_entra_sso"]

import server
import auth_utils
from routes import auth as auth_route
auth_route.db = db_module.db

from fastapi.testclient import TestClient
import httpx

admin_user = {"id": "u1", "email": "admin@x.com", "role": "admin", "name": "Admin", "teams": []}
app = server.app
# Don't override get_current_user globally here -- the whole point of this test file
# is the unauthenticated SSO entry points, and /auth/me etc. aren't exercised.
client = TestClient(app)

db = db_module.db


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ============ not configured at all -- ENTRA_SSO_ENABLED unset ============

for var in ("ENTRA_SSO_ENABLED", "ENTRA_SSO_REDIRECT_URI", "ENTRA_SSO_ALLOWED_DOMAIN", "ENTRA_SSO_DEFAULT_ROLE"):
    os.environ.pop(var, None)

r = client.get("/api/auth/entra/status")
assert r.status_code == 200 and r.json()["configured"] is False
assert "ENTRA_SSO_ENABLED" in r.json()["reason"]
print("PASS: GET /auth/entra/status reports unconfigured when ENTRA_SSO_ENABLED isn't set")

r2 = client.get("/api/auth/entra/login", follow_redirects=False)
assert r2.status_code == 501
print("PASS: GET /auth/entra/login 501s when SSO isn't enabled")

# ============ enabled but redirect URI missing ============

os.environ["ENTRA_SSO_ENABLED"] = "true"
r3 = client.get("/api/auth/entra/status")
assert r3.status_code == 200 and r3.json()["configured"] is False
assert "ENTRA_SSO_REDIRECT_URI" in r3.json()["reason"]
print("PASS: GET /auth/entra/status reports unconfigured when ENTRA_SSO_REDIRECT_URI isn't set")

# ============ enabled + redirect URI set, but the Entra ID integration itself isn't configured ============

os.environ["ENTRA_SSO_REDIRECT_URI"] = "https://nightwatch.example.com/api/auth/entra/callback"
r4 = client.get("/api/auth/entra/status")
assert r4.status_code == 200 and r4.json()["configured"] is False
assert "Microsoft Entra ID integration isn't configured" in r4.json()["reason"]
print("PASS: GET /auth/entra/status reports unconfigured when the Entra ID connector's tenant/client/secret aren't set")

# ============ fully configured ============

run(db.integrations.insert_one({
    "id": "int-entra", "name": "Microsoft Entra ID", "type": "identity",
    "config": {"tenant_id": "tenant-123", "client_id": "client-abc", "client_secret": "super-secret"},
}))

r5 = client.get("/api/auth/entra/status")
assert r5.status_code == 200 and r5.json()["configured"] is True
print("PASS: GET /auth/entra/status reports configured once ENTRA_SSO_ENABLED + redirect URI + the connector's app registration are all set")

r6 = client.get("/api/auth/entra/login", follow_redirects=False)
assert r6.status_code == 302
loc = r6.headers["location"]
assert loc.startswith("https://login.microsoftonline.com/tenant-123/oauth2/v2.0/authorize")
assert "client_id=client-abc" in loc
assert "redirect_uri=https%3A%2F%2Fnightwatch.example.com%2Fapi%2Fauth%2Fentra%2Fcallback" in loc
assert "state=" in loc
assert "entra_oauth_state" in r6.cookies
print("PASS: GET /auth/entra/login redirects to Microsoft's authorize endpoint with the right params and sets a CSRF state cookie")

# ============ callback -- error passthrough from Microsoft ============

r7 = client.get("/api/auth/entra/callback", params={"error": "access_denied", "error_description": "user cancelled"}, follow_redirects=False)
assert r7.status_code == 302 and r7.headers["location"] == "/login?error=entra_sso"
print("PASS: GET /auth/entra/callback redirects to the login error page when Microsoft itself reports an error")

# ============ callback -- missing / mismatched state (CSRF guard) ============

r8 = client.get("/api/auth/entra/callback", params={"code": "abc"}, follow_redirects=False)
assert r8.status_code == 302 and "error=entra_sso" in r8.headers["location"]
print("PASS: GET /auth/entra/callback rejects a callback with no state at all")

r9 = client.get(
    "/api/auth/entra/callback", params={"code": "abc", "state": "wrong-state"},
    cookies={"entra_oauth_state": "the-real-state"}, follow_redirects=False,
)
assert r9.status_code == 302 and "error=entra_sso" in r9.headers["location"]
print("PASS: GET /auth/entra/callback rejects a callback whose state doesn't match the CSRF cookie")

# ============ callback -- full happy path, Microsoft calls faked out ============

class FakeResponse:
    def __init__(self, status_code, json_data=None, content=b"x"):
        self.status_code = status_code
        self._json = json_data or {}
        self.content = content
        self.text = ""

    def json(self):
        return self._json


class FakeAsyncClient:
    responses = []  # queue consumed in call order: [token_response, graph_me_response]

    def __init__(self, *a, **kw):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, url, **kw):
        assert url == "https://login.microsoftonline.com/tenant-123/oauth2/v2.0/token"
        return FakeAsyncClient.responses.pop(0)

    async def get(self, url, **kw):
        assert url == "https://graph.microsoft.com/v1.0/me"
        assert kw["headers"]["Authorization"].startswith("Bearer fake-access-token")
        return FakeAsyncClient.responses.pop(0)


_real_async_client = httpx.AsyncClient
httpx.AsyncClient = FakeAsyncClient

FakeAsyncClient.responses = [
    FakeResponse(200, {"access_token": "fake-access-token", "expires_in": 3600}),
    FakeResponse(200, {"mail": "Jane.Doe@Contoso.com", "displayName": "Jane Doe", "id": "aad-oid-1"}),
]

r10 = client.get(
    "/api/auth/entra/callback", params={"code": "real-code", "state": "matching-state"},
    cookies={"entra_oauth_state": "matching-state"}, follow_redirects=False,
)
assert r10.status_code == 302 and r10.headers["location"] == "/"
assert "access_token" in r10.cookies
print("PASS: GET /auth/entra/callback completes the exchange, fetches the profile from Graph, and redirects to / with a session cookie")

new_user = run(db.users.find_one({"email": "jane.doe@contoso.com"}, {"_id": 0}))
assert new_user is not None
assert new_user["name"] == "Jane Doe" and new_user["auth_provider"] == "entra" and new_user["entra_oid"] == "aad-oid-1"
assert new_user["role"] == "analyst"  # ENTRA_SSO_DEFAULT_ROLE default
print("PASS: a first-time SSO login auto-provisions a local user with email lowercased, correct provider/oid, and the default role")

login_record = run(db.login_audit.find_one({"email": "jane.doe@contoso.com", "success": True}, {"_id": 0}))
assert login_record is not None and login_record["reason"] == "sso_entra"
print("PASS: a successful SSO login is recorded in login_audit with reason=sso_entra")

# --- second login for the same user: role must NOT be silently changed even if
# an admin promoted them in between logins ---
run(db.users.update_one({"email": "jane.doe@contoso.com"}, {"$set": {"role": "manager"}}))
FakeAsyncClient.responses = [
    FakeResponse(200, {"access_token": "fake-access-token-2", "expires_in": 3600}),
    FakeResponse(200, {"mail": "Jane.Doe@Contoso.com", "displayName": "Jane Doe Updated", "id": "aad-oid-1"}),
]
r11 = client.get(
    "/api/auth/entra/callback", params={"code": "real-code-2", "state": "matching-state-2"},
    cookies={"entra_oauth_state": "matching-state-2"}, follow_redirects=False,
)
assert r11.status_code == 302 and r11.headers["location"] == "/"
updated_user = run(db.users.find_one({"email": "jane.doe@contoso.com"}, {"_id": 0}))
assert updated_user["role"] == "manager"  # untouched by SSO
assert updated_user["name"] == "Jane Doe Updated"  # display name still refreshed
print("PASS: a repeat SSO login refreshes the display name but never touches an existing user's role")

# --- a disabled account must be rejected even though SSO auth itself succeeded ---
run(db.users.update_one({"email": "jane.doe@contoso.com"}, {"$set": {"active": False}}))
FakeAsyncClient.responses = [
    FakeResponse(200, {"access_token": "fake-access-token-3", "expires_in": 3600}),
    FakeResponse(200, {"mail": "Jane.Doe@Contoso.com", "displayName": "Jane Doe", "id": "aad-oid-1"}),
]
r12 = client.get(
    "/api/auth/entra/callback", params={"code": "real-code-3", "state": "matching-state-3"},
    cookies={"entra_oauth_state": "matching-state-3"}, follow_redirects=False,
)
assert r12.status_code == 302 and "error=entra_sso" in r12.headers["location"]
assert "access_token" not in r12.cookies
print("PASS: a disabled account is rejected at the SSO callback even with a valid Microsoft identity")
run(db.users.update_one({"email": "jane.doe@contoso.com"}, {"$set": {"active": True}}))

# --- token exchange failure surfaces cleanly instead of raising ---
FakeAsyncClient.responses = [FakeResponse(400, {"error": "invalid_grant", "error_description": "code expired"})]
r13 = client.get(
    "/api/auth/entra/callback", params={"code": "expired-code", "state": "matching-state-4"},
    cookies={"entra_oauth_state": "matching-state-4"}, follow_redirects=False,
)
assert r13.status_code == 302 and "error=entra_sso" in r13.headers["location"]
print("PASS: a failed token exchange (e.g. expired code) redirects to the error page instead of raising")

# --- userPrincipalName fallback when Graph doesn't return `mail` ---
FakeAsyncClient.responses = [
    FakeResponse(200, {"access_token": "fake-access-token-4", "expires_in": 3600}),
    FakeResponse(200, {"mail": None, "userPrincipalName": "svc.account@contoso.com", "displayName": "Service Account", "id": "aad-oid-2"}),
]
r14 = client.get(
    "/api/auth/entra/callback", params={"code": "real-code-4", "state": "matching-state-5"},
    cookies={"entra_oauth_state": "matching-state-5"}, follow_redirects=False,
)
assert r14.status_code == 302 and r14.headers["location"] == "/"
svc_user = run(db.users.find_one({"email": "svc.account@contoso.com"}, {"_id": 0}))
assert svc_user is not None
print("PASS: falls back to userPrincipalName when Graph doesn't return a `mail` field")

httpx.AsyncClient = _real_async_client

# ============ ENTRA_SSO_ALLOWED_DOMAIN restriction ============

os.environ["ENTRA_SSO_ALLOWED_DOMAIN"] = "contoso.com"
httpx.AsyncClient = FakeAsyncClient
FakeAsyncClient.responses = [
    FakeResponse(200, {"access_token": "fake-access-token-5", "expires_in": 3600}),
    FakeResponse(200, {"mail": "outsider@othercorp.com", "displayName": "Outsider", "id": "aad-oid-3"}),
]
r15 = client.get(
    "/api/auth/entra/callback", params={"code": "real-code-5", "state": "matching-state-6"},
    cookies={"entra_oauth_state": "matching-state-6"}, follow_redirects=False,
)
assert r15.status_code == 302 and "error=entra_sso" in r15.headers["location"]
outsider = run(db.users.find_one({"email": "outsider@othercorp.com"}, {"_id": 0}))
assert outsider is None
print("PASS: ENTRA_SSO_ALLOWED_DOMAIN rejects an out-of-domain account and never creates a user for it")

FakeAsyncClient.responses = [
    FakeResponse(200, {"access_token": "fake-access-token-6", "expires_in": 3600}),
    FakeResponse(200, {"mail": "insider@contoso.com", "displayName": "Insider", "id": "aad-oid-4"}),
]
r16 = client.get(
    "/api/auth/entra/callback", params={"code": "real-code-6", "state": "matching-state-7"},
    cookies={"entra_oauth_state": "matching-state-7"}, follow_redirects=False,
)
assert r16.status_code == 302 and r16.headers["location"] == "/"
print("PASS: ENTRA_SSO_ALLOWED_DOMAIN still allows an in-domain account through")

httpx.AsyncClient = _real_async_client
for var in ("ENTRA_SSO_ENABLED", "ENTRA_SSO_REDIRECT_URI", "ENTRA_SSO_ALLOWED_DOMAIN", "ENTRA_SSO_DEFAULT_ROLE"):
    os.environ.pop(var, None)

print("\nALL MICROSOFT ENTRA ID SSO TESTS PASSED")
