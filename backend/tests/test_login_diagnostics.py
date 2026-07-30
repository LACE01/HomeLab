"""A failed sign-in must say WHY it failed.

"Login failed" was shown for every possible cause: wrong password, backend
container down, database unreachable, rate limit, and a frontend built without
REACT_APP_BACKEND_URL. Those need four different actions, and three of them are
not the user's password — so the one message that gets shown is actively
misleading in the majority of cases.

This is the same defect as "OpenCTI HTTP 403: <!DOCTYPE html>": an infrastructure
failure wearing the costume of a credential failure. These tests pin the
backend guarantees the frontend's classifier depends on, and statically check the
frontend actually classifies rather than falling back to one string.
"""
import os, sys, asyncio, re
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_login_diag"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_login_diag"]

import server
from routes import auth as auth_route, health as health_route
auth_route.db = db_module.db
health_route.db = db_module.db

from fastapi.testclient import TestClient
from auth_utils import hash_password

client = TestClient(server.app)
db = db_module.db
run = lambda c: asyncio.get_event_loop().run_until_complete(c)

run(db.users.insert_one({"id": "u1", "email": "luis@example.com", "name": "Luis", "role": "admin",
                          "password_hash": hash_password("Correct-Horse-1"), "active": True, "teams": []}))


# ============ the health probe the login page relies on ============

# The whole classification hinges on being able to ask "is the backend there?"
# WITHOUT a session -- if this needed auth it would be useless on a login screen.
r = client.get("/api/v1/healthz")
assert r.status_code == 200, r.status_code
assert r.json()["status"] == "ok"
print("PASS: /api/v1/healthz answers without authentication, so a login page can distinguish "
      "'backend is down' from 'credentials rejected'")

# and it reports a database problem rather than lying that everything is fine
class BrokenDB:
    async def command(self, *a, **kw):
        raise RuntimeError("connection refused")

_real_db = health_route.db
health_route.db = BrokenDB()
body = client.get("/api/v1/healthz").json()
assert body["status"] == "error" and "connection refused" in body["error"]
health_route.db = _real_db
print("PASS: healthz reports an unreachable database instead of returning ok — 'API up, DB down' is a "
      "distinct failure and logins cannot succeed in it")


# ============ the backend still distinguishes its own failure modes ============

r = client.post("/api/auth/login", json={"email": "luis@example.com", "password": "Correct-Horse-1"})
assert r.status_code == 200 and r.json()["token"]
print("PASS: a correct password still logs in (the diagnostics change did not touch the auth path)")

r = client.post("/api/auth/login", json={"email": "luis@example.com", "password": "wrong"})
assert r.status_code == 401 and r.json()["detail"] == "Invalid credentials"
print("PASS: a wrong password is a 401 with a specific detail, which the frontend shows verbatim")

r = client.post("/api/auth/login", json={"email": "nobody@example.com", "password": "x"})
assert r.status_code == 401, "an unknown account must not be distinguishable from a bad password"
print("PASS: an unknown account is indistinguishable from a bad password (no account enumeration)")


# ============ the frontend classifies instead of collapsing to one string ============

api_js = open("../frontend/src/lib/api.js").read()
login_jsx = open("../frontend/src/pages/Login.jsx").read()

# the build-time trap: REACT_APP_BACKEND_URL is compiled in, so a build without
# it produces requests to the literal string "undefined/api"
assert "BACKEND_URL_MISSING" in api_js
assert '"undefined"' in api_js and '"null"' in api_js, \
    "a missing env var stringifies to 'undefined' -- that literal must be treated as missing"
assert "probeBackend" in api_js and "/v1/healthz" in api_js
print("PASS: the frontend detects being built without REACT_APP_BACKEND_URL — the failure that makes "
      "every request fail with no response and looks exactly like a bad password")

assert "describeLoginError" in login_jsx and "probeBackend" in login_jsx
assert 'setErr(ex.response?.data?.detail || "Login failed")' not in login_jsx, \
    "the catch-all 'Login failed' string must no longer be the answer to every failure"
print("PASS: the login page routes failures through the classifier instead of the catch-all string")

# each distinct cause must produce a distinct, actionable sentence
for needle, why in [
    ("REACT_APP_BACKEND_URL", "names the env var for the build-misconfig case"),
    ("never checked", "says the credentials were never checked when nothing responded"),
    ("still starting", "offers 'backend restarting' as a cause"),
    ("can't reach its database", "separates API-up-DB-down from a credential problem"),
    ("Too many failed attempts", "explains a 429 rate-limit as a wait, not a retype"),
]:
    assert needle in api_js, f"the classifier does not {why}"
print("PASS: build misconfig, unreachable backend, restarting backend, database down, and rate-limit "
      "each produce their own message naming the actual fix")

# the classifier must never tell someone their password is wrong when nothing answered
no_response_branch = api_js[api_js.index("if (!ex?.response)"):api_js.index("if (probe?.reason === \"database\")")]
assert "credential" not in no_response_branch.lower() or "never checked" in no_response_branch, \
    "the no-response branch must not imply the credentials were the problem"
assert "Invalid credentials" not in no_response_branch
print("PASS: when nothing responded, the message never implies the password was wrong")

# a missing backend URL is reported before the user even tries to sign in
assert "BACKEND_URL_MISSING" in login_jsx
print("PASS: a frontend built with no backend URL says so on page load, rather than after a failed attempt")
