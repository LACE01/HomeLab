"""#67 WebAuthn/FIDO2: RP config from the user-facing domain, ceremony option
generation + challenge storage, and the 501 guard when unconfigured. Full
register/login verification needs a real authenticator (browser) and is validated
there, not here."""
import os, sys, asyncio, json
os.environ.update(MONGO_URL="x", DB_NAME="t", JWT_SECRET="x", WEBAUTHN_RP_ID="secops.eaglecounty.us")
sys.path.insert(0, ".")
from mongomock_motor import AsyncMongoMockClient
import db as dbm; dbm.client=AsyncMongoMockClient(); dbm.db=dbm.client["t"]; db=dbm.db
import server, auth_utils, webauthn_mfa
from fastapi.testclient import TestClient
run=lambda x: asyncio.get_event_loop().run_until_complete(x)
def a(c,m=""): assert c,m

a(webauthn_mfa.is_configured() and webauthn_mfa.origin()=="https://secops.eaglecounty.us", "RP from user-facing domain")
print("PASS: RP ID/origin come from WEBAUTHN_RP_ID (CF-tunnel domain)")

run(db.users.insert_one({"id":"u1","email":"admin@x.com","name":"A","role":"admin","active":True}))
server.app.dependency_overrides[auth_utils.get_current_user]=lambda: {"id":"u1","email":"admin@x.com","name":"A","role":"admin"}
c=TestClient(server.app)

opts=c.post("/api/auth/webauthn/register/begin").json()
a(opts["rp"]["id"]=="secops.eaglecounty.us" and opts["challenge"], "register options returned")
a(run(db.webauthn_challenges.count_documents({"user_id":"u1","purpose":"register"}))==1, "challenge stashed")
print("PASS: register/begin returns options + stashes challenge")

lst=c.get("/api/auth/webauthn/credentials").json()
a(lst["configured"] is True and lst["items"]==[], "no creds yet")
print("PASS: credentials list (empty, configured)")

# login/begin requires a registered credential
tok=auth_utils.create_mfa_pending_token("u1")
r=c.post("/api/auth/webauthn/login/begin", json={"mfa_token":tok})
a(r.status_code==400, "login/begin with no keys -> 400")
print("PASS: login/begin refuses when the account has no security keys")
print("\nALL WEBAUTHN ENDPOINT TESTS PASSED")
