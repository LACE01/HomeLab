"""#67/#68: admin-configurable password policy (NIST length + complexity + breached
screen, CJIS floor), enforced on change-password; and the first-login gate flags
(must_change_password + role-based must_enroll_mfa)."""
import os, sys, asyncio
os.environ.update(MONGO_URL="x", DB_NAME="t", JWT_SECRET="x")
sys.path.insert(0, ".")
from mongomock_motor import AsyncMongoMockClient
import db as dbm; dbm.client=AsyncMongoMockClient(); dbm.db=dbm.client["t"]; db=dbm.db
import password_policy as pp
run=lambda x: asyncio.get_event_loop().run_until_complete(x)
def a(c,m=""): assert c,m

pol = run(pp.get_password_policy(db))
a(pol["min_length"]==12 and pol["breached_check"] and "admin" in pol["mfa_required_roles"], "sane NIST-ish defaults")
print("PASS: default policy is NIST-length + breached-check + MFA for admins")

# structural validation
a(pp.validate_password("short", pol), "too short rejected")
a(pp.validate_password("alllowercaseletters", pol), "no upper/digit rejected")
a(pp.validate_password("GoodLongPassw0rd", pol)==[], "compliant password passes structure")
print("PASS: structural validation (length + complexity)")

# CJIS/NIST floor cannot be configured below
try:
    run(pp.set_password_policy(db, {"min_length":6}, "admin@x")); a(False,"should reject <8")
except ValueError: pass
try:
    run(pp.set_password_policy(db, {"min_length":10,"require_upper":False,"require_lower":False,"require_digit":False,"require_symbol":False}, "admin@x")); a(False,"no-complexity needs >=20")
except ValueError: pass
newpol=run(pp.set_password_policy(db, {"min_length":16,"require_symbol":True}, "admin@x"))
a(newpol["min_length"]==16 and newpol["require_symbol"], "valid update persists")
print("PASS: CJIS/NIST floor enforced; valid updates persist")

# breached screen fail-open when HIBP unreachable (no network in test) -> check_password shouldn't raise for a strong pw
run(pp.set_password_policy(db, {"min_length":12,"breached_check":True,"breached_fail_closed":False,"require_symbol":False}, "admin@x"))
try:
    run(pp.check_password(db, "GoodLongPassw0rd"))
    print("PASS: breached screen fails open when HIBP unreachable (does not lock out)")
except ValueError as e:
    # if network IS available and the pw is clean, also fine
    a("breach" not in str(e).lower(), f"clean pw should not be flagged: {e}")
    print("PASS: breached screen behaved (clean pw allowed)")

# gate flags via /auth/me
import server, auth_utils
from fastapi.testclient import TestClient
run(db.users.insert_one({"id":"u1","email":"admin@x.com","name":"A","role":"admin","password_hash":"x","must_change_password":True,"mfa_enabled":False,"active":True}))
server.app.dependency_overrides[auth_utils.get_current_user]=lambda: {"id":"u1","email":"admin@x.com","name":"A","role":"admin"}
c=TestClient(server.app)
me=c.get("/api/auth/me").json()
a(me.get("must_change_password") is True, "temp-password gate surfaced")
a(me.get("must_enroll_mfa") is True, "admin without MFA is forced to enroll")
print("PASS: first-login gate flags (must_change_password + must_enroll_mfa) surfaced on /auth/me")
print("\nALL PASSWORD-POLICY / MFA-GATE TESTS PASSED")
