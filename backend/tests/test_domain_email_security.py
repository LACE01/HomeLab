import os, sys, asyncio
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_domain_email_security"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_domain_email_security"]

import server
import auth_utils
from routes import domain_email_security as domain_route
domain_route.db = db_module.db

from fastapi.testclient import TestClient

admin_user = {"id": "u1", "email": "admin@x.com", "role": "admin", "name": "Admin", "teams": []}
app = server.app
app.dependency_overrides[auth_utils.get_current_user] = lambda: admin_user
client = TestClient(app)

db = db_module.db


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


import domain_email_security as des

# ============ classify() -- pure unit tests, no DNS involved ============

NO_SPF = {"present": False, "record": None, "record_count": 0, "all_mechanism": None}
GOOD_SPF = {"present": True, "record": "v=spf1 include:_spf.example.com -all", "record_count": 1, "all_mechanism": "-all"}
PERMISSIVE_SPF = {"present": True, "record": "v=spf1 include:_spf.example.com +all", "record_count": 1, "all_mechanism": "+all"}
MULTI_SPF = {"present": True, "record": "v=spf1 -all", "record_count": 2, "all_mechanism": "-all"}

NO_DMARC = {"present": False, "record": None, "policy": None, "rua": None}
NONE_DMARC = {"present": True, "record": "v=DMARC1; p=none", "policy": "none", "rua": None}
NO_RUA_DMARC = {"present": True, "record": "v=DMARC1; p=reject", "policy": "reject", "rua": None}
GOOD_DMARC = {"present": True, "record": "v=DMARC1; p=reject; rua=mailto:dmarc@example.com", "policy": "reject", "rua": "mailto:dmarc@example.com"}

NO_DKIM = {"found_selectors": []}
GOOD_DKIM = {"found_selectors": ["google"]}

issues = des.classify(NO_SPF, NO_DMARC, NO_DKIM)
by_check = {i[0]: i for i in issues}
assert by_check["spf"][1] == "High" and by_check["dmarc"][1] == "High" and by_check["dkim"][1] == "Low"
assert len(issues) == 3
print("PASS: classify() flags all three checks independently when everything is missing")

issues2 = des.classify(GOOD_SPF, GOOD_DMARC, GOOD_DKIM)
assert issues2 == []
print("PASS: classify() returns no issues for a fully healthy domain")

issues3 = des.classify(MULTI_SPF, GOOD_DMARC, GOOD_DKIM)
assert len(issues3) == 1 and issues3[0][0] == "spf" and issues3[0][1] == "High"
assert "Multiple SPF records" in issues3[0][2]
print("PASS: classify() flags multiple SPF records as High (RFC 7208 violation) even though a -all mechanism is present")

issues4 = des.classify(PERMISSIVE_SPF, GOOD_DMARC, GOOD_DKIM)
assert len(issues4) == 1 and issues4[0] == ("spf", "Medium", issues4[0][2])
print("PASS: classify() flags a +all SPF record as Medium (present but permissive)")

issues5 = des.classify(GOOD_SPF, NONE_DMARC, GOOD_DKIM)
assert len(issues5) == 1 and issues5[0][0] == "dmarc" and issues5[0][1] == "Medium"
print("PASS: classify() flags DMARC p=none as Medium (monitor-only, not enforced)")

issues6 = des.classify(GOOD_SPF, NO_RUA_DMARC, GOOD_DKIM)
assert len(issues6) == 1 and issues6[0] == ("dmarc", "Low", issues6[0][2])
print("PASS: classify() flags a DMARC record with an enforcing policy but no rua reporting as Low")

# ============ check_spf / check_dmarc / check_dkim -- DNS mocked out ============

_FAKE_TXT = {}


def _fake_txt_strings(name):
    return _FAKE_TXT.get(name, [])


des._txt_strings = _fake_txt_strings

_FAKE_TXT["good.example.com"] = ["v=spf1 include:_spf.google.com -all"]
r = des.check_spf("good.example.com")
assert r["present"] is True and r["all_mechanism"] == "-all" and r["record_count"] == 1
print("PASS: check_spf parses a single well-formed SPF record")

_FAKE_TXT["multi.example.com"] = ["v=spf1 -all", "v=spf1 include:other.com ~all"]
r2 = des.check_spf("multi.example.com")
assert r2["record_count"] == 2
print("PASS: check_spf detects multiple SPF records on the same domain")

_FAKE_TXT["none.example.com"] = ["some-unrelated-txt-record"]
r3 = des.check_spf("none.example.com")
assert r3["present"] is False and r3["record_count"] == 0
print("PASS: check_spf correctly reports absence when no v=spf1 record exists")

_FAKE_TXT["_dmarc.good.example.com"] = ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100"]
d = des.check_dmarc("good.example.com")
assert d["present"] and d["policy"] == "reject" and d["rua"] == "mailto:dmarc@example.com" and d["pct"] == "100"
print("PASS: check_dmarc looks up _dmarc.<domain> and parses tag=value pairs correctly")

r4 = des.check_dmarc("nodmarc.example.com")
assert r4["present"] is False
print("PASS: check_dmarc reports absence cleanly when no DMARC record exists")

_FAKE_TXT["google._domainkey.dkim.example.com"] = ["v=DKIM1; k=rsa; p=MIIBIjANBg..."]
k = des.check_dkim("dkim.example.com", selectors=["nope", "google", "alsonope"])
assert k["found_selectors"] == ["google"]
assert k["best_effort"] is True
print("PASS: check_dkim finds a matching selector among a candidate list and marks the check best-effort")

k2 = des.check_dkim("nodkim.example.com", selectors=["nope1", "nope2"])
assert k2["found_selectors"] == []
print("PASS: check_dkim returns no selectors when none of the candidates resolve")

# ============ run_domain_check -- findings lifecycle ============

des.check_spf = lambda domain: dict(NO_SPF)
des.check_dmarc = lambda domain: dict(NONE_DMARC)
des.check_dkim = lambda domain, selectors=None: dict(GOOD_DKIM)

result = run(des.run_domain_check(db, "acme.com"))
assert result["domain"] == "acme.com" and len(result["issues"]) == 2
print("PASS: run_domain_check aggregates SPF+DMARC issues (DKIM healthy -> no 3rd issue) into the stored result")

spf_finding = run(db.findings.find_one({"canonical_key": "email-auth:acme.com:spf"}, {"_id": 0}))
dmarc_finding = run(db.findings.find_one({"canonical_key": "email-auth:acme.com:dmarc"}, {"_id": 0}))
dkim_finding = run(db.findings.find_one({"canonical_key": "email-auth:acme.com:dkim"}, {"_id": 0}))
assert spf_finding is not None and spf_finding["severity"] == "High" and spf_finding["status"] == "New"
assert dmarc_finding is not None and dmarc_finding["severity"] == "Medium"
assert dkim_finding is None
print("PASS: run_domain_check creates independent findings only for the checks that actually have an issue")

stored = run(db.domain_email_security.find_one({"id": "acme.com"}, {"_id": 0}))
assert stored is not None and stored["spf"]["present"] is False
print("PASS: run_domain_check upserts the raw check result into domain_email_security")

# Re-run with a worse SPF condition present (still no SPF) but bump severity path via DMARC now fixed
des.check_dmarc = lambda domain: dict(GOOD_DMARC)
result2 = run(des.run_domain_check(db, "acme.com"))
dmarc_finding2 = run(db.findings.find_one({"canonical_key": "email-auth:acme.com:dmarc"}, {"_id": 0}))
assert dmarc_finding2["status"] == "Fixed validated"
print("PASS: run_domain_check auto-resolves a finding whose underlying check now passes")

spf_finding2 = run(db.findings.find_one({"canonical_key": "email-auth:acme.com:spf"}, {"_id": 0}))
assert spf_finding2["status"] == "New"  # still broken, untouched
print("PASS: run_domain_check leaves a still-broken check's finding open across re-checks")

# A human closes the SPF finding manually -- re-running while still broken must not reopen it
run(db.findings.update_one({"id": spf_finding2["id"]}, {"$set": {"status": "Fixed validated"}}))
run(des.run_domain_check(db, "acme.com"))
spf_finding3 = run(db.findings.find_one({"canonical_key": "email-auth:acme.com:spf"}, {"_id": 0}))
assert spf_finding3["status"] == "Fixed validated"
print("PASS: run_domain_check never auto-reopens a finding a human already closed, even if the check still fails")

# ============ run_all_domain_checks -- batch runner over enabled watch targets ============

run(db.domain_watch_targets.insert_many([
    {"id": "t1", "domain": "acme.com", "enabled": True, "asset_id": None, "label": None},
    {"id": "t2", "domain": "beta.com", "enabled": True, "asset_id": None, "label": None},
    {"id": "t3", "domain": "disabled.com", "enabled": False, "asset_id": None, "label": None},
]))
des.check_spf = lambda domain: dict(GOOD_SPF)
des.check_dmarc = lambda domain: dict(GOOD_DMARC)
des.check_dkim = lambda domain, selectors=None: dict(GOOD_DKIM)
batch = run(des.run_all_domain_checks(db))
assert batch["checked"] == 2  # disabled.com skipped
assert batch["issues"] == 0
print("PASS: run_all_domain_checks only checks enabled targets and reports a clean batch")

# ============ routes ============

des.check_spf = lambda domain: dict(NO_SPF)
des.check_dmarc = lambda domain: dict(NO_DMARC)
des.check_dkim = lambda domain, selectors=None: dict(NO_DKIM)

r = client.post("/api/v1/admin/email-auth/targets", json={"domain": "Widget.COM", "label": "Primary"})
assert r.status_code == 200, r.text
created = r.json()
assert created["domain"] == "widget.com"  # lowercased
print("PASS: POST /v1/admin/email-auth/targets creates a watch target and normalizes the domain to lowercase")

r_bad = client.post("/api/v1/admin/email-auth/targets", json={"domain": "not a domain"})
assert r_bad.status_code == 400
print("PASS: POST /v1/admin/email-auth/targets rejects an invalid domain")

r2 = client.get("/api/v1/admin/email-auth/targets")
assert r2.status_code == 200, r2.text
items = r2.json()["items"]
assert any(t["domain"] == "widget.com" for t in items)
print("PASS: GET /v1/admin/email-auth/targets lists watch targets")

r3 = client.post(f"/api/v1/admin/email-auth/targets/{created['id']}/check-now")
assert r3.status_code == 200, r3.text
assert len(r3.json()["issues"]) == 3
print("PASS: POST /v1/admin/email-auth/targets/{id}/check-now runs a real check through the route")

r4 = client.get("/api/v1/admin/email-auth/targets")
widget = next(t for t in r4.json()["items"] if t["domain"] == "widget.com")
assert widget["latest"] is not None and widget["latest"]["domain"] == "widget.com"
print("PASS: GET /v1/admin/email-auth/targets merges each target with its latest check result")

r5 = client.put(f"/api/v1/admin/email-auth/targets/{created['id']}", json={"domain": "widget.com", "label": "Updated", "enabled": False})
assert r5.status_code == 200 and r5.json()["enabled"] is False
print("PASS: PUT /v1/admin/email-auth/targets/{id} updates a watch target")

r6 = client.post("/api/v1/admin/email-auth/check-all")
assert r6.status_code == 200, r6.text
print("PASS: POST /v1/admin/email-auth/check-all runs the batch route")

r7 = client.delete(f"/api/v1/admin/email-auth/targets/{created['id']}")
assert r7.status_code == 200 and r7.json()["ok"] is True
r8 = client.get("/api/v1/admin/email-auth/targets")
assert not any(t["id"] == created["id"] for t in r8.json()["items"])
print("PASS: DELETE /v1/admin/email-auth/targets/{id} removes the watch target")

# ============ feature flag + notification template wiring ============

import feature_flags
assert "email_auth_nightly_check" in feature_flags.FLAG_KEYS
print("PASS: email_auth_nightly_check is registered in the feature flag registry")

import notifier
assert "email_auth_issue" in notifier.TRIGGERS
assert "email_auth_issue" in notifier.TEMPLATES
rendered_subject = notifier.TEMPLATES["email_auth_issue"]["subject"].format(check_type="SPF", domain="acme.com")
assert "SPF" in rendered_subject and "acme.com" in rendered_subject
print("PASS: email_auth_issue notification trigger + template are wired and render correctly")

# ============ rbac module registration ============

import rbac
assert any(m["key"] == "/admin/email-auth" for m in rbac.MODULE_REGISTRY)
print("PASS: /admin/email-auth is registered as an RBAC module key")

print("\nALL SPF/DKIM/DMARC EMAIL AUTH MONITORING TESTS PASSED")
