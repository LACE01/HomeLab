"""OWASP WSTG library: findings -> test cases, and honest coverage.

The value of a testing GUIDE over an ad-hoc checklist is that it tells you what
you did NOT test. So the tests here weight as heavily toward "a category with no
findings is reported as untested, not clean" as toward the mappings themselves.
"""
import os, sys
sys.path.insert(0, ".")
import wstg


def a(c, m=""): assert c, m


# ============ catalogue integrity ============

ids = [t["id"] for t in wstg.TESTS]
a(len(ids) == len(set(ids)), "duplicate WSTG ids in the catalogue")
for t in wstg.TESTS:
    a(t["id"].startswith("WSTG-"), f"malformed id {t['id']}")
    a(t["category"] in wstg.CATEGORY_NAME, f"{t['id']} has an unknown category")
    a(t["name"], f"{t['id']} has no name")
    a(t["cwes"] or t["keywords"], f"{t['id']} maps from neither CWE nor keyword — it can never match")
print(f"PASS: all {len(wstg.TESTS)} WSTG test cases are well-formed, uniquely id'd, in a known "
      "category, and reachable by at least one of CWE or keyword")

a(len(wstg.CATEGORIES) == 11, "WSTG has eleven categories")
print("PASS: all eleven WSTG categories are represented")


# ============ CWE mapping is precise ============

for cwe, expect in [("CWE-89", "WSTG-INPV-05"), ("CWE-79", "WSTG-INPV-01"),
                     ("CWE-22", "WSTG-ATHZ-01"), ("CWE-352", "WSTG-SESS-05"),
                     ("CWE-918", "WSTG-INPV-19"), ("CWE-611", "WSTG-INPV-07")]:
    hits = wstg.tests_for_finding({"cwe": cwe, "title": "x"})
    ids = [h["id"] for h in hits]
    a(expect in ids, f"{cwe} should map to {expect}, got {ids}")
    a(next(h for h in hits if h["id"] == expect)["basis"] == "cwe", f"{cwe} should be a CWE-basis map")
print("PASS: findings with a CWE map precisely — CWE-89 -> SQL Injection, CWE-352 -> CSRF, "
      "CWE-918 -> SSRF — and are marked 'cwe' basis")

# a bare Qualys-style CWE number still maps
a([h["id"] for h in wstg.tests_for_finding({"cwe": "89"})] == ["WSTG-INPV-05"],
  "a bare '89' CWE should normalize and map")
print("PASS: a bare-number CWE (as Qualys emits) normalizes and maps")


# ============ the CWE-less majority maps on text ============

cases = [
    ("SSL/TLS Server Supports Deprecated Protocol SSLv3", "WSTG-CRYP-01"),
    ("HTTP Strict Transport Security (HSTS) Not Enforced", "WSTG-CONF-07"),
    ("Session Cookie Missing HttpOnly and Secure Flags", "WSTG-SESS-02"),
    ("Web Server Directory Listing Enabled", "WSTG-INFO-10"),
    ("Clickjacking: X-Frame-Options Header Missing", "WSTG-CLNT-09"),
    ("Open Redirect in Login Page", "WSTG-CLNT-04"),
    ("Verbose Error Message Discloses Stack Trace", "WSTG-ERRH-01"),
    ("Default Credentials on Admin Console", "WSTG-ATHN-02"),
    ("User Enumeration via Login Response", "WSTG-IDNT-04"),
]
for title, expect in cases:
    hits = wstg.tests_for_finding({"title": title})
    ids = [h["id"] for h in hits]
    a(expect in ids, f"{title!r} should map to {expect}, got {ids}")
    a(next(h for h in hits if h["id"] == expect)["basis"] == "signature",
      f"{title!r} has no CWE, so it should be a signature-basis map")
print(f"PASS: all {len(cases)} real CWE-less scanner titles map on their text — the configuration "
      "findings WSTG most needs to cover, marked 'signature' basis so the inference is visible")


# ============ web-irrelevant findings map to nothing, and that's correct ============

# CWE-416 (use-after-free) is not a WSTG web test, and the title carries no
# web-testing keyword -- so this maps to nothing, which is correct.
hits = wstg.tests_for_finding({"title": "Linux Kernel Use-After-Free in netfilter subsystem",
                                "cwe": "CWE-416"})
a(hits == [], f"a kernel memory-corruption CVE should map to no WSTG test, got {hits}")
print("PASS: a non-web finding maps to nothing — WSTG covers web app testing, and forcing an "
      "irrelevant test onto a kernel CVE would be worse than an honest blank")

# Contrast: a finding whose text DOES contain a web-testing keyword maps, even
# though it might not be strictly web -- keyword matching is medium confidence by
# design, and the 'signature' basis says so. A web app's own privilege-escalation
# finding SHOULD reach WSTG-ATHZ-03.
web_pe = wstg.tests_for_finding({"title": "Vertical Privilege Escalation in the admin portal"})
a("WSTG-ATHZ-03" in [h["id"] for h in web_pe], "web PE should reach ATHZ-03")
print("PASS: a web finding that mentions privilege escalation DOES reach WSTG-ATHZ-03 — text "
      "matching is medium-confidence and labelled 'signature', not suppressed")


# ============ coverage reports untested categories as untested ============

findings = [
    {"title": "SQL Injection in search", "cwe": "CWE-89"},
    {"title": "Reflected XSS in profile", "cwe": "CWE-79"},
    {"title": "SSL/TLS Supports SSLv3"},
    {"title": "SSL Weak Cipher RC4"},          # same test, second finding
]
cov = wstg.coverage(findings)
by_cat = {c["category"]: c for c in cov["categories"]}

a(by_cat["INPV"]["status"] == "evidence" and by_cat["INPV"]["tests_with_evidence"] >= 2)
a(by_cat["CRYP"]["status"] == "evidence")
# categories with no matching findings must be flagged, not silently 0
a(by_cat["ATHZ"]["status"] == "no_evidence")
a(by_cat["BUSL"]["status"] == "no_evidence")
print("PASS: coverage marks categories with findings as evidenced and categories WITHOUT as "
      "'no_evidence' — the distinction a checklist can't make and a methodology must")

a("not tested, not that it is clean" in cov["note"])
print("PASS: the coverage note states plainly that absence of a finding is absence of a test")

# a category's evidenced tests carry their finding counts
cryp = by_cat["CRYP"]
tls = next(t for t in cryp["evidenced_tests"] if t["id"] == "WSTG-CRYP-01")
a(tls["findings"] == 2, "two TLS findings should both count toward WSTG-CRYP-01")
print("PASS: an evidenced test shows how many findings support it — two weak-TLS findings both "
      "count toward WSTG-CRYP-01")

a(cov["tests_total"] == len(wstg.TESTS))
a(0 < cov["coverage_pct"] < 100)
print("PASS: overall coverage is a real fraction of the catalogue, not a fabricated 100%")


# ============ Security Review questionnaire domains map to WSTG ============

auth = [t["id"] for t in wstg.tests_for_domain("authentication")]
a("WSTG-ATHN-01" in auth and "WSTG-SESS-02" in auth)
appsec = [t["id"] for t in wstg.tests_for_domain("application_security")]
a("WSTG-INPV-05" in appsec)
a(wstg.tests_for_domain("nonexistent-domain") == [])
print("PASS: questionnaire domains map to their WSTG categories — a Security Review's "
      "authentication questions point at the ATHN/IDNT/SESS methodology, app-security at INPV")


# ============ catalogue view groups by category in order ============

cat = wstg.catalogue()
a([c["category"] for c in cat] == [c[0] for c in wstg.CATEGORIES], "catalogue order should match")
a(sum(len(c["tests"]) for c in cat) == len(wstg.TESTS), "every test appears once in the catalogue")
print("PASS: the catalogue groups every test under its category, in WSTG assessment order")


# ============ routes ============

import asyncio
os.environ.setdefault("MONGO_URL", "mongodb://localhost:27017")
os.environ.setdefault("DB_NAME", "test_wstg")
os.environ.setdefault("JWT_SECRET", "testsecret")
from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_wstg"]
db = db_module.db

import server, auth_utils
from routes import wstg as wstg_route
wstg_route.db = db
from fastapi.testclient import TestClient
run = lambda c: asyncio.get_event_loop().run_until_complete(c)

admin = {"id": "u1", "email": "a@x.com", "role": "admin", "name": "A", "teams": []}
server.app.dependency_overrides[auth_utils.get_current_user] = lambda: admin
client = TestClient(server.app)

run(db.findings.insert_many([
    {"id": "f-sqli", "title": "SQL Injection in search", "cwe": "CWE-89", "status": "New"},
    {"id": "f-tls", "title": "SSL/TLS Server Supports SSLv3", "status": "New"},
    {"id": "f-kernel", "title": "Linux Kernel Use-After-Free", "cwe": "CWE-416", "status": "New"},
]))

r = client.get("/api/v1/wstg/catalogue")
assert r.status_code == 200 and r.json()["test_count"] == len(wstg.TESTS)
assert len(r.json()["categories"]) == 11
print("PASS: GET /v1/wstg/catalogue returns the full library grouped into eleven categories")

r = client.get("/api/v1/findings/f-sqli/wstg")
assert r.status_code == 200, r.text
body = r.json()
assert body["in_scope"] is True
assert "WSTG-INPV-05" in [t["id"] for t in body["tests"]]
print("PASS: GET /v1/findings/{id}/wstg maps a SQLi finding to WSTG-INPV-05 — the route resolves "
      "alongside the other /v1/findings/{id}/* endpoints")

r = client.get("/api/v1/findings/f-kernel/wstg")
assert r.json()["in_scope"] is False
assert "not web-related" in r.json()["note"]
print("PASS: a non-web finding reports in_scope=false with an explanation, not an empty list that "
      "looks like a mapping failure")

assert client.get("/api/v1/findings/nope/wstg").status_code == 404

r = client.get("/api/v1/wstg/coverage")
cov = r.json()
assert cov["tests_with_evidence"] >= 2
inpv = next(c for c in cov["categories"] if c["category"] == "INPV")
assert inpv["status"] == "evidence"
athz = next(c for c in cov["categories"] if c["category"] == "ATHZ")
assert athz["status"] == "no_evidence"
print("PASS: GET /v1/wstg/coverage reports evidenced vs untested categories across the live "
      "backlog, cached like the other whole-backlog aggregates")
