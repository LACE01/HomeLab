"""Item 30 (two-panel External Checks) + item 35 (shared CT service with
retry/backoff, fallback, empty-is-clean, untruncated errors)."""
import os, sys, asyncio, uuid
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_ext_checks"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_ext_checks"]

import server
import auth_utils
from routes import security_reviews as sr_route
sr_route.db = db_module.db
import ct_service
import external_checks

from fastapi.testclient import TestClient

admin_user = {"id": "u1", "email": "admin@x.com", "role": "admin", "name": "Admin", "teams": []}
app = server.app
app.dependency_overrides[auth_utils.get_current_user] = lambda: admin_user
app.dependency_overrides[auth_utils.get_current_user_optional] = lambda: admin_user
client = TestClient(app)
db = db_module.db


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# =========================================================================
# Item 35 -- shared CT service
# =========================================================================

class Resp:
    def __init__(self, status_code=200, json_data=None, text=None):
        self.status_code = status_code
        self._json = json_data
        self.text = text if text is not None else (str(json_data) if json_data is not None else "")
    def json(self):
        if self._json is None:
            raise ValueError("no json")
        return self._json


CALLS = {"crtsh": 0, "certspotter": 0}
SCRIPT = {"crtsh": [], "certspotter": []}


class FakeClient:
    def __init__(self, *a, **kw): pass
    async def __aenter__(self): return self
    async def __aexit__(self, *a): return False
    async def get(self, url, **kw):
        if "crt.sh" in url:
            CALLS["crtsh"] += 1
            seq = SCRIPT["crtsh"]
            return seq[min(CALLS["crtsh"] - 1, len(seq) - 1)]
        if "certspotter" in url:
            CALLS["certspotter"] += 1
            seq = SCRIPT["certspotter"]
            return seq[min(CALLS["certspotter"] - 1, len(seq) - 1)]
        return Resp(200, {})


import httpx
_real = httpx.AsyncClient
httpx.AsyncClient = FakeClient
ct_service.BASE_BACKOFF = 0.001  # keep the test fast; behaviour is unchanged


def _reset_ct():
    CALLS["crtsh"] = 0
    CALLS["certspotter"] = 0


CERT = [{"id": 1, "common_name": "www.x.com", "name_value": "www.x.com\nvpn.x.com",
         "issuer_name": "Let's Encrypt", "not_before": "2026-01-01", "not_after": "2026-04-01"}]

# --- happy path ---
_reset_ct()
SCRIPT["crtsh"] = [Resp(200, CERT)]
certs = run(ct_service.fetch_certificates("x.com"))
assert len(certs) == 1 and certs[0]["source"] == "crt.sh"
assert CALLS["crtsh"] == 1
print("PASS: CT service returns normalized certs from crt.sh on the first try")

# --- empty result is CLEAN, not an error (the EASM bug) ---
_reset_ct()
SCRIPT["crtsh"] = [Resp(200, [])]
assert run(ct_service.fetch_certificates("empty.com")) == []
_reset_ct()
SCRIPT["crtsh"] = [Resp(404, None, text="not found")]
assert run(ct_service.fetch_certificates("none.com")) == []
print("PASS: an empty CT result (and a 404) is a CLEAN zero-result, not a hard error")

# --- transient 502 retries and then succeeds ---
_reset_ct()
SCRIPT["crtsh"] = [Resp(502, None, text="Bad Gateway"), Resp(502, None, text="Bad Gateway"), Resp(200, CERT)]
certs = run(ct_service.fetch_certificates("flaky.com"))
assert len(certs) == 1
assert CALLS["crtsh"] == 3, "must retry with backoff before giving up"
print("PASS: transient crt.sh 502s are retried with backoff instead of failing the scan")

# --- HTML-with-200 maintenance page is recognized and retried ---
_reset_ct()
SCRIPT["crtsh"] = [Resp(200, None, text="<html><body>maintenance</body></html>"), Resp(200, CERT)]
certs = run(ct_service.fetch_certificates("html.com"))
assert len(certs) == 1 and CALLS["crtsh"] == 2
print("PASS: crt.sh serving an HTML maintenance page with HTTP 200 is detected and retried")

# --- exhausted crt.sh falls back to certspotter ---
_reset_ct()
SCRIPT["crtsh"] = [Resp(503, None, text="down")]
SCRIPT["certspotter"] = [Resp(200, [{"id": "9", "dns_names": ["a.y.com", "b.y.com"],
                                      "issuer": {"name": "DigiCert"},
                                      "not_before": "2026-01-01", "not_after": "2026-06-01"}])]
certs = run(ct_service.fetch_certificates("y.com"))
assert len(certs) == 1 and certs[0]["source"] == "certspotter"
assert CALLS["certspotter"] == 1
print("PASS: when crt.sh is exhausted the CT service falls back to certspotter rather than returning nothing")

# --- both down: full, untruncated error mentioning both sources ---
_reset_ct()
SCRIPT["crtsh"] = [Resp(503, None, text="crtsh detail " + "D" * 300)]
SCRIPT["certspotter"] = [Resp(500, None, text="certspotter detail " + "E" * 300)]
try:
    run(ct_service.fetch_certificates("dead.com"))
    raise AssertionError("expected CTError")
except ct_service.CTError as e:
    msg = str(e)
    assert "crt.sh" in msg and "certspotter" in msg
    assert len(msg) > 200, "error message must not be truncated -- that was the reported complaint"
print("PASS: total CT failure raises one error naming BOTH sources with full (untruncated) upstream text")

# --- hostname helper ---
_reset_ct()
SCRIPT["crtsh"] = [Resp(200, CERT)]
hosts = run(ct_service.fetch_hostnames("x.com"))
assert hosts == ["vpn.x.com", "www.x.com"]
print("PASS: fetch_hostnames extracts deduped in-domain subdomains for EASM discovery")

# --- EASM discovery now delegates to it ---
import easm
_reset_ct()
SCRIPT["crtsh"] = [Resp(502, None, text="busy"), Resp(200, CERT)]
names = run(easm.query_crtsh("x.com"))
assert "vpn.x.com" in names and "x.com" in names
assert CALLS["crtsh"] == 2, "EASM must inherit the shared retry behaviour"
print("PASS: EASM subdomain discovery delegates to the shared CT service and inherits retry/backoff")


# =========================================================================
# Item 30 -- two-panel external checks
# =========================================================================

class ExtClient:
    """Covers OpenCorporates, the vendor site, NVD, Shodan, and crt.sh."""
    def __init__(self, *a, **kw): pass
    async def __aenter__(self): return self
    async def __aexit__(self, *a): return False
    async def get(self, url, **kw):
        if "opencorporates" in url:
            return Resp(200, {"results": {"companies": [
                {"company": {"name": "ACME CORPORATION", "jurisdiction_code": "us_co",
                             "current_status": "Good Standing", "incorporation_date": "2009-04-01",
                             "opencorporates_url": "https://opencorporates.com/companies/us_co/1"}}]}})
        if "nvd.nist.gov" in url:
            return Resp(200, {"totalResults": 3, "vulnerabilities": [{"cve": {"id": "CVE-2026-1"}}]})
        if "shodan.io" in url:
            return Resp(200, {"total": 2, "matches": [{"port": 443, "vulns": ["CVE-2026-2"]}, {"port": 22}]})
        if "crt.sh" in url:
            return Resp(200, CERT)
        if "certspotter" in url:
            return Resp(200, [])
        # the vendor's own site
        class H(dict):
            pass
        r = Resp(200, None, text="ok")
        r.headers = {"Strict-Transport-Security": "max-age=1", "X-Frame-Options": "DENY"}
        r.url = "https://acme.com/"
        return r


run(db.integrations.insert_many([
    {"id": "i1", "name": "Shodan", "type": "threat_intel", "config": {"api_key": "k"}},
]))

client.get("/api/v1/security-reviews/meta")
review = client.post("/api/v1/security-reviews", json={
    "title": "Acme SaaS", "review_type": "New software purchase (SaaS / COTS / on-prem)",
    "entity_name": "Acme", "entity_domain": "acme.com"}).json()
rid = review["id"]

# prerequisite editing (item 30 prereq: domain + legal name on the entity)
r = client.patch(f"/api/v1/security-reviews/{rid}/entity", json={})
assert r.status_code == 400
r = client.patch(f"/api/v1/security-reviews/{rid}/entity",
                  json={"legal_name": "Acme Corporation", "domain": "ACME.com", "jurisdiction": "us_co"})
assert r.status_code == 200
entity = run(db.reviewed_entities.find_one({"name": "Acme"}, {"_id": 0}))
assert entity["legal_name"] == "Acme Corporation" and entity["domain"] == "acme.com"
print("PASS: the entity's legal name / domain / jurisdiction can be filled in from the review workspace")

# certifications feed the company panel
run(db.reviewed_entities.update_one({"id": entity["id"]}, {"$set": {
    "certifications": [{"name": "SOC 2 Type II", "expires_at": "2020-01-01"}]}}))

# seed breach-reputation signals the panel should notice
run(db.cti_ransomware_victims.insert_one({
    "id": "r1", "key": "k", "victim": "Acme", "victim_domain": "acme.com",
    "group": "LockBit", "discovered": "2026-01-01", "match": None, "fetched_at": "2026-01-01"}))
run(db.osint_findings.insert_one({
    "id": "o1", "key": "k", "module": "otx_domain", "target": "acme.com",
    "label": "pulse", "found_at": "2026-01-01"}))

httpx.AsyncClient = ExtClient

r = client.post(f"/api/v1/security-reviews/{rid}/external-checks", params={"panel": "company"})
assert r.status_code == 200
payload = r.json()
assert "company_posture" in payload and "technical_posture" not in payload
company = {c["check"]: c for c in payload["company_posture"]["results"]}
assert set(company) == {"corporate_registration", "breach_reputation",
                         "certification_status", "viability_signals"}
assert company["corporate_registration"]["status"] == "ok"
assert "Good Standing" in company["corporate_registration"]["summary"]
assert company["breach_reputation"]["status"] == "attention"
assert "leak-site" in company["breach_reputation"]["summary"]
assert company["certification_status"]["status"] == "attention"
assert "EXPIRED" in company["certification_status"]["summary"]
assert all(c.get("source_tag") for c in payload["company_posture"]["results"])
print("PASS: Company Posture panel reports registration, breach reputation, certification expiry, and viability -- each source-tagged")

r = client.post(f"/api/v1/security-reviews/{rid}/external-checks", params={"panel": "technical"})
tech = {c["check"]: c for c in r.json()["technical_posture"]["results"]}
assert set(tech) >= {"tls_security_headers", "cve_lookup", "email_authentication",
                      "shodan_exposure", "certificate_transparency", "dns_whois", "typosquat"}
assert tech["tls_security_headers"]["status"] == "attention"      # 3 of 5 headers missing
assert "content-security-policy" in tech["tls_security_headers"]["detail"]["missing"]
assert tech["cve_lookup"]["status"] == "attention" and tech["cve_lookup"]["detail"]["total"] == 3
assert tech["shodan_exposure"]["detail"]["vulns"] == ["CVE-2026-2"]
assert tech["certificate_transparency"]["detail"]["cert_count"] == 1
print("PASS: Technical Posture panel runs TLS/headers, CVEs, email auth, Shodan, CT, DNS/WHOIS, and typosquats")

r = client.post(f"/api/v1/security-reviews/{rid}/external-checks", params={"panel": "bogus"})
assert r.status_code == 400
r = client.post(f"/api/v1/security-reviews/{rid}/external-checks")
both = r.json()
assert "company_posture" in both and "technical_posture" in both
assert both["prerequisites"] == []       # domain + legal name are both set now
saved = run(db.security_reviews.find_one({"id": rid}, {"_id": 0}))
assert saved["external_checks"]["company_posture"]
print("PASS: both panels run together, validate the panel argument, and persist onto the review")

# a review with no domain/legal name reports its prerequisites instead of failing
bare = client.post("/api/v1/security-reviews", json={
    "title": "Mystery tool", "review_type": "Ad-hoc investigation"}).json()
r = client.post(f"/api/v1/security-reviews/{bare['id']}/external-checks")
p2 = r.json()
assert any("domain" in x for x in p2["prerequisites"])
tech2 = {c["check"]: c for c in p2["technical_posture"]["results"]}
assert tech2["tls_security_headers"]["status"] == "manual"
assert "add one" in tech2["tls_security_headers"]["summary"].lower()
print("PASS: with prerequisites missing the panels say exactly what's needed instead of silently returning nothing")

httpx.AsyncClient = _real
