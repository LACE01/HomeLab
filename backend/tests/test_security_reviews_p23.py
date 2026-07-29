"""Security Reviews Phases 2+3: auto-fill hooks, auto-answered questions,
pre-drafted findings, vendor questionnaire workflow, interviews, share links,
dashboard, suggested risk + override enforcement, comparison mode,
re-validation, external checks, requestor portal, playbook admin."""
import os, sys, asyncio, uuid
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_security_reviews_p23"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_security_reviews_p23"]

import server
import auth_utils
from routes import security_reviews as sr_route
sr_route.db = db_module.db
import security_reviews_hooks as hooks
hooks_db_patch = db_module.db

from fastapi.testclient import TestClient

admin_user = {"id": "u1", "email": "admin@x.com", "role": "admin", "name": "Admin", "teams": [], "team": "SecOps"}
app = server.app
app.dependency_overrides[auth_utils.get_current_user] = lambda: admin_user
app.dependency_overrides[auth_utils.get_current_user_optional] = lambda: admin_user
client = TestClient(app)

db = db_module.db


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# seed a review
client.get("/api/v1/security-reviews/meta")
body = {
    "title": "Acme AI Notetaker", "review_type": "AI tool adoption",
    "requestor_name": "Sam", "requestor_department": "Clerk",
    "data_classifications": ["PII (Colorado)", "CJIS"],
    "entity_name": "Acme AI", "entity_domain": "acmeai.com",
}
review = client.post("/api/v1/security-reviews", json=body).json()
rid = review["id"]

# ============ typed playbooks ============

assert review["playbook_key"] == "ai_tool", f"AI review should pin the AI playbook, got {review['playbook_key']}"
steps = client.get(f"/api/v1/security-reviews/{rid}").json()["steps"]
titles = [s["title"] for s in steps]
assert "Training-data usage" in titles and "Prompt & data retention" in titles
assert len(steps) == 16  # 13 SaaS spine + 3 AI-specific
assert [s["order"] for s in steps] == list(range(1, 17))  # renumbered contiguously
print("PASS: AI review pins the AI playbook (SaaS spine + 3 AI steps, renumbered)")

# ============ governance_crosswalk hook ============

r = client.get(f"/api/v1/security-reviews/{rid}/autofill/governance_crosswalk")
assert r.status_code == 200
items = r.json()["items"]
reqs = [i["requirement"] for i in items]
assert any("CJIS Security Addendum" in x for x in reqs)
assert any("6-1-713.5" in x for x in reqs)          # Colorado PII statute
assert any("AI usage policy" in x for x in reqs)    # review-type extra
assert not any("BAA" in x for x in reqs)            # PHI not selected
assert r.json()["source_tag"].startswith("Pulled from Governance Crosswalk")
print("PASS: governance_crosswalk derives items from classifications + review type, with a source tag")

# ============ asset_inventory_check hook + shadow-deployment auto-finding ============

run(db.assets.insert_one({"id": "a1", "hostname": "clerk-pc-01", "os": "Windows 11", "criticality": "Medium", "owner_team": "Clerk"}))
run(db.software_inventory.insert_one({"vendor": "Acme AI", "name": "Acme AI Desktop", "version": "2.1",
                                       "asset_id": "a1", "source": "defender_device"}))
r = client.get(f"/api/v1/security-reviews/{rid}/autofill/asset_inventory_check")
data = r.json()
assert data["shadow_deployment"] is True
assert len(data["software_hits"]) == 1
draft = run(db.security_review_findings.find_one({"review_id": rid, "shadow_deployment_auto": True}, {"_id": 0}))
assert draft is not None and draft["status"] == "draft" and "Shadow deployment" in draft["description"]
# re-running doesn't duplicate the draft
client.get(f"/api/v1/security-reviews/{rid}/autofill/asset_inventory_check")
assert run(db.security_review_findings.count_documents({"review_id": rid, "shadow_deployment_auto": True})) == 1
print("PASS: asset_inventory_check detects shadow deployment and auto-drafts ONE finding (idempotent)")

# ============ open_findings_pull + auto-answer ============

r = client.post(f"/api/v1/security-reviews/{rid}/auto-answer")
assert r.status_code == 200
resp = run(db.security_review_responses.find_one({"review_id": rid, "question_order": 52}, {"_id": 0}))
assert resp["answer"] == "na" and resp["auto_answered"] is True  # no linked assets yet
print("PASS: auto-answer answers Q52 'na' with no linked assets, marked auto_answered")

client.patch(f"/api/v1/security-reviews/{rid}", json={"linked_asset_ids": ["a1"]})
run(db.findings.insert_one({"id": "f1", "asset_id": "a1", "severity": "Critical", "status": "New",
                             "qid": "110123", "title": "Critical RCE", "due_at": "2020-01-01T00:00:00+00:00"}))
r = client.post(f"/api/v1/security-reviews/{rid}/auto-answer")
resp = run(db.security_review_responses.find_one({"review_id": rid, "question_order": 52}, {"_id": 0}))
assert resp["answer"] == "no" and "110123" in resp["evidence_text"]
assert resp["source_tag"].startswith("Pulled from Findings")
print("PASS: auto-answer flips Q52 to 'no' once a linked asset has open Critical findings, citing the QIDs")

r = client.get(f"/api/v1/security-reviews/{rid}/autofill/open_findings_pull")
data = r.json()
assert data["severity_counts"].get("Critical") == 1 and data["overdue"] == 1
assert data["top_qids"][0]["qid"] == "110123"
print("PASS: open_findings_pull reports severity counts, overdue SLAs, and top QIDs for linked assets")

# analyst override of an auto answer is recorded
r = client.put(f"/api/v1/security-reviews/{rid}/responses",
                json={"question_order": 52, "answer": "partial", "evidence_text": "Patch scheduled this week"})
resp = run(db.security_review_responses.find_one({"review_id": rid, "question_order": 52}, {"_id": 0}))
assert resp["analyst_overridden"] is True and resp["auto_answered"] is False
audit_entries = client.get(f"/api/v1/security-reviews/{rid}/audit").json()["items"]
assert any(a["action"] == "auto_answer_overridden" for a in audit_entries)
# and auto-answer won't clobber the analyst's override
client.post(f"/api/v1/security-reviews/{rid}/auto-answer")
resp = run(db.security_review_responses.find_one({"review_id": rid, "question_order": 52}, {"_id": 0}))
assert resp["answer"] == "partial"
print("PASS: analyst override of an auto answer is recorded and never clobbered by re-running auto-answer")

# ============ osint_compromise_pull ============

run(db.osint_findings.insert_one({"id": "o1", "key": "k", "module": "otx_domain", "module_label": "AlienVault OTX",
                                   "target": "acmeai.com", "label": "OTX pulse hit", "detail": "malware pulse",
                                   "raw": {}, "found_at": "2026-07-01T00:00:00+00:00", "acknowledged": False}))
r = client.get(f"/api/v1/security-reviews/{rid}/autofill/osint_compromise_pull")
assert len(r.json()["hits"]) == 1 and r.json()["hits"][0]["label"] == "OTX pulse hit"
print("PASS: osint_compromise_pull returns full drillable OSINT docs for the vendor domain")

# ============ pre-drafted findings from questionnaire answers ============

r = client.put(f"/api/v1/security-reviews/{rid}/responses",
                json={"question_order": 2, "answer": "no"})  # MFA, weight 5
draft = run(db.security_review_findings.find_one({"review_id": rid, "from_question_order": 2}, {"_id": 0}))
assert draft is not None and draft["status"] == "draft" and draft["severity"] == "High"
assert draft["cis_mapping"] == "6.5"
# no duplicate on re-answer
client.put(f"/api/v1/security-reviews/{rid}/responses", json={"question_order": 2, "answer": "no"})
assert run(db.security_review_findings.count_documents({"review_id": rid, "from_question_order": 2})) == 1
# low-weight questions don't draft (v3 Q33 = log retention, weight 2)
client.put(f"/api/v1/security-reviews/{rid}/responses", json={"question_order": 33, "answer": "no"})
assert run(db.security_review_findings.count_documents({"review_id": rid, "from_question_order": 33})) == 0
print("PASS: No/Partial answers on weight>=4 questions pre-draft findings (weight-5 'no' = High), once, never for low weights")

# ============ vendor questionnaire compile + SLA tracking ============

r = client.get(f"/api/v1/security-reviews/{rid}/vendor-questionnaire")
vq = r.json()
orders = [q["order"] for q in vq["questions"]]
# v3 numbering: 2 = MFA (vendor-facing, gated on has_user_accounts -- on for this
# AI review), 45 = CJIS conditional (CJIS is selected), 46 = PHI (not selected),
# 11 = network exposure (not vendor-facing, and creates_network_exposure is off).
assert 2 in orders
assert 45 in orders
assert 46 not in orders
assert 11 not in orders
assert "## Identity & Access" in vq["text"]
print("PASS: vendor questionnaire compiles vendor-facing + applicable-conditional questions into a copy-paste document")

r = client.post(f"/api/v1/security-reviews/{rid}/vendor-questionnaire/track", json={"sent": True})
doc = run(db.security_reviews.find_one({"id": rid}, {"_id": 0}))
assert doc["vendor_q_sent_at"] and doc["sla_paused_at"]
r = client.post(f"/api/v1/security-reviews/{rid}/vendor-questionnaire/track", json={"received": True})
doc = run(db.security_reviews.find_one({"id": rid}, {"_id": 0}))
assert doc["vendor_q_received_at"] and doc["sla_paused_at"] is None
print("PASS: vendor questionnaire sent/received tracking auto-pauses and resumes the SLA clock")

# ============ interviews ============

r = client.post(f"/api/v1/security-reviews/{rid}/interviews",
                 json={"who": "Jane Doe", "role": "Clerk & Recorder", "summary": "Confirmed data scope"})
assert r.status_code == 200
rep = client.get(f"/api/v1/security-reviews/{rid}/report-data").json()
assert len(rep["interviews"]) == 1 and rep["interviews"][0]["who"] == "Jane Doe"
print("PASS: interview capture records stakeholder input and renders into report data")

# ============ suggested risk + override enforcement ============

r = client.get(f"/api/v1/security-reviews/{rid}/suggested-risk")
sug = r.json()
assert sug["likelihood"] >= 4  # bad answers + open criticals + OSINT hit all push it up
assert sug["impacts"]["confidentiality"] == 5  # CJIS selected
assert sug["band"] in ("High", "Critical")
assert len(sug["rationale"]) >= 3
print("PASS: suggested risk combines weighted answers, open criticals, OSINT hits, and classifications with rationale")

low_score = {"inherent_likelihood": 1, "inherent_impacts": {"confidentiality": 1, "integrity": 1, "availability": 1, "compliance_legal": 1, "reputational": 1},
             "suggested_band": sug["band"]}
r = client.put(f"/api/v1/security-reviews/{rid}/risk-score", json=low_score)
assert r.status_code == 400 and "override justification" in r.json()["detail"].lower()
r = client.put(f"/api/v1/security-reviews/{rid}/risk-score",
                json={**low_score, "override_justification": "Pilot limited to 3 users with synthetic data only"})
assert r.status_code == 200
print("PASS: scoring below the displayed suggestion without a justification is rejected; with one it's allowed")

# ============ executive summary drafting + edit ============

rep = client.get(f"/api/v1/security-reviews/{rid}/report-data").json()
assert "Acme AI" in rep["executive_summary"]
client.put(f"/api/v1/security-reviews/{rid}/executive-summary", json={"text": "Custom summary."})
rep = client.get(f"/api/v1/security-reviews/{rid}/report-data").json()
assert rep["executive_summary"] == "Custom summary."
print("PASS: executive summary is auto-drafted and analyst-editable (edit wins)")

# ============ share links ============

# Item 26 replaced anyone-with-the-link sharing with recipient-scoped grants:
# an external email must exchange a one-time code, so the link alone is inert.
r = client.post(f"/api/v1/security-reviews/{rid}/share", json={"email": "ext@partner.com", "expires_days": 7})
token = r.json()["token"]
grant = run(db.security_review_share_grants.find_one({"token": token}, {"_id": 0}))
r = client.get(f"/api/v1/shared/security-review/{token}")
assert r.status_code == 401  # link alone is not enough
r = client.post(f"/api/v1/shared/security-review/{token}/verify", json={"code": grant["code"]})
assert r.status_code == 200
shared = r.json()
assert shared["review"]["review_number"] == review["review_number"]
assert all(f["status"] != "draft" for f in shared["findings"])  # drafts never leak into shared reports
r = client.get("/api/v1/shared/security-review/not-a-token/meta")
assert r.status_code == 404
run(db.security_review_share_grants.update_one({"token": token}, {"$set": {"expires_at": "2020-01-01T00:00:00+00:00"}}))
r = client.get(f"/api/v1/shared/security-review/{token}")
assert r.status_code == 404
print("PASS: recipient-scoped share grants serve the report only after code verification (drafts excluded) and expire")

# ============ external checks (fake httpx) ============

class FakeResp:
    def __init__(self, headers=None, status_code=200, json_data=None, url="https://acmeai.com/"):
        self.headers = headers or {}
        self.status_code = status_code
        self._json = json_data or {}
        self.url = url
    def json(self):
        return self._json

class FakeAsyncClient:
    def __init__(self, *a, **kw): pass
    async def __aenter__(self): return self
    async def __aexit__(self, *a): return False
    async def get(self, url, **kw):
        if "nvd.nist.gov" in url:
            return FakeResp(json_data={"totalResults": 2, "vulnerabilities": [
                {"cve": {"id": "CVE-2026-0001"}}, {"cve": {"id": "CVE-2026-0002"}}]})
        return FakeResp(headers={"Strict-Transport-Security": "max-age=63072000"})

import httpx
_real = httpx.AsyncClient
httpx.AsyncClient = FakeAsyncClient
r = client.post(f"/api/v1/security-reviews/{rid}/external-checks")
httpx.AsyncClient = _real
assert r.status_code == 200
checks = {c["check"]: c for c in r.json()["results"]}
assert checks["tls_security_headers"]["status"] == "attention"  # 3 of 4 headers missing
assert "content-security-policy" in checks["tls_security_headers"]["detail"]["missing"]
assert checks["breach_history"]["status"] == "attention"  # OSINT hit on file
assert checks["cve_lookup"]["status"] == "attention" and "CVE-2026-0001" in checks["cve_lookup"]["summary"]
assert all(c.get("source_tag") for c in r.json()["results"])
print("PASS: external checks run TLS-header scan, breach-history signal, and NVD CVE lookup with source tags")

# ============ comparison mode ============

review_b = client.post("/api/v1/security-reviews", json={**body, "title": "Rival AI Notetaker", "entity_name": "Rival AI", "entity_domain": "rivalai.com"}).json()
r = client.post(f"/api/v1/security-reviews/{rid}/comparison", json={"review_ids": [review_b["id"]]})
assert r.status_code == 200
r = client.get(f"/api/v1/security-reviews/{rid}/comparison-data")
cd = r.json()
assert len(cd["reviews"]) == 2
names = {c["entity_name"] for c in cd["reviews"]}
assert names == {"Acme AI", "Rival AI"}
acme_col = next(c for c in cd["reviews"] if c["entity_name"] == "Acme AI")
assert acme_col["answers"].get("2") == "no" or acme_col["answers"].get(2) == "no"
print("PASS: comparison mode links candidate reviews and returns side-by-side ratings + answers")

# ============ dashboard ============

r = client.get("/api/v1/security-reviews/dashboard")
assert r.status_code == 200
dash = r.json()
assert dash["open_total"] >= 2
assert "AI tool adoption" in dash["by_type"]
assert "risk_distribution" in dash and "completed_per_quarter" in dash
print("PASS: dashboard reports workload + program metrics in one payload")

# ============ requestor portal ============

requestor = {"id": "u2", "email": "dept@x.com", "role": "analyst", "name": "Dept User", "teams": ["Clerk"], "team": "Clerk"}
app.dependency_overrides[auth_utils.get_current_user] = lambda: requestor
r = client.post("/api/v1/security-reviews/request", json={
    "title": "New GIS mapping tool", "review_type": "New software purchase (SaaS / COTS / on-prem)",
    "requestor_department": "GIS"})
assert r.status_code == 200, r.text
req_id = r.json()["id"]
r = client.get("/api/v1/security-reviews/my-requests")
assert any(i["id"] == req_id for i in r.json()["items"])
print("PASS: any authenticated user can submit a review request and track their own submissions")

# decision + requestor acknowledgment
app.dependency_overrides[auth_utils.get_current_user] = lambda: admin_user
client.put(f"/api/v1/security-reviews/{req_id}/decision",
            json={"outcome": "Approved with Conditions", "decision_maker": "CISO"})
app.dependency_overrides[auth_utils.get_current_user] = lambda: requestor
r = client.post(f"/api/v1/security-reviews/{req_id}/acknowledge", json={"acknowledged": True})
assert r.status_code == 200
doc = run(db.security_reviews.find_one({"id": req_id}, {"_id": 0}))
assert doc["decision"]["requestor_acknowledged"] is True
# a third party cannot acknowledge
stranger = {"id": "u3", "email": "other@x.com", "role": "analyst", "name": "Other", "teams": [], "team": None}
app.dependency_overrides[auth_utils.get_current_user] = lambda: stranger
r = client.post(f"/api/v1/security-reviews/{req_id}/acknowledge", json={"acknowledged": True})
assert r.status_code == 403
app.dependency_overrides[auth_utils.get_current_user] = lambda: admin_user
print("PASS: requestor (and only the requestor/admin) can acknowledge the decision")

# ============ re-validation clone ============

client.put(f"/api/v1/security-reviews/{rid}/risk-score", json={
    "inherent_likelihood": 3, "inherent_impacts": {"confidentiality": 4, "integrity": 2, "availability": 2, "compliance_legal": 4, "reputational": 2},
    "residual_likelihood": 2, "residual_impacts": {"confidentiality": 2, "integrity": 2, "availability": 2, "compliance_legal": 2, "reputational": 2},
    "override_justification": "post-controls"})
client.post(f"/api/v1/security-reviews/{rid}/status", json={"status": "Closed"})
entity = run(db.reviewed_entities.find_one({"name": "Acme AI"}, {"_id": 0}))
assert entity["next_review_date"] is not None  # Low residual -> 36 months out
print("PASS: closing schedules the entity's next_review_date from the residual risk tier")

r = client.post(f"/api/v1/security-reviews/{rid}/revalidate")
assert r.status_code == 200
new_id = r.json()["id"]
new_doc = run(db.security_reviews.find_one({"id": new_id}, {"_id": 0}))
assert new_doc["revalidation_of"] == rid and new_doc["status"] == "Requested"
assert new_doc["title"].startswith("Re-validation:")
cloned_resp = run(db.security_review_responses.find_one({"review_id": new_id, "question_order": 2}, {"_id": 0}))
assert cloned_resp is not None and cloned_resp["source_tag"].startswith("Prior review")
print("PASS: re-validation clones the review with prior answers tagged 'Prior review' for confirm-what-changed flow")

# ============ playbook/template admin versioning ============

r = client.post("/api/v1/review-playbooks", json={
    "key": "saas_acquisition", "name": "SaaS / Software Acquisition",
    "review_types": ["New software purchase (SaaS / COTS / on-prem)"],
    "steps": [{"title": "Only step", "guidance": "Do the thing"}]})
assert r.status_code == 200 and r.json()["version"] == 2
r = client.get("/api/v1/review-playbooks")
saas_versions = [p["version"] for p in r.json()["items"] if p["key"] == "saas_acquisition"]
assert sorted(saas_versions) == [1, 2]
r = client.post("/api/v1/review-questionnaires", json={
    "key": "saas_acquisition_internal", "name": "Internal Questionnaire",
    "questions": [{"text": "Single question?"}]})
assert r.json()["version"] == 3
print("PASS: playbook/template admin creates NEW versions (never edits), old reviews keep their pinned versions")

# entity certifications
r = client.patch(f"/api/v1/reviewed-entities/{entity['id']}",
                  json={"certifications": [{"name": "SOC 2 Type II", "expires_at": "2026-08-15"}]})
assert r.status_code == 200
dash = client.get("/api/v1/security-reviews/dashboard").json()
assert any(c["name"] == "SOC 2 Type II" for c in dash["expiring_certifications"])
print("PASS: entity certifications with expirations surface on the dashboard when expiring soon")
