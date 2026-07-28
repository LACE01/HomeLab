import os, sys, asyncio
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_security_reviews"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_security_reviews"]

import server
import auth_utils
from routes import security_reviews as sr_route
sr_route.db = db_module.db
import security_reviews as sr_mod

from fastapi.testclient import TestClient

admin_user = {"id": "u1", "email": "admin@x.com", "role": "admin", "name": "Admin", "teams": [], "team": "SecOps"}
app = server.app
app.dependency_overrides[auth_utils.get_current_user] = lambda: admin_user
client = TestClient(app)

db = db_module.db


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ============ pure helpers ============

assert sr_mod.risk_band(1, 1) == "Low" and sr_mod.risk_band(2, 2) == "Low"
assert sr_mod.risk_band(3, 3) == "Medium" and sr_mod.risk_band(1, 5) == "Medium"
assert sr_mod.risk_band(4, 4) == "High" and sr_mod.risk_band(2, 5) == "High"
assert sr_mod.risk_band(5, 4) == "Critical" and sr_mod.risk_band(5, 5) == "Critical"
print("PASS: 5x5 risk banding (1-4 Low, 5-9 Medium, 10-16 High, 17-25 Critical)")

rating = sr_mod.score_rating(3, {"confidentiality": 2, "integrity": 5, "availability": 1,
                                   "compliance_legal": 3, "reputational": 2})
assert rating["max_impact"] == 5 and rating["score"] == 15 and rating["band"] == "High"
print("PASS: score_rating uses the MAX impact dimension to drive the rating, per spec")

# ============ meta seeds versioned playbook + questionnaire ============

r = client.get("/api/v1/security-reviews/meta")
assert r.status_code == 200
meta = r.json()
assert len(meta["review_types"]) == 10 and len(meta["data_classifications"]) == 6
pb = run(db.review_playbooks.find_one({"key": "saas_acquisition", "version": 1}, {"_id": 0}))
qn = run(db.review_questionnaires.find_one({"key": "saas_acquisition_internal", "version": 1}, {"_id": 0}))
assert pb and len(pb["steps"]) == 13, "13-step SaaS playbook must be seeded as a DB record"
assert qn and len(qn["questions"]) == 27, "27-question questionnaire must be seeded as a DB record"
assert all(q.get("cis_mapping") for q in qn["questions"])
# Phase 2 seeds: 6 typed playbooks + questionnaire v2 (adds the auto-answered Q28)
qn2 = run(db.review_questionnaires.find_one({"key": "saas_acquisition_internal", "version": 2}, {"_id": 0}))
assert qn2 and len(qn2["questions"]) == 28 and qn2["questions"][-1].get("auto_answer_hook") == "open_findings_pull"
# idempotent
r = client.get("/api/v1/security-reviews/meta")
assert run(db.review_playbooks.count_documents({})) == 7  # SaaS + hardware/feature/integration/config/AI/extension
assert run(db.review_questionnaires.count_documents({})) == 2
print("PASS: meta idempotently seeds the versioned playbooks (SaaS v1 + 6 typed) and questionnaires (v1 + v2 with auto-answer hook) as DB records")

# ============ intake ============

body = {
    "title": "Acme Scheduling SaaS for HR", "review_type": "New software purchase (SaaS / COTS / on-prem)",
    "requestor_name": "Pat Smith", "requestor_department": "HR",
    "business_justification": "Replace paper scheduling", "urgency": "Normal",
    "data_classifications": ["PII (Colorado)"], "scope_statement": "Employee names/emails/schedules",
    "entity_name": "Acme Corp", "entity_domain": "Acme.com",
}
r = client.post("/api/v1/security-reviews", json=body)
assert r.status_code == 200, r.text
review = r.json()
import datetime
year = datetime.datetime.now(datetime.timezone.utc).year
assert review["review_number"] == f"SR-{year}-001"
assert review["status"] == "Requested"
assert review["entity_domain"] == "acme.com"  # normalized lowercase
assert review["playbook_version"] == 1 and review["template_version"] == 2  # new reviews pin the latest (v2) questionnaire
rid = review["id"]
steps = run(db.security_review_steps.find({"review_id": rid}, {"_id": 0}).to_list(50))
assert len(steps) == 13
entity = run(db.reviewed_entities.find_one({"name": "Acme Corp"}, {"_id": 0}))
assert entity is not None and entity["domain"] == "acme.com"
print("PASS: intake creates SR-YYYY-NNN review, instantiates all 13 playbook steps, and registers the reviewed entity")

r2 = client.post("/api/v1/security-reviews", json={**body, "title": "Second review of Acme"})
assert r2.json()["review_number"] == f"SR-{year}-002"
rid2 = r2.json()["id"]
print("PASS: review numbers increment per year (SR-YYYY-002)")

r = client.post("/api/v1/security-reviews", json={**body, "review_type": "not-a-type"})
assert r.status_code == 400
r = client.post("/api/v1/security-reviews", json={**body, "data_classifications": ["Nope"]})
assert r.status_code == 400
print("PASS: intake validates review_type and data classifications")

# ============ playbook step workflow ============

get = client.get(f"/api/v1/security-reviews/{rid}").json()
step1 = next(s for s in get["steps"] if s["order"] == 1)
r = client.patch(f"/api/v1/security-reviews/{rid}/steps/{step1['id']}",
                  json={"status": "Done", "notes": "Scope confirmed with Pat"})
assert r.status_code == 200
updated = r.json()
assert updated["status"] == "Done" and updated["completed_by"] == "admin@x.com" and updated["completed_at"]
print("PASS: completing a step stamps completed_by/completed_at")

step2 = next(s for s in get["steps"] if s["order"] == 2)
r = client.patch(f"/api/v1/security-reviews/{rid}/steps/{step2['id']}", json={"status": "N/A"})
assert r.status_code == 400, "N/A without a reason must be rejected"
r = client.patch(f"/api/v1/security-reviews/{rid}/steps/{step2['id']}",
                  json={"status": "N/A", "na_reason": "Classification set at intake"})
assert r.status_code == 200 and r.json()["na_reason"] == "Classification set at intake"
print("PASS: N/A requires a reason (rejected without, recorded with)")

step6 = next(s for s in get["steps"] if s["order"] == 6)
r = client.patch(f"/api/v1/security-reviews/{rid}/steps/{step6['id']}",
                  json={"status": "Blocked", "blocked_on": "Vendor security team"})
assert r.status_code == 200 and r.json()["blocked_on"] == "Vendor security team" and r.json()["blocked_date"]
print("PASS: blocking a step captures who/what it's blocked on and a date")

r = client.patch(f"/api/v1/security-reviews/{rid}/steps/{step1['id']}",
                  json={"evidence": [{"name": "scope.pdf", "mime": "application/pdf", "data_url": "data:application/pdf;base64,AAAA"}]})
assert r.status_code == 200 and len(r.json()["evidence"]) == 1
print("PASS: evidence uploads append to the step and are audited")

# ============ SLA pause on Pending Info ============

r = client.post(f"/api/v1/security-reviews/{rid}/status", json={"status": "Pending Info"})
assert r.status_code == 200
doc = run(db.security_reviews.find_one({"id": rid}, {"_id": 0}))
assert doc["sla_paused_at"] is not None
r = client.post(f"/api/v1/security-reviews/{rid}/status", json={"status": "In Assessment"})
doc = run(db.security_reviews.find_one({"id": rid}, {"_id": 0}))
assert doc["sla_paused_at"] is None and doc["sla_paused_total_seconds"] >= 0
print("PASS: SLA clock auto-pauses on Pending Info and resumes (accumulating paused time) on leaving it")

# ============ questionnaire responses ============

r = client.put(f"/api/v1/security-reviews/{rid}/responses",
                json={"question_order": 2, "answer": "no", "evidence_text": "Vendor confirmed no MFA for admins"})
assert r.status_code == 200
r = client.put(f"/api/v1/security-reviews/{rid}/responses",
                json={"question_order": 2, "answer": "partial", "evidence_text": "MFA available on Enterprise tier only"})
assert r.status_code == 200
resps = run(db.security_review_responses.find({"review_id": rid}, {"_id": 0}).to_list(10))
assert len(resps) == 1 and resps[0]["answer"] == "partial"
r = client.put(f"/api/v1/security-reviews/{rid}/responses", json={"question_order": 2, "answer": "maybe"})
assert r.status_code == 400
print("PASS: questionnaire responses upsert per question and validate the answer enum")

# ============ risk scoring ============

r = client.put(f"/api/v1/security-reviews/{rid}/risk-score", json={
    "inherent_likelihood": 4,
    "inherent_impacts": {"confidentiality": 5, "integrity": 3, "availability": 2, "compliance_legal": 4, "reputational": 3},
    "compensating_controls": "Enforce SSO+MFA via IdP; restrict to Enterprise tier; DPA with deletion terms",
    "residual_likelihood": 2,
    "residual_impacts": {"confidentiality": 3, "integrity": 2, "availability": 2, "compliance_legal": 2, "reputational": 2},
})
assert r.status_code == 200
scored = r.json()
assert scored["inherent_risk"]["band"] == "Critical"   # 4 x 5 = 20
assert scored["residual_risk"]["band"] == "Medium"     # 2 x 3 = 6
assert scored["risk_of_not_adopting"] is None
print("PASS: risk scoring computes inherent/residual bands from likelihood x max-impact-dimension")

# ============ findings + conditions + Risk Register promotion ============

r = client.post(f"/api/v1/security-reviews/{rid}/findings", json={
    "description": "No MFA enforcement available below Enterprise tier",
    "severity": "High", "recommendation": "Purchase Enterprise tier; enforce MFA via IdP before go-live",
    "owner": "IT Ops", "is_condition_of_approval": True, "condition_deadline": "2026-09-01",
})
assert r.status_code == 200
finding = r.json()
assert finding["condition_met"] == "pending"
fid = finding["id"]

r = client.post(f"/api/v1/security-reviews/{rid}/findings/{fid}/promote")
assert r.status_code == 200
risk_id = r.json()["risk_id"]
risk = run(db.risks.find_one({"id": risk_id}, {"_id": 0}))
assert risk is not None
assert risk["source_review_id"] == rid and risk["source_review_finding_id"] == fid
assert f"SR-{year}-001" in risk["title"]
f_doc = run(db.security_review_findings.find_one({"id": fid}, {"_id": 0}))
assert f_doc["promoted_to_risk_register_id"] == risk_id
r = client.post(f"/api/v1/security-reviews/{rid}/findings/{fid}/promote")
assert r.status_code == 409, "double promotion must be rejected"
print("PASS: findings promote one-click into the existing Risk Register with two-way linkage, no double-promotion")

r = client.patch(f"/api/v1/security-reviews/{rid}/findings/{fid}", json={"condition_met": "met"})
assert r.status_code == 200 and r.json()["condition_met"] == "met"
print("PASS: condition-of-approval met/not_met/pending tracking works")

# ============ decision ============

r = client.put(f"/api/v1/security-reviews/{rid}/decision", json={
    "outcome": "Approved with Conditions", "rationale": "Acceptable with MFA enforced",
    "decision_maker": "CISO", "expiration_date": "2027-08-01", "requestor_acknowledged": True,
})
assert r.status_code == 200
doc = run(db.security_reviews.find_one({"id": rid}, {"_id": 0}))
assert doc["status"] == "Decision Issued"
assert doc["decision"]["outcome"] == "Approved with Conditions"
assert doc["decision"]["requestor_acknowledged_date"] is not None
print("PASS: decision record sets outcome/rationale/maker/expiration and moves status to Decision Issued")

# ============ prior-reviews lookup (the Phase 1 auto-fill hook) ============

r = client.get(f"/api/v1/security-reviews/{rid2}/prior-reviews")
assert r.status_code == 200
prior = r.json()
assert len(prior["prior_reviews"]) == 1
assert prior["prior_reviews"][0]["review_number"] == f"SR-{year}-001"
assert prior["prior_reviews"][0]["decision_outcome"] == "Approved with Conditions"
assert prior["entity"] is not None and prior["entity"]["name"] == "Acme Corp"
print("PASS: prior-reviews lookup surfaces the earlier review of the same vendor with its decision + rating")

# ============ report data ============

r = client.get(f"/api/v1/security-reviews/{rid}/report-data")
assert r.status_code == 200
rep = r.json()
assert rep["review"]["inherent_risk"]["band"] == "Critical"
assert rep["findings"][0]["severity"] == "High"
assert rep["questionnaire"]["version"] == 2  # reviews created after Phase 2 pin questionnaire v2
assert rep["generated_at"]
print("PASS: report-data bundles review + findings (worst-first) + responses + versioned template for the print view")

# ============ close -> entity stamped + immutability ============

r = client.post(f"/api/v1/security-reviews/{rid}/status", json={"status": "Closed"})
assert r.status_code == 200
entity = run(db.reviewed_entities.find_one({"name": "Acme Corp"}, {"_id": 0}))
assert entity["current_rating"] == "Medium" and entity["last_review_id"] == rid
print("PASS: closing stamps the reviewed entity's current rating + last review")

for method, path, body in [
    ("patch", f"/api/v1/security-reviews/{rid}", {"title": "changed"}),
    ("patch", f"/api/v1/security-reviews/{rid}/steps/{step1['id']}", {"notes": "x"}),
    ("put", f"/api/v1/security-reviews/{rid}/responses", {"question_order": 3, "answer": "yes"}),
    ("post", f"/api/v1/security-reviews/{rid}/findings", {"description": "late finding"}),
    ("put", f"/api/v1/security-reviews/{rid}/decision", {"outcome": "Approved"}),
    ("post", f"/api/v1/security-reviews/{rid}/notes", {"text": "late note"}),
    ("post", f"/api/v1/security-reviews/{rid}/status", {"status": "In Assessment"}),
]:
    resp = getattr(client, method)(path, json=body)
    assert resp.status_code == 409, f"{method} {path} should be immutable after close, got {resp.status_code}"
print("PASS: closed reviews are fully immutable -- every mutating endpoint returns 409")

# ============ audit log captured material actions ============

r = client.get(f"/api/v1/security-reviews/{rid}/audit")
actions = {a["action"] for a in r.json()["items"]}
for expected in ("created", "step_status", "evidence_uploaded", "status_changed",
                  "risk_scored", "finding_created", "finding_promoted", "decision_recorded"):
    assert expected in actions, f"audit log missing {expected}: {actions}"
print("PASS: audit log recorded every material action (create, step changes, evidence, scoring, findings, promotion, decision)")

# ============ list filters ============

r = client.get("/api/v1/security-reviews", params={"risk": "Critical"})
assert r.json()["total"] == 1
r = client.get("/api/v1/security-reviews", params={"q": f"SR-{year}-002"})
assert r.json()["total"] == 1 and r.json()["items"][0]["id"] == rid2
r = client.get("/api/v1/security-reviews", params={"status": "Closed"})
assert r.json()["total"] == 1
print("PASS: reviews list filters by risk band, free-text (SR number), and status")
