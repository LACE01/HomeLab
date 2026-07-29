"""Item 28 -- adaptive capability-gated questionnaire engine (v3), including the
spec's own acceptance test: re-run the RCS review and it should produce ~15
nearly-all-applicable questions instead of a pile of N/As."""
import os, sys, asyncio, uuid
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_q_v3"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_q_v3"]

import server
import auth_utils
from routes import security_reviews as sr_route
sr_route.db = db_module.db
import questionnaire_v3 as qv3

from fastapi.testclient import TestClient

admin_user = {"id": "u1", "email": "admin@x.com", "role": "admin", "name": "Admin", "teams": []}
app = server.app
app.dependency_overrides[auth_utils.get_current_user] = lambda: admin_user
app.dependency_overrides[auth_utils.get_current_user_optional] = lambda: admin_user
client = TestClient(app)
db = db_module.db


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ============ pure engine ============

T = qv3.QUESTIONNAIRE_V3
assert len(T["capability_flags"]) == 10
assert set(qv3.NA_REASON_CODES) == {"na_by_design", "unknown", "pending_vendor"}
assert qv3.NA_REASON_CODES["na_by_design"]["counts_against_confidence"] is False
assert qv3.NA_REASON_CODES["unknown"]["counts_against_confidence"] is True
modules = {q["domain"] for q in T["questions"]}
for new_module in ("Endpoint & MDM Control", "Communications Security",
                    "Records & Retention", "Hardware & Firmware Lifecycle"):
    assert new_module in modules, f"missing new module {new_module}"
assert any(q["order"] == 99 and "fail to capture" in q["text"] for q in T["questions"])
print("PASS: v3 defines 10 capability flags, 3 N/A reason codes, the 4 new modules, and the standing catch-all question")

caps_all_off = {f["key"]: False for f in T["capability_flags"]}
app_none = qv3.applicable_questions(T, caps_all_off, [])
# only the always-applicable questions survive with every capability off
assert all(q.get("requires_capability") is None for q in app_none)
assert len(app_none) < 8, f"expected a tiny always-on core, got {len(app_none)}"

caps_saas = {**caps_all_off, "has_user_accounts": True, "stores_our_data": True,
             "has_vendor_relationship": True}
app_saas = qv3.applicable_questions(T, caps_saas, ["PII (Colorado)"])
domains_saas = {q["domain"] for q in app_saas}
assert "Identity & Access" in domains_saas and "Data Protection" in domains_saas
assert "Hardware & Firmware Lifecycle" not in domains_saas
assert "Communications Security" not in domains_saas
assert any(q["conditional_on"] == "PII (Colorado)" for q in app_saas)
assert not any(q["conditional_on"] == "CJIS" for q in app_saas)
print("PASS: capability flags gate whole modules, and data classifications still gate compliance questions")

# ============ ACCEPTANCE TEST: the RCS case ============
# "RCS on an existing Verizon account" -- a comms feature on an already-approved
# platform. Under v1 this produced a wall of N/As; under v3 it should produce a
# small, almost-entirely-applicable set.
caps_rcs = {**caps_all_off,
            "is_comms_channel": True,
            "touches_records": True,
            "is_existing_platform_feature": True,
            "has_vendor_relationship": True}
app_rcs = qv3.applicable_questions(T, caps_rcs, [])
n = len(app_rcs)
assert 12 <= n <= 18, f"RCS review should yield ~15 questions, got {n}"
d_rcs = {q["domain"] for q in app_rcs}
assert "Communications Security" in d_rcs and "Records & Retention" in d_rcs
assert "Delta Scope" in d_rcs
# the base platform isn't re-reviewed
assert "Vendor Security Program" not in d_rcs, "delta-scoped review must not re-review the base platform"
assert "Resilience" not in d_rcs
# and none of the irrelevant modules appear at all
for absent in ("Identity & Access", "Hardware & Firmware Lifecycle", "Endpoint & MDM Control", "AI Features"):
    assert absent not in d_rcs, f"{absent} should not apply to an RCS feature review"
print(f"PASS: ACCEPTANCE -- the RCS review yields {n} applicable questions, comms/records/delta-scoped, "
      "with the already-approved base platform's modules suppressed (no wall of N/As)")

# ============ scoring + confidence ============

applicable = app_saas
scored_qs = [q for q in applicable if q["risk_weight"] > 0]
# all yes -> perfect confidence, zero bad ratio
responses = [{"question_order": q["order"], "answer": "yes"} for q in scored_qs]
s = qv3.score_questionnaire(applicable, responses)
assert s["confidence_pct"] == 100 and s["weighted_bad_ratio"] == 0.0
assert s["unknown_count"] == 0

# na_by_design is EXCLUDED, not counted against us
responses2 = [{"question_order": q["order"], "answer": "yes"} for q in scored_qs[1:]]
responses2.append({"question_order": scored_qs[0]["order"], "answer": "na", "na_reason_code": "na_by_design"})
s2 = qv3.score_questionnaire(applicable, responses2)
assert s2["confidence_pct"] == 100, "na_by_design must not dent confidence"
assert s2["scored_weight"] < s["scored_weight"], "na_by_design must leave the scoring pool"

# unknown / pending_vendor DO dent confidence
responses3 = [{"question_order": q["order"], "answer": "yes"} for q in scored_qs[2:]]
responses3.append({"question_order": scored_qs[0]["order"], "answer": "na", "na_reason_code": "unknown"})
responses3.append({"question_order": scored_qs[1]["order"], "answer": "na", "na_reason_code": "pending_vendor"})
s3 = qv3.score_questionnaire(applicable, responses3)
assert s3["confidence_pct"] < 100
assert s3["unknown_count"] == 1 and s3["pending_vendor_count"] == 1
assert s3["scored_weight"] == s["scored_weight"], "unknown/pending stay in the pool, they just aren't answered"

note = qv3.confidence_note(s3, "Low")
assert note.startswith("Low, confidence ") and "1 unknown" in note and "1 pending vendor" in note
print("PASS: scoring covers applicable questions only; na_by_design leaves the pool, unknown/pending cut confidence; "
      f"summary reads like \"{note}\"")

# bad answers drive the ratio, computed over ANSWERED weight
responses4 = [{"question_order": q["order"], "answer": "no"} for q in scored_qs]
s4 = qv3.score_questionnaire(applicable, responses4)
assert s4["weighted_bad_ratio"] == 1.0
print("PASS: weighted bad ratio is computed over answered applicable weight")

# ============ API: capability profile drives the served questionnaire ============

client.get("/api/v1/security-reviews/meta")
meta = client.get("/api/v1/security-reviews/meta").json()
assert len(meta["capability_flags"]) == 10 and "unknown" in meta["na_reason_codes"]

review = client.post("/api/v1/security-reviews", json={
    "title": "RCS on existing Verizon account",
    "review_type": "Feature enablement on an existing platform",
    "entity_name": "Verizon", "entity_domain": "verizon.com"}).json()
rid = review["id"]
assert review["template_version"] == 3, "new reviews must pin the adaptive template"
# preset from the feature_enablement playbook
assert review["capabilities"]["is_existing_platform_feature"] is True
print("PASS: intake pins questionnaire v3 and pre-seeds the capability profile from the playbook type")

caps = {**{f["key"]: False for f in meta["capability_flags"]},
        "is_comms_channel": True, "touches_records": True,
        "is_existing_platform_feature": True, "has_vendor_relationship": True}
r = client.put(f"/api/v1/security-reviews/{rid}/capabilities", json={"capabilities": caps})
assert r.status_code == 200
assert 12 <= r.json()["applicable_count"] <= 18
r = client.put(f"/api/v1/security-reviews/{rid}/capabilities", json={"capabilities": {"not_a_flag": True}})
assert r.status_code == 400

got = client.get(f"/api/v1/security-reviews/{rid}").json()
assert got["questionnaire"]["engine"] == "capability_gated"
assert 12 <= len(got["applicable_questions"]) <= 18
# nothing answered yet => 0% confidence: confidence is "how much of the applicable
# weight do we actually have an answer for", so an untouched questionnaire is 0.
assert got["questionnaire_scoring"]["confidence_pct"] == 0
assert got["questionnaire_scoring"]["unanswered_count"] > 0
print("PASS: setting capabilities reshapes the served questionnaire and the review view returns only applicable questions")

# ============ API: N/A reason codes ============

first = got["applicable_questions"][0]
r = client.put(f"/api/v1/security-reviews/{rid}/responses",
                json={"question_order": first["order"], "answer": "na"})
assert r.status_code == 400, "bare N/A must be rejected -- v3 requires a reason"
r = client.put(f"/api/v1/security-reviews/{rid}/responses",
                json={"question_order": first["order"], "answer": "na", "na_reason_code": "nonsense"})
assert r.status_code == 400
r = client.put(f"/api/v1/security-reviews/{rid}/responses",
                json={"question_order": first["order"], "answer": "na", "na_reason_code": "unknown"})
assert r.status_code == 200 and r.json()["na_reason_code"] == "unknown"
sc = client.get(f"/api/v1/security-reviews/{rid}/questionnaire-scoring").json()
assert sc["unknown_count"] == 1 and sc["confidence_pct"] < 100
assert "unknown" in sc["summary"]
print("PASS: the API enforces N/A reason codes and surfaces them in the confidence read")

# ============ API: custom questions + promote-to-template ============

r = client.post(f"/api/v1/security-reviews/{rid}/custom-questions", json={
    "text": "Can residents opt out of RCS messages and fall back to SMS?",
    "domain": "Communications Security", "risk_weight": 3})
assert r.status_code == 200
cq = r.json()
assert cq["order"] >= 1000, "custom questions must not collide with template orders"
got = client.get(f"/api/v1/security-reviews/{rid}").json()
assert any(q.get("custom") for q in got["applicable_questions"])
assert any(q["order"] == cq["order"] for q in got["applicable_questions"])

before = run(db.review_questionnaires.count_documents({"key": "adaptive_internal"}))
r = client.post(f"/api/v1/security-reviews/{rid}/custom-questions/{cq['id']}/promote")
assert r.status_code == 200 and r.json()["version"] == 4
after = run(db.review_questionnaires.count_documents({"key": "adaptive_internal"}))
assert after == before + 1, "promotion creates a NEW template version, never edits v3"
v4 = run(db.review_questionnaires.find_one({"key": "adaptive_internal", "version": 4}, {"_id": 0}))
assert any("opt out of RCS" in q["text"] for q in v4["questions"])
v3 = run(db.review_questionnaires.find_one({"key": "adaptive_internal", "version": 3}, {"_id": 0}))
assert not any("opt out of RCS" in q["text"] for q in v3["questions"]), "v3 must be untouched"
print("PASS: per-review custom questions render in the adaptive set and promote into a NEW template version")

# ============ vendor questionnaire respects capabilities + pending flags ============

vq = client.get(f"/api/v1/security-reviews/{rid}/vendor-questionnaire").json()
vq_domains = {q["domain"] for q in vq["questions"]}
assert "Hardware & Firmware Lifecycle" not in vq_domains
assert "Identity & Access" not in vq_domains
assert vq["questions"], "there should still be vendor-facing comms/records questions"
print("PASS: the vendor questionnaire only compiles questions from applicable modules")

# ============ suggested risk carries confidence ============

sug = client.get(f"/api/v1/security-reviews/{rid}/suggested-risk").json()
assert "confidence" in sug and sug["confidence"]["confidence_pct"] < 100
assert any("confidence" in x for x in sug["rationale"])
print("PASS: suggested risk reports confidence and flags low-confidence suggestions as provisional")
