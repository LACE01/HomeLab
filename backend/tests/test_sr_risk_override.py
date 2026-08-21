"""#52 Manual risk override: an analyst can set the inherent/residual band directly,
overriding the calculated 5x5 (likelihood x impact) score. The override is allowed
but requires a justification when it differs from the calculated band, and it
records the original calculated band so the UI/report can show 'adjusted from X'."""
import os, sys, asyncio
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_sr_risk_override"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_sr_risk_override"]

import server, auth_utils
from routes import security_reviews as sr_route
sr_route.db = db_module.db
from fastapi.testclient import TestClient

admin = {"id": "u1", "email": "admin@x.com", "role": "admin", "name": "Admin", "teams": [], "team": "SecOps"}
server.app.dependency_overrides[auth_utils.get_current_user] = lambda: admin
server.app.dependency_overrides[auth_utils.get_current_user_optional] = lambda: admin
client = TestClient(server.app)
def a(c, m=""): assert c, m

rid = client.post("/api/v1/security-reviews", json={
    "title": "Override test", "review_type": "New software purchase (SaaS / COTS / on-prem)",
    "entity_name": "Acme", "entity_domain": "acme.com", "data_classifications": ["PII (Colorado)"],
}).json()["id"]

# likelihood 3 x max impact 3 = 9 -> calculated band "Medium"
base = {"inherent_likelihood": 3, "inherent_impacts": {"confidentiality": 3}}

# ---- no override: band is the calculated one ----
r = client.put(f"/api/v1/security-reviews/{rid}/risk-score", json={**base})
a(r.status_code == 200, r.text)
a(r.json()["inherent_risk"]["band"] == "Medium")
a(not r.json()["inherent_risk"].get("overridden"))
print("PASS: with no override, the inherent band is the calculated 5×5 value (Medium)")

# ---- override to Critical WITHOUT justification -> rejected ----
r = client.put(f"/api/v1/security-reviews/{rid}/risk-score",
               json={**base, "inherent_override_band": "Critical"})
a(r.status_code == 400 and "justification is required" in r.json()["detail"], r.text)
print("PASS: overriding the calculated band without a justification is rejected")

# ---- override to Critical WITH justification -> accepted, records calculated_band ----
r = client.put(f"/api/v1/security-reviews/{rid}/risk-score",
               json={**base, "inherent_override_band": "Critical",
                     "override_justification": "System of record for court filings; failure is catastrophic."})
a(r.status_code == 200, r.text)
ir = r.json()["inherent_risk"]
a(ir["band"] == "Critical" and ir["overridden"] is True and ir["calculated_band"] == "Medium", ir)
print("PASS: with a justification the override is accepted — band=Critical, calculated_band=Medium, "
      "overridden=true (so the UI/report can show 'adjusted from Medium')")

# ---- override that MATCHES the calculated band needs no justification ----
r = client.put(f"/api/v1/security-reviews/{rid}/risk-score",
               json={**base, "inherent_override_band": "Medium"})
a(r.status_code == 200 and not r.json()["inherent_risk"].get("overridden"), r.text)
print("PASS: an 'override' equal to the calculated band is a no-op and needs no justification")

# ---- residual override works the same way ----
r = client.put(f"/api/v1/security-reviews/{rid}/risk-score",
               json={**base,
                     "residual_likelihood": 2, "residual_impacts": {"confidentiality": 2},  # 2x2=4 -> Low
                     "residual_override_band": "Medium",
                     "override_justification": "Controls are contractual only, not yet verified."})
a(r.status_code == 200, r.text)
rr = r.json()["residual_risk"]
a(rr["band"] == "Medium" and rr["calculated_band"] == "Low" and rr["overridden"] is True, rr)
print("PASS: residual risk supports the same override + calculated_band record")

# ---- invalid band value rejected ----
r = client.put(f"/api/v1/security-reviews/{rid}/risk-score",
               json={**base, "inherent_override_band": "Catastrophic", "override_justification": "x"})
a(r.status_code == 400 and "must be one of" in r.json()["detail"], r.text)
print("PASS: an override band outside Low/Medium/High/Critical is rejected")

# ---- persisted on the review for the report ----
# re-apply an inherent override, then confirm it (and the justification) persist
client.put(f"/api/v1/security-reviews/{rid}/risk-score",
           json={**base, "inherent_override_band": "High",
                 "override_justification": "Aggregation risk across linked systems."})
doc = asyncio.get_event_loop().run_until_complete(
    db_module.db.security_reviews.find_one({"id": rid}, {"_id": 0}))
a(doc["inherent_risk"]["overridden"] is True and doc["inherent_risk"]["calculated_band"] == "Medium")
a(doc["analyst_override_justification"])
print("PASS: the override + calculated_band + justification persist on the review row for the report to render")

server.app.dependency_overrides.clear()
print("\nALL RISK OVERRIDE TESTS PASSED")
