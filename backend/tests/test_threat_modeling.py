import os, sys, asyncio, uuid
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_threat_modeling"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_threat_modeling"]

import server
import auth_utils
from routes import threat_modeling as tm_route
tm_route.db = db_module.db
import threat_modeling as tm

from fastapi.testclient import TestClient

admin_user = {"id": "u1", "email": "admin@x.com", "role": "admin", "name": "Admin", "teams": []}
app = server.app
app.dependency_overrides[auth_utils.get_current_user] = lambda: admin_user
client = TestClient(app)

db = db_module.db


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ============ pure helpers ============

assert tm.dread_score({"damage": 8, "reproducibility": 6, "exploitability": 7, "affected_users": 9, "discoverability": 5}) == 7.0
assert tm.dread_score({"damage": 8, "reproducibility": None, "exploitability": 7, "affected_users": 9, "discoverability": 5}) is None
print("PASS: DREAD score is the mean of five 1-10 components, None until all five are set")

sug = tm.dread_to_5x5({"damage": 10, "reproducibility": 10, "exploitability": 10, "affected_users": 10, "discoverability": 10})
assert sug == {"likelihood": 5, "impact": 5, "band": "Critical"}
sug = tm.dread_to_5x5({"damage": 2, "reproducibility": 2, "exploitability": 2, "affected_users": 2, "discoverability": 2})
assert sug["band"] == "Low"
print("PASS: dread_to_5x5 maps DREAD components onto a suggested likelihood/impact/band")

assert tm.CWE_TO_STRIDE["CWE-89"] == "Tampering"
assert tm.CWE_TO_STRIDE["CWE-287"] == "Spoofing"
assert tm.STRIDE_BY_ELEMENT["boundary"] == []
assert "Spoofing" not in tm.STRIDE_BY_ELEMENT["datastore"]
print("PASS: CWE->STRIDE map and per-element STRIDE applicability are coherent")

# ============ meta + blank model CRUD ============

r = client.get("/api/v1/threat-models/meta")
assert r.status_code == 200 and len(r.json()["stride"]) == 6

r = client.post("/api/v1/threat-models", json={"name": "Web services", "description": "test"})
assert r.status_code == 200
model_id = r.json()["id"]

# diagram save with elements + flows
el_a, el_b, el_c = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
diagram = {
    "elements": [
        {"id": el_a, "type": "external", "name": "Internet", "x": 50, "y": 50},
        {"id": el_b, "type": "process", "name": "web01", "x": 250, "y": 50},
        {"id": el_c, "type": "datastore", "name": "DB", "x": 450, "y": 50},
    ],
    "flows": [
        {"from_id": el_a, "to_id": el_b, "label": "HTTPS"},
        {"from_id": el_b, "to_id": el_c, "label": "SQL"},
    ],
}
r = client.put(f"/api/v1/threat-models/{model_id}/diagram", json=diagram)
assert r.status_code == 200 and r.json()["elements"] == 3 and r.json()["flows"] == 2
r = client.put(f"/api/v1/threat-models/{model_id}/diagram",
                json={"elements": [{"id": "x", "type": "nope", "name": "bad", "x": 0, "y": 0}], "flows": []})
assert r.status_code == 400
r = client.put(f"/api/v1/threat-models/{model_id}/diagram",
                json={"elements": diagram["elements"], "flows": [{"from_id": el_a, "to_id": "ghost"}]})
assert r.status_code == 400
print("PASS: diagram saves atomically, validating element types and flow endpoints")

# ============ STRIDE suggestions per element ============

r = client.get(f"/api/v1/threat-models/{model_id}/stride-suggestions/{el_c}")
sugs = r.json()["suggestions"]
cats = [s["stride"] for s in sugs]
assert "Spoofing" not in cats and "Tampering" in cats  # datastore subset
assert all("DB" in s["example"] for s in sugs)
assert all(s["covered"] is False for s in sugs)
print("PASS: STRIDE suggestions respect the element type's applicability subset and instantiate examples with the element name")

# ============ threats CRUD + DREAD + band ============

r = client.post(f"/api/v1/threat-models/{model_id}/threats", json={
    "element_id": el_b, "stride": "Elevation of Privilege",
    "title": "RCE on web01 leads to internal pivot", "likelihood": 4, "impact": 5})
assert r.status_code == 200
threat = r.json()
assert threat["band"] == "Critical"  # 4x5=20
tid = threat["id"]

r = client.get(f"/api/v1/threat-models/{model_id}/stride-suggestions/{el_b}")
eop = next(s for s in r.json()["suggestions"] if s["stride"] == "Elevation of Privilege")
assert eop["covered"] is True
print("PASS: creating a threat marks its STRIDE category covered on the element checklist")

r = client.patch(f"/api/v1/threat-models/{model_id}/threats/{tid}", json={
    "dread": {"damage": 9, "reproducibility": 8, "exploitability": 7, "affected_users": 9, "discoverability": 6}})
t = r.json()
assert t["dread_score"] == 7.8
assert t["dread_suggestion"]["band"] in ("High", "Critical")
print("PASS: DREAD components merge incrementally and produce a score + 5x5 suggestion")

r = client.patch(f"/api/v1/threat-models/{model_id}/threats/{tid}", json={"likelihood": 2, "impact": 2})
assert r.json()["band"] == "Low"
print("PASS: band recomputes on likelihood/impact changes")

# ============ attack tree ============

r = client.post(f"/api/v1/threat-models/{model_id}/threats", json={
    "element_id": el_b, "stride": "Spoofing", "title": "Phish admin credentials",
    "parent_threat_id": tid})
child_id = r.json()["id"]
r = client.post(f"/api/v1/threat-models/{model_id}/threats", json={
    "element_id": el_b, "stride": "Tampering", "title": "Bad parent", "parent_threat_id": "ghost"})
assert r.status_code == 404
# deleting the parent promotes children to roots, not orphans
client.delete(f"/api/v1/threat-models/{model_id}/threats/{tid}")
child = run(db.threat_model_threats.find_one({"id": child_id}, {"_id": 0}))
assert child["parent_threat_id"] is None
print("PASS: attack-tree children attach to parents; deleting a parent promotes children to roots")

# ============ mitigations + auto-mitigated ============

r = client.post(f"/api/v1/threat-models/{model_id}/threats/{child_id}/mitigations",
                 json={"description": "Enforce phishing-resistant MFA", "owner": "IT"})
mit_id = r.json()["id"]
r = client.post(f"/api/v1/threat-models/{model_id}/threats/{child_id}/mitigations",
                 json={"description": "Security awareness training"})
mit2_id = r.json()["id"]
client.patch(f"/api/v1/threat-models/{model_id}/threats/{child_id}/mitigations/{mit_id}", json={"status": "done"})
t = run(db.threat_model_threats.find_one({"id": child_id}, {"_id": 0}))
assert t["status"] == "open"  # one of two done -- still open
r = client.patch(f"/api/v1/threat-models/{model_id}/threats/{child_id}/mitigations/{mit2_id}", json={"status": "done"})
assert r.json()["status"] == "mitigated"  # all done -> auto-mitigated
print("PASS: mitigation tracking; threat auto-flips to mitigated only when EVERY mitigation is done")

# ============ matrix ============

client.post(f"/api/v1/threat-models/{model_id}/threats", json={
    "element_id": el_c, "stride": "Information Disclosure", "title": "DB exfil", "likelihood": 3, "impact": 5})
r = client.get(f"/api/v1/threat-models/{model_id}/matrix")
m = r.json()
assert m["cells"].get("3x5") == 1
assert m["total_open"] == 1  # the mitigated one doesn't count
assert m["band_totals"].get("High") == 1
print("PASS: 5x5 matrix counts only open threats per cell with band totals")

# ============ diagram element deletion detaches (not deletes) threats ============

r = client.put(f"/api/v1/threat-models/{model_id}/diagram", json={
    "elements": [e for e in diagram["elements"] if e["id"] != el_c],
    "flows": [f for f in diagram["flows"] if f["to_id"] != el_c and f["from_id"] != el_c]})
assert r.status_code == 200
orphan = run(db.threat_model_threats.find_one({"model_id": model_id, "title": "DB exfil"}, {"_id": 0}))
assert orphan is not None and orphan["element_id"] is None
print("PASS: deleting a diagram element detaches its threats (kept, unplaced) instead of silently destroying analysis")

# ============ bootstrap from assets + findings ============

run(db.assets.delete_many({}))
run(db.findings.delete_many({}))
run(db.assets.insert_many([
    {"id": "a-web", "hostname": "pub-web01", "os": "Ubuntu", "criticality": "High", "owner_team": "IT", "internet_facing": True},
    {"id": "a-db", "hostname": "sql01", "os": "Windows Server", "criticality": "Critical", "owner_team": "IT", "internet_facing": False},
    {"id": "a-hr", "hostname": "hr-app01", "os": "Windows Server", "criticality": "Medium", "owner_team": "HR", "internet_facing": False},
]))
run(db.findings.insert_many([
    {"id": "f-sqli", "asset_id": "a-web", "cwe": "CWE-89", "severity": "Critical", "title": "SQL injection", "status": "New", "kev_flag": True},
    {"id": "f-auth", "asset_id": "a-web", "cwe": "CWE-287", "severity": "High", "title": "Broken auth", "status": "Valid", "kev_flag": False},
    {"id": "f-info", "asset_id": "a-db", "cwe": "CWE-319", "severity": "Medium", "title": "Cleartext transmission", "status": "New", "kev_flag": False},
    {"id": "f-closed", "asset_id": "a-db", "cwe": "CWE-89", "severity": "Critical", "title": "Old SQLi", "status": "Fixed validated", "kev_flag": False},
    {"id": "f-nocwe", "asset_id": "a-hr", "cwe": None, "severity": "Critical", "title": "Mystery critical", "status": "New", "kev_flag": False},
]))

r = client.post("/api/v1/threat-models/bootstrap", json={"name": "County infra"})
assert r.status_code == 200
boot = r.json()
bid = boot["id"]
els = boot["elements"]
names = {e["name"] for e in els}
assert "Internet" in names and "pub-web01" in names and "sql01" in names
assert any(e["type"] == "boundary" and "DMZ" in e["name"] for e in els)
assert any(e["type"] == "boundary" and "HR" in e["name"] for e in els)
web_el = next(e for e in els if e["name"] == "pub-web01")
assert any(f["to_id"] == web_el["id"] for f in boot["flows"])  # Internet -> web flow
print("PASS: bootstrap builds Internet + DMZ + per-team boundaries with flows from the asset inventory")

threats = run(db.threat_model_threats.find({"model_id": bid}, {"_id": 0}).to_list(50))
assert boot["auto_threats_created"] == len(threats) and len(threats) == 4
by_key = {(t["element_id"], t["stride"]): t for t in threats}
tampering = next(t for t in threats if t["stride"] == "Tampering")
assert tampering["likelihood"] == 4  # KEV bump
assert tampering["impact"] == 5     # Critical severity
assert "f-sqli" in tampering["linked_finding_ids"]
assert tampering["source"] == "auto"
spoofing = next(t for t in threats if t["stride"] == "Spoofing")
assert "f-auth" in spoofing["linked_finding_ids"]
info = next(t for t in threats if t["stride"] == "Information Disclosure")
assert info["impact"] == 3  # Medium
eop = next(t for t in threats if t["stride"] == "Elevation of Privilege")
assert "f-nocwe" in eop["linked_finding_ids"]  # no CWE but Critical -> EoP fallback
assert not any("f-closed" in t["linked_finding_ids"] for t in threats)  # closed findings excluded
print("PASS: bootstrap drafts source-tagged threats from open findings (CWE->STRIDE, severity->impact, KEV->likelihood, "
      "no-CWE Critical->EoP fallback, closed findings excluded)")

# list includes counts
r = client.get("/api/v1/threat-models")
entry = next(m for m in r.json()["items"] if m["id"] == bid)
assert entry["threat_count"] == 4 and entry["open_threat_count"] == 4
print("PASS: model list reports threat counts")

# delete cascades threats
client.delete(f"/api/v1/threat-models/{bid}")
assert run(db.threat_model_threats.count_documents({"model_id": bid})) == 0
print("PASS: deleting a model cascades to its threats")
