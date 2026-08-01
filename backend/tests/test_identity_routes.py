"""The identity API: seeing duplicates, repairing them, and reviewing weak links.

Resolution running correctly on ingest does not fix the duplicates that years of
hostname-string matching already created, and it does not make a weak-key match
something you should trust blindly. These routes are what make an automated
identity system auditable rather than something you take on faith.
"""
import os, sys, asyncio
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_identity_routes"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_identity_routes"]
db = db_module.db

import server, auth_utils
from routes import identity as identity_route
identity_route.db = db
import entity_resolution as er

from fastapi.testclient import TestClient

admin = {"id": "u1", "email": "admin@x.com", "role": "admin", "name": "Admin", "teams": []}
app = server.app
app.dependency_overrides[auth_utils.get_current_user] = lambda: admin
client = TestClient(app)
run = lambda c: asyncio.get_event_loop().run_until_complete(c)


# ============ route ordering: literals must not be eaten by /{asset_id} ============

# inventory registers "/v1/assets/{asset_id}". If it were registered first, every
# request below would be interpreted as "find the asset whose id is 'duplicates'".
# This has bitten this codebase five separate times, so it gets an explicit test.
r = client.get("/api/v1/assets/duplicates")
assert r.status_code == 200, r.text
assert "items" in r.json(), "the literal route was shadowed by /v1/assets/{asset_id}"
r = client.get("/api/v1/assets/merges")
assert r.status_code == 200 and "items" in r.json()
r = client.get("/api/v1/assets/identity-links/uncertain")
assert r.status_code == 200 and "items" in r.json()
print("PASS: /v1/assets/duplicates, /merges and /identity-links/uncertain resolve to the identity "
      "router rather than being swallowed by the /v1/assets/{asset_id} catch-all")


# ============ backfill turns existing asset fields into resolvable identity ============

run(db.assets.insert_many([
    # The same laptop, created twice: once by Qualys from a short name, once by
    # Defender from an FQDN. This is the damage already in the database.
    {"id": "a-qualys", "hostname": "laptop-7", "ip": "10.1.2.3", "status": "active",
     "qualys_host_id": "Q-1001", "owner_team": "IT", "criticality": "medium"},
    {"id": "a-defender", "hostname": "laptop-7.corp.example.com", "status": "active",
     "defender_device_id": "D-77", "operating_system": "Windows 10"},
    # A genuinely separate machine
    {"id": "a-other", "hostname": "fileserver-1", "ip": "10.1.9.9", "status": "active"},
]))
run(db.findings.insert_many([
    {"id": "f1", "asset_id": "a-defender", "status": "New"},
    {"id": "f2", "asset_id": "a-defender", "status": "Valid"},
]))

r = client.post("/api/v1/assets/backfill-identity")
assert r.status_code == 200, r.text
body = r.json()
assert body["assets_scanned"] == 3
assert body["identifiers_written"] > 0
assert body["duplicate_candidates_found"] >= 1
print("PASS: backfill reads identity out of asset fields that already existed, so years of "
      "accumulated data becomes resolvable immediately instead of waiting for every connector "
      "to see every machine again")

assert "never merged automatically" in body["note"]
print("PASS: backfill reports duplicates and refuses to merge them itself — an automatic merge on "
      "weak evidence is the exact failure this system exists to prevent")


# ============ duplicates are surfaced with enough context to decide ============

r = client.get("/api/v1/assets/duplicates")
items = r.json()["items"]
dup = next(d for d in items if d["value"] == "laptop-7")
assert set(a["id"] for a in dup["assets"]) == {"a-qualys", "a-defender"}
assert dup["strength"] == "weak" and dup["safe_to_automerge"] is False
by_id = {a["id"]: a for a in dup["assets"]}
assert by_id["a-defender"]["open_findings"] == 2
assert by_id["a-qualys"]["open_findings"] == 0
print("PASS: a duplicate pair is shown with each side's hostname, owner, criticality and OPEN "
      "FINDING COUNT — you cannot choose which record to keep without knowing what would move")

assert "two servers can legitimately be named the same" in r.json()["note"]
print("PASS: the response states plainly that a shared short hostname is not proof of sameness")


# ============ merging, and undoing it ============

r = client.post("/api/v1/assets/merge",
                 json={"keep_id": "a-qualys", "absorb_id": "a-defender",
                        "reason": "same laptop, two names"})
assert r.status_code == 200, r.text
merge = r.json()
assert merge["findings_moved"] == 2
assert run(db.findings.count_documents({"asset_id": "a-qualys"})) == 2
kept = run(db.assets.find_one({"id": "a-qualys"}, {"_id": 0}))
assert kept["owner_team"] == "IT", "an existing value must survive the merge"
assert kept["operating_system"] == "Windows 10", "a blank on the survivor gets filled"
assert kept["defender_device_id"] == "D-77"
print("PASS: merging moves the findings and fills only the survivor's blanks — the merged record "
      "knows more than either original did, and loses nothing")

r = client.get("/api/v1/assets/duplicates")
assert not any(d["value"] == "laptop-7" for d in r.json()["items"]), \
    "a merged pair should no longer be offered as a duplicate"
print("PASS: once merged, the pair drops off the duplicates list")

r = client.get("/api/v1/assets/merges")
assert r.json()["items"][0]["keep_id"] == "a-qualys"
assert "absorbed_snapshot" not in r.json()["items"][0], \
    "the full snapshot is for undo, not for shipping to every client"
print("PASS: merge history is listed without dumping each absorbed asset's full document")

r = client.post(f"/api/v1/assets/merges/{merge['id']}/undo")
assert r.status_code == 200
restored = run(db.assets.find_one({"id": "a-defender"}, {"_id": 0}))
assert restored["status"] == "active" and restored.get("merged_into") is None
print("PASS: the merge is undoable through the API, not just in principle")

r = client.post(f"/api/v1/assets/merges/{merge['id']}/undo")
assert r.status_code == 400 and "already undone" in r.json()["detail"]
print("PASS: a second undo is refused with a clear reason instead of corrupting state")


# ============ identity, and the coverage answer that falls out of it ============

r = client.get("/api/v1/assets/a-qualys/identity")
assert r.status_code == 200, r.text
ident = r.json()
assert "qualys" in ident["sources"]
gaps = {g["source"] for g in ident["coverage_gaps"]}
assert "defender" in gaps and "intune" in gaps
assert any("No endpoint detection & response data" in g["means"] for g in ident["coverage_gaps"])
print("PASS: identity doubles as control coverage — 'no Defender identifier has ever been seen for "
      "this asset' means there is no EDR on it, which is a finding rather than a blank field")

r = client.get("/api/v1/assets/does-not-exist/identity")
assert r.status_code == 404
print("PASS: identity for an unknown asset 404s rather than returning an empty shell")


# ============ reviewing a weak link, and rejecting it ============

run(db.asset_identity_links.insert_one({
    "id": "link-1", "asset_id": "a-other", "source": "albert", "confidence": 0.5,
    "matched_on": {"kind": "hostname", "value": "fileserver-1"},
    "reason": "Matched only on short hostname 'fileserver-1'.",
    "created_at": er._now_iso(), "reviewed": False}))
run(er.record_identifiers(db, "a-other", er.identifiers_from(
    {"hostname": "fileserver-1", "ip": "10.1.9.9"}), "albert"))

r = client.get("/api/v1/assets/identity-links/uncertain")
items = r.json()["items"]
assert any(i["id"] == "link-1" for i in items)
assert items[0]["asset"]["hostname"] == "fileserver-1"
print("PASS: low-confidence links are queued for review with the asset they attached to")

before = run(db.asset_identifiers.count_documents({"asset_id": "a-other", "source": "albert"}))
assert before > 0
r = client.post("/api/v1/assets/identity-links/link-1/review",
                 json={"accept": False, "note": "different box"})
assert r.status_code == 200 and r.json()["identifiers_removed"] == before
after = run(db.asset_identifiers.count_documents({"asset_id": "a-other", "source": "albert"}))
assert after == 0
print("PASS: rejecting a link REMOVES the identifiers that source contributed — so the bad join "
      "stops influencing every downstream answer, which is the only reason reviewing it matters")

r = client.get("/api/v1/assets/identity-links/uncertain")
assert not any(i["id"] == "link-1" for i in r.json()["items"])
print("PASS: a reviewed link leaves the queue")
