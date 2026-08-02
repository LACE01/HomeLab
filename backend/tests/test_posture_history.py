"""Blast radius, point-in-time posture, and the change feed."""
import os, sys, asyncio
from datetime import datetime, timezone, timedelta
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_posture_history"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_posture_history"]
db = db_module.db

import posture_history as ph

run = lambda c: asyncio.get_event_loop().run_until_complete(c)
now = datetime.now(timezone.utc)
TODAY = now.strftime("%Y-%m-%d")
YESTERDAY = (now - timedelta(days=1)).strftime("%Y-%m-%d")
LAST_WEEK = (now - timedelta(days=7)).strftime("%Y-%m-%d")


# ============ blast radius ============

run(db.assets.insert_many([
    {"id": "web-1", "hostname": "web-1", "status": "active", "criticality": "high",
     "product_id": "p1", "product_name": "Permit Portal", "owner_team": "Infra",
     "intune_device_id": "I-1"},
    {"id": "web-2", "hostname": "web-2", "status": "active", "product_id": "p1",
     "product_name": "Permit Portal", "owner_team": "Infra"},
    {"id": "dc-1", "hostname": "dc-1", "status": "active", "owner_team": "Identity"},
    {"id": "lonely", "hostname": "lonely", "status": "active", "owner_team": "Unassigned"},
]))
run(db.attack_paths.insert_one({
    "id": "p-1", "status": "active", "node_asset_ids": ["web-1", "dc-1"],
    "target_label": "Domain Controller", "score": 90}))
run(db.directory_users.insert_one({
    "id": "u1", "primary_device_id": "I-1", "is_privileged": True,
    "display_name": "Dana Admin"}))
run(db.security_reviews.insert_one({
    "id": "sr-1", "review_number": "SR-2026-004", "title": "Permit Portal",
    "linked_asset_ids": ["web-1"], "decision": "Approved with conditions"}))
run(db.risk_register.insert_one({
    "id": "r-1", "title": "Portal availability", "status": "open",
    "linked_asset_ids": ["web-1"], "owner": "Infra"}))

br = run(ph.blast_radius(db, "web-1"))
kinds = {r["kind"] for r in br["relations"]}
assert kinds == {"service", "ownership", "attack_path", "governance", "identity", "risk"}, kinds
print("PASS: blast radius pulls six DIFFERENT kinds of relationship — service, ownership, attack "
      "path, governance, identity and tracked risk")

for r in br["relations"]:
    assert r["why"], f"{r['kind']} has no explanation"
assert len(br["relations"]) == len({r["kind"] for r in br["relations"]})
print("PASS: each relationship explains why it constitutes blast radius, rather than just listing "
      "related records")

path_rel = next(r for r in br["relations"] if r["kind"] == "attack_path")
assert path_rel["items"][0]["id"] == "dc-1"
assert "demonstrated route" in path_rel["why"]
print("PASS: downstream attack-path nodes are reported as reachable FROM here — only what comes "
      "after this asset on the path, not the whole path")

assert "privileged user's primary device" in br["summary"]
assert "not contained to this host" in br["summary"]
assert br["related_total"] >= 6
print("PASS: the summary names the two facts that change the response — an identity risk and an "
      "uncontained blast radius")

# the counts are NOT merged into a single number
assert "blast_radius_score" not in br
print("PASS: relationships are kept separate rather than collapsed into one score — 'blast radius: "
      "47' would not be actionable")

lonely = run(ph.blast_radius(db, "lonely"))
assert lonely["relations"] == []
assert "may mean ownership and service mapping were never filled in" in lonely["summary"]
print("PASS: an asset with no relationships says the data might simply be missing, rather than "
      "asserting it is isolated — an unmapped asset and an isolated one look identical")

assert run(ph.blast_radius(db, "nope")) is None


# ============ snapshots ============

run(db.findings.insert_many([
    {"id": "f1", "status": "New", "severity": "Critical", "kev_flag": True,
     "asset_id": "web-1", "due_at": (now - timedelta(days=2)).isoformat()},
    {"id": "f2", "status": "New", "severity": "High", "kev_flag": False, "asset_id": "web-1"},
    {"id": "f3", "status": "Fixed validated", "severity": "High", "asset_id": "web-2"},
]))
run(db.assets.update_one({"id": "web-1"}, {"$set": {"internet_facing": True}}))

snap = run(ph.take_snapshot(db, day=LAST_WEEK))
assert snap["counts"]["open_findings"] == 2, "closed findings must not count as open"
assert snap["counts"]["by_severity"]["Critical"] == 1
assert snap["counts"]["kev"] == 1
assert snap["counts"]["overdue"] == 1
assert snap["counts"]["internet_facing_assets"] == 1
assert "ids" not in snap, "the return value should not ship the id lists to every caller"
print("PASS: a snapshot records open findings by severity, KEV, overdue, exposure and paths — and "
      "correctly excludes closed findings")

stored = run(db.posture_snapshots.find_one({"day": LAST_WEEK}, {"_id": 0}))
assert set(stored["ids"]["open_findings"]) == {"f1", "f2"}
assert "title" not in str(stored["ids"]), "ids only, not copies of the documents"
print("PASS: the stored snapshot keeps ID LISTS rather than document copies — so a year of daily "
      "history stays small while 'open then but not now' remains answerable")

# idempotent per day
run(ph.take_snapshot(db, day=LAST_WEEK))
assert run(db.posture_snapshots.count_documents({"day": LAST_WEEK})) == 1
print("PASS: taking a snapshot twice in one day replaces rather than duplicates")


# ============ point-in-time lookup falls back gracefully ============

got = run(ph.snapshot_for(db, LAST_WEEK))
assert got["exact"] is True

missing_day = (now - timedelta(days=3)).strftime("%Y-%m-%d")
got = run(ph.snapshot_for(db, missing_day))
assert got["exact"] is False and got["day"] == LAST_WEEK
assert "closest earlier one" in got["note"]
print("PASS: asking for a day with no snapshot returns the nearest EARLIER one and says so — "
      "someone asking about a specific date shouldn't get nothing because the platform was down "
      "that night")

before_everything = run(ph.snapshot_for(db, "2020-01-01"))
assert before_everything is None


# ============ the change feed reports movement ============

# Now things get worse: a new KEV finding, a newly exposed asset, a new path.
run(db.findings.insert_one({
    "id": "f4", "status": "New", "severity": "Critical", "kev_flag": True,
    "asset_id": "web-2", "cve": "CVE-2026-1", "title": "New KEV bug",
    "asset_hostname": "web-2"}))
run(db.assets.update_one({"id": "web-2"}, {"$set": {"internet_facing": True}}))
run(db.attack_paths.insert_one({"id": "p-2", "status": "active",
                                 "node_asset_ids": ["web-2"], "target_label": "File server",
                                 "score": 60}))
run(ph.take_snapshot(db, day=TODAY))

ch = run(ph.changes_between(db, LAST_WEEK, TODAY))
assert ch["available"] is True
kinds = {e["kind"] for e in ch["events"]}
assert {"newly_kev", "newly_internet_facing", "new_attack_path"} <= kinds, kinds
print("PASS: the change feed detects newly-KEV findings, newly internet-facing assets and new "
      "attack paths — movement, not state")

kev_event = next(e for e in ch["events"] if e["kind"] == "newly_kev")
assert kev_event["items"][0]["cve"] == "CVE-2026-1"
assert "theoretical to confirmed" in kev_event["detail"]
print("PASS: each event carries the actual records that moved, not just a count")

deltas = {d["label"]: d for d in ch["deltas"]}
assert deltas["Open findings"]["change"] == 1
assert deltas["Open findings"]["direction"] == "worsened"
assert deltas["Known-exploited (KEV)"]["direction"] == "worsened"
print("PASS: deltas carry a DIRECTION, so 'up' on open findings reads as worse while 'up' on a "
      "good metric would not be miscoloured")

assert ch["events"][0]["severity"] == "high", "high-severity events must sort first"
assert "became known-exploited" in ch["summary"] or "internet-facing" in ch["summary"]
print("PASS: the summary leads with what got worse, and high-severity events sort to the top")


# ============ improvement is reported too ============

run(db.findings.update_many({"id": {"$in": ["f1", "f4"]}},
                             {"$set": {"status": "Fixed validated"}}))
tomorrow = (now + timedelta(days=1)).strftime("%Y-%m-%d")
run(ph.take_snapshot(db, day=tomorrow))
ch2 = run(ph.changes_between(db, TODAY, tomorrow))
closed = next(e for e in ch2["events"] if e["kind"] == "closed")
assert closed["count"] == 2
improved = [d for d in ch2["deltas"] if d["direction"] == "improved"]
assert improved
assert "Nothing got worse" in ch2["summary"] or "Down:" in ch2["summary"]
print("PASS: closures and improving metrics are reported as well — a change feed that only ever "
      "shows bad news gets ignored")


# ============ no history yet ============

run(db.posture_snapshots.delete_many({}))
ch3 = run(ph.changes_between(db, LAST_WEEK, TODAY))
assert ch3["available"] is False
assert "starts from the first snapshot taken" in ch3["note"]
print("PASS: with no prior snapshot the feed explains that history starts now, instead of showing "
      "a comparison against zero that would look like everything appeared today")


# ============ routes ============

import server, auth_utils
from routes import corroboration as corr_route
corr_route.db = db
from fastapi.testclient import TestClient

admin = {"id": "u1", "email": "a@x.com", "role": "admin", "name": "A", "teams": []}
server.app.dependency_overrides[auth_utils.get_current_user] = lambda: admin
client = TestClient(server.app)

# /v1/assets/{id}/blast-radius must not be swallowed by /v1/assets/{asset_id}
r = client.get("/api/v1/assets/web-1/blast-radius")
assert r.status_code == 200, r.text
assert r.json()["related_total"] >= 6
print("PASS: GET /v1/assets/{id}/blast-radius resolves correctly alongside the inventory router's "
      "own /v1/assets/{asset_id} routes")

assert client.get("/api/v1/assets/nope/blast-radius").status_code == 404

run(ph.take_snapshot(db, day=LAST_WEEK))
run(ph.take_snapshot(db, day=TODAY))

r = client.get("/api/v1/posture/snapshot")
assert r.status_code == 200
assert "ids" not in r.json(), "id lists are for diffing, not for shipping to a browser"
print("PASS: the snapshot endpoint returns counts without the internal id lists")

r = client.get(f"/api/v1/posture/changes?since={LAST_WEEK}&to={TODAY}")
body = r.json()
assert body["available"] is True and body["summary"]
print("PASS: GET /v1/posture/changes compares two days and returns a summary")

r = client.get("/api/v1/posture/history")
items = r.json()["items"]
assert len(items) >= 2
assert items[0]["day"] <= items[-1]["day"], "history should be oldest-first for charting"
assert all("ids" not in i for i in items)
print("PASS: the history endpoint returns oldest-first for charting, without id lists")
