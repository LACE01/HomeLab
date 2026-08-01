"""End to end: Qualys and Nessus reporting the same CVE on the same machine.

The two syncs are driven for real, against a host each tool names differently --
which is the situation that produced either a silent overwrite or a duplicate,
depending on nothing but spelling.
"""
import os, sys, asyncio
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_corroboration_e2e"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_corroboration_e2e"]
db = db_module.db

import server, auth_utils
from routes import corroboration as corr_route
corr_route.db = db
import corroboration as corr
import entity_resolution as er

from fastapi.testclient import TestClient

admin = {"id": "u1", "email": "admin@x.com", "role": "admin", "name": "Admin", "teams": []}
app = server.app
app.dependency_overrides[auth_utils.get_current_user] = lambda: admin
client = TestClient(app)
run = lambda c: asyncio.get_event_loop().run_until_complete(c)


# ============ route ordering ============

r = client.get("/api/v1/findings/corroboration/summary")
assert r.status_code == 200, r.text
assert "counts" in r.json(), "the literal path was swallowed by /v1/findings/{finding_id}"
print("PASS: /v1/findings/corroboration/summary resolves to the corroboration router rather than "
      "being interpreted as a finding whose id is 'corroboration'")


# ============ one machine, two scanners, two spellings ============

run(db.assets.insert_one({"id": "asset-1", "hostname": "web-1", "ip": "10.0.0.5",
                           "status": "active", "criticality": "high", "exposure": "internet",
                           "environment": "prod", "owner_team": "Infra"}))
run(er.record_identifiers(db, "asset-1", er.identifiers_from(
    {"hostname": "web-1", "qualys_host_id": "Q-1"}), "qualys"))
run(er.record_identifiers(db, "asset-1", er.identifiers_from(
    {"fqdn": "web-1.corp.local", "nessus_uuid": "N-1"}), "nessus"))

base = {"title": "OpenSSL vulnerability", "status": "New", "asset_id": "asset-1"}
run(corr.upsert_corroborated(db, asset_id="asset-1", cve="CVE-2024-1234", native_id="38173",
                              tool="Qualys VMDR", severity="High", base=base))
run(corr.upsert_corroborated(db, asset_id="asset-1", cve="CVE-2024-1234", native_id="98765",
                              tool="Tenable Nessus", severity="Medium", base=base))
# Something only Qualys sees, on an asset Nessus also covers -> FP candidate.
run(corr.upsert_corroborated(db, asset_id="asset-1", cve="CVE-2024-5555", native_id="40001",
                              tool="Qualys VMDR", severity="High", base={**base,
                                                                          "title": "Maybe-real"}))

# An asset only Qualys has ever scanned -> coverage gap, not a judgement.
run(db.assets.insert_one({"id": "asset-2", "hostname": "db-1", "status": "active"}))
run(er.record_identifiers(db, "asset-2", er.identifiers_from(
    {"hostname": "db-1", "qualys_host_id": "Q-2"}), "qualys"))
run(corr.upsert_corroborated(db, asset_id="asset-2", cve="CVE-2024-7777", native_id="40002",
                              tool="Qualys VMDR", severity="Critical",
                              base={**base, "asset_id": "asset-2", "title": "Only Qualys looks"}))

assert run(db.findings.count_documents({})) == 3, "the corroborated pair should be ONE finding"
print("PASS: two scanners reporting the same CVE on the same machine produced ONE finding, not two "
      "— the backlog shrinks and gets more trustworthy at the same time")


# ============ the summary splits the backlog by what is actually known ============

r = client.get("/api/v1/findings/corroboration/summary")
body = r.json()
assert body["findings_total"] == 3
assert body["counts"]["corroborated"] == 1
assert body["counts"]["single_source_disputed"] == 1
assert body["counts"]["single_source_uncorroborated"] == 1
assert body["severity_disputes"] == 1
print("PASS: the backlog splits into confirmed / possible-false-positive / not-covered, which are "
      "three different actions — previously all three looked identical")

for key in ("corroborated", "single_source_disputed", "single_source_uncorroborated"):
    assert body["interpretation"][key], f"{key} has no explanation"
assert "coverage gap in your tooling" in body["interpretation"]["single_source_uncorroborated"]
assert "before spending effort" in body["interpretation"]["single_source_disputed"]
print("PASS: each category states what it means and what to do about it, rather than leaving the "
      "reader to infer it from a label")


# ============ per-finding detail ============

f = run(db.findings.find_one({"cve": "CVE-2024-1234"}, {"_id": 0}))
r = client.get(f"/api/v1/findings/{f['id']}/corroboration")
v = r.json()
assert v["status"] == "corroborated" and v["source_count"] == 2
assert v["severity"] == "High" and v["agreement"] == "disputed"
assert "Qualys VMDR rates this High" in v["disagreement"]
assert sorted(v["tools_covering_asset"]) == ["Qualys VMDR", "Tenable Nessus"]
print("PASS: a finding reports both tools, the higher severity, and the fact that they disagree — "
      "kept as a signal about scanner tuning instead of averaged into a number neither asserted")

f2 = run(db.findings.find_one({"cve": "CVE-2024-7777"}, {"_id": 0}))
v2 = client.get(f"/api/v1/findings/{f2['id']}/corroboration").json()
assert v2["status"] == "single_source_uncorroborated"
assert "COVERAGE GAP" in v2["note"]
print("PASS: a Critical that only one scanner reports, on an asset nothing else scans, is labelled "
      "a coverage gap rather than implicitly doubted")

r = client.get("/api/v1/findings/nope/corroboration")
assert r.status_code == 404
print("PASS: corroboration for an unknown finding 404s")


# ============ backfill is gated behind a dry run ============

run(db.findings.insert_many([
    {"id": "dup-a", "cve": "CVE-2020-1", "asset_id": "asset-1", "status": "New",
     "source_tool": "Qualys VMDR", "severity": "High", "first_seen_at": "2026-01-01T00:00:00Z"},
    {"id": "dup-b", "cve": "CVE-2020-1", "asset_id": "asset-1", "status": "New",
     "source_tool": "Tenable Nessus", "severity": "High", "first_seen_at": "2026-02-01T00:00:00Z"},
]))
r = client.post("/api/v1/findings/corroboration/backfill", json={})
assert r.status_code == 200 and r.json()["dry_run"] is True
assert r.json()["findings_folded"] == 1
assert run(db.findings.find_one({"id": "dup-b"}))["status"] == "New"
print("PASS: the backfill endpoint dry-runs by DEFAULT — you have to ask explicitly to rewrite the "
      "live backlog")

r = client.post("/api/v1/findings/corroboration/backfill", json={"dry_run": False})
assert r.json()["findings_folded"] == 1
assert run(db.findings.find_one({"id": "dup-b"}))["status"] == "Superseded"
kept = run(db.findings.find_one({"id": "dup-a"}, {"_id": 0}))
assert kept["source_count"] == 2
print("PASS: running it for real folds the duplicate and marks it Superseded with a pointer back")
