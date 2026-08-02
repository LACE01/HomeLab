"""Changing a canonical key is a MIGRATION, and I shipped it without one.

The evidence, from the user's Engagements page: fourteen consecutive Qualys syncs
created 0 findings and updated ~7,467. The first sync after my key change created
7,361 and updated 105. It looked up every finding by the new key, found nothing,
and wrote a second copy of the entire backlog.

Two things are tested here: that a sync can no longer do this, and that the
damage already done can be repaired without destroying anything a human put into
those findings.
"""
import os, sys, asyncio
from datetime import datetime, timezone, timedelta
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_dedupe_repair"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_dedupe_repair"]
db = db_module.db

import corroboration as corr
import dedupe_repair as dr

run = lambda c: asyncio.get_event_loop().run_until_complete(c)
now = datetime.now(timezone.utc)


def reset():
    run(db.findings.delete_many({}))
    run(db.assets.delete_many({}))


# ============ the sync recognises a finding written under the OLD key ============

reset()
run(db.assets.insert_one({"id": "asset-1", "hostname": "web-1", "status": "active"}))
# Exactly as it existed before the key change.
run(db.findings.insert_one({
    "id": "legacy-1", "canonical_key": "CVE-2024-1234::web-1", "cve": "CVE-2024-1234",
    "asset_id": "asset-1", "status": "Valid", "severity": "High",
    "source_tool": "Qualys VMDR", "source_native_id": "38173",
    "first_seen_at": "2026-01-01T00:00:00Z", "owner_notes": "assigned to Infra"}))

doc, key = run(corr.find_existing(db, asset_id="asset-1", hostname="web-1",
                                   cve="CVE-2024-1234", native_id="38173",
                                   tool="Qualys VMDR"))
assert doc is not None, "the legacy-keyed finding was not found — this is the duplicate storm"
assert doc["id"] == "legacy-1"
assert key == "CVE-2024-1234::asset-1"
print("PASS: a finding stored under the OLD hostname-based key is found by the new lookup — this "
      "single fallback is what stops a sync writing a second copy of the whole backlog")

# and the key is migrated, so the fallback runs once per finding rather than forever
migrated = run(db.findings.find_one({"id": "legacy-1"}, {"_id": 0}))
assert migrated["canonical_key"] == "CVE-2024-1234::asset-1"
assert migrated["canonical_key_migrated_from"] == "CVE-2024-1234::web-1"
print("PASS: the key is migrated in place and records what it was migrated from — the fallback is "
      "a one-time cost per finding, and the change is auditable")

# a genuinely new finding is still created
doc, key = run(corr.find_existing(db, asset_id="asset-1", hostname="web-1",
                                   cve="CVE-2099-0001", native_id="99999",
                                   tool="Qualys VMDR"))
assert doc is None and key == "CVE-2099-0001::asset-1"
print("PASS: a vulnerability that genuinely has no existing record still returns None, so real new "
      "findings are not suppressed by the fallback")


# ============ the migration must not create a collision ============

reset()
run(db.assets.insert_one({"id": "a1", "hostname": "h1", "status": "active"}))
run(db.findings.insert_many([
    {"id": "old", "canonical_key": "CVE-1::h1", "cve": "CVE-1", "asset_id": "a1",
     "status": "New", "first_seen_at": "2026-01-01T00:00:00Z"},
    {"id": "new", "canonical_key": "CVE-1::a1", "cve": "CVE-1", "asset_id": "a1",
     "status": "New", "first_seen_at": "2026-08-01T00:00:00Z"},
]))
doc, key = run(corr.find_existing(db, asset_id="a1", hostname="h1", cve="CVE-1"))
assert doc["id"] == "new", "the new-key row should win the direct lookup"
assert run(db.findings.find_one({"id": "old"}))["canonical_key"] == "CVE-1::h1", \
    "the legacy row must not be re-keyed onto a key another row already holds"
print("PASS: when both an old-key and a new-key row exist, the migration does NOT collide them — "
      "two rows sharing a canonical key would make every later lookup ambiguous")


# ============ legacy key formats are all recognised ============

keys = corr.legacy_keys(hostname="web-1", cve="CVE-2024-1", native_id="38173",
                        tool="Qualys VMDR")
assert "CVE-2024-1::web-1" in keys and "38173::web-1" in keys
keys = corr.legacy_keys(hostname="web-1", native_id="12345", tool="Tenable Nessus")
assert "NESSUS-12345::web-1" in keys, "Nessus' own historical prefix must be recognised"
print("PASS: every historical key format is enumerated, including Nessus' NESSUS-<id> prefix — a "
      "future format change has one place to add its predecessor")


# ============ repairing the duplicates already written ============

reset()
run(db.assets.insert_one({"id": "a1", "hostname": "h1", "status": "active"}))
run(db.findings.insert_many([
    # The original, triaged by a human months ago.
    {"id": "orig", "canonical_key": "CVE-9::h1", "cve": "CVE-9", "asset_id": "a1",
     "status": "Risk accepted", "severity": "High", "source_tool": "Qualys VMDR",
     "source_native_id": "111", "first_seen_at": "2026-01-01T00:00:00Z",
     "reopened_count": 2, "exception_id": "exc-1"},
    # The copy the broken sync created this morning.
    {"id": "dupe", "canonical_key": "CVE-9::a1", "cve": "CVE-9", "asset_id": "a1",
     "status": "New", "severity": "Critical", "source_tool": "Qualys VMDR",
     "source_native_id": "111", "first_seen_at": "2026-08-02T18:29:00Z"},
    # An unrelated finding that must not be touched.
    {"id": "other", "canonical_key": "CVE-8::a1", "cve": "CVE-8", "asset_id": "a1",
     "status": "New", "severity": "Low", "first_seen_at": "2026-05-01T00:00:00Z"},
]))

preview = run(dr.repair(db, dry_run=True))
assert preview["duplicate_groups"] == 1 and preview["findings_folded"] == 1
assert preview["examples"][0]["keeping"]["id"] == "orig"
assert run(db.findings.find_one({"id": "dupe"}))["status"] == "New", "dry run mutated data"
assert "Nothing was changed" in preview["note"]
print("PASS: the repair dry-runs by default and shows exactly which row it would keep — this "
      "rewrites a live backlog, so seeing it first is the difference between a migration and a "
      "second accident")

result = run(dr.repair(db, dry_run=False))
assert result["findings_folded"] == 1

kept = run(db.findings.find_one({"id": "orig"}, {"_id": 0}))
# Everything a human or time put on the original survives.
assert kept["status"] == "Risk accepted", "a human's triage decision was discarded"
assert kept["reopened_count"] == 2 and kept["exception_id"] == "exc-1"
assert kept["first_seen_at"] == "2026-01-01T00:00:00Z", "the SLA clock was reset"
assert kept["canonical_key"] == "CVE-9::a1", "the survivor should carry the CURRENT key"
print("PASS: the ORIGINAL survives with its accepted-risk decision, exception link, reopen count "
      "and first_seen intact — 'delete the newer row' would have thrown all of that away")

folded = run(db.findings.find_one({"id": "dupe"}, {"_id": 0}))
assert folded["status"] == "Superseded" and folded["superseded_by"] == "orig"
assert "without a migration path" in folded["superseded_reason"]
print("PASS: the duplicate is marked Superseded with a pointer and the reason, not deleted — its "
      "id may already appear in a report, a ticket or an IR case")

assert run(db.findings.find_one({"id": "other"}))["status"] == "New"
print("PASS: an unrelated finding is untouched")


# ============ a triaged duplicate wins over an older untriaged one ============

reset()
run(db.findings.insert_many([
    {"id": "older-untouched", "cve": "CVE-7", "asset_id": "a1", "status": "New",
     "first_seen_at": "2026-01-01T00:00:00Z"},
    {"id": "newer-triaged", "cve": "CVE-7", "asset_id": "a1", "status": "False positive",
     "first_seen_at": "2026-07-01T00:00:00Z"},
]))
run(dr.repair(db, dry_run=False))
assert run(db.findings.find_one({"id": "newer-triaged"}))["status"] == "False positive"
assert run(db.findings.find_one({"id": "older-untouched"}))["status"] == "Superseded"
survivor = run(db.findings.find_one({"id": "newer-triaged"}, {"_id": 0}))
assert survivor["first_seen_at"] == "2026-01-01T00:00:00Z", \
    "the earliest observation date should carry over to the survivor"
print("PASS: a triaged copy beats an older untriaged one, and still inherits the earliest "
      "first_seen — losing a false-positive decision is worse than losing a few days of age, and "
      "neither has to be lost")


# ============ two conflicting decisions are NOT merged ============

reset()
run(db.findings.insert_many([
    {"id": "accepted", "cve": "CVE-6", "asset_id": "a1", "status": "Risk accepted",
     "first_seen_at": "2026-01-01T00:00:00Z"},
    {"id": "fp", "cve": "CVE-6", "asset_id": "a1", "status": "False positive",
     "first_seen_at": "2026-02-01T00:00:00Z"},
]))
result = run(dr.repair(db, dry_run=False))
assert result["conflict_count"] == 1
assert result["findings_folded"] == 0
assert "would silently discard one" in result["conflicts"][0]["reason"]
assert run(db.findings.find_one({"id": "fp"}))["status"] == "False positive"
assert run(db.findings.find_one({"id": "accepted"}))["status"] == "Risk accepted"
print("PASS: when two copies carry DIFFERENT human decisions the repair refuses to choose and "
      "reports the conflict — automatically discarding one of two triage decisions is exactly the "
      "kind of quiet damage this whole exercise is about")


# ============ two tools' proprietary ids are not the same finding ============

reset()
run(db.findings.insert_many([
    {"id": "q", "asset_id": "a1", "status": "New", "source_tool": "Qualys VMDR",
     "source_native_id": "999", "first_seen_at": "2026-01-01T00:00:00Z"},
    {"id": "n", "asset_id": "a1", "status": "New", "source_tool": "Tenable Nessus",
     "source_native_id": "999", "first_seen_at": "2026-01-02T00:00:00Z"},
]))
result = run(dr.repair(db, dry_run=True))
assert result["findings_folded"] == 0, \
    "two different scanners' check ids were merged just because the numbers matched"
print("PASS: QID 999 and Nessus plugin 999 are not merged — with no CVE, a check id is only "
      "comparable within the scanner that issued it")


# ============ routes ============

import server, auth_utils
from routes import corroboration as corr_route
corr_route.db = db
from fastapi.testclient import TestClient

admin = {"id": "u1", "email": "a@x.com", "role": "admin", "name": "A", "teams": []}
server.app.dependency_overrides[auth_utils.get_current_user] = lambda: admin
client = TestClient(server.app)

reset()
run(db.findings.insert_many([
    {"id": "o", "cve": "CVE-5", "asset_id": "a1", "status": "New", "title": "dup",
     "first_seen_at": "2026-01-01T00:00:00Z"},
    {"id": "d", "cve": "CVE-5", "asset_id": "a1", "status": "New", "title": "dup",
     "first_seen_at": "2026-08-02T00:00:00Z"},
]))

r = client.get("/api/v1/findings/duplicates")
assert r.status_code == 200, r.text
body = r.json()
assert body["group_count"] == 1 and body["extra_findings"] == 1
assert len(body["groups"][0]["findings"]) == 2
print("PASS: GET /v1/findings/duplicates reports the groups and how many EXTRA findings exist — "
      "the number that tells you how inflated the backlog is")

r = client.post("/api/v1/findings/duplicates/repair", json={})
assert r.json()["dry_run"] is True and r.json()["findings_folded"] == 1
assert run(db.findings.find_one({"id": "d"}))["status"] == "New"

r = client.post("/api/v1/findings/duplicates/repair", json={"dry_run": False})
assert r.json()["findings_folded"] == 1
assert run(db.findings.find_one({"id": "d"}))["status"] == "Superseded"
print("PASS: the repair endpoint dry-runs unless explicitly told otherwise")


# ============ the actual regression: a sync must not double the backlog ============

# The scenario that produced 7,361 duplicates, driven through the real
# _upsert_finding rather than a stand-in.
reset()
import qualys_sync as qs

KB = {"38173": {"title": "OpenSSL vuln", "cve": "CVE-2024-1234", "cvss": 7.5,
                "cwe": "CWE-119", "category": "General remote services",
                "consequence": "c", "diagnosis": "d", "solution": "s"},
      "90001": {"title": "Config check", "cve": None, "cvss": None, "cwe": None,
                "category": "Windows", "consequence": "c", "diagnosis": "d", "solution": "s"}}

DET = [{"qid": "38173", "hostname": "web-1", "ip": "10.0.0.5", "os": "Linux",
        "severity": "4", "first_found": "2026-01-01T00:00:00Z",
        "qualys_host_id": "Q1"},
       {"qid": "90001", "hostname": "web-1", "ip": "10.0.0.5", "os": "Linux",
        "severity": "2", "first_found": "2026-01-01T00:00:00Z",
        "qualys_host_id": "Q1"}]

# First sync: creates the findings, under whatever key the code writes today.
outcomes = [run(qs._upsert_finding(db, d, KB)) for d in DET]
assert outcomes.count("created") == 2, outcomes
after_first = run(db.findings.count_documents({}))
assert after_first == 2

# Now rewrite their keys to the v1 hostname-based format, which is what every
# finding in the live database actually looks like.
for f in run(db.findings.find({}, {"_id": 0}).to_list(10)):
    legacy = f"{f.get('cve') or f.get('qid')}::web-1"
    run(db.findings.update_one({"id": f["id"]}, {"$set": {"canonical_key": legacy}}))

# Second sync -- the one that created 7,361 duplicates in production.
outcomes = [run(qs._upsert_finding(db, d, KB)) for d in DET]
after_second = run(db.findings.count_documents({}))

assert after_second == 2, (
    f"the sync created {after_second - after_first} duplicate finding(s) — this is the exact "
    "failure that produced 7,361 new findings in one run")
assert "created" not in outcomes, outcomes
print("PASS: running the REAL Qualys upsert against findings stored under the old key format "
      "updates them instead of duplicating them — driven end to end, because the unit-level "
      "lookup passing is not the same as the sync being fixed")

# and the keys were migrated on the way through
for f in run(db.findings.find({}, {"_id": 0}).to_list(10)):
    assert "::web-1" not in f["canonical_key"], f["canonical_key"]
    assert f.get("canonical_key_migrated_from")
print("PASS: both findings were migrated to the current key format during that sync, so the "
      "legacy fallback is not paid again on every future run")

# a third sync is a plain no-op
outcomes = [run(qs._upsert_finding(db, d, KB)) for d in DET]
assert run(db.findings.count_documents({})) == 2 and "created" not in outcomes
print("PASS: a third sync creates nothing — the steady state is 'updated', which is what the "
      "fourteen healthy runs before the regression looked like")


# ============ the CLI entry point ============

# The HTTP endpoints need an admin token and a booted API. A repair you cannot
# run because the thing you are repairing is unhealthy is not much of a repair,
# so the same logic is reachable from the command line inside the container.
import subprocess, sys as _sys, os as _os

proc = subprocess.run(
    [_sys.executable, "dedupe_repair.py", "--help"],
    capture_output=True, text=True, cwd=_os.getcwd())
assert proc.returncode == 0, proc.stderr
assert "--apply" in proc.stdout and "dry run" in proc.stdout
print("PASS: dedupe_repair.py runs as a script and documents that --apply is required to change "
      "anything")

# the report renders every section without needing a database
import io, contextlib
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    dr._print_report({
        "dry_run": True, "duplicate_groups": 2, "findings_folded": 3, "conflict_count": 1,
        "examples": [{"identity": ["cve", "CVE-1", "a1"],
                       "keeping": {"id": "k", "status": "Risk accepted",
                                    "first_seen_at": "2026-01-01"},
                       "folding": [{"id": "d", "status": "New",
                                     "first_seen_at": "2026-08-02"}],
                       "tools_after_merge": ["Qualys VMDR"]}],
        "conflicts": [{"identity": ["cve", "CVE-9", "a1"], "reason": "r",
                        "findings": [{"id": "a", "status": "Risk accepted"},
                                      {"id": "b", "status": "False positive"}]}],
        "note": "Nothing was changed."})
out = buf.getvalue()
assert "DRY RUN" in out and "nothing changed" in out
assert "keep   k" in out and "fold   d" in out
assert "NOT MERGED" in out and "Resolve them by hand" in out
print("PASS: the printed report shows which row is kept, which are folded, and lists conflicts "
      "separately as needing a human — the decision is visible before it is made, not after")

# a non-CVE group is labelled by its scanner and check id rather than a bare tuple
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    dr._print_report({"dry_run": True, "duplicate_groups": 1, "findings_folded": 1,
                       "conflict_count": 0,
                       "examples": [{"identity": ["native", "qualys vmdr", "90001", "a1"],
                                      "keeping": {"id": "k", "status": "New",
                                                   "first_seen_at": "2026-01-01"},
                                      "folding": [], "tools_after_merge": []}],
                       "conflicts": [], "note": "n"})
assert "qualys vmdr check 90001" in buf.getvalue()
print("PASS: a finding with no CVE is described by its scanner and check id, so the report is "
      "readable for configuration findings too — which is most of the backlog")


# ============ purging: delete only what nothing points at ============

reset()
run(db.tickets.delete_many({}))
run(db.ir_cases.delete_many({}))

run(db.findings.insert_many([
    {"id": "keeper", "cve": "CVE-100", "asset_id": "a1", "status": "New",
     "first_seen_at": "2026-01-01T00:00:00Z"},
    # Three duplicates from the bad sync.
    {"id": "dup-free", "cve": "CVE-100", "asset_id": "a1", "status": "New",
     "first_seen_at": "2026-08-01T18:29:00Z"},
    {"id": "dup-ticketed", "cve": "CVE-101", "asset_id": "a1", "status": "New",
     "first_seen_at": "2026-08-01T18:29:00Z"},
    {"id": "keeper-101", "cve": "CVE-101", "asset_id": "a1", "status": "New",
     "first_seen_at": "2026-01-01T00:00:00Z"},
    {"id": "dup-in-case", "cve": "CVE-102", "asset_id": "a1", "status": "New",
     "first_seen_at": "2026-08-01T18:29:00Z"},
    {"id": "keeper-102", "cve": "CVE-102", "asset_id": "a1", "status": "New",
     "first_seen_at": "2026-01-01T00:00:00Z"},
]))
# Someone opened a ticket against one of the duplicates, and an IR case cites another.
run(db.tickets.insert_one({"id": "t1", "finding_id": "dup-ticketed"}))
run(db.ir_cases.insert_one({"id": "c1", "finding_ids": ["dup-in-case", "other"]}))

run(dr.repair(db, dry_run=False))
assert run(db.findings.count_documents({"status": "Superseded"})) == 3

preview = run(dr.purge_superseded(db, dry_run=True))
assert preview["candidates"] == 3
assert preview["deletable"] == 1, preview
assert preview["kept_because_referenced"] == 2
assert run(db.findings.count_documents({})) == 6, "dry run deleted something"
print("PASS: the purge finds 3 superseded duplicates but marks only 1 deletable — the other two "
      "are referenced by a ticket and an IR case, and a dangling id turns a working case into one "
      "that silently drops a row")

refs = {r["id"]: r["referenced_by"] for r in preview["referenced_examples"]}
assert "tickets.finding_id" in refs["dup-ticketed"]
assert "ir_cases.finding_ids" in refs["dup-in-case"]
print("PASS: each kept row names exactly what still points at it, so the decision is checkable "
      "rather than a bare count")

result = run(dr.purge_superseded(db, dry_run=False))
assert result["deleted"] == 1
assert run(db.findings.find_one({"id": "dup-free"})) is None
assert run(db.findings.find_one({"id": "dup-ticketed"}))["status"] == "Superseded"
assert run(db.findings.find_one({"id": "keeper"}))["status"] == "New"
print("PASS: only the unreferenced duplicate is deleted; the referenced ones stay as tombstones "
      "and the originals are untouched")


# ============ the purge cannot touch a human's own supersede ============

reset()
run(db.findings.insert_one({
    "id": "human-superseded", "cve": "CVE-200", "asset_id": "a1", "status": "Superseded",
    "superseded_by": "something", "superseded_reason": "Merged by an analyst during triage",
    "first_seen_at": "2026-08-01T18:29:00Z"}))
result = run(dr.purge_superseded(db, dry_run=True))
assert result["candidates"] == 0, "a human's supersede was treated as machine-generated"
print("PASS: only rows superseded BY THIS REPAIR are eligible — a finding an analyst superseded "
      "themselves is never swept up by a cleanup they did not ask for")


# ============ scoping to the one bad run ============

reset()
run(db.findings.insert_many([
    # imported_at is the field that matters -- see the dedicated test further
    # down for why first_seen_at is the wrong one.
    {"id": "old-dup", "cve": "CVE-300", "asset_id": "a1", "status": "Superseded",
     "superseded_reason": "Duplicate created when the finding key changed from hostname-based "
                           "to asset-id-based without a migration path. Folded into the original.",
     "first_seen_at": "2025-06-01T00:00:00Z", "imported_at": "2025-06-01T00:00:00Z"},
    {"id": "new-dup", "cve": "CVE-301", "asset_id": "a1", "status": "Superseded",
     "superseded_reason": "Duplicate created when the finding key changed from hostname-based "
                           "to asset-id-based without a migration path. Folded into the original.",
     "first_seen_at": "2025-06-01T00:00:00Z", "imported_at": "2026-08-01T18:29:00Z"},
]))
scoped = run(dr.purge_superseded(db, dry_run=True, created_after="2026-08-01T18:00:00Z"))
assert scoped["candidates"] == 1 and scoped["deletable"] == 1
assert scoped["scope"]["created_after"] == "2026-08-01T18:00:00Z"
print("PASS: --since scopes the purge to a single sync window, so cleaning up one bad run cannot "
      "quietly reach back through all of history")

unscoped = run(dr.purge_superseded(db, dry_run=True))
assert unscoped["candidates"] == 2
print("PASS: without --since every machine-folded duplicate is a candidate")


# ============ THE ONE THE USER'S DRY RUN CAUGHT ============
#
# Their real output: every example showed keep=Fixed validated, fold=New. The
# duplicate is evidence from the CURRENT scan that the vulnerability is still
# present; the survivor is a record that was closed at some earlier point.
#
# Folding the open row into the closed one and stopping there would mark 7,361
# live vulnerabilities as fixed, and the finding COUNT would look perfectly
# correct afterwards -- which is what makes it the most dangerous outcome this
# repair could produce.

reset()
run(db.findings.insert_many([
    {"id": "closed-orig", "cve": "CVE-2013-3900", "asset_id": "a1",
     "status": "Fixed validated", "reopened_count": 1,
     "first_seen_at": "2023-04-07T16:29:43Z", "imported_at": "2023-04-07T16:29:43Z"},
    {"id": "new-dup", "cve": "CVE-2013-3900", "asset_id": "a1", "status": "New",
     "first_seen_at": "2023-04-07T16:29:43Z", "imported_at": "2026-08-01T18:29:00Z"},
]))

preview = run(dr.repair(db, dry_run=True))
assert preview["reopened"] == 1, preview
assert any(t["from"] == "Fixed validated" and t["to"] == "Reopened"
            for t in preview["status_transitions"])
print("PASS: the dry run REPORTS that a closed survivor will be reopened, and shows the status "
      "transition — the user's run showed 'keep status=Fixed validated / fold status=New' on "
      "every example and nothing said what that would do to the survivor")

run(dr.repair(db, dry_run=False))
kept = run(db.findings.find_one({"id": "closed-orig"}, {"_id": 0}))
assert kept["status"] == "Reopened", \
    "a live vulnerability was left marked fixed — the count would look right and the data would be wrong"
assert kept["reopened_count"] == 2, "the reopen counter must advance, as the sync would have"
assert "reported this as present while this record was closed" in kept["verification_note"]
print("PASS: folding OPEN evidence into a CLOSED survivor REOPENS it, increments reopened_count "
      "and records why — finishing the job the broken sync started rather than silently closing "
      "a vulnerability the scanner still sees")

assert run(db.findings.find_one({"id": "new-dup"}))["status"] == "Superseded"
print("PASS: the duplicate is still folded away; only the survivor's status changes")


# a closed survivor with a closed duplicate must NOT be reopened
reset()
run(db.findings.insert_many([
    {"id": "c1", "cve": "CVE-1", "asset_id": "a1", "status": "Fixed validated",
     "first_seen_at": "2024-01-01T00:00:00Z"},
    {"id": "c2", "cve": "CVE-1", "asset_id": "a1", "status": "Fixed validated",
     "first_seen_at": "2024-06-01T00:00:00Z"},
]))
result = run(dr.repair(db, dry_run=False))
assert result["reopened"] == 0
assert run(db.findings.find_one({"id": "c1"}))["status"] == "Fixed validated"
print("PASS: two closed copies stay closed — reopening requires actual open evidence, not merely "
      "the presence of a duplicate")

# an open survivor is untouched
reset()
run(db.findings.insert_many([
    {"id": "o1", "cve": "CVE-2", "asset_id": "a1", "status": "Valid",
     "first_seen_at": "2024-01-01T00:00:00Z"},
    {"id": "o2", "cve": "CVE-2", "asset_id": "a1", "status": "New",
     "first_seen_at": "2026-08-01T18:29:00Z"},
]))
run(dr.repair(db, dry_run=False))
assert run(db.findings.find_one({"id": "o1"}))["status"] == "Valid"
print("PASS: an already-open survivor keeps its triage status")


# ============ --since must filter the ROW's write time ============

reset()
run(db.findings.insert_many([
    {"id": "d1", "status": "Superseded",
     "superseded_reason": "Duplicate created when the finding key changed from hostname-based "
                           "to asset-id-based without a migration path.",
     # The scanner first saw this vulnerability in 2023; the ROW was written by
     # the bad sync last night. Scoping on first_seen_at would exclude it.
     "first_seen_at": "2023-04-07T16:29:43Z", "imported_at": "2026-08-01T18:29:00Z"},
    {"id": "d2", "status": "Superseded",
     "superseded_reason": "Duplicate created when the finding key changed from hostname-based "
                           "to asset-id-based without a migration path.",
     "first_seen_at": "2023-04-07T16:29:43Z", "imported_at": "2024-01-01T00:00:00Z"},
]))
scoped = run(dr.purge_superseded(db, dry_run=True, created_after="2026-08-01T18:00:00Z"))
assert scoped["candidates"] == 1, (
    f"--since found {scoped['candidates']} rows; it must filter imported_at (when the ROW was "
    "written), not first_seen_at (the scanner's own first_found, which duplicates inherit and "
    "which is years old)")
assert scoped["referenced_examples"] == [] and scoped["deletable"] == 1
print("PASS: --since filters on imported_at, the time the ROW was written — filtering the "
      "inherited first_seen_at is why the user's purge reported 0 candidates for 7,361 duplicates")
