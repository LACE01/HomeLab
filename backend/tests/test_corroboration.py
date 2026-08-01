"""Two scanners finding the same thing must corroborate, not collide or duplicate.

Both syncs keyed findings as f"{cve}::{asset['hostname']}", so depending only on
how each tool spelled the host you got either a silent overwrite (the finding
claims to come from whichever scanner ran last) or a duplicate. These tests pin
the fix and, more importantly, the SIGNAL it makes available: a single-source
finding means something completely different depending on whether the other
scanners looked and disagreed, or never looked at all.
"""
import os, sys, asyncio
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_corroboration"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_corroboration"]
db = db_module.db

import corroboration as corr
import entity_resolution as er

run = lambda c: asyncio.get_event_loop().run_until_complete(c)


# ============ the key is identity, not a name ============

k1 = corr.canonical_key(asset_id="asset-1", cve="CVE-2024-1234")
k2 = corr.canonical_key(asset_id="asset-1", cve="cve-2024-1234")
assert k1 == k2 == "CVE-2024-1234::asset-1"
print("PASS: the finding key is (CVE, resolved asset id) and is case-insensitive on the CVE — "
      "hostname spelling can no longer decide whether two reports are the same finding")

# Without a CVE, two tools' proprietary check ids are NOT claims about the same
# thing, so they must not merge just because they landed on the same host.
a = corr.canonical_key(asset_id="asset-1", native_id="38173", tool="Qualys VMDR")
b = corr.canonical_key(asset_id="asset-1", native_id="12345", tool="Tenable Nessus")
assert a != b and "asset-1" in a and "asset-1" in b
print("PASS: with no CVE, each tool's own check id keys its own finding — merging two proprietary "
      "ids because they share a host would be inventing agreement that doesn't exist")


# ============ a second scanner corroborates instead of overwriting ============

run(db.findings.delete_many({}))
base = {"title": "OpenSSL vulnerability", "status": "New", "asset_hostname": "web-1"}
r1 = run(corr.upsert_corroborated(db, asset_id="asset-1", cve="CVE-2024-1234",
                                   native_id="38173", tool="Qualys VMDR",
                                   severity="High", base=base))
assert r1["outcome"] == "created" and r1["source_count"] == 1

# Nessus, which spells the host "web-1.corp.local", reports the same CVE.
r2 = run(corr.upsert_corroborated(db, asset_id="asset-1", cve="CVE-2024-1234",
                                   native_id="98765", tool="Tenable Nessus",
                                   severity="High",
                                   base={**base, "asset_hostname": "web-1.corp.local"}))
assert r2["outcome"] == "corroborated"
assert run(db.findings.count_documents({})) == 1, "a duplicate finding was created"
doc = run(db.findings.find_one({}, {"_id": 0}))
assert doc["source_count"] == 2
assert {s["tool"] for s in doc["sources"]} == {"Qualys VMDR", "Tenable Nessus"}
assert {s["native_id"] for s in doc["sources"]} == {"38173", "98765"}
print("PASS: the same CVE from a second scanner becomes a second SOURCE on one finding, keeping "
      "both native ids — previously this either created a duplicate or overwrote source_tool, "
      "destroying the fact that two tools agreed")

# A human-edited field must not be rewritten by the next scanner to arrive.
run(db.findings.update_one({}, {"$set": {"remediation": "Ticket INC-4471; patching Tuesday"}}))
run(corr.upsert_corroborated(db, asset_id="asset-1", cve="CVE-2024-1234",
                              native_id="98765", tool="Tenable Nessus", severity="High",
                              base={**base, "remediation": "Upgrade OpenSSL"}))
doc = run(db.findings.find_one({}, {"_id": 0}))
assert doc["remediation"] == "Ticket INC-4471; patching Tuesday"
print("PASS: a later scanner fills blanks but never overwrites an existing value — notes a human "
      "wrote survive the next sync")

# re-reporting must not reset the SLA clock
first = next(s for s in doc["sources"] if s["tool"] == "Qualys VMDR")["first_seen"]
run(corr.upsert_corroborated(db, asset_id="asset-1", cve="CVE-2024-1234", native_id="38173",
                              tool="Qualys VMDR", severity="High", base=base))
doc = run(db.findings.find_one({}, {"_id": 0}))
assert next(s for s in doc["sources"] if s["tool"] == "Qualys VMDR")["first_seen"] == first
print("PASS: re-reporting refreshes last_seen but preserves first_seen — SLA clocks are measured "
      "from it and would otherwise reset on every sync, making every finding look brand new")


# ============ severity disagreement is kept, not averaged away ============

sources = [corr.make_source(tool="Qualys VMDR", native_id="1", severity="High"),
           corr.make_source(tool="Tenable Nessus", native_id="2", severity="Medium")]
sev = corr.reconcile_severity(sources)
assert sev["severity"] == "High", "the higher rating must win; rounding down overrules a tool"
assert sev["agreement"] == "disputed"
assert "Qualys VMDR rates this High" in sev["disagreement"]
assert "Tenable Nessus rates it Medium" in sev["disagreement"]
print("PASS: when scanners disagree the higher severity is used AND the disagreement is recorded "
      "in words — averaging would invent a rating no tool actually asserted")

sev = corr.reconcile_severity([corr.make_source(tool="a", native_id="1", severity="High"),
                                corr.make_source(tool="b", native_id="2", severity="High")])
assert sev["agreement"] == "unanimous"
print("PASS: agreement between tools is recorded explicitly, not just implied by a matching number")


# ============ THE payoff: what a single source actually means ============

# Case 1: other scanners cover this asset and stayed silent -> evidence toward FP.
verdict = corr.assess({"sources": [corr.make_source(tool="Qualys VMDR", native_id="1",
                                                     severity="High")]},
                       tools_covering_asset={"Qualys VMDR", "Tenable Nessus"})
assert verdict["status"] == "single_source_disputed" and verdict["confidence"] == "low"
assert "did not report it" in verdict["note"] and "false positive" in verdict["note"]
print("PASS: one scanner reporting something the OTHER scanners on that asset didn't is flagged as "
      "weak evidence of a false positive — before spending remediation effort on it")

# Case 2: nothing else scans this asset -> a gap in tooling, not a claim about the finding.
verdict = corr.assess({"sources": [corr.make_source(tool="Qualys VMDR", native_id="1",
                                                     severity="High")]},
                       tools_covering_asset={"Qualys VMDR"})
assert verdict["status"] == "single_source_uncorroborated" and verdict["confidence"] == "medium"
assert "COVERAGE GAP" in verdict["note"]
assert "not evidence either way" in verdict["note"]
print("PASS: the SAME single-source finding on an asset no other scanner covers is reported as a "
      "coverage gap in the tooling — the opposite conclusion from identical-looking data, and a "
      "distinction that is only possible because identity was solved first")

verdict = corr.assess({"sources": [
    corr.make_source(tool="Qualys VMDR", native_id="1", severity="High"),
    corr.make_source(tool="Tenable Nessus", native_id="2", severity="High")]})
assert verdict["status"] == "corroborated" and verdict["confidence"] == "high"
assert "Independently confirmed by 2 tools" in verdict["note"]
print("PASS: a corroborated finding says so in words a person fixing it can act on")

# An IDS staying quiet about a CVE is not a dissenting vote.
verdict = corr.assess({"sources": [corr.make_source(tool="Qualys VMDR", native_id="1",
                                                     severity="High")]},
                       tools_covering_asset={"Qualys VMDR", "Albert"})
assert verdict["status"] == "single_source_uncorroborated", \
    "a non-VA tool's silence was counted as disagreement"
print("PASS: only host vulnerability scanners count as dissenting voices — an IDS not reporting a "
      "CVE says nothing, and treating its silence as disagreement would manufacture false positives")


# ============ tools_covering reads from entity resolution ============

run(db.asset_identifiers.delete_many({}))
run(er.record_identifiers(db, "asset-1", er.identifiers_from(
    {"hostname": "web-1", "qualys_host_id": "Q1"}), "qualys"))
run(er.record_identifiers(db, "asset-1", er.identifiers_from(
    {"computerDnsName": "web-1.corp.local", "defender_device_id": "D1"}), "defender"))
covering = run(corr.tools_covering(db, "asset-1"))
assert covering == {"Qualys VMDR", "Microsoft Defender for Endpoint"}, covering
print("PASS: which tools cover an asset is derived from its identifiers — the question is only "
      "answerable because every source now attaches identity to the same canonical asset")


# ============ backfilling the duplicates already in the backlog ============

run(db.findings.delete_many({}))
run(db.findings.insert_many([
    # The same CVE on the same machine, twice, because the tools spelled the host
    # differently back when the key was built from a name.
    {"id": "old-q", "cve": "CVE-2024-9999", "asset_id": "asset-7", "status": "New",
     "source_tool": "Qualys VMDR", "source_native_id": "111", "severity": "High",
     "first_seen_at": "2026-01-01T00:00:00Z", "canonical_key": "CVE-2024-9999::web-7"},
    {"id": "old-n", "cve": "CVE-2024-9999", "asset_id": "asset-7", "status": "New",
     "source_tool": "Tenable Nessus", "source_native_id": "222", "severity": "Medium",
     "first_seen_at": "2026-02-01T00:00:00Z",
     "canonical_key": "CVE-2024-9999::web-7.corp.local"},
    # A genuine single finding that must be left alone
    {"id": "solo", "cve": "CVE-2024-1111", "asset_id": "asset-8", "status": "New",
     "source_tool": "Qualys VMDR", "severity": "Low", "first_seen_at": "2026-03-01T00:00:00Z"},
]))

preview = run(corr.backfill_existing(db, dry_run=True))
assert preview["duplicate_groups"] == 1 and preview["findings_folded"] == 1
assert preview["examples"][0]["kept"] == "old-q"
assert run(db.findings.find_one({"id": "old-n"}))["status"] == "New", "dry run changed data"
assert preview["note"] == "Nothing was changed."
print("PASS: the backfill defaults to a dry run and shows exactly what it would fold — this "
      "rewrites the live backlog, so seeing it first is the difference between a migration and "
      "an accident")

result = run(corr.backfill_existing(db, dry_run=False))
assert result["findings_folded"] == 1
kept = run(db.findings.find_one({"id": "old-q"}, {"_id": 0}))
assert kept["source_count"] == 2
assert {s["tool"] for s in kept["sources"]} == {"Qualys VMDR", "Tenable Nessus"}
assert kept["severity"] == "High" and kept["severity_agreement"] == "disputed"
assert kept["canonical_key"] == "CVE-2024-9999::asset-7", "the key must be rebuilt on asset id"
print("PASS: folding keeps the OLDEST finding (its first_seen drives the SLA clock), carries both "
      "tools across, and re-keys on asset id so it can't duplicate again")

folded = run(db.findings.find_one({"id": "old-n"}, {"_id": 0}))
assert folded["status"] == "Superseded" and folded["superseded_by"] == "old-q"
assert "spelled the hostname differently" in folded["superseded_reason"]
print("PASS: the folded finding is marked Superseded with a pointer and a reason, not deleted — "
      "its id may appear in an IR case, a report or a ticket")

assert run(db.findings.find_one({"id": "solo"}))["status"] == "New"
print("PASS: a genuinely single finding is untouched")
