"""Nikto findings on the platform's real finding backbone.

Nikto was already native (it shells out to the nikto binary), but its findings
bypassed the corroboration/reopen model every other scanner now uses: it keyed
them on a transient hostname/title string, so a re-scan of an issue that had been
marked Fixed created a DUPLICATE instead of reopening -- the exact bug class that
produced the 7,361-finding storm, waiting to happen again on the web scanner.
"""
import os, sys, asyncio
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_nikto_findings"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_nikto_findings"]
db = db_module.db

import nikto_scan

run = lambda c: asyncio.get_event_loop().run_until_complete(c)


PARSED = {
    "host": "app.example.com", "ip": "10.0.0.9", "port": "443",
    "vulnerabilities": [
        {"id": "999950", "method": "GET", "url": "/admin/",
         "msg": "Admin login page/section found."},
        {"id": "999103", "method": "GET", "url": "/",
         "msg": "The X-Frame-Options header is not present (clickjacking)."},
    ],
}


# ============ first scan creates findings with a sources[] array ============

r1 = run(nikto_scan.import_nikto_results(db, "https://app.example.com", PARSED))
assert r1["findings_created"] == 2 and r1["findings_reopened"] == 0
findings = run(db.findings.find({"source_tool": "Nikto"}, {"_id": 0}).to_list(10))
assert len(findings) == 2
for f in findings:
    assert f["source_count"] == 1
    assert f["sources"][0]["tool"] == "Nikto"
    assert f["asset_id"] in f["canonical_key"], "the key must be built on the resolved asset id"
    assert "::" in f["canonical_key"]
print("PASS: a Nikto scan creates findings keyed on the resolved asset id, each with a sources[] "
      "array — on the same backbone as Qualys and Nessus, not an ad-hoc orphan key")


# ============ a re-scan updates, does NOT duplicate ============

r2 = run(nikto_scan.import_nikto_results(db, "https://app.example.com", PARSED))
assert r2["findings_created"] == 0, "a re-scan of the same issues must not create new findings"
assert run(db.findings.count_documents({"source_tool": "Nikto"})) == 2
print("PASS: re-scanning the same issues creates ZERO new findings — the old code's per-URL "
      "hostname key would have deduped here too, but only while the finding stayed open")


# ============ the real fix: a CLOSED finding reopens instead of duplicating ============

target = run(db.findings.find_one({"canonical_key": {"$regex": "999950"}}, {"_id": 0}))
run(db.findings.update_one({"id": target["id"]}, {"$set": {"status": "Fixed validated"}}))

r3 = run(nikto_scan.import_nikto_results(db, "https://app.example.com", PARSED))
assert r3["findings_reopened"] == 1, "the closed finding should have reopened"
assert r3["findings_created"] == 0, "reopening must not create a duplicate"
assert run(db.findings.count_documents({"source_tool": "Nikto"})) == 2, "still two findings, not three"

reopened = run(db.findings.find_one({"id": target["id"]}, {"_id": 0}))
assert reopened["status"] == "Reopened"
assert reopened["reopened_count"] == 1
assert "present again" in reopened["verification_note"]
print("PASS: an issue Nikto sees again after it was marked Fixed REOPENS the original finding — the "
      "old code created a duplicate here, the same defect that caused the Qualys/Nessus storm on "
      "the web scanner")


# ============ per-URL issues stay distinct ============

reset_parsed = {
    "host": "app.example.com", "port": "443",
    "vulnerabilities": [
        {"id": "999103", "method": "GET", "url": "/", "msg": "X-Frame-Options not present."},
        {"id": "999103", "method": "GET", "url": "/reports", "msg": "X-Frame-Options not present."},
    ],
}
run(db.findings.delete_many({}))
r4 = run(nikto_scan.import_nikto_results(db, "https://app.example.com", reset_parsed))
assert r4["findings_created"] == 2, "the same check on two different URLs is two findings"
print("PASS: the same Nikto check on two different URLs stays two findings — the URL is part of the "
      "key because Nikto reports per-path, so /admin and /reports don't collapse into one")


# ============ Nikto findings light up WSTG (the library built for #44) ============

import wstg
xfo = run(db.findings.find_one({"canonical_key": {"$regex": "999103"}}, {"_id": 0}))
tests = wstg.tests_for_finding(xfo)
assert "WSTG-CLNT-09" in [t["id"] for t in tests], \
    f"a clickjacking finding should map to WSTG-CLNT-09, got {[t['id'] for t in tests]}"
print("PASS: a Nikto clickjacking finding maps to WSTG-CLNT-09 with no extra wiring — being on the "
      "standard finding model means it feeds the WSTG methodology automatically")
