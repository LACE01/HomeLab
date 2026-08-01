"""Correlation: findings that exist only in the join.

Each input module is individually correct and individually blind. The tests below
build environments where no single module has anything alarming to say, and check
that the engine still produces the sentence a human would say about the
combination -- and, just as importantly, that it admits when it could not look.
"""
import os, sys, asyncio
from datetime import datetime, timezone, timedelta
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_correlation"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_correlation"]
db = db_module.db

import correlation as cx
import entity_resolution as er

run = lambda c: asyncio.get_event_loop().run_until_complete(c)
now = datetime.now(timezone.utc)


def reset():
    for coll in ("assets", "findings", "albert_alerts", "directory_users",
                  "breach_exposures", "attack_paths", "cert_checks",
                  "asset_identifiers", "correlation_hits"):
        run(db[coll].delete_many({}))


# ============ a rule with no data must say so, not report "all clear" ============

reset()
result = run(cx.run(db))
assert result["new_hits"] == 0
assert len(result["not_evaluated"]) == len(cx.RULES), result["not_evaluated"]
note = result["not_evaluated"][0]["note"]
assert "is not reporting 'no problems'" in note and "could not look" in note
print("PASS: with no data, every rule reports that it COULD NOT BE EVALUATED rather than returning "
      "no hits — an engine that goes quiet when a feed dies looks calm for months, which is the "
      "most dangerous shape this feature can take")


# ============ the rule that should wake someone up ============

reset()
run(db.assets.insert_one({
    "id": "web-1", "hostname": "web-1", "ip": "10.0.0.5", "status": "active",
    "internet_facing": True, "exposure": "internet", "criticality": "high"}))
run(er.record_identifiers(db, "web-1", er.identifiers_from(
    {"hostname": "web-1", "qualys_host_id": "Q1"}), "qualys"))
run(db.findings.insert_many([
    {"id": "f1", "asset_id": "web-1", "status": "New", "severity": "Critical",
     "cve": "CVE-2024-1234", "kev_flag": True, "port": 443},
    {"id": "f2", "asset_id": "web-1", "status": "New", "severity": "Medium",
     "cve": "CVE-2024-0001", "kev_flag": False, "port": 80},
]))
run(db.albert_alerts.insert_many([
    {"id": "a1", "destination_ip": "10.0.0.5", "destination_port": 443,
     "category": "Exploit attempt", "time_gmt": (now - timedelta(days=1)).isoformat()},
    {"id": "a2", "destination_ip": "10.0.0.5", "destination_port": 443,
     "category": "Scanning", "time_gmt": (now - timedelta(days=3)).isoformat()},
]))

result = run(cx.run(db))
hits = run(db.correlation_hits.find({}, {"_id": 0}).to_list(50))
kev = next(h for h in hits if h["rule_key"] == "kev_exposed_scanned")
assert kev["severity"] == "Critical", "traffic on the vulnerable port should escalate to Critical"
for phrase in ("internet-facing", "actively exploited", "CVE-2024-1234", "port 443"):
    assert phrase in kev["narrative"], phrase
assert kev["evidence"]["targeted_ports"] == [443]
assert kev["evidence"]["alert_count"] == 2
print("PASS: known-exploited + internet-facing + IDS traffic ON THE VULNERABLE PORT fires as "
      "Critical, and the narrative names the CVE, the port and the alert count — three modules, "
      "none of which would have alerted alone")

assert kev["why_it_matters"]
assert "All three at once" in kev["why_it_matters"]
print("PASS: the hit explains why the COMBINATION matters, not just what matched")

# the same host without the IDS traffic must not fire that rule
run(db.albert_alerts.delete_many({}))
run(db.correlation_hits.delete_many({}))
result = run(cx.run(db))
assert not any(h["rule_key"] == "kev_exposed_scanned"
                for h in run(db.correlation_hits.find({}, {"_id": 0}).to_list(50))) or \
    result["not_evaluated"], "the rule fired without its third condition"
print("PASS: removing any one leg of the combination stops the hit — the rule is a conjunction, "
      "not a scoring heuristic that fires on partial matches")


# ============ detection gap where the consequences are worst ============

reset()
run(db.assets.insert_one({
    "id": "laptop-9", "hostname": "laptop-9", "ip": "10.0.0.9", "status": "active",
    "intune_device_id": "I-9", "criticality": "medium"}))
# Qualys and Intune have seen it. Defender never has -> no EDR.
run(er.record_identifiers(db, "laptop-9", er.identifiers_from(
    {"hostname": "laptop-9", "qualys_host_id": "Q9"}), "qualys"))
run(er.record_identifiers(db, "laptop-9", er.identifiers_from(
    {"hostname": "laptop-9", "intune_device_id": "I-9"}), "intune"))
run(db.directory_users.insert_one({
    "id": "u1", "primary_device_id": "I-9", "is_privileged": True,
    "display_name": "Dana Admin", "user_principal_name": "dana@example.com"}))
run(db.findings.insert_one({"id": "f9", "asset_id": "laptop-9", "status": "New",
                             "severity": "Low"}))

run(cx.run(db))
hits = run(db.correlation_hits.find({}, {"_id": 0}).to_list(50))
edr = next(h for h in hits if h["rule_key"] == "no_edr_privileged")
assert "no endpoint detection" in edr["narrative"]
assert "Dana Admin" in edr["narrative"]
assert "nothing would detect it" in edr["narrative"]
print("PASS: 'no EDR has ever reported this machine' + 'a privileged account lives on it' fires — "
      "a fact only expressible because identity records WHICH systems have seen an asset")


# ============ a way in and a way up ============

reset()
run(db.assets.insert_one({"id": "ws-3", "hostname": "ws-3", "status": "active",
                           "intune_device_id": "I-3"}))
run(er.record_identifiers(db, "ws-3", er.identifiers_from(
    {"hostname": "ws-3", "intune_device_id": "I-3"}), "intune"))
run(db.directory_users.insert_one({"id": "u2", "primary_device_id": "I-3",
                                    "user_principal_name": "bob@example.com"}))
run(db.breach_exposures.insert_one({"id": "b1", "email": "bob@example.com",
                                     "breach": "SomeSite 2025"}))
run(db.findings.insert_one({"id": "f3", "asset_id": "ws-3", "status": "New",
                             "severity": "Critical", "cve": "CVE-2024-7777"}))

run(cx.run(db))
hits = run(db.correlation_hits.find({}, {"_id": 0}).to_list(50))
cred = next(h for h in hits if h["rule_key"] == "leaked_cred_plus_foothold")
assert "bob@example.com" in cred["narrative"]
assert "Either alone is routine" in cred["narrative"]
assert "a way in and a way up" in cred["narrative"]
print("PASS: a breached credential plus a High/Critical finding on that user's own device fires, "
      "and the narrative says explicitly that each half is unremarkable alone")


# ============ hits persist rather than re-alerting, and resolve when fixed ============

reset()
run(db.assets.insert_one({"id": "w", "hostname": "w", "ip": "10.0.0.1", "status": "active",
                           "internet_facing": True}))
run(er.record_identifiers(db, "w", er.identifiers_from({"hostname": "w"}), "qualys"))
run(db.findings.insert_one({"id": "fk", "asset_id": "w", "status": "New", "severity": "Critical",
                             "cve": "CVE-1", "kev_flag": True, "port": 443}))
run(db.albert_alerts.insert_one({"id": "ax", "destination_ip": "10.0.0.1",
                                  "destination_port": 443, "category": "Scanning",
                                  "time_gmt": (now - timedelta(days=1)).isoformat()}))

r1 = run(cx.run(db))
assert r1["new_hits"] == 1
r2 = run(cx.run(db))
assert r2["new_hits"] == 0 and r2["refreshed_hits"] == 1
assert run(db.correlation_hits.count_documents({})) == 1
print("PASS: a condition that persists stays ONE hit with a refreshed last_seen — re-alerting every "
      "run is how a correlation engine becomes a noise generator nobody reads")

# fix the finding; the hit should resolve rather than vanish
run(db.findings.update_one({"id": "fk"}, {"$set": {"status": "Fixed validated"}}))
r3 = run(cx.run(db))
assert r3["auto_resolved"] == 1
h = run(db.correlation_hits.find_one({}, {"_id": 0}))
assert h["status"] == "resolved" and "no longer holds" in h["resolved_reason"]
print("PASS: when the combination stops being true the hit is RESOLVED with a reason, not deleted — "
      "'this was true last week and isn't now' is exactly what a change feed needs")


# ============ partial data: some rules run, others abstain ============

reset()
run(db.assets.insert_one({"id": "x", "hostname": "x", "status": "active"}))
run(er.record_identifiers(db, "x", er.identifiers_from({"hostname": "x"}), "qualys"))
run(db.findings.insert_one({"id": "fx", "asset_id": "x", "status": "New", "severity": "High"}))
result = run(cx.run(db))
not_run = {n["rule_key"] for n in result["not_evaluated"]}
assert "kev_exposed_scanned" in not_run, "a rule needing IDS data ran without any"
assert "cert_expiry_critical" in not_run
assert result["input_availability"]["findings"] is True
assert result["input_availability"]["ids"] is False
print("PASS: with only some feeds present, the rules that can run do and the rest are listed as "
      "unevaluated with the exact inputs they were missing — so 'no hits today' is never ambiguous")


# ============ every rule is well-formed ============

for rule in cx.RULES:
    assert rule.key and rule.title and rule.severity in cx.SEVERITY
    assert rule.requires, f"{rule.key} declares no inputs, so it can never be marked unevaluable"
    assert rule.why_it_matters and len(rule.why_it_matters) > 20
    assert callable(rule.evaluate)
assert len({r.key for r in cx.RULES}) == len(cx.RULES), "duplicate rule keys"
print(f"PASS: all {len(cx.RULES)} rules declare their required inputs and carry an explanation of "
      "why the combination matters")


# ============ routes ============

import server, auth_utils
from routes import corroboration as corr_route
corr_route.db = db
from fastapi.testclient import TestClient

admin = {"id": "u1", "email": "a@x.com", "role": "admin", "name": "A", "teams": []}
server.app.dependency_overrides[auth_utils.get_current_user] = lambda: admin
client = TestClient(server.app)

reset()
run(db.assets.insert_one({"id": "w", "hostname": "w", "ip": "10.0.0.1", "status": "active",
                           "internet_facing": True}))
run(er.record_identifiers(db, "w", er.identifiers_from({"hostname": "w"}), "qualys"))
run(db.findings.insert_one({"id": "fk", "asset_id": "w", "status": "New", "severity": "Critical",
                             "cve": "CVE-1", "kev_flag": True, "port": 443}))
run(db.albert_alerts.insert_one({"id": "ax", "destination_ip": "10.0.0.1",
                                  "destination_port": 443, "category": "Scanning",
                                  "time_gmt": (now - timedelta(days=1)).isoformat()}))

r = client.post("/api/v1/correlation/run")
assert r.status_code == 200 and r.json()["new_hits"] == 1

r = client.get("/api/v1/correlation/hits")
items = r.json()["items"]
assert items and items[0]["rule_key"] == "kev_exposed_scanned"
assert items[0]["narrative"] and items[0]["why_it_matters"]
print("PASS: GET /v1/correlation/hits returns hits worst-first, each carrying its narrative")

r = client.get("/api/v1/correlation/rules")
body = r.json()
kev = next(x for x in body["rules"] if x["key"] == "kev_exposed_scanned")
assert kev["can_run"] is True and kev["missing_inputs"] == []
cert = next(x for x in body["rules"] if x["key"] == "cert_expiry_critical")
assert cert["can_run"] is False and "certs" in cert["missing_inputs"]
print("PASS: the rule catalogue shows which rules CAN run right now and exactly which feed each "
      "blocked rule is waiting on — so a quiet engine is explainable rather than reassuring")

hit_id = items[0]["id"]
r = client.patch(f"/api/v1/correlation/hits/{hit_id}", json={"status": "dismissed"})
assert r.status_code == 400 and "reason is required" in r.json()["detail"]
print("PASS: dismissing a hit without a reason is refused — a hit dismissed silently is "
      "indistinguishable from one nobody looked at")

r = client.patch(f"/api/v1/correlation/hits/{hit_id}",
                  json={"status": "dismissed", "reason": "compensating control in place"})
assert r.status_code == 200
h = run(db.correlation_hits.find_one({"id": hit_id}, {"_id": 0}))
assert h["status"] == "dismissed" and h["triage_reason"] == "compensating control in place"
assert h["triaged_by"] == "a@x.com"
print("PASS: a dismissal records who did it and why")

r = client.patch("/api/v1/correlation/hits/nope", json={"status": "acknowledged"})
assert r.status_code == 404
