"""The context panel: why this finding matters HERE.

Two identical Critical findings, one on an internet-facing box under active
scanning with no EDR, one on an internal box with an approved exception. Severity
cannot tell them apart. This can, and these tests check that it says so in words
a person can act on -- with a source on every claim, and gaps reported rather
than hidden.
"""
import os, sys, asyncio
from datetime import datetime, timezone, timedelta
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_finding_context"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_finding_context"]
db = db_module.db

import finding_context as fc
import entity_resolution as er
import corroboration as corr

run = lambda c: asyncio.get_event_loop().run_until_complete(c)
now = datetime.now(timezone.utc)


# ---- the dangerous one -----------------------------------------------------
run(db.assets.insert_many([
    {"id": "web-1", "hostname": "web-1", "ip": "10.0.0.5", "status": "active",
     "exposure": "internet", "internet_facing": True, "criticality": "high",
     "intune_device_id": "I-1", "owner_team": "Infra"},
    {"id": "lab-1", "hostname": "lab-1", "ip": "10.9.9.9", "status": "active",
     "exposure": "internal", "internet_facing": False, "criticality": "low"},
]))
# web-1 has Qualys + Nessus + Intune, but NO Defender -> a real EDR gap
run(er.record_identifiers(db, "web-1", er.identifiers_from(
    {"hostname": "web-1", "qualys_host_id": "Q1"}), "qualys"))
run(er.record_identifiers(db, "web-1", er.identifiers_from(
    {"hostname": "web-1", "nessus_uuid": "N1"}), "nessus"))
run(er.record_identifiers(db, "web-1", er.identifiers_from(
    {"hostname": "web-1", "intune_device_id": "I-1"}), "intune"))
# lab-1 has everything, including EDR
for src, ident in [("qualys", {"hostname": "lab-1", "qualys_host_id": "Q2"}),
                    ("defender", {"hostname": "lab-1", "defender_device_id": "D2"}),
                    ("intune", {"hostname": "lab-1", "intune_device_id": "I-2"})]:
    run(er.record_identifiers(db, "lab-1", er.identifiers_from(ident), src))
run(db.assets.update_one({"id": "lab-1"}, {"$set": {
    "defender_risk_score": "Low", "intune_compliance_state": "compliant"}}))
run(db.assets.update_one({"id": "web-1"}, {"$set": {"intune_compliance_state": "noncompliant"}}))

run(db.easm_assets.insert_one({"hostname": "web-1", "ip": "10.0.0.5",
                                "open_ports": [443, 8080]}))
run(db.albert_alerts.insert_many([
    {"id": "al-1", "destination_ip": "10.0.0.5", "destination_port": 443,
     "category": "Exploit attempt", "time_gmt": (now - timedelta(days=1)).isoformat()},
    {"id": "al-2", "destination_ip": "10.0.0.5", "destination_port": 22,
     "category": "Scanning", "time_gmt": (now - timedelta(days=2)).isoformat()},
    {"id": "al-old", "destination_ip": "10.0.0.5", "destination_port": 443,
     "category": "Scanning", "time_gmt": (now - timedelta(days=90)).isoformat()},
]))
run(db.attack_paths.insert_one({
    "id": "p1", "status": "active", "node_asset_ids": ["web-1", "dc-1"], "score": 88,
    "target_label": "Domain Controller", "hop_count": 2,
    "narrative": "Exploit the exposed web service, then reuse credentials to reach the DC.",
    "breaking_finding_ids": ["f-web"]}))
run(db.directory_users.insert_one({
    "id": "u-admin", "primary_device_id": "I-1", "is_privileged": True,
    "display_name": "Dana Admin", "user_principal_name": "dana@example.com"}))
run(db.cti_reports.insert_one({
    "id": "r1", "cves": ["CVE-2024-1234"], "title": "Actor X exploiting CVE-2024-1234",
    "summary": "Mass exploitation observed.", "source": "OpenCTI",
    "url": "https://example/report", "published": "2026-07-01"}))

f_web = {
    "id": "f-web", "asset_id": "web-1", "cve": "CVE-2024-1234", "severity": "Critical",
    "title": "OpenSSL RCE", "kev_flag": True, "epss_score": 0.42, "port": 443,
    "status": "New",
    "sources": [corr.make_source(tool="Qualys VMDR", native_id="1", severity="Critical"),
                 corr.make_source(tool="Tenable Nessus", native_id="2", severity="Critical")],
}
run(db.findings.insert_one(dict(f_web)))

ctx = run(fc.build(db, f_web))


# ============ every claim cites a source ============

items = [i for g in ctx["sections"].values() for i in g]
assert items, "the panel produced nothing"
for i in items:
    assert i["source"], f"claim with no source: {i['headline']}"
    assert i["headline"].endswith(".") or i["headline"].endswith("?"), i["headline"]
print(f"PASS: all {len(items)} statements carry the module they came from — a panel that asserts "
      "things without saying where they came from is unfalsifiable, and an analyst who can't "
      "check it eventually stops believing any of it")


# ============ each module contributes what only it knows ============

def has(key):
    return any(i["key"] == key for i in items)


assert has("internet_facing") and has("easm_confirmed")
easm = next(i for i in items if i["key"] == "easm_confirmed")
assert "observed from outside" in easm["detail"]
print("PASS: reachability is corroborated by an outside-in scan, not just the inventory's own "
      "exposure field, which is usually a stale manual classification")

assert has("attack_path")
path = next(i for i in items if i["key"] == "attack_path")
assert "Domain Controller" in path["headline"]
assert "Fixing THIS finding breaks that path" in path["detail"]
print("PASS: the panel says this asset sits on a path to a crown jewel AND that fixing this "
      "particular finding breaks the chain — which is the difference between 'severe' and "
      "'fix this one first'")

assert has("active_attack") and has("active_attack_same_port")
act = next(i for i in items if i["key"] == "active_attack")
assert act["evidence"]["alert_count"] == 2, "the 90-day-old alert must fall outside the window"
same = next(i for i in items if i["key"] == "active_attack_same_port")
assert "port 443" in same["headline"] and "no longer a theoretical exposure" in same["detail"]
print("PASS: IDS traffic is correlated to the asset and to THE PORT this finding is on, inside a "
      "7-day window — this join is only possible because identity resolution ties the alert and "
      "the vulnerability to the same machine")

assert has("kev") and has("epss") and has("cti")
print("PASS: KEV, EPSS and threat-intel reporting are all surfaced as exploitation evidence")

assert has("privileged_user")
pu = next(i for i in items if i["key"] == "privileged_user")
assert "Dana Admin" in pu["detail"]
print("PASS: a privileged account using this as its primary device is named — compromising the box "
      "reaches those sessions")

assert has("corroboration_corroborated")
print("PASS: the fact that two scanners independently confirmed it is part of the context")


# ============ absence is reported, not hidden ============

assert has("edr_missing")
edr = next(i for i in items if i["key"] == "edr_missing")
assert edr["weight"] == "aggravating"
assert "control gap in its own right" in edr["detail"]
print("PASS: 'no EDR has ever reported on this machine' is stated as an aggravating fact — a panel "
      "that renders nothing when data is missing converts a blind spot into apparent safety")

assert has("unmanaged") is False and has("managed")
mgd = next(i for i in items if i["key"] == "managed")
assert mgd["weight"] == "aggravating" and "NOT compliant" in mgd["detail"]
print("PASS: enrolled-but-noncompliant is distinguished from compliant, because patch delivery is "
      "not assured in the first case")


# ============ the verdict is a sentence, not another score ============

v = ctx["verdict"]
assert "score" not in v and isinstance(v["headline"], str)
assert v["headline"] == "Act on this before other findings of the same severity."
assert "What makes it worse HERE:" in v["body"]
assert "port 443" in v["body"] or "Known Exploited" in v["body"]
assert v["aggravating_count"] >= 5
print("PASS: the verdict is a paragraph naming the specific reasons — the platform already has a "
      "risk score; what it lacked was the reasoning, and a second number wouldn't supply it")


# ============ the same finding, different asset, opposite answer ============

run(db.exceptions.insert_one({
    "id": "e1", "status": "active", "asset_ids": ["lab-1"],
    "approved_by": "CISO", "expires_at": "2027-01-01T00:00:00Z",
    "justification": "Isolated lab segment, compensating controls in place."}))
f_lab = {"id": "f-lab", "asset_id": "lab-1", "cve": "CVE-2024-1234", "severity": "Critical",
         "title": "OpenSSL RCE", "kev_flag": False, "epss_score": 0.0, "port": 443,
         "status": "New",
         "sources": [corr.make_source(tool="Qualys VMDR", native_id="9", severity="Critical")]}
run(db.findings.insert_one(dict(f_lab)))

ctx2 = run(fc.build(db, f_lab))
items2 = [i for g in ctx2["sections"].values() for i in g]
keys2 = {i["key"] for i in items2}

assert "internal_only" in keys2 and "no_attack_path" in keys2
assert "no_active_attack" in keys2 and "edr_present" in keys2 and "exception" in keys2
assert ctx2["verdict"]["headline"] == "Already accepted as a known risk."
assert ctx2["verdict"]["environmental_aggravators"] == 0
print("PASS: an IDENTICAL Critical CVE on a different asset produces the opposite verdict — same "
      "severity, same CVE, different environment, and the panel explains which facts differ")

# The CVE-intrinsic facts are correctly IDENTICAL on both assets: threat-intel
# reporting is a property of the vulnerability, not of where it happens to be
# installed. It is the ENVIRONMENTAL facts that diverge, and the panel keeps the
# two kinds apart rather than blending them into one number.
assert "cti" in keys2, "CVE-level intel should appear on both assets"
assert "kev" not in keys2, "this finding is not KEV-flagged"
env_only_on_web = {"internet_facing", "easm_confirmed", "attack_path", "active_attack",
                    "active_attack_same_port", "privileged_user", "edr_missing"}
assert not (env_only_on_web & keys2), (env_only_on_web & keys2)
# The CTI item is aggravating on BOTH assets, and must not be allowed to make the
# lab box read as urgent: it raises the base severity of the CVE everywhere,
# which is exactly what it does NOT distinguish between instances.
assert ctx2["verdict"]["intrinsic_aggravators"] >= 1
assert "true wherever it is installed" in ctx2["verdict"]["body"]
print("PASS: CVE-intrinsic evidence (threat intel) appears on both assets while every ENVIRONMENTAL "
      "aggravator appears on neither — the panel keeps 'what this bug is' separate from 'what it "
      "means here', which is the whole distinction severity cannot express")

exc = next(i for i in items2 if i["key"] == "exception")
assert "CISO" in exc["detail"] and "Isolated lab segment" in exc["detail"]
print("PASS: an existing approved exception is surfaced with who approved it and why, so nobody "
      "re-litigates a decision the organization already made")

# and the single-source finding is called out as disputed, since Qualys covers
# lab-1 alongside Defender... but only Qualys is a VA tool here plus defender
corro2 = next(i for i in items2 if i["key"].startswith("corroboration_"))
assert corro2["key"] == "corroboration_single_source_disputed", corro2["key"]
assert corro2["weight"] == "mitigating"
print("PASS: on an asset Defender also covers, a Qualys-only finding is flagged as a possible "
      "false positive — and that MITIGATES rather than aggravates, which is the correct direction")


# ============ missing data is its own category ============

run(db.assets.insert_one({"id": "no-ip", "hostname": "ghost", "status": "active",
                           "exposure": "internal"}))
f_ghost = {"id": "f-ghost", "asset_id": "no-ip", "severity": "High", "status": "New"}
ctx3 = run(fc.build(db, f_ghost))
items3 = [i for g in ctx3["sections"].values() for i in g]
gap = next(i for i in items3 if i["key"] == "no_ids_data")
assert gap["weight"] == "missing"
assert "can't be correlated" in gap["headline"]
assert "gaps in what we could check" in ctx3["verdict"]["body"]
print("PASS: an asset with no IP reports that IDS traffic COULDN'T be checked, and the verdict says "
      "so — 'we didn't look' and 'we looked and found nothing' are different claims and must not "
      "render identically")


# ============ a finding with no asset doesn't explode ============

ctx4 = run(fc.build(db, {"id": "orphan", "severity": "Low"}))
assert ctx4["verdict"]["headline"]
print("PASS: a finding with no linked asset still produces a coherent panel")


# ============ the route, and its ordering ============

import server, auth_utils
from routes import corroboration as corr_route
corr_route.db = db
from fastapi.testclient import TestClient

admin = {"id": "u1", "email": "a@x.com", "role": "admin", "name": "A", "teams": []}
server.app.dependency_overrides[auth_utils.get_current_user] = lambda: admin
client = TestClient(server.app)

r = client.get("/api/v1/findings/f-web/context")
assert r.status_code == 200, r.text
body = r.json()
assert body["verdict"]["headline"] == "Act on this before other findings of the same severity."
assert body["asset_hostname"] == "web-1"
assert set(body["section_labels"]) == set(body["sections"])
print("PASS: GET /v1/findings/{id}/context returns the assembled panel, and every section has a "
      "human-readable label rather than a raw key")

r = client.get("/api/v1/findings/nope/context")
assert r.status_code == 404
print("PASS: context for an unknown finding 404s instead of returning an empty panel that looks "
      "like 'nothing is wrong here'")

# The section labels are questions, which is what makes the panel readable by
# someone who is not a vulnerability analyst.
assert body["section_labels"]["active_attack"] == "Is anyone attacking it now?"
assert body["section_labels"]["controls"] == "What is protecting it?"
print("PASS: sections are phrased as the questions a person actually asks, not as module names")
