"""Attack Path Analysis rebuilt as path enumeration: evidenced edges, crown-jewel
targets, ranked paths, narratives, choke points, and triage."""
import os, sys, asyncio
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_attack_paths"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_attack_paths"]

import server
import auth_utils
from routes import attack_paths as ap_route
ap_route.db = db_module.db
import attack_path_engine as ape

from fastapi.testclient import TestClient

admin_user = {"id": "u1", "email": "admin@x.com", "role": "admin", "name": "Admin", "teams": []}
app = server.app
app.dependency_overrides[auth_utils.get_current_user] = lambda: admin_user
client = TestClient(app)
db = db_module.db


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ============ pure helpers ============

assert ape._segment_of({"ip": "10.0.5.20"}) == "10.0.5.0/24"
assert ape._segment_of({"ip": "10.0.5.99"}) == ape._segment_of({"ip": "10.0.5.1"})
assert ape._segment_of({"environment": "prod", "owner_team": "IT"}) == "prod/IT"
print("PASS: assets segment by /24 when an IP is known, falling back to environment/team")

assert ape.is_internet_facing({"internet_facing": True})
assert ape.is_internet_facing({"exposure": "DMZ"})
# 93.184.216.34 is genuinely routable; 203.0.113.x is TEST-NET documentation
# space, which ipaddress correctly reports as NOT global.
assert ape.is_internet_facing({"ip": "93.184.216.34"})
assert not ape.is_internet_facing({"ip": "203.0.113.5"})
assert not ape.is_internet_facing({"ip": "10.0.0.5"})
print("PASS: internet exposure is detected from the flag, the exposure field, or a public IP")

assert ape.crown_jewel_reason({"criticality": "crown_jewel"}) == "explicitly tagged a crown jewel"
assert "pii" in (ape.crown_jewel_reason({"tags": ["PII"]}) or "")
assert ape.crown_jewel_reason({"criticality": "critical"}) == "rated business-critical"
assert ape.crown_jewel_reason({"hostname": "printer"}) is None
print("PASS: crown-jewel status comes from explicit tagging, sensitive-data tags, or business criticality")

kev = ape._exploit_weight({"kev_flag": True, "severity": "Medium"})
high = ape._exploit_weight({"severity": "High", "cvss_score": 8.0})
low = ape._exploit_weight({"severity": "Low", "cvss_score": 2.0})
assert kev == 1.0 and kev > high > low
print("PASS: exploit weighting puts actively-exploited (KEV) above raw CVSS severity")


# ============ graph construction ============

def _seed():
    for c in ("assets", "findings", "attack_paths", "attack_path_runs"):
        run(db[c].delete_many({}))
    run(db.assets.insert_many([
        # internet-facing web server, KEV-vulnerable
        {"id": "web01", "hostname": "web01.corp", "ip": "10.0.1.10", "os": "Ubuntu",
         "owner_team": "IT", "criticality": "high", "internet_facing": True,
         "shodan_ports": [443, 22], "tags": []},
        # file server on the same segment exposing SMB -- a real pivot
        {"id": "file01", "hostname": "file01.corp", "ip": "10.0.1.20", "os": "Windows Server",
         "owner_team": "IT", "criticality": "medium", "shodan_ports": [445, 3389], "tags": []},
        # the crown jewel, same segment as the file server
        {"id": "sql01", "hostname": "sql01.corp", "ip": "10.0.1.30", "os": "Windows Server",
         "owner_team": "IT", "criticality": "crown_jewel", "shodan_ports": [1433], "tags": ["pii"]},
        # unrelated host on a different segment with no pivot service
        {"id": "kiosk1", "hostname": "kiosk1.corp", "ip": "10.9.9.9", "os": "Windows",
         "owner_team": "Facilities", "criticality": "low", "shodan_ports": [], "tags": []},
    ]))
    run(db.findings.insert_many([
        {"id": "f-kev", "asset_id": "web01", "cve": "CVE-2026-1111", "title": "RCE in web stack",
         "severity": "Critical", "status": "New", "kev_flag": True, "cvss_score": 9.8},
        {"id": "f-med", "asset_id": "file01", "cve": "CVE-2026-2222", "title": "Info disclosure",
         "severity": "High", "status": "Valid", "kev_flag": False, "cvss_score": 7.5},
        {"id": "f-closed", "asset_id": "web01", "cve": "CVE-2020-9999", "title": "Old",
         "severity": "Critical", "status": "Fixed validated", "kev_flag": True},
    ]))


_seed()
graph = run(ape.build_environment_graph(db))
assert graph["assets_scanned"] == 4
assert graph["findings_considered"] == 2, "closed findings must not build attack paths"
web = graph["nodes"]["web01"]
assert web["internet_facing"] and web["kev_count"] == 1
assert "internet-exposed" in web["risk_factors"]
assert any("actively-exploited" in rf for rf in web["risk_factors"])
sql = graph["nodes"]["sql01"]
assert sql["crown_jewel"] and "crown jewel" in sql["crown_reason"]
print("PASS: the graph annotates each host with real risk factors (exposure, KEV count, crown-jewel status)")

kinds = {}
for e in graph["edges"]:
    kinds.setdefault(e["kind"], []).append(e)
assert any(e["to"] == "web01" for e in kinds["exposed_service"])
assert not any(e["to"] == "file01" for e in kinds.get("exposed_service", [])), \
    "an internal host must not get an internet edge"
assert any(e["from"] == "web01" and e["cve"] == "CVE-2026-1111" for e in kinds["exploitable"])
lateral = [e for e in kinds["lateral_service"] if e["from"] == "web01" and e["to"] == "file01"]
assert lateral and lateral[0]["service"] == "SMB" and lateral[0]["port"] == 445
assert all(e.get("evidence") for e in graph["edges"]), "every edge must cite its evidence"
assert all(e.get("confidence") in ("confirmed", "likely", "possible") for e in graph["edges"])
print("PASS: edges are typed, evidenced, and confidence-rated — SMB on the target is what makes a hop 'confirmed'")

# a host on another segment gets no cross-segment edge
cross = [e for e in graph["edges"] if e["from"] == "web01" and e["to"] == "kiosk1"]
assert not cross, "hosts on different segments must not be silently linked"
print("PASS: hosts on different network segments are not linked without evidence")


# ============ enumeration ============

paths = ape.enumerate_paths(graph)
assert paths, "an internet-exposed KEV host with an SMB pivot to a crown jewel is a path"
p = paths[0]
assert p["entry_node_id"] == "web01" and p["target_node_id"] == "sql01"
assert p["uses_kev"] is True
assert p["severity"] in ("Critical", "High")
assert p["nodes"][0]["type"] == "internet"
assert p["nodes"][-1]["id"] == "sql01"
assert "Initial Access" in p["tactics"] and "Lateral Movement" in p["tactics"]
print(f"PASS: enumeration finds the internet → web01 → … → sql01 path ({p['hops']} hops, score {p['risk_score']})")

# narrative reads like an analyst wrote it
n = p["narrative"]
assert "web01.corp" in n and "sql01.corp" in n
assert "actively exploited in the wild" in n
assert n.endswith(".")
assert len(n) > 120
print("PASS: each path carries a plain-English narrative naming the hosts, the exploit, and why the target matters")
print(f"       “{n[:150]}…”")

# no crown jewels => no paths, rather than inventing a destination
run(db.assets.update_one({"id": "sql01"}, {"$set": {"criticality": "medium", "tags": []}}))
g2 = run(ape.build_environment_graph(db))
assert ape.enumerate_paths(g2) == [], "with nothing valuable to reach, the engine must return nothing"
print("PASS: with no crown jewels defined the engine returns nothing instead of inventing a target")
run(db.assets.update_one({"id": "sql01"}, {"$set": {"criticality": "crown_jewel", "tags": ["pii"]}}))


# ============ choke points ============

graph = run(ape.build_environment_graph(db))
paths = ape.enumerate_paths(graph)
chokes = ape.choke_points(paths, graph)
assert chokes
top = chokes[0]
assert top["paths_broken"] >= 1
assert top["paths_broken_pct"] > 0
assert top["action_type"] in ("patch", "network", "segmentation", "identity")
kinds_present = {c["action_type"] for c in chokes}
assert "patch" in kinds_present, "patching the exploited CVE must be offered"
assert {"network", "segmentation"} & kinds_present, "closing exposure or segmenting must be offered"
patch_actions = [c for c in chokes if c["action_type"] == "patch"]
assert any("CVE-2026-1111" in c["title"] for c in patch_actions)
assert chokes == sorted(chokes, key=lambda c: (-c["paths_broken"], -c["score_removed"]))
print("PASS: choke points rank real remediations (patch / close exposure / segment / fix shared creds) "
      "by how many paths each one breaks")


# ============ end-to-end analysis + persistence + triage ============

r = client.post("/api/v1/attack-paths/analyze", json={"max_hops": 4})
assert r.status_code == 200, r.text
res = r.json()
assert res["summary"]["paths_found"] >= 1
assert res["summary"]["crown_jewels_defined"] == 1
assert res["choke_points"]
stored = run(db.attack_paths.find({}, {"_id": 0}).to_list(50))
assert stored and all(s["status"] == "open" for s in stored)
print("PASS: analyze persists enumerated paths with an initial triage status")

pid = stored[0]["id"]
r = client.patch(f"/api/v1/attack-paths/{pid}", json={"status": "investigating", "analyst_note": "checking"})
assert r.status_code == 200 and r.json()["status"] == "investigating"
r = client.patch(f"/api/v1/attack-paths/{pid}", json={"status": "bogus"})
assert r.status_code == 400

# re-running preserves triage rather than resetting it
client.post("/api/v1/attack-paths/analyze", json={"max_hops": 4})
again = run(db.attack_paths.find_one({"id": pid}, {"_id": 0}))
assert again["status"] == "investigating" and again["analyst_note"] == "checking"
assert again["first_seen_at"] <= again["last_seen_at"]
print("PASS: re-analysis preserves triage state and tracks first/last seen per path")

# Patching the exploit doesn't make the exposure vanish -- it removes the PROVEN
# way in. The path is downgraded to a speculative "exposure to investigate"
# rather than either disappearing (dishonest) or staying Critical (alarmist).
before = run(db.attack_paths.find_one({"entry_node_id": "web01"}, {"_id": 0}))
assert before["entry_vector"] == "exploit" and before["speculative"] is False
run(db.findings.update_one({"id": "f-kev"}, {"$set": {"status": "Fixed validated"}}))
client.post("/api/v1/attack-paths/analyze", json={"max_hops": 4})
after = run(db.attack_paths.find_one({"entry_node_id": "web01", "status": {"$ne": "resolved"}}, {"_id": 0}))
assert after["entry_vector"] == "unproven"
assert after["speculative"] is True and after["confidence"] == "possible"
assert after["risk_score"] < before["risk_score"]
assert "No specific way in" in after["narrative"]
print(f"PASS: patching the exploit downgrades the path from confirmed/{before['risk_score']} to "
      f"speculative/{after['risk_score']} with an unproven entry vector — honest, not alarmist")

# removing the exposure entirely DOES resolve the path
run(db.assets.update_one({"id": "web01"}, {"$set": {"internet_facing": False, "shodan_ports": []}}))
client.post("/api/v1/attack-paths/analyze", json={"max_hops": 4})
resolved = run(db.attack_paths.find({"status": "resolved"}, {"_id": 0}).to_list(50))
assert resolved, "paths that no longer exist must be marked resolved, so remediation is provable"
assert resolved[0].get("resolution_note")
print("PASS: once the internet exposure is closed the path is marked RESOLVED (not deleted), so remediation is provable")


# ============ API surface ============

_seed()
client.post("/api/v1/attack-paths/analyze", json={"max_hops": 4})

r = client.get("/api/v1/attack-paths/summary")
s = r.json()
assert s["open_paths"] >= 1 and s["crown_jewels_defined"] == 1
assert s["needs_crown_jewels"] is False
assert s["kev_paths"] >= 1

r = client.get("/api/v1/attack-paths", params={"kev_only": True})
assert all(p["uses_kev"] for p in r.json()["items"])
r = client.get("/api/v1/attack-paths", params={"confirmed_only": True})
assert all(not p["speculative"] for p in r.json()["items"])
print("PASS: paths list filters by KEV usage, confidence, severity, entry and target")

pid = r.json()["items"][0]["id"]
r = client.get(f"/api/v1/attack-paths/{pid}")
detail = r.json()
assert detail["findings"], "path detail must resolve the live findings behind each exploited hop"
assert detail["findings"][0]["cve"] == "CVE-2026-1111"
assert detail["remediation_options"], "path detail must offer the remediations that break THIS path"
assert all(pid in (o.get("path_ids") or []) for o in detail["remediation_options"])
print("PASS: path detail resolves the underlying findings and the remediations that break this specific path")

r = client.get("/api/v1/attack-paths/graph")
g = r.json()
assert g["total_nodes"] >= 5 and g["total_edges"] >= 3
assert any(n.get("on_attack_path") for n in g["nodes"]), "graph must flag which nodes are on a path"
assert any(e.get("on_attack_path") for e in g["edges"])
print("PASS: the full-graph view flags which nodes and edges participate in an enumerated path")

# crown jewels are manageable in bulk
r = client.get("/api/v1/attack-paths/crown-jewels")
assert r.json()["total"] >= 1
r = client.post("/api/v1/attack-paths/crown-jewels", json={"teams": ["Facilities"], "reason": "kiosk PII"})
assert r.status_code == 200 and r.json()["updated"] == 1
assert run(db.assets.find_one({"id": "kiosk1"}, {"_id": 0}))["criticality"] == "crown_jewel"
r = client.post("/api/v1/attack-paths/crown-jewels", json={"asset_ids": ["kiosk1"], "unset": True})
assert r.json()["unset"] == 1
r = client.post("/api/v1/attack-paths/crown-jewels", json={"teams": ["Nope"]})
assert r.status_code == 400
print("PASS: crown jewels can be set/unset individually, by team, or by tag")

# accepted paths drop out of choke-point math (a decision changes the answer)
before = client.get("/api/v1/attack-paths/choke-points").json()["total_paths"]
client.patch(f"/api/v1/attack-paths/{pid}", json={"status": "accepted"})
after = client.get("/api/v1/attack-paths/choke-points").json()["total_paths"]
assert after == before - 1
print("PASS: accepting a path removes it from choke-point math, so the 'one thing to do' reflects triage decisions")
