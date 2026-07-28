import os, sys, asyncio, uuid, json
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_cti"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_cti"]

import server
import auth_utils
from routes import cti as cti_route
cti_route.db = db_module.db
import cti

from fastapi.testclient import TestClient

admin_user = {"id": "u1", "email": "admin@x.com", "role": "admin", "name": "Admin", "teams": []}
app = server.app
app.dependency_overrides[auth_utils.get_current_user] = lambda: admin_user
client = TestClient(app)

db = db_module.db


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ============ pure helpers ============

assert cti.classify_indicator("1.2.3.4") == "ip"
assert cti.classify_indicator("evil.example.com") == "domain"
assert cti.classify_indicator("https://evil.example.com/x") == "url"
assert cti.classify_indicator("a" * 64) == "hash"
assert cti.classify_indicator("a" * 32) == "hash"
assert cti.classify_indicator("not an indicator!") == "unknown"
print("PASS: classify_indicator distinguishes ip/domain/url/hash and rejects garbage")

perms = cti.typosquat_permutations("eaglecounty.com")
assert "eaglecounty.net" in perms                 # TLD swap
assert "eagelcounty.com" in perms                 # transposition
assert "eaglecounty-secure.com" in perms          # suffix
assert "secure-eaglecounty.com" in perms          # prefix
assert "eag1ecounty.com" in perms                 # homoglyph l->1
assert "eaglecounty.com" not in perms             # never the domain itself
assert len(perms) <= 300
assert cti.typosquat_permutations("nodot") == []
print("PASS: typosquat permutations cover omission/doubling/transposition/homoglyph/hyphen/TLD/affix families, capped and self-excluding")


def _reset():
    for c in ("cti_feeds", "cti_keywords", "cti_articles", "cti_ransomware_victims",
               "cti_certificates", "cti_typosquats", "cti_investigations",
               "domain_watch_targets", "vendors", "security_events", "easm_candidates",
               "findings", "kev_catalog", "assets", "ioc_watchlist", "osint_findings"):
        run(db[c].delete_many({}))


# ============ owned domains registry (reuses domain_watch_targets) ============

_reset()
run(db.domain_watch_targets.insert_many([
    {"id": "d1", "domain": "eaglecounty.com", "enabled": True},
    {"id": "d2", "domain": "EagleVotes.gov", "enabled": True},
]))
domains = run(cti.owned_domains(db))
assert domains == ["eaglecounty.com", "eaglevotes.gov"]
print("PASS: owned-domain registry reuses domain_watch_targets, normalized and deduped")


# ============ fake httpx covering feeds / ransomware.live / crt.sh ============

RSS = b"""<?xml version="1.0"?><rss version="2.0"><channel>
<item><title>Acme Corp breached by ransomware crew</title><link>https://news.example/1</link>
<description>Attackers hit Acme Corp</description><pubDate>Mon, 27 Jul 2026 10:00:00 GMT</pubDate></item>
<item><title>Unrelated patch Tuesday roundup</title><link>https://news.example/2</link>
<description>Nothing to do with us</description><pubDate>Mon, 27 Jul 2026 11:00:00 GMT</pubDate></item>
<item><title>Phishing campaign targets eaglecounty.com users</title><link>https://news.example/3</link>
<description>Local government targeted</description><pubDate>Mon, 27 Jul 2026 12:00:00 GMT</pubDate></item>
</channel></rss>"""

RANSOM = [
    {"post_title": "Acme Corp", "group_name": "LockBit", "website": "https://acme.example",
     "discovered": "2026-07-20", "description": "leak"},
    {"post_title": "Eagle County", "group_name": "BlackCat", "website": "eaglecounty.com",
     "discovered": "2026-07-21", "description": "leak"},
    {"post_title": "Totally Unrelated Ltd", "group_name": "Cl0p", "website": "unrelated.example",
     "discovered": "2026-07-22", "description": "leak"},
]

CRTSH = [
    {"id": 111, "common_name": "www.eaglecounty.com", "name_value": "www.eaglecounty.com\nportal.eaglecounty.com",
     "issuer_name": "Let's Encrypt", "not_before": "2026-07-01T00:00:00", "not_after": "2026-10-01T00:00:00"},
    {"id": 222, "common_name": "vpn.eaglecounty.com", "name_value": "vpn.eaglecounty.com",
     "issuer_name": "DigiCert", "not_before": "2026-07-10T00:00:00", "not_after": "2027-07-10T00:00:00"},
]
CRTSH_SECOND = CRTSH + [
    {"id": 333, "common_name": "sso.eaglecounty.com", "name_value": "sso.eaglecounty.com",
     "issuer_name": "Unknown CA", "not_before": "2026-07-26T00:00:00", "not_after": "2027-07-26T00:00:00"},
]

STATE = {"crtsh": CRTSH}


class FakeResp:
    def __init__(self, content=b"", status_code=200, json_data=None):
        self.content = content
        self.status_code = status_code
        self._json = json_data
        self.text = str(json_data)[:200] if json_data is not None else content.decode(errors="replace")[:200]
    def json(self):
        if self._json is None:
            raise ValueError("no json")
        return self._json


class FakeAsyncClient:
    def __init__(self, *a, **kw): pass
    async def __aenter__(self): return self
    async def __aexit__(self, *a): return False
    async def get(self, url, **kw):
        if "ransomware.live" in url:
            return FakeResp(json_data=RANSOM)
        if "crt.sh" in url:
            return FakeResp(json_data=STATE["crtsh"])
        return FakeResp(content=RSS)


import httpx
_real = httpx.AsyncClient
httpx.AsyncClient = FakeAsyncClient


# ============ custom feeds + keyword/domain/vendor matching ============

run(db.vendors.insert_one({"id": "v1", "name": "Acme Corp", "domain": "acme.example"}))
r = client.post("/api/v1/cti/feeds", json={"name": "Example News", "url": "https://news.example/feed.xml"})
assert r.status_code == 200
r = client.post("/api/v1/cti/feeds", json={"name": "dup", "url": "https://news.example/feed.xml"})
assert r.status_code == 409
r = client.post("/api/v1/cti/keywords", json={"keyword": "ab"})
assert r.status_code == 400  # too short to be a useful match term

r = client.post("/api/v1/cti/feeds/sync")
assert r.status_code == 200, r.text
res = r.json()
assert res["articles_created"] == 3
assert res["articles_matched"] == 2  # vendor "Acme Corp" + owned domain "eaglecounty.com"
arts = run(db.cti_articles.find({}, {"_id": 0}).to_list(10))
matched = {a["title"]: a["matches"] for a in arts if a["matches"]}
assert any(m[0]["kind"] == "vendor" for m in matched.values())
assert any(m[0]["kind"] == "owned_domain" for m in matched.values())
events = run(db.security_events.find({"event_type": "threat_news_match"}, {"_id": 0}).to_list(10))
assert len(events) == 2
print("PASS: custom feed sync matches articles against owned domains + tracked vendors and raises security events")

r = client.post("/api/v1/cti/feeds/sync")
assert r.json()["articles_created"] == 0  # dedup by link
print("PASS: feed sync dedups articles by link on re-run")

r = client.get("/api/v1/cti/articles", params={"matched_only": True})
assert len(r.json()["items"]) == 2
print("PASS: article list filters to watchlist matches")


# ============ ransomware.live ============

r = client.post("/api/v1/cti/ransomware/sync")
assert r.status_code == 200
res = r.json()
assert res["created"] == 3 and res["matched"] == 2  # Acme (vendor domain) + Eagle County (owned domain)
victims = run(db.cti_ransomware_victims.find({}, {"_id": 0}).to_list(10))
eagle = next(v for v in victims if v["victim"] == "Eagle County")
assert eagle["match"]["kind"] == "owned_domain"
acme = next(v for v in victims if v["victim"] == "Acme Corp")
assert acme["match"]["kind"] == "vendor" and acme["match"]["vendor_id"] == "v1"
unrelated = next(v for v in victims if v["victim"] == "Totally Unrelated Ltd")
assert unrelated["match"] is None
ev = run(db.security_events.find({"event_type": "ransomware_victim_match"}, {"_id": 0}).to_list(10))
assert len(ev) == 2
assert any(e["severity"] == "Critical" for e in ev)  # owned domain = Critical
assert any(e["severity"] == "High" for e in ev)      # vendor = High
r = client.post("/api/v1/cti/ransomware/sync")
assert r.json()["created"] == 0  # dedup by group:victim key
print("PASS: ransomware.live matches victims to owned domains (Critical) and vendors (High), dedups on re-sync")


# ============ certificate transparency ============

STATE["crtsh"] = CRTSH
r = client.post("/api/v1/cti/certificates/sync", json={"domain": "eaglecounty.com"})
assert r.status_code == 200
res = r.json()
assert res["new_certs"] == 2
assert res["new_hostnames"] == 3  # www, portal, vpn -> easm_candidates
certs = run(db.cti_certificates.find({}, {"_id": 0}).to_list(10))
assert all(c["newly_issued"] is False for c in certs), "first sweep must not flag everything as newly issued"
assert run(db.security_events.count_documents({"event_type": "new_certificate_issued"})) == 0
cands = run(db.easm_candidates.find({}, {"_id": 0}).to_list(10))
assert {c["hostname"] for c in cands} == {"www.eaglecounty.com", "portal.eaglecounty.com", "vpn.eaglecounty.com"}
assert all(c["source"] == "certificate-transparency" for c in cands)
print("PASS: first CT sweep records certs + feeds hostnames to EASM without firing false 'newly issued' alerts")

STATE["crtsh"] = CRTSH_SECOND
r = client.post("/api/v1/cti/certificates/sync", json={"domain": "eaglecounty.com"})
res = r.json()
assert res["new_certs"] == 1 and res["new_hostnames"] == 1
new_cert = run(db.cti_certificates.find_one({"crt_id": "333"}, {"_id": 0}))
assert new_cert["newly_issued"] is True
assert run(db.security_events.count_documents({"event_type": "new_certificate_issued"})) == 1
print("PASS: a certificate appearing after the first sweep is flagged newly_issued and raises an alert")

r = client.get("/api/v1/cti/certificates", params={"new_only": True})
assert len(r.json()["items"]) == 1

httpx.AsyncClient = _real


# ============ CISA KEV reporting ============

run(db.kev_catalog.insert_many([
    {"cveID": "CVE-2026-1111", "vendorProject": "Acme", "product": "Gateway",
     "vulnerabilityName": "Acme Gateway RCE", "dueDate": "2020-01-01",
     "knownRansomwareCampaignUse": "Known", "requiredAction": "Apply updates"},
    {"cveID": "CVE-2026-2222", "vendorProject": "Widget", "product": "Server",
     "vulnerabilityName": "Widget auth bypass", "dueDate": "2099-01-01",
     "knownRansomwareCampaignUse": "Unknown", "requiredAction": "Apply updates"},
    {"cveID": "CVE-2026-3333", "vendorProject": "Nobody", "product": "Nothing",
     "vulnerabilityName": "Not present here", "dueDate": "2030-01-01"},
]))
run(db.findings.insert_many([
    {"id": "f1", "cve": "CVE-2026-1111", "kev_flag": True, "status": "New", "asset_id": "a1",
     "asset_hostname": "web01", "severity": "Critical", "title": "RCE", "due_at": "2026-01-01T00:00:00+00:00"},
    {"id": "f2", "cve": "CVE-2026-1111", "kev_flag": True, "status": "Valid", "asset_id": "a2",
     "asset_hostname": "web02", "severity": "Critical", "title": "RCE", "due_at": None},
    {"id": "f3", "cve": "CVE-2026-2222", "kev_flag": True, "status": "New", "asset_id": "a1",
     "asset_hostname": "web01", "severity": "High", "title": "Auth bypass", "due_at": None},
    {"id": "f4", "cve": "CVE-2026-3333", "kev_flag": True, "status": "Fixed validated", "asset_id": "a3",
     "asset_hostname": "old01", "severity": "High", "title": "Closed one", "due_at": None},
]))
r = client.get("/api/v1/cti/kev-report")
rep = r.json()
assert rep["catalog_size"] == 3
assert rep["kev_in_environment"] == 2       # 3333 is closed -> not present
assert rep["open_kev_findings"] == 3
assert rep["past_kev_due_date"] == 1        # 1111 due 2020
assert rep["ransomware_linked"] == 1
first = rep["items"][0]
assert first["cve"] == "CVE-2026-1111"      # sorted by KEV due date
assert first["asset_count"] == 2 and first["finding_count"] == 2
assert first["vulnerability_name"] == "Acme Gateway RCE"
print("PASS: KEV report joins the catalog to open findings, counts assets, sorts by CISA due date, excludes closed findings")


# ============ ad-hoc investigation (internal sources need no API key) ============

run(db.ioc_watchlist.insert_one({"id": "i1", "ioc_type": "ip", "value": "9.9.9.9",
                                  "source": "otx_feed", "severity": "High", "notes": "C2 node"}))
run(db.assets.insert_one({"id": "a9", "hostname": "dmz01", "ip": "9.9.9.9",
                           "owner_team": "IT", "criticality": "High"}))
run(db.findings.insert_one({"id": "f9", "asset_id": "a9", "status": "New", "severity": "High",
                             "title": "x", "cve": None}))
run(db.osint_findings.insert_one({"id": "o9", "key": "k", "module": "otx_ip", "module_label": "OTX",
                                   "target": "9.9.9.9", "label": "pulse hit", "detail": "malware",
                                   "found_at": "2026-07-01T00:00:00+00:00"}))

r = client.post("/api/v1/cti/investigate", json={"value": "9.9.9.9"})
assert r.status_code == 200
inv = r.json()
assert inv["kind"] == "ip"
by_source = {s["source"]: s for s in inv["results"]}
assert by_source["IOC Watchlist (internal)"]["status"] == "found"
assert by_source["OSINT history (internal)"]["status"] == "found"
assert by_source["Internal inventory"]["status"] == "found"
assert "1 open finding(s)" in by_source["Internal inventory"]["rows"][0]["detail"]
# external sources aren't configured in this test env -- they degrade individually, never fail the run
assert by_source["OpenCTI"]["status"] == "not_configured"
assert inv["verdict_counts"]["found"] >= 3
print("PASS: investigation runs internal checks with no API key and degrades unconfigured external sources individually")

r = client.post("/api/v1/cti/investigate", json={"value": "definitely not an indicator"})
assert r.status_code == 400
r = client.get("/api/v1/cti/investigations")
assert len(r.json()["items"]) == 1
print("PASS: investigation rejects unclassifiable input and records history")


# ============ typosquats (DNS faked) ============

REGISTERED = {"eaglecounty.net": ["6.6.6.6"], "eagelcounty.com": ["7.7.7.7"]}


class FakeAnswer:
    def __init__(self, ip): self._ip = ip
    def to_text(self): return self._ip


class FakeResolver:
    timeout = 3
    lifetime = 3
    def resolve(self, name, rtype):
        if name in REGISTERED:
            return [FakeAnswer(ip) for ip in REGISTERED[name]]
        raise Exception("NXDOMAIN")


import dns.resolver
_real_resolver = dns.resolver.Resolver
dns.resolver.Resolver = FakeResolver

r = client.post("/api/v1/cti/typosquats/scan", json={"domain": "eaglecounty.com"})
assert r.status_code == 200
res = r.json()
assert res["registered"] == 2 and res["new"] == 2
assert res["checked"] > 50
found = {i["domain_candidate"] for i in res["items"]}
assert found == {"eaglecounty.net", "eagelcounty.com"}
ev = run(db.security_events.find({"event_type": "typosquat_registered"}, {"_id": 0}).to_list(10))
assert len(ev) == 2 and all(e["severity"] == "High" for e in ev)
# re-scan finds the same two but reports no NEW ones
r = client.post("/api/v1/cti/typosquats/scan", json={"domain": "eaglecounty.com"})
assert r.json()["registered"] == 2 and r.json()["new"] == 0
assert run(db.security_events.count_documents({"event_type": "typosquat_registered"})) == 2
print("PASS: typosquat scan records only REGISTERED lookalikes, alerts once on first discovery, no duplicate alerts on re-scan")

squat = run(db.cti_typosquats.find_one({"domain_candidate": "eaglecounty.net"}, {"_id": 0}))
r = client.patch(f"/api/v1/cti/typosquats/{squat['id']}", json={"status": "malicious"})
assert r.status_code == 200 and r.json()["status"] == "malicious"
r = client.patch(f"/api/v1/cti/typosquats/{squat['id']}", json={"status": "bogus"})
assert r.status_code == 400
dns.resolver.Resolver = _real_resolver
print("PASS: typosquat triage status is settable and validated")


# ============ shodan rollup ============

run(db.assets.insert_many([
    {"id": "s1", "hostname": "edge01", "ip": "1.1.1.1", "shodan_ports": [22, 443],
     "shodan_vulns": ["CVE-2026-9999"], "owner_team": "IT"},
    {"id": "s2", "hostname": "edge02", "ip": "1.1.1.2", "shodan_ports": [443],
     "shodan_vulns": [], "owner_team": "IT"},
]))
r = client.get("/api/v1/cti/shodan-exposure")
sh = r.json()
assert sh["assets_with_exposure"] == 2
assert sh["top_ports"][0] == {"port": "443", "count": 2}
assert sh["top_vulns"][0]["cve"] == "CVE-2026-9999"
print("PASS: Shodan rollup aggregates exposed ports/CVEs across assets already enriched by the connector")


# ============ overview ============

r = client.get("/api/v1/cti/overview")
ov = r.json()
assert ov["owned_domains"] == ["eaglecounty.com", "eaglevotes.gov"]
assert ov["ransomware_matches"] == 2
assert ov["kev_in_environment"] == 2
assert ov["certificates_new"] == 1
assert ov["typosquats_registered"] == 2
print("PASS: hub overview aggregates counts across every CTI source in one call")
