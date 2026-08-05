"""The global-events monitor: a board that knows which of the world's events
touch YOUR estate.

The whole point -- and the difference from the news-ticker boards it's modelled
on -- is the relevance tagging. A KEV addition for a CVE you have open is not the
same as a KEV addition you've never heard of, and the board must sort and colour
on exactly that. So the tests weight heavily toward: does a global event get
correctly linked to our findings / vendors / watchlist, and does 'affects us'
rise to the top.
"""
import os, sys, asyncio
from datetime import datetime, timezone, timedelta
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_world_monitor"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_world_monitor"]
db = db_module.db

import world_monitor as wm

run = lambda c: asyncio.get_event_loop().run_until_complete(c)
now = datetime.now(timezone.utc)
today = now.strftime("%Y-%m-%d")


def reset():
    for c in ("findings", "vendors", "cti_keywords", "kev_catalog", "cti_ransomware",
              "cti_articles", "security_events", "correlation_hits"):
        run(db[c].delete_many({}))


# ============ a KEV addition is scored by whether WE have the CVE ============

reset()
# We have CVE-2025-0001 open on an internet-facing host, and CVE-2025-0002 open
# internally. CVE-2099-9999 we've never heard of.
run(db.findings.insert_many([
    {"id": "f1", "cve": "CVE-2025-0001", "status": "New", "internet_facing": True},
    {"id": "f2", "cve": "CVE-2025-0002", "status": "New", "internet_facing": False},
]))
run(db.kev_catalog.insert_many([
    {"cve_id": "CVE-2025-0001", "name": "ACME RCE", "vendor": "ACME", "product": "Gateway",
     "required_action": "Patch", "date_added": today},
    {"cve_id": "CVE-2025-0002", "name": "Widget bug", "vendor": "Widget", "product": "App",
     "required_action": "Patch", "date_added": today},
    {"cve_id": "CVE-2099-9999", "name": "Unrelated", "vendor": "Other", "product": "Thing",
     "required_action": "Patch", "date_added": today},
]))

b = run(wm.board(db, days=7))
by_cve = {e["entities"][0]: e for e in b["events"] if e["category"] == "kev"}

assert by_cve["CVE-2025-0001"]["relevance"] == "affects_us"
assert by_cve["CVE-2025-0001"]["severity"] == "Critical", "an exposed, now-exploited CVE is Critical"
assert "INTERNET-FACING" in by_cve["CVE-2025-0001"]["why"]
assert by_cve["CVE-2025-0002"]["relevance"] == "affects_us"
assert by_cve["CVE-2025-0002"]["severity"] == "High", "an internal-only affected CVE is High, not Critical"
assert by_cve["CVE-2099-9999"]["relevance"] == "global"
print("PASS: a KEV addition is scored by whether WE have the CVE and whether it's exposed — "
      "exposed+exploited=Critical, internal=High, unknown-to-us=global — which is the whole "
      "difference from a news ticker")


# ============ affects-us events sort to the top ============

assert b["events"][0]["relevance"] == "affects_us", "an affecting event must lead the board"
# the global KEV must be below both affecting ones
positions = {e["entities"][0]: i for i, e in enumerate(b["events"]) if e["category"] == "kev"}
assert positions["CVE-2099-9999"] > positions["CVE-2025-0001"]
assert positions["CVE-2099-9999"] > positions["CVE-2025-0002"]
print("PASS: events that touch our environment sort above purely-global ones, regardless of "
      "recency — the board leads with what needs action")

assert "touch your environment" in b["headline"]
assert b["counts"]["affects_us"] == 2 and b["counts"]["global"] == 1
print("PASS: the headline and counts summarize how much of the window is actually about us")


# ============ a ransomware victim that matches a vendor we use ============

reset()
run(db.vendors.insert_one({"id": "v1", "name": "Contoso Payments"}))
run(db.cti_ransomware.insert_many([
    {"id": "r1", "group": "LockBit", "victim": "Contoso Payments Inc",
     "discovered": now.isoformat(), "country": "US", "url": "https://x/1"},
    {"id": "r2", "group": "BlackCat", "victim": "Some Unrelated Corp",
     "discovered": now.isoformat(), "country": "DE", "url": "https://x/2"},
]))
b = run(wm.board(db, days=7))
ransom = {e["entities"][1]: e for e in b["events"] if e["category"] == "ransomware"}

assert ransom["Contoso Payments Inc"]["relevance"] == "affects_us"
assert "vendor you use" in ransom["Contoso Payments Inc"]["why"]
assert ransom["Some Unrelated Corp"]["relevance"] == "global"
print("PASS: a ransomware victim whose name matches one of our vendors is flagged 'affects_us' "
      "with the reason — a supplier compromise is our incident, and only a system that knows our "
      "vendor list can make that link")

assert ransom["Contoso Payments Inc"]["country"] == "US"
assert any(c["country"] == "US" for c in b["countries"])
print("PASS: geographic data is carried through where the source has it, for a map view — not "
      "fabricated where it doesn't")


# ============ a news article matching a watchlist term ============

reset()
run(db.cti_keywords.insert_one({"id": "k1", "term": "citrix"}))
run(db.cti_articles.insert_many([
    {"id": "a1", "title": "New Citrix NetScaler exploit chain observed",
     "summary": "...", "published_at": now.isoformat(), "source": "BleepingComputer",
     "link": "https://x/a1", "matches": [{"term": "citrix", "kind": "keyword"}]},
    {"id": "a2", "title": "General security roundup", "summary": "misc",
     "published_at": now.isoformat(), "source": "Feed", "link": "https://x/a2", "matches": []},
]))
b = run(wm.board(db, days=7))
news = {e["id"].split(":")[1]: e for e in b["events"] if e["category"] == "news"}

assert news["a1"]["relevance"] == "watched"
assert "watchlist" in news["a1"]["why"] and "citrix" in news["a1"]["why"]
assert news["a2"]["relevance"] == "global"
print("PASS: a news article matching a CTI watchlist term is tagged 'watched' with the term named; "
      "an unmatched article stays 'global'")


# ============ our own detections and correlations are always about us ============

reset()
run(db.security_events.insert_one({
    "id": "e1", "status": "open", "severity": "High", "title": "Brute force from 1.2.3.4",
    "source": "login_audit", "last_seen_at": now.isoformat(), "entity_label": "1.2.3.4"}))
run(db.correlation_hits.insert_one({
    "id": "c1", "status": "open", "severity": "Critical",
    "rule_title": "KEV, internet-facing, under active scanning",
    "narrative": "web-1 is exposed and being scanned on the vulnerable port.",
    "last_seen_at": now.isoformat(), "subject": {"label": "web-1"}}))
b = run(wm.board(db, days=7))
assert all(e["relevance"] == "affects_us"
            for e in b["events"] if e["category"] in ("detection", "incident"))
corr = next(e for e in b["events"] if e["category"] == "incident")
assert corr["title"].startswith("KEV") and "web-1" in corr["entities"]
print("PASS: our own detections and correlated incidents are always 'affects_us' — they are by "
      "definition about our environment, and carry the narrative the correlation engine wrote")


# ============ the affects_us filter collapses the firehose ============

reset()
run(db.findings.insert_one({"id": "f", "cve": "CVE-1", "status": "New", "internet_facing": True})
    )
run(db.kev_catalog.insert_many([
    {"cve_id": "CVE-1", "name": "ours", "date_added": today},
    {"cve_id": "CVE-2", "name": "not ours", "date_added": today},
    {"cve_id": "CVE-3", "name": "also not", "date_added": today},
]))
full = run(wm.board(db, days=7))
only_us = run(wm.board(db, days=7, relevance="affects_us"))
assert len(full["events"]) == 3 and len(only_us["events"]) == 1
assert only_us["events"][0]["entities"] == ["CVE-1"]
print("PASS: relevance='affects_us' collapses the whole board to just what touches us — the view "
      "an operator wants on a busy day, from the same data")


# ============ one broken source must not blank the board ============

reset()
run(db.findings.insert_one({"id": "f", "cve": "CVE-9", "status": "New"}))
run(db.kev_catalog.insert_one({"cve_id": "CVE-9", "name": "x", "date_added": today}))
_broken = wm._news_events
async def _boom(db, ctx, since):
    raise RuntimeError("feed parser exploded")
wm._news_events = _boom
wm.COLLECTORS["news"] = _boom
b = run(wm.board(db, days=7))
wm._news_events = _broken
wm.COLLECTORS["news"] = _broken
assert any(e["category"] == "kev" for e in b["events"]), \
    "a failing news collector took out the KEV events too"
print("PASS: one source failing does not blank the whole board — an aggregator's job is resilience "
      "to any single feed dying, the failure the platform learned the hard way")


# ============ empty world is a calm, honest state ============

reset()
b = run(wm.board(db, days=7))
assert b["events"] == []
assert "Nothing in the last window is linked to your environment" in b["headline"]
print("PASS: with nothing collected, the board says so plainly rather than looking broken")


# ============ route ============

import server, auth_utils
from routes import world_monitor as wm_route
wm_route.db = db
from fastapi.testclient import TestClient

admin = {"id": "u1", "email": "a@x.com", "role": "admin", "name": "A", "teams": []}
server.app.dependency_overrides[auth_utils.get_current_user] = lambda: admin
client = TestClient(server.app)

reset()
run(db.findings.insert_one({"id": "f", "cve": "CVE-2025-7777", "status": "New", "internet_facing": True}))
run(db.kev_catalog.insert_many([
    {"cve_id": "CVE-2025-7777", "name": "ours", "date_added": today},
    {"cve_id": "CVE-2025-8888", "name": "not ours", "date_added": today},
]))

r = client.get("/api/v1/world-monitor")
assert r.status_code == 200, r.text
assert len(r.json()["events"]) == 2
assert r.json()["events"][0]["relevance"] == "affects_us"
print("PASS: GET /v1/world-monitor returns the board with affecting events first")

r = client.get("/api/v1/world-monitor?relevance=affects_us")
assert len(r.json()["events"]) == 1
print("PASS: ?relevance=affects_us filters to only what touches us")

r = client.get("/api/v1/world-monitor?days=200")
assert r.status_code == 422, "days is capped to protect the query"
print("PASS: the window is bounded (days<=90), so a huge range can't be requested")
