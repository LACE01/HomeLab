import os, sys, asyncio
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_security_news"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_security_news"]

import server
import auth_utils
from routes import vendors as vendors_route
vendors_route.db = db_module.db

from fastapi.testclient import TestClient
import httpx

admin_user = {"id": "u1", "email": "admin@x.com", "role": "admin", "name": "Admin", "teams": []}
app = server.app
app.dependency_overrides[auth_utils.get_current_user] = lambda: admin_user
client = TestClient(app)

db = db_module.db


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


class FakeResponse:
    def __init__(self, status_code, content=b""):
        self.status_code = status_code
        self.content = content
        self.text = content.decode(errors="replace") if isinstance(content, bytes) else str(content)


class FakeAsyncClient:
    responses_by_source = {}  # url -> FakeResponse, set per test

    def __init__(self, *a, **kw):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url, **kw):
        return FakeAsyncClient.responses_by_source[url]


_real = httpx.AsyncClient
httpx.AsyncClient = FakeAsyncClient

RSS_ADOBE = b"""<?xml version="1.0"?>
<rss version="2.0"><channel>
<title>FakeOutlet</title>
<item>
  <title>Adobe patches critical Acrobat Reader zero-day</title>
  <link>https://example.com/adobe-zero-day</link>
  <guid>https://example.com/adobe-zero-day</guid>
  <pubDate>Wed, 15 Jul 2026 12:00:00 GMT</pubDate>
  <description>&lt;p&gt;Adobe has released an emergency patch for Acrobat Reader.&lt;/p&gt;</description>
</item>
<item>
  <title>Unrelated npm supply chain attack</title>
  <link>https://example.com/npm-attack</link>
  <guid>https://example.com/npm-attack</guid>
  <pubDate>Wed, 15 Jul 2026 10:00:00 GMT</pubDate>
  <description>Some malicious npm packages were found.</description>
</item>
</channel></rss>"""

RSS_EMPTY = b"""<?xml version="1.0"?><rss version="2.0"><channel><title>Other</title></channel></rss>"""

import security_news

FakeAsyncClient.responses_by_source = {
    security_news.NEWS_FEEDS[0]["url"]: FakeResponse(200, RSS_ADOBE),
    security_news.NEWS_FEEDS[1]["url"]: FakeResponse(200, RSS_EMPTY),
    security_news.NEWS_FEEDS[2]["url"]: FakeResponse(500, b"error"),
    security_news.NEWS_FEEDS[3]["url"]: FakeResponse(200, RSS_EMPTY),
    security_news.NEWS_FEEDS[4]["url"]: FakeResponse(200, RSS_EMPTY),
}

result = run(security_news.sync_security_news(db))
assert result["articles_created"] == 2, result
assert len(result["errors"]) == 1 and "HTTP 500" in result["errors"][0]
print("PASS: sync_security_news parses RSS, dedups by guid, isolates a single feed failure")

# re-running with the same feed content should not duplicate (guid-based dedup)
result2 = run(security_news.sync_security_news(db))
assert result2["articles_created"] == 0, result2
print("PASS: re-sync doesn't duplicate already-seen articles")

news = run(security_news.get_vendor_news(db, "Adobe", []))
assert len(news) == 1 and "Adobe" in news[0]["title"]
print("PASS: get_vendor_news matches Adobe article by vendor name")

news_none = run(security_news.get_vendor_news(db, "TotallyUnrelatedVendorXYZ", []))
assert news_none == []
print("PASS: an unrelated vendor name matches nothing")

# short vendor name/term should be skipped, not cause a noisy broad match
news_short = run(security_news.get_vendor_news(db, "Ad", []))
assert news_short == []
print("PASS: sub-3-character vendor name doesn't produce noisy matches")

# --- end-to-end through the real vendor detail route ---
import uuid
vendor_id = str(uuid.uuid4())
run(db.vendors.insert_one({
    "id": vendor_id, "name": "Adobe", "category": "Software", "match_terms": [],
    "org_criticality": 3, "status": "active", "monitoring_enabled": False,
    "renewal_reminder_sent": False, "created_at": "2026-01-01T00:00:00+00:00",
    "created_by": "test", "updated_at": "2026-01-01T00:00:00+00:00",
}))
r = client.get(f"/api/v1/vendors/{vendor_id}")
assert r.status_code == 200, r.text
body = r.json()
assert "news" in body and len(body["news"]) == 1
assert body["news"][0]["source"] == "BleepingComputer"
print("PASS: GET /v1/vendors/{id} embeds matched security news articles")

# admin trigger + status endpoints
r = client.post("/api/v1/admin/enrich/security-news")
assert r.status_code == 200, r.text
r2 = client.get("/api/v1/admin/security-news/status")
assert r2.status_code == 200
assert r2.json()["articles_cached"] == 2
print("PASS: admin sync-now + status endpoints work")

httpx.AsyncClient = _real
print("\nALL SECURITY NEWS TESTS PASSED")
