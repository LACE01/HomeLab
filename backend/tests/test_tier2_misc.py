"""Tier 2 second pass: #48 generic Test no longer passes on 4xx and Cloudflare
dispatch, #36 shared Albert anomaly acknowledgement."""
import asyncio, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("MONGO_URL", "x"); os.environ.setdefault("DB_NAME", "t"); os.environ.setdefault("JWT_SECRET", "x")
import httpx

_real = httpx.AsyncClient
def with_status(code):
    def handler(req):
        return httpx.Response(code, text="nope")
    class C(_real):
        def __init__(self, *a, **k):
            k["transport"] = httpx.MockTransport(handler); super().__init__(*a, **k)
    return C

import routes.integrations as ri
async def probe(code):
    httpx.AsyncClient = with_status(code)
    try:
        return await ri._generic_reachability_check({"endpoint": "https://x.example/api", "api_key": "k"})
    finally:
        httpx.AsyncClient = _real

res = {c: asyncio.run(probe(c)) for c in (200, 302, 400, 401, 403, 404, 405, 500)}
assert res[200]["ok"] and res[302]["ok"] and res[405]["ok"]
for c in (400, 401, 403, 404, 500):
    assert not res[c]["ok"], (c, res[c])
assert "credential was rejected" in res[401]["message"]
print("PASS: generic connection test fails on 4xx/5xx (400 is no longer success)")

src = open(os.path.join(os.path.dirname(ri.__file__), "integrations.py")).read()
i_cf, i_pre = src.index('"cloudflare" in name.lower()'), src.index("Missing endpoint or api_key")
assert i_cf < i_pre, "Cloudflare must dispatch before the generic endpoint precheck"
print("PASS: Cloudflare test dispatches before the endpoint precheck, case-insensitively")

from mongomock_motor import AsyncMongoMockClient
import routes.albert as ra

async def albert():
    db = AsyncMongoMockClient()["t"]; ra.db = db
    anomalies = [{"day": "2026-09-30", "category": "Scan", "count": 40},
                 {"day": "2026-10-01", "category": "Malware", "count": 9}]
    async def fake_stats(_db, days=30, include_suppressed=False):
        return {"anomalies": [dict(a) for a in anomalies]}
    ra.compute_albert_stats = fake_stats
    s = await ra.albert_stats(days=30, include_suppressed=False, user={"email": "a@x"})
    assert not any(a["acknowledged"] for a in s["anomalies"])
    await ra.albert_ack_anomalies(ra.AnomalyAckBody(keys=["2026-09-30:Scan"]), user={"email": "a@x"})
    s = await ra.albert_stats(days=30, include_suppressed=False, user={"email": "b@x"})
    by = {a["day"]: a for a in s["anomalies"]}
    assert by["2026-09-30"]["acknowledged"] and by["2026-09-30"]["acknowledged_by"] == "a@x"
    assert not by["2026-10-01"]["acknowledged"]
    # count growth on an acknowledged day does not resurrect it
    anomalies[0]["count"] = 55
    s = await ra.albert_stats(days=30, include_suppressed=False, user={"email": "b@x"})
    assert {a["day"]: a for a in s["anomalies"]}["2026-09-30"]["acknowledged"]
    # re-ack keeps the original acknowledger
    await ra.albert_ack_anomalies(ra.AnomalyAckBody(keys=["2026-09-30:Scan"]), user={"email": "c@x"})
    assert (await db.albert_anomaly_acks.find_one({"key": "2026-09-30:Scan"}))["by"] == "a@x"
    print("PASS: Albert anomaly acknowledgement is shared, attributed, and per day/category")
asyncio.run(albert())
