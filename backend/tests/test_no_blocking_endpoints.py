"""No endpoint may hold the event loop.

This exists because I shipped the bug twice. blocking_io.py fixed the first shape
(a synchronous network call in a background loop). Then /v1/mitre/coverage
reintroduced it in a different shape: a CPU-bound loop over the whole backlog --
7,500 findings x 44 regexes, measured at 5.5 SECONDS -- running synchronously on
every Finding Detail page view.

In a single-process asyncio app that is 5.5 seconds of the API answering nothing,
and requests queue, so a few concurrent page loads produced 504s and pages stuck
on "Loading...". The event loop cannot interrupt CPU any more than it can
interrupt a blocking socket.

The test measures the property directly -- how long the loop is unavailable while
a request is served -- rather than asserting something about how the code is
written, because the next version of this bug will be written differently.
"""
import os, sys, asyncio, time
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_no_blocking"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_no_blocking"]
db = db_module.db

import server, auth_utils
from routes import findings as findings_route
from routes import corroboration as corr_route
findings_route.db = db
corr_route.db = db

from fastapi.testclient import TestClient

admin = {"id": "u1", "email": "a@x.com", "role": "admin", "name": "A", "teams": []}
server.app.dependency_overrides[auth_utils.get_current_user] = lambda: admin
client = TestClient(server.app)
run = lambda c: asyncio.get_event_loop().run_until_complete(c)


# A backlog big enough that the old implementation was unmistakably slow.
TITLES = ["SSL/TLS Server Supports Deprecated Protocol SSLv3",
          "Microsoft Windows SMBv1 Protocol Enabled",
          "Telnet Service Detected on Port 23",
          "Some vendor-specific check that matches nothing at all",
          "EOL/Obsolete Software: Windows Server 2012 R2 Detected"]

run(db.findings.insert_many([{
    "id": f"f{i}",
    "title": TITLES[i % len(TITLES)],
    "description": "lorem ipsum " * 40,
    "consequence": "consequence text " * 30,
    "remediation": "remediation text " * 30,
    "detection_logic": "Web Application",
    "severity": "High",
    "status": "New",
    "asset_id": f"a{i % 50}",
} for i in range(3000)]))


# ============ the loop stays responsive while the endpoint is served ============

async def _measure(path):
    """Serve `path` while a ticker counts how often the loop comes back to us.

    A CPU-bound handler pins the ticker at ~0 no matter how many awaits it
    contains, which is exactly why "it's async" is not the same as "it doesn't
    block".
    """
    ticks = 0
    stop = False

    async def ticker():
        nonlocal ticks
        while not stop:
            await asyncio.sleep(0.01)
            ticks += 1

    t = asyncio.create_task(ticker())
    started = time.monotonic()
    # TestClient is synchronous, so drive the app directly on this loop instead.
    import httpx
    transport = httpx.ASGITransport(app=server.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get(path, timeout=60)
    elapsed = time.monotonic() - started
    stop = True
    t.cancel()
    return r, elapsed, ticks


r, elapsed, ticks = run(_measure("/api/v1/mitre/coverage"))
assert r.status_code == 200, r.text
assert ticks >= 5, (
    f"the event loop only ran {ticks} times while /v1/mitre/coverage was served "
    f"({elapsed:.2f}s) — it is holding the loop, which means the whole API is "
    "unavailable for that long")
print(f"PASS: /v1/mitre/coverage keeps the event loop running ({ticks} iterations in "
      f"{elapsed:.2f}s) — the CPU-bound resolution happens on a worker thread, so other requests "
      "and the healthcheck continue to be served")


# ============ and it is not recomputed per request ============

first = client.get("/api/v1/mitre/coverage").json()
assert first["_cache"]["hit"] in (False, True)
computed_at = first["_cache"]["computed_at"]

t0 = time.monotonic()
for _ in range(5):
    again = client.get("/api/v1/mitre/coverage").json()
warm = time.monotonic() - t0

assert again["_cache"]["hit"] is True
assert again["_cache"]["computed_at"] == computed_at, "recomputed despite being fresh"
assert warm < 1.0, f"five cached reads took {warm:.2f}s"
assert again["findings_total"] == first["findings_total"]
print(f"PASS: five further requests are served from cache in {warm:.3f}s total and do not "
      "recompute — this is a property of the whole backlog, not of the finding being viewed, so "
      "computing it per page view was never right regardless of speed")


# ============ an expired entry serves stale rather than making you wait ============

import aggregate_cache as ac
from datetime import datetime, timezone, timedelta

run(db.aggregate_cache.update_one({"key": "mitre_coverage"}, {"$set": {
    "computed_at": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()}}))

async def _timed_get(path):
    """Time to RESPONSE, measured on the app's own loop.

    TestClient is synchronous and its portal drains pending tasks before handing
    control back, so it would also wait for the background refresh -- measuring
    something the browser never experiences. Under uvicorn the response is
    written and the refresh continues behind it, which is the behaviour under
    test.
    """
    import httpx
    transport = httpx.ASGITransport(app=server.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        t = time.monotonic()
        r = await c.get(path, timeout=60)
        return r.json(), time.monotonic() - t

stale, stale_time = run(_timed_get("/api/v1/mitre/coverage"))
assert stale["_cache"]["stale"] is True
assert "Refreshing in the background" in stale["_cache"]["note"]
assert stale_time < 1.0, f"a stale read blocked for {stale_time:.2f}s"
print(f"PASS: an expired entry returns the previous value immediately ({stale_time:.3f}s) and "
      "refreshes behind the request — a coverage figure ten minutes old is worth as much as a "
      "fresh one; a six-second page is not")


# ============ a burst does not stampede into N recomputes ============

ac._refreshing.clear()
run(db.aggregate_cache.update_one({"key": "mitre_coverage"}, {"$set": {
    "computed_at": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()}}))

calls = {"n": 0}
_orig = ac._run


async def _counting(compute, *, cpu_bound, timeout):
    calls["n"] += 1
    return await _orig(compute, cpu_bound=cpu_bound, timeout=timeout)


ac._run = _counting


async def _burst():
    import httpx
    transport = httpx.ASGITransport(app=server.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        await asyncio.gather(*[c.get("/api/v1/mitre/coverage") for _ in range(10)])
    await asyncio.sleep(0.3)   # let the single background refresh land

run(_burst())
ac._run = _orig
assert calls["n"] <= 1, f"{calls['n']} concurrent recomputes were started for one expired key"
print("PASS: ten simultaneous requests for an expired key trigger at most ONE recompute — without "
      "that guard, expiry turns a slow aggregate into a stampede, which is how a cache makes an "
      "outage worse rather than better")


# ============ the corroboration summary is cached too ============

r = client.get("/api/v1/findings/corroboration/summary")
assert r.status_code == 200 and "_cache" in r.json()
t0 = time.monotonic()
for _ in range(5):
    client.get("/api/v1/findings/corroboration/summary")
assert time.monotonic() - t0 < 1.0
print("PASS: the corroboration summary is cached on the same terms — it walks every open finding "
      "and does one identifier lookup per distinct asset")


# ============ correlation prefetches instead of querying per asset ============

import correlation as cx
import entity_resolution as er

run(db.assets.insert_many([
    {"id": f"a{i}", "hostname": f"h{i}", "ip": f"10.0.{i // 250}.{i % 250}",
     "status": "active", "internet_facing": i % 10 == 0} for i in range(300)]))
for i in range(0, 300, 10):
    run(er.record_identifiers(db, f"a{i}", er.identifiers_from({"hostname": f"h{i}"}), "qualys"))

# `db.findings` returns a NEW collection wrapper on every attribute access, so
# patching a method on one instance counts nothing. Wrap the DATABASE'S
# collection accessor instead, which is the only place every caller goes through.
queries = {"find": 0}


class _CountingDB:
    def __init__(self, real):
        self._real = real

    def __getattr__(self, name):
        coll = getattr(self._real, name)
        if name != "findings":
            return coll
        outer = self

        class _Counted:
            def __getattr__(self, attr):
                target = getattr(coll, attr)
                if attr != "find":
                    return target

                def _wrapped(*a, **kw):
                    outer_queries = outer
                    queries["find"] += 1
                    return target(*a, **kw)
                return _wrapped

            def __getitem__(self, k):
                return coll[k]
        return _Counted()

    def __getitem__(self, k):
        return self._real[k]


run(cx.run(_CountingDB(db)))
assert queries["find"] >= 1, "the counter never fired, so this assertion proves nothing"
assert queries["find"] <= 3, (
    f"{queries['find']} findings queries for 300 assets — correlation is querying per asset, "
    "which grows linearly with the estate and monopolises the database for minutes on a real one")
print(f"PASS: a correlation run over 300 assets issues {queries['find']} findings query(ies), not "
      "one per asset — the per-asset version did ~6 round trips each, so it got slower exactly as "
      "the platform got more useful")


# ============ correlation yields while evaluating ============

async def _measure_correlation():
    ticks = 0
    stop = False

    async def ticker():
        nonlocal ticks
        while not stop:
            await asyncio.sleep(0.01)
            ticks += 1

    t = asyncio.create_task(ticker())
    await cx.run(db)
    stop = True
    t.cancel()
    return ticks

# Measuring cx.run() end to end cannot answer this question in a test: mongomock
# performs its "I/O" synchronously on the calling thread, so the prefetch phase
# starves the loop here in a way real motor would not. Measuring that would be
# measuring the test harness.
#
# So the two phases are checked for what each can actually be held to:
#   * the CPU phase, directly -- it must stay small as the estate grows, because
#     nothing can interrupt it;
#   * the loop, structurally -- it must yield periodically, since a big enough
#     estate would eventually make even cheap per-asset work add up.

async def _cpu_phase():
    await db.assets.insert_many([
        {"id": f"b{i}", "hostname": f"bh{i}", "status": "active"} for i in range(3000)])
    assets = await db.assets.find({}, {"_id": 0}).to_list(10000)
    pre = await cx._prefetch(db, assets)
    started = time.monotonic()
    for a in assets:
        ctx = cx._context_for(a, pre)
        for rule in cx.RULES:
            try:
                rule.evaluate(rule, ctx)
            except Exception:
                pass
    return len(assets), time.monotonic() - started

count, cpu = run(_cpu_phase())
per_asset_us = (cpu / count) * 1_000_000
assert cpu < 1.0, (
    f"evaluating {count} assets took {cpu:.2f}s of uninterruptible CPU — that is time the API "
    "answers nothing, and it grows with the estate")
print(f"PASS: evaluating every rule against {count} assets costs {cpu:.3f}s of CPU "
      f"({per_asset_us:.0f}us each) because the data is prefetched into maps first — the earlier "
      "version did ~6 database round trips per asset instead")

src = open("correlation.py").read()
assert "await asyncio.sleep(0)" in src, (
    "the evaluation loop must yield periodically; cheap per-asset work still adds up on a large "
    "enough estate, and nothing can preempt it")
print("PASS: the evaluation loop yields to the event loop periodically, so growth in the estate "
      "cannot silently turn a sweep into a stall")


# ============ emptiness is never cached ============

import aggregate_cache as ac

run(db.aggregate_cache.delete_many({}))
calls = {"n": 0}


async def _sometimes_empty():
    calls["n"] += 1
    return {"findings_total": 0 if calls["n"] == 1 else 42}


empty_check = lambda v: not v.get("findings_total")

first = run(ac.get_or_compute(db, "emptytest", _sometimes_empty, is_empty=empty_check))
assert first["findings_total"] == 0
assert run(db.aggregate_cache.count_documents({"key": "emptytest"})) == 0, \
    "an empty result was written to the cache"

second = run(ac.get_or_compute(db, "emptytest", _sometimes_empty, is_empty=empty_check))
assert second["findings_total"] == 42, "a cached zero was served after data arrived"
print("PASS: an EMPTY aggregate is never cached — the computation had nothing to iterate so it was "
      "free anyway, and pinning '0 findings' would keep the dashboard showing zeros straight "
      "through the first sync after a deploy, which reads as 'we have no vulnerabilities'")

third = run(ac.get_or_compute(db, "emptytest", _sometimes_empty, is_empty=empty_check))
assert third["_cache"]["hit"] is True and third["findings_total"] == 42
print("PASS: once the result is non-empty it caches normally")
