"""Backlog-wide statistics: computed rarely, off the event loop, served instantly.

WHAT WENT WRONG

/v1/mitre/coverage loaded all 7,501 open findings and ran the ATT&CK resolver
over every one of them -- 44 regexes against title + description + consequence +
remediation each. Measured: 5.5 SECONDS of pure CPU, synchronously, on the event
loop, on every single Finding Detail page view.

This is a single-process asyncio app, so that is 5.5 seconds during which the API
answers nothing at all -- and because requests queue, five people opening a
finding at once is nearly half a minute of the product being down. That is what
produced the 504s and the pages stuck on "Loading...".

It is precisely the failure blocking_io.py was written to prevent, reintroduced
by me in a different shape: not a blocking network call this time, but a
CPU-bound loop, which the event loop cannot interrupt either.

THE TWO FIXES, BOTH NEEDED

  1. OFF THE LOOP. The computation runs on a worker thread, so however long it
     takes, requests keep being served.
  2. NOT PER REQUEST. It is a property of the whole backlog, not of the finding
     being viewed. Recomputing it for every page view was never right, no matter
     how fast it was. It is cached with a TTL and refreshed in the background.

SERVING STALE IS BETTER THAN SERVING SLOW. When a cached value expires, the
request returns the old value immediately and triggers a refresh, rather than
making the user wait for a recompute. A coverage percentage that is ten minutes
old is worth exactly as much as a fresh one; a page that takes six seconds is
not.
"""
import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Callable

logger = logging.getLogger("vulnops.cache")

DEFAULT_TTL = timedelta(minutes=15)

# Refreshes in flight, so a burst of requests for an expired key triggers ONE
# recompute rather than one per request -- the stampede that turns a slow
# endpoint into an outage.
_refreshing: set = set()


def _now():
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now().isoformat()


# An EMPTY result is never cached at all.
#
# The reasoning is simple once stated: if the result is empty, the computation
# had nothing to iterate over, so it was cheap BY DEFINITION -- caching saves
# nothing. And it is the single most misleading thing to serve stale. The first
# request after a deploy runs against an empty database; pinning "0 findings"
# would keep the dashboard showing zeros straight through the first sync, which
# reads as "we have no vulnerabilities" -- the worst wrong answer this product
# can give.


async def get_or_compute(db, key: str, compute: Callable, *,
                          ttl: timedelta = DEFAULT_TTL,
                          is_empty: Callable = None,
                          cpu_bound: bool = False, timeout: float = 120.0) -> dict:
    """Return the cached value for `key`, refreshing it when stale.

    `compute` is an async callable returning the value. Set `cpu_bound` when it
    does significant work in Python rather than waiting on I/O -- it is then run
    on a worker thread so it cannot stall request handling.

    `is_empty(value)` marks a result as "nothing there yet"; such results are
    recomputed every time rather than cached.
    """
    def _empty(value) -> bool:
        if is_empty is None:
            return False
        try:
            return bool(is_empty(value or {}))
        except Exception:
            return False

    row = await db.aggregate_cache.find_one({"key": key}, {"_id": 0})
    fresh = False
    if row and row.get("computed_at") and not _empty(row.get("value")):
        try:
            fresh = (_now() - datetime.fromisoformat(row["computed_at"])) < ttl
        except Exception:
            fresh = False

    if row and fresh:
        return {**row["value"], "_cache": {"hit": True, "computed_at": row["computed_at"],
                                            "stale": False}}

    if row and not fresh and not _empty(row.get("value")):
        # Serve the stale value NOW and refresh behind it. Making this request
        # wait for a recompute is how a slow aggregate becomes a slow product.
        _schedule_refresh(db, key, compute, cpu_bound=cpu_bound, timeout=timeout)
        return {**row["value"], "_cache": {"hit": True, "computed_at": row["computed_at"],
                                            "stale": True,
                                            "note": "Refreshing in the background."}}

    # Nothing usable cached -- compute it, but still off the loop.
    value = await _run(compute, cpu_bound=cpu_bound, timeout=timeout)
    if not _empty(value):
        await _store(db, key, value)
    return {**value, "_cache": {"hit": False, "computed_at": _now_iso(), "stale": False}}


async def _run(compute: Callable, *, cpu_bound: bool, timeout: float):
    if not cpu_bound:
        return await compute()
    from blocking_io import run_blocking
    # compute() is async but CPU-heavy; run its synchronous core in a thread by
    # driving a fresh event loop there. Cheap relative to the work itself.
    def _sync():
        return asyncio.run(compute())
    return await run_blocking(_sync, timeout=timeout, label="cached aggregate")


async def _store(db, key: str, value: dict) -> None:
    await db.aggregate_cache.replace_one(
        {"key": key},
        {"key": key, "value": value, "computed_at": _now_iso()},
        upsert=True)


def _schedule_refresh(db, key: str, compute: Callable, *, cpu_bound: bool,
                       timeout: float) -> None:
    if key in _refreshing:
        return
    _refreshing.add(key)

    async def _job():
        try:
            value = await _run(compute, cpu_bound=cpu_bound, timeout=timeout)
            await _store(db, key, value)
        except Exception:
            logger.exception("Background refresh of %s failed; the stale value is kept", key)
        finally:
            _refreshing.discard(key)

    asyncio.create_task(_job())


async def invalidate(db, key: str = None) -> int:
    q = {"key": key} if key else {}
    res = await db.aggregate_cache.delete_many(q)
    return res.deleted_count


async def status(db) -> dict:
    """What is cached and how old, for the health page."""
    rows = await db.aggregate_cache.find({}, {"_id": 0, "value": 0}).to_list(100)
    for r in rows:
        try:
            r["age_seconds"] = int((_now() - datetime.fromisoformat(r["computed_at"])).total_seconds())
        except Exception:
            r["age_seconds"] = None
    return {"items": rows, "refreshing": sorted(_refreshing)}
