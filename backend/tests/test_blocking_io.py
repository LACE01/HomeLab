"""The API must keep answering while a slow external lookup is in flight.

This is the bug that presented as "logging in is broken, it just says login
failed". The auth code was fine. A synchronous DNS/WHOIS lookup in a background
task was holding the single event loop, so the process answered NOTHING -- not
other requests, not logins, not the container healthcheck. `docker compose ps`
said Up (unhealthy) and the log simply went quiet, which reads like "no traffic"
instead of "nothing is being served".

These tests assert the property that actually matters -- the loop stays free --
by racing a real request against a deliberately blocking call.
"""
import os, sys, asyncio, time
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_blocking_io"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_blocking_io"]

import blocking_io
from blocking_io import run_blocking, gather_blocking, BlockingTimeout

run = lambda c: asyncio.get_event_loop().run_until_complete(c)


# ============ the loop stays free ============

def slow_sync(seconds=0.6):
    """Stands in for dns.resolver.resolve / whois.whois / socket.gethostbyname:
    a plain blocking call with no async support."""
    time.sleep(seconds)
    return "done"


async def _loop_stays_responsive():
    """Count how many times the loop comes back to us while a blocking call runs.
    If the call were made directly, this counter would be stuck at 0."""
    ticks = 0

    async def ticker():
        nonlocal ticks
        while True:
            await asyncio.sleep(0.02)
            ticks += 1

    t = asyncio.create_task(ticker())
    result = await run_blocking(slow_sync, 0.6, timeout=5)
    t.cancel()
    return result, ticks

result, ticks = run(_loop_stays_responsive())
assert result == "done"
assert ticks >= 10, f"the loop only ran {ticks} times during a 0.6s blocking call -- it was blocked"
print(f"PASS: the event loop kept running ({ticks} iterations) while a 0.6s blocking call was in "
      "flight — other requests and the healthcheck continue to be served")

# proof the direct call is what breaks it: awaiting nothing, the loop can't tick
async def _direct_call_blocks():
    ticks = 0

    async def ticker():
        nonlocal ticks
        while True:
            await asyncio.sleep(0.02)
            ticks += 1

    t = asyncio.create_task(ticker())
    await asyncio.sleep(0.05)          # let the ticker start
    before = ticks
    slow_sync(0.5)                      # the bug: blocking call ON the loop
    during = ticks - before
    t.cancel()
    return during

assert run(_direct_call_blocks()) == 0, "expected a directly-called blocking function to freeze the loop"
print("PASS: the same call made directly freezes the loop completely (0 iterations) — this is the "
      "defect being fixed, pinned so it can't come back unnoticed")


# ============ a library with no timeout of its own can't hang a request ============

# python-whois's actual behaviour against an unresponsive WHOIS server: it takes
# no timeout argument and will wait indefinitely. Modelled with an Event rather
# than a long sleep so the abandoned worker thread can be released once the
# assertion is made -- ThreadPoolExecutor threads are joined at interpreter exit,
# so a thread still sleeping would stall the whole test run on the way out. That
# join is also the reason run_blocking's docstring insists on passing a library's
# own timeout where one exists.
import threading
_release = threading.Event()


def never_returns():
    _release.wait(30)
    return "never observed"

async def _deadline_holds():
    started = time.monotonic()
    try:
        await run_blocking(never_returns, timeout=0.4, label="WHOIS lookup")
        raise AssertionError("expected BlockingTimeout")
    except BlockingTimeout as e:
        return time.monotonic() - started, str(e)

elapsed, msg = run(_deadline_holds())
_release.set()  # let the abandoned worker finish so the process can exit promptly
assert elapsed < 3, f"the caller waited {elapsed:.1f}s on a 0.4s deadline"
assert "WHOIS lookup" in msg and "timed out" in msg
print(f"PASS: a call that never returns is abandoned after its deadline ({elapsed:.2f}s), naming which "
      "lookup was slow — offloading alone would still hang the request forever")


# ============ concurrency: 16 DKIM selectors must not be 16 x timeout ============

async def _concurrent():
    started = time.monotonic()
    results = await gather_blocking([(slow_sync, (0.3,)) for _ in range(16)], timeout=5)
    return time.monotonic() - started, results

elapsed, results = run(_concurrent())
assert all(r == "done" for r in results), results
assert elapsed < 2.0, f"16 x 0.3s ran in {elapsed:.1f}s -- they were serialized, not concurrent"
print(f"PASS: 16 blocking lookups complete in {elapsed:.2f}s instead of ~4.8s serial — the DKIM probe "
      "sweeps every selector at once")

# one bad probe must not discard the good ones
def boom():
    raise RuntimeError("SERVFAIL")

out = run(gather_blocking([(slow_sync, (0.05,)), (boom, ()), (slow_sync, (0.05,))], timeout=2))
assert out[0] == "done" and out[2] == "done"
assert isinstance(out[1], Exception)
print("PASS: one failing lookup is returned as an exception in place, leaving the others intact — "
      "independent probes don't take each other down")


# ============ the watchdog reports a stalled loop ============

async def _watchdog_fires():
    import logging
    records = []

    class Grab(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())

    logger = logging.getLogger("vulnops.blocking")
    h = Grab()
    logger.addHandler(h)
    t = asyncio.create_task(blocking_io.loop_lag_monitor(threshold=0.2, interval=0.05))
    await asyncio.sleep(0.1)
    time.sleep(0.5)                     # simulate a blocking call on the loop
    await asyncio.sleep(0.15)
    t.cancel()
    logger.removeHandler(h)
    return records

records = run(_watchdog_fires())
assert any("EVENT LOOP BLOCKED" in r for r in records), records
blocked = next(r for r in records if "EVENT LOOP BLOCKED" in r)
assert "answered nothing" in blocked and "run_blocking" in blocked
print("PASS: the watchdog logs 'EVENT LOOP BLOCKED for Ns', says the API answered nothing during it, "
      "and names the fix — so this failure announces itself instead of looking like a broken login")


# ============ the real call sites are fixed ============

des = open("domain_email_security.py").read()
assert "check_dkim_async" in des and "gather_blocking" in des
assert "await run_blocking(check_spf" in des and "await run_blocking(check_dmarc" in des
assert "spf = check_spf(domain)" not in des, "SPF still resolved directly on the event loop"
print("PASS: SPF/DMARC/DKIM lookups are offloaded, and DKIM's selector sweep is concurrent")

ec = open("external_checks.py").read()
assert "gather_blocking" in ec, "the A/NS/MX lookups are still serial on the loop"
assert "run_blocking(_whois_lookup" in ec, "whois.whois can still hang the whole API"
assert "w = whois.whois(domain)" not in ec
assert "for a in resolver.resolve(domain, rtype)]\n            except" not in ec
print("PASS: the external-check DNS sweep is concurrent and off the loop, and the WHOIS lookup — which "
      "accepts no timeout of its own — now has a deadline the caller enforces")

auth = open("routes/auth.py").read()
assert "_requests.get(" not in auth, "a synchronous requests.get in an async route blocks every user"
assert "httpx" in auth
print("PASS: the OAuth relay call uses async httpx, so one person signing in can't freeze everyone "
      "else's login")

srv = open("server.py").read()
assert "loop_lag_monitor" in srv
assert srv.index("loop_lag_monitor()") < srv.index("nightly_loop(db"), \
    "the watchdog must start before the background loops it is meant to catch"
print("PASS: the watchdog is started at boot, ahead of the background loops")
