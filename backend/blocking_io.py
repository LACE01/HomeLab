"""Run blocking I/O off the event loop, with a deadline that actually holds.

WHY THIS EXISTS

This app is a single asyncio process. Every request for every user is handled by
one event loop. A synchronous network call inside an `async def` does not just
slow that one request down -- it stops the loop, so for its whole duration the
API accepts nothing: no other request, no background task, and not the container
healthcheck. From the outside the process looks alive (the port is open, docker
says Up) but nothing is answered.

That is exactly how a hang presents itself in the UI: the login page posts
credentials, gets no response, and shows "Login failed" -- pointing at auth,
which is fine, while the real cause is a DNS or WHOIS lookup somewhere else
entirely holding the loop.

The offenders are easy to miss because they look harmless:

    dns.resolver.resolve(name, "TXT", lifetime=8.0)   # 8s of frozen API
    whois.whois(domain)                               # NO TIMEOUT AT ALL
    socket.gethostbyname(host)                        # blocks, timeout not settable
    requests.get(url, timeout=10)                     # 10s of frozen API

TWO GUARANTEES

  1. `asyncio.to_thread` gets the call off the loop.
  2. `asyncio.wait_for` puts a ceiling on how long the CALLER waits.

Both are needed. Offloading alone is not enough: a library with no timeout of its
own (python-whois opens a raw socket to a WHOIS server and will happily wait
forever) would leave the awaiting request hanging indefinitely even though the
loop itself stayed responsive.

A NOTE ON THE LEAKED THREAD

When the deadline fires, the worker thread is NOT killed -- Python cannot
interrupt a thread blocked in a syscall. It finishes on its own and its result is
discarded. That is an accepted, bounded cost: a handful of threads in the default
executor may sit idle for a while. It is strictly better than the alternative,
which is the whole API hanging. Where a library exposes its own timeout, pass it
too, so the thread also gives up rather than lingering.
"""
import asyncio
import logging
from typing import Callable, TypeVar

logger = logging.getLogger("vulnops.blocking")

T = TypeVar("T")

# Deliberately short. These wrap third-party network lookups whose results are
# "nice to have" enrichment; none of them is worth making a user wait on, and a
# generous default is how a slow dependency turns into a slow product.
DEFAULT_TIMEOUT = 10.0


class BlockingTimeout(Exception):
    """The blocking call outlived its deadline. Callers should treat this the
    same as any other lookup failure -- 'we could not find out' -- not as a
    reason to fail the whole operation."""


async def run_blocking(fn: Callable[..., T], *args, timeout: float = DEFAULT_TIMEOUT,
                        label: str | None = None, **kwargs) -> T:
    """Await `fn(*args, **kwargs)` on a worker thread, with a hard deadline.

    Raises BlockingTimeout past the deadline; anything the function itself raises
    propagates unchanged, so existing error handling keeps working."""
    name = label or getattr(fn, "__name__", "blocking call")
    try:
        return await asyncio.wait_for(asyncio.to_thread(fn, *args, **kwargs), timeout=timeout)
    except asyncio.TimeoutError:
        # Logged at warning, not exception: a slow external resolver is an
        # expected condition, and the useful signal is WHICH lookup was slow.
        logger.warning("%s exceeded %.1fs and was abandoned (the API stayed responsive)",
                        name, timeout)
        raise BlockingTimeout(f"{name} timed out after {timeout:.0f}s") from None


async def gather_blocking(calls: list, *, timeout: float = DEFAULT_TIMEOUT,
                           label: str | None = None) -> list:
    """Run several blocking calls CONCURRENTLY on worker threads.

    `calls` is a list of (fn, args_tuple) pairs. Results come back positionally,
    with a BlockingTimeout or the raised exception in place of any that failed --
    never a raise, because these are independent probes and one bad name should
    not discard the others.

    This matters more than it looks: probing 16 candidate DKIM selectors serially
    at 8 seconds each is over two minutes; concurrently it is one timeout.
    """
    async def one(fn, args):
        try:
            return await run_blocking(fn, *args, timeout=timeout, label=label)
        except Exception as e:
            return e

    return await asyncio.gather(*(one(fn, args) for fn, args in calls))


async def loop_lag_monitor(threshold: float = 2.0, interval: float = 1.0):
    """Log a warning whenever the event loop stalls.

    The loop is supposed to come back to us every `interval` seconds. If it took
    materially longer, something blocked it, and that something is degrading
    every request in the process. Without this the symptom is invisible from the
    server side -- the log simply goes quiet, which reads like "no traffic"
    rather than "the process stopped answering", and that ambiguity is what makes
    these bugs so expensive to find.

    Cheap enough to run permanently: one sleep and one subtraction per second.
    """
    loop = asyncio.get_running_loop()
    while True:
        before = loop.time()
        await asyncio.sleep(interval)
        lag = loop.time() - before - interval
        if lag >= threshold:
            logger.warning(
                "EVENT LOOP BLOCKED for %.1fs -- the API answered nothing during that time "
                "(including healthchecks and logins). Something ran synchronous I/O or a long "
                "CPU-bound computation on the loop; wrap it in blocking_io.run_blocking.", lag)
