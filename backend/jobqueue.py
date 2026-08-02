"""A durable job queue, so long work stops living in the API process.

WHY THIS EXISTS

The API froze for everyone, including the login page, because a background task
in the same process made a blocking call. blocking_io.py fixed that class of bug,
but it treated the symptom. The structural problem remains: nmap sweeps, nikto
scans, trivy image scans and EASM enumeration all run as
`asyncio.create_task(...)` inside the process that serves requests. They compete
with request handling for the same event loop and the same CPU, and if one of
them wedges, the product is down.

They also lose their work on every deploy. A container restart mid-scan leaves no
record that the scan was ever running -- it simply never finishes, and nobody
finds out.

THE MODEL

Jobs are DOCUMENTS, not tasks. Enqueue writes a row; a worker claims it with an
atomic find-and-modify; progress and result are written back to the row. From
that one change several things follow for free:

  * a restart cannot lose a job -- an unfinished one is still sitting there, and
    is requeued rather than forgotten
  * the queue is inspectable ("what is running, what is stuck, what failed and
    why") instead of being invisible task objects
  * concurrency is a number you can set, rather than however many tasks happen to
    have been created
  * the same scan requested twice does not run twice

CLAIMING MUST BE ATOMIC. Two workers reading "queued" and both deciding to run it
is the classic bug here, and with scanners it means firing two nmap sweeps at the
same subnet. find_one_and_update with a status precondition makes the claim and
the state change one operation, so exactly one worker can win.

A STUCK JOB IS NOT A RUNNING JOB. Anything claimed but not updated inside its
lease is presumed dead -- its worker was killed, deployed over, or is wedged --
and is requeued, with the attempt recorded. Without this a crashed worker's job
stays "running" forever and the queue silently drains to nothing.
"""
import asyncio
import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Callable, Optional

logger = logging.getLogger("vulnops.jobs")

QUEUED = "queued"
RUNNING = "running"
DONE = "done"
FAILED = "failed"
CANCELLED = "cancelled"

# How long a worker may hold a job without a heartbeat before it is presumed
# dead. Generous, because real scans are slow; the worker heartbeats while it
# works, so this only fires on an actual death.
LEASE = timedelta(minutes=15)
MAX_ATTEMPTS = 3

_HANDLERS: dict = {}


def _now():
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now().isoformat()


def handler(kind: str):
    """Register the function that performs a job of this kind."""
    def wrap(fn: Callable):
        _HANDLERS[kind] = fn
        return fn
    return wrap


def registered_kinds() -> list:
    return sorted(_HANDLERS)


async def ensure_indexes(db):
    try:
        await db.jobs.create_index([("status", 1), ("priority", -1), ("enqueued_at", 1)])
        await db.jobs.create_index([("dedupe_key", 1)])
        await db.jobs.create_index([("kind", 1)])
    except Exception:
        pass


async def enqueue(db, kind: str, payload: dict = None, *, priority: int = 0,
                   dedupe_key: str = None, requested_by: str = "system") -> dict:
    """Queue a job. Returns the existing one if an identical job is pending.

    Deduplication is not an optimisation -- it prevents a user who clicks "Scan"
    three times from starting three concurrent nmap runs against one subnet.
    """
    if kind not in _HANDLERS:
        raise ValueError(f"No handler registered for job kind '{kind}'. "
                          f"Known kinds: {', '.join(registered_kinds()) or 'none'}")
    dedupe_key = dedupe_key or f"{kind}:{sorted((payload or {}).items())}"
    existing = await db.jobs.find_one(
        {"dedupe_key": dedupe_key, "status": {"$in": [QUEUED, RUNNING]}}, {"_id": 0})
    if existing:
        return {**existing, "deduped": True}

    job = {
        "id": str(uuid.uuid4()),
        "kind": kind,
        "payload": payload or {},
        "dedupe_key": dedupe_key,
        "status": QUEUED,
        "priority": priority,
        "attempts": 0,
        "requested_by": requested_by,
        "enqueued_at": _now_iso(),
        "started_at": None,
        "finished_at": None,
        "progress": None,
        "result": None,
        "error": None,
        "history": [],
    }
    await db.jobs.insert_one(dict(job))
    return {**job, "deduped": False}


async def claim(db, *, worker_id: str, kinds: Optional[list] = None) -> Optional[dict]:
    """Atomically take the next job. Exactly one worker can win.

    A read-then-write would let two workers both see 'queued' and both run it --
    which for a scanner means two simultaneous sweeps of the same network.
    """
    q = {"status": QUEUED}
    if kinds:
        q["kind"] = {"$in": kinds}
    # Deliberately does NOT ask for the post-update document.
    #
    # `return_document=True` combined with `sort` and `projection` is not handled
    # consistently across drivers -- one of them applies the update and then hands
    # back None, which would look like "nothing to claim" while a job sat in
    # RUNNING with no worker. Taking the pre-update document (which every driver
    # returns) and re-reading by id is one extra round trip and behaves the same
    # everywhere.
    #
    # The atomicity guarantee is unaffected: the status precondition and the write
    # are still a single operation, so exactly one worker can win.
    before = await db.jobs.find_one_and_update(
        q,
        {"$set": {"status": RUNNING, "worker_id": worker_id,
                   "started_at": _now_iso(), "lease_until": (_now() + LEASE).isoformat()},
         "$inc": {"attempts": 1}},
        sort=[("priority", -1), ("enqueued_at", 1)],
        projection={"_id": 0},
    )
    if not before:
        return None
    return await db.jobs.find_one({"id": before["id"]}, {"_id": 0})


async def heartbeat(db, job_id: str, progress: dict = None) -> None:
    """Extend the lease and optionally report progress.

    Long jobs must say they are alive; otherwise the reaper cannot tell a slow
    scan from a dead worker, and would have to choose between killing healthy
    work and never reclaiming anything.
    """
    patch = {"lease_until": (_now() + LEASE).isoformat()}
    if progress is not None:
        patch["progress"] = progress
    await db.jobs.update_one({"id": job_id}, {"$set": patch})


async def complete(db, job_id: str, result: dict) -> None:
    await db.jobs.update_one({"id": job_id}, {"$set": {
        "status": DONE, "result": result, "finished_at": _now_iso(),
        "error": None, "lease_until": None}})


async def fail(db, job_id: str, error: str, *, retry: bool = True) -> dict:
    """Record a failure, and requeue if attempts remain.

    The attempt history is kept rather than overwritten: 'failed three times with
    the same DNS error' and 'failed once' call for completely different
    responses, and a single error field cannot tell them apart.
    """
    job = await db.jobs.find_one({"id": job_id}, {"_id": 0})
    if not job:
        return {"requeued": False}
    entry = {"at": _now_iso(), "attempt": job.get("attempts", 0), "error": error[:500]}
    can_retry = retry and job.get("attempts", 0) < MAX_ATTEMPTS
    await db.jobs.update_one({"id": job_id}, {
        "$set": {"status": QUEUED if can_retry else FAILED,
                  "error": error[:2000],
                  "lease_until": None,
                  "finished_at": None if can_retry else _now_iso()},
        "$push": {"history": entry}})
    return {"requeued": can_retry, "attempts": job.get("attempts", 0)}


async def reap_expired(db) -> int:
    """Requeue jobs whose worker died.

    Without this a job claimed by a container that was then deployed over stays
    'running' forever: the queue drains to nothing and the work silently never
    happens. That failure is invisible precisely because the record LOOKS busy.
    """
    now_iso = _now_iso()
    stuck = await db.jobs.find(
        {"status": RUNNING, "lease_until": {"$lt": now_iso}}, {"_id": 0}).to_list(500)
    for job in stuck:
        await fail(db, job["id"],
                    f"Worker {job.get('worker_id')} stopped reporting; the job was presumed dead "
                    f"and requeued.", retry=True)
    if stuck:
        logger.warning("Requeued %d job(s) whose worker stopped reporting", len(stuck))
    return len(stuck)


async def run_one(db, job: dict) -> None:
    """Execute a claimed job with its handler."""
    fn = _HANDLERS.get(job["kind"])
    if not fn:
        await fail(db, job["id"], f"No handler registered for '{job['kind']}'", retry=False)
        return
    try:
        async def _hb(progress=None):
            await heartbeat(db, job["id"], progress)
        result = await fn(db, job["payload"], _hb)
        await complete(db, job["id"], result if isinstance(result, dict) else {"ok": True})
    except asyncio.CancelledError:
        await fail(db, job["id"], "Cancelled", retry=True)
        raise
    except Exception as e:
        logger.exception("Job %s (%s) failed", job["id"], job["kind"])
        await fail(db, job["id"], f"{type(e).__name__}: {e}")


async def worker(db, *, worker_id: str = None, kinds: Optional[list] = None,
                  concurrency: int = 2, poll_seconds: float = 5.0) -> None:
    """Long-running worker loop.

    Runs in its own process (see docker-compose 'worker' service). Concurrency is
    an explicit number rather than "however many tasks got created", which is what
    the old create_task approach amounted to.
    """
    worker_id = worker_id or f"worker-{uuid.uuid4().hex[:8]}"
    await ensure_indexes(db)
    running: set = set()
    logger.info("Job worker %s started (kinds=%s, concurrency=%d)",
                 worker_id, kinds or "all", concurrency)
    while True:
        try:
            await reap_expired(db)
            while len(running) < concurrency:
                job = await claim(db, worker_id=worker_id, kinds=kinds)
                if not job:
                    break
                task = asyncio.create_task(run_one(db, job))
                running.add(task)
                task.add_done_callback(running.discard)
            if not running:
                await asyncio.sleep(poll_seconds)
            else:
                await asyncio.wait(running, timeout=poll_seconds,
                                    return_when=asyncio.FIRST_COMPLETED)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Worker loop error; continuing")
            await asyncio.sleep(poll_seconds)


async def stats(db) -> dict:
    """Queue health, for the observability page."""
    out = {}
    for status in (QUEUED, RUNNING, DONE, FAILED, CANCELLED):
        out[status] = await db.jobs.count_documents({"status": status})
    oldest = await db.jobs.find({"status": QUEUED}, {"_id": 0, "enqueued_at": 1}).sort(
        "enqueued_at", 1).to_list(1)
    failing = await db.jobs.find(
        {"status": FAILED}, {"_id": 0, "id": 1, "kind": 1, "error": 1, "attempts": 1}
    ).sort("finished_at", -1).to_list(10)
    return {
        "counts": out,
        "oldest_queued_at": oldest[0]["enqueued_at"] if oldest else None,
        "recent_failures": failing,
        "registered_kinds": registered_kinds(),
        "note": ("A growing queued count with nothing running means no worker is connected — "
                  "check that the worker container is up."),
    }
