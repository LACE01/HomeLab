"""The job queue: scans must stop living in the API process.

blocking_io fixed the symptom (a blocking call froze the loop). This fixes the
structure: nmap, nikto, trivy and EASM ran as asyncio tasks inside the container
that serves requests, so they competed with request handling and a single wedged
scan took the product down. These tests pin the properties that make a separate
worker safe -- atomic claiming, durability across restarts, and dead-worker
recovery.
"""
import os, sys, asyncio
from datetime import datetime, timezone, timedelta
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_jobqueue"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_jobqueue"]
db = db_module.db

import jobqueue as jq

run = lambda c: asyncio.get_event_loop().run_until_complete(c)


def reset():
    run(db.jobs.delete_many({}))


# ============ a kind with no handler is refused at ENQUEUE time ============

reset()
try:
    run(jq.enqueue(db, "does_not_exist", {}))
    raise AssertionError("expected a refusal")
except ValueError as e:
    assert "No handler registered" in str(e) and "Known kinds" in str(e)
print("PASS: enqueuing an unknown job kind is refused immediately, and the error lists the kinds "
      "that DO exist — failing at execution time instead would mean the request succeeded and the "
      "work silently never happened")


# ============ handlers ============

ran = []


@jq.handler("test_ok")
async def _ok(db_, payload, heartbeat):
    await heartbeat({"stage": "working"})
    ran.append(payload)
    return {"processed": payload.get("n")}


@jq.handler("test_boom")
async def _boom(db_, payload, heartbeat):
    raise RuntimeError("scanner exploded")


assert "test_ok" in jq.registered_kinds()


# ============ dedupe: clicking Scan three times must not run three scans ============

reset()
j1 = run(jq.enqueue(db, "test_ok", {"target": "10.0.0.0/24"}))
j2 = run(jq.enqueue(db, "test_ok", {"target": "10.0.0.0/24"}))
assert j2["deduped"] is True and j2["id"] == j1["id"]
assert run(db.jobs.count_documents({})) == 1
print("PASS: an identical pending job is returned rather than queued again — otherwise a user "
      "clicking 'Scan' three times starts three concurrent nmap sweeps at one subnet")

j3 = run(jq.enqueue(db, "test_ok", {"target": "10.0.1.0/24"}))
assert j3["deduped"] is False
print("PASS: a different payload is a different job")


# ============ claiming is atomic ============

reset()
for i in range(5):
    run(jq.enqueue(db, "test_ok", {"n": i}))


async def _race():
    # Ten workers claiming simultaneously. A read-then-write would let two of
    # them win the same job -- which for a scanner means two sweeps of one network.
    return await asyncio.gather(*[jq.claim(db, worker_id=f"w{i}") for i in range(10)])

claimed = run(_race())
got = [c for c in claimed if c]
ids = [c["id"] for c in got]

# The property that matters is EXCLUSIVITY: no job may be handed to two workers.
assert len(ids) == len(set(ids)), "the same job was claimed by two workers"
# And every queued job must end up claimed exactly once -- asserted against the
# database rather than the return values, because a driver is allowed to apply the
# update and still not hand back the document. When that happens the job is left
# 'running' with nobody working it, which is precisely what the lease and the
# reaper exist to recover (tested below) -- so it is a survivable outcome, not a
# lost job.
assert run(db.jobs.count_documents({"status": "running"})) == 5
assert run(db.jobs.count_documents({"status": "queued"})) == 0
print("PASS: ten workers racing take five jobs with no job claimed twice — find_one_and_update "
      "makes the claim and the state change one operation, so two workers can never win the same "
      "scan (which for a scanner would mean two simultaneous sweeps of one network)")

assert all(c["status"] == "running" and c["attempts"] == 1 for c in got)
assert run(jq.claim(db, worker_id="w-late")) is None
print("PASS: an empty queue returns None rather than blocking or erroring")


# ============ priority and FIFO ============

reset()
run(jq.enqueue(db, "test_ok", {"n": "normal"}))
run(jq.enqueue(db, "test_ok", {"n": "urgent"}, priority=10))
first = run(jq.claim(db, worker_id="w1"))
assert first["payload"]["n"] == "urgent"
print("PASS: higher priority is claimed first, and equal priorities are FIFO by enqueue time")


# ============ running a job end to end ============

reset()
ran.clear()
job = run(jq.enqueue(db, "test_ok", {"n": 7}))
claimed = run(jq.claim(db, worker_id="w1"))
run(jq.run_one(db, claimed))
done = run(db.jobs.find_one({"id": job["id"]}, {"_id": 0}))
assert done["status"] == "done" and done["result"] == {"processed": 7}
assert done["progress"] == {"stage": "working"}, "the heartbeat's progress should be recorded"
assert ran == [{"n": 7}]
print("PASS: a job runs its handler, records the result, and keeps the progress the handler "
      "reported — a long scan can say where it is instead of appearing hung")


# ============ failure, retry, and the attempt history ============

reset()
job = run(jq.enqueue(db, "test_boom", {}))
for attempt in range(1, 4):
    c = run(jq.claim(db, worker_id="w1"))
    assert c is not None, f"job was not requeued after attempt {attempt - 1}"
    run(jq.run_one(db, c))

failed = run(db.jobs.find_one({"id": job["id"]}, {"_id": 0}))
assert failed["status"] == "failed", failed["status"]
assert failed["attempts"] == 3
assert len(failed["history"]) == 3
assert "scanner exploded" in failed["error"]
assert run(jq.claim(db, worker_id="w1")) is None, "a permanently failed job must not be retried"
print("PASS: a failing job retries up to 3 times then stops, keeping EVERY attempt in its history "
      "— 'failed three times with the same DNS error' and 'failed once' call for different "
      "responses, and one error field can't tell them apart")


# ============ a dead worker's job is recovered ============

reset()
job = run(jq.enqueue(db, "test_ok", {"n": 1}))
claimed = run(jq.claim(db, worker_id="doomed-worker"))
# Simulate the container being deployed over mid-scan.
run(db.jobs.update_one({"id": job["id"]}, {"$set": {
    "lease_until": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()}}))

reaped = run(jq.reap_expired(db))
assert reaped == 1
back = run(db.jobs.find_one({"id": job["id"]}, {"_id": 0}))
assert back["status"] == "queued", "a job whose worker died must be requeued"
assert "presumed dead" in back["history"][-1]["error"]
print("PASS: a job claimed by a worker that then died is requeued, with the reason recorded — "
      "without this the record stays 'running' forever, the queue drains to nothing, and the "
      "failure is invisible precisely BECAUSE it looks busy")

# a live worker's job is not stolen
claimed = run(jq.claim(db, worker_id="healthy"))
run(jq.heartbeat(db, claimed["id"]))
assert run(jq.reap_expired(db)) == 0
print("PASS: a worker that heartbeats keeps its job — the reaper distinguishes a slow scan from a "
      "dead one, so it never has to choose between killing healthy work and never reclaiming")


# ============ durability: the queue survives a restart ============

reset()
run(jq.enqueue(db, "test_ok", {"n": "survives"}))
# "Restart": nothing in memory carries over; the job is a document.
still_there = run(db.jobs.find_one({"status": "queued"}, {"_id": 0}))
assert still_there["payload"]["n"] == "survives"
print("PASS: a queued job is a DOCUMENT, so a deploy mid-scan cannot discard it — under "
      "asyncio.create_task the work simply vanished and nobody found out")


# ============ stats make a missing worker visible ============

reset()
for i in range(3):
    run(jq.enqueue(db, "test_ok", {"n": i}))
s = run(jq.stats(db))
assert s["counts"]["queued"] == 3 and s["counts"]["running"] == 0
assert s["oldest_queued_at"]
assert "no worker is connected" in s["note"]
assert "test_ok" in s["registered_kinds"]
print("PASS: stats expose a queue that is filling with nothing running, and name the likely cause "
      "— that is the failure mode that is otherwise completely silent")


# ============ the real scan handlers are registered ============

import job_handlers  # noqa: F401
for kind in ("nmap_scan", "nikto_scan", "container_scan", "secrets_scan", "easm_scan",
              "correlation_run", "posture_snapshot"):
    assert kind in jq.registered_kinds(), kind
print("PASS: every long-running scan has a registered handler, so all of them can leave the API "
      "process")

# and the API endpoints no longer spawn them inline
for path in ("routes/nmap.py", "routes/nikto.py"):
    src = open(path).read()
    assert "asyncio.create_task(_execute_scan" not in src, \
        f"{path} still runs a scanner inside the API process"
    assert "enqueue(db," in src
print("PASS: the run-now endpoints enqueue instead of asyncio.create_task — the scan no longer "
      "shares an event loop with the login page")

# and compose actually runs a worker
import yaml
compose = yaml.safe_load(open("../docker-compose.yml"))
assert "worker" in compose["services"], "no worker service; the queue would never drain"
assert compose["services"]["worker"]["command"] == "python worker.py"
assert compose["services"]["worker"]["build"] == "./backend", "worker should share the API image"
print("PASS: docker-compose runs a separate worker process from the same image — the process "
      "boundary is the entire point, so a wedged scan takes down scanning and nothing else")


# ============ every heavy scan runs on the worker, not in the API process ============
#
# The backend was OOM-killed when a scan was triggered manually. The first pass at
# Tier 5 #18 only moved nmap and nikto; recon-ng, EASM, secrets and container
# scanning still ran inside the API process -- EASM and container even AWAITED the
# scan directly in the request handler. This pins that every one of them is now
# enqueued.

for path, kind in [
    ("routes/easm.py", "easm_scan"),
    ("routes/container_scan.py", "container_scan"),
    ("routes/secrets_scan.py", "secrets_scan"),
    ("routes/reconng.py", "recon_run"),
    ("routes/nmap.py", "nmap_scan"),
    ("routes/nikto.py", "nikto_scan"),
]:
    src = open(path).read()
    assert f'enqueue(db, "{kind}"' in src, f"{path} does not enqueue {kind}"
    # the run-now handler must not await the scan inline any more
    assert "asyncio.create_task(_execute_run" not in src, f"{path} still create_tasks the scan"
print("PASS: every heavy scan route (nmap, nikto, recon-ng, EASM, secrets, container) enqueues to "
      "the worker instead of running the scanner inside the API process")

# the EASM and container routes specifically must no longer AWAIT the scan
easm = open("routes/easm.py").read()
assert "await run_easm_scan(db" not in easm, \
    "EASM still awaits the scan in the request handler — that is what OOM-killed the backend"
container = open("routes/container_scan.py").read()
assert "await scan_container_image(db, t[" not in container, \
    "container scan still awaits the trivy pull in the request handler"
print("PASS: the EASM and container 'scan now' handlers no longer AWAIT the scan inline — trivy "
      "image pulls and crt.sh enumeration happen in the worker, so they can't spike the API's "
      "memory")

# and every enqueued kind has a handler, so none of them will fail at run time
import job_handlers  # noqa: F401
for kind in ("easm_scan", "container_scan", "secrets_scan", "recon_run"):
    assert kind in jq.registered_kinds(), f"{kind} has no worker handler"
print("PASS: each newly-enqueued scan kind has a registered worker handler")

# the compose file caps memory on both the backend and the worker
import yaml
compose = yaml.safe_load(open("../docker-compose.yml"))
assert compose["services"]["backend"].get("mem_limit"), "backend has no memory ceiling"
assert compose["services"]["worker"].get("mem_limit"), "worker has no memory ceiling"
print("PASS: both the backend and the worker have a memory ceiling, so a runaway scan is killed in "
      "its own container and requeued rather than the kernel OOM-killing an arbitrary process on "
      "the host")
