"""Can the platform tell you when it isn't working?

Written against a real outage: the backend was up, the port was open, docker said
Up (unhealthy), and it was answering nothing. The log went quiet, which reads like
"no traffic" rather than "nothing is being served". Every check here exists
because that state was invisible.
"""
import os, sys, asyncio
from datetime import datetime, timezone, timedelta
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_platform_health"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_platform_health"]
db = db_module.db

import platform_health as ph
import jobqueue as jq

run = lambda c: asyncio.get_event_loop().run_until_complete(c)
now = datetime.now(timezone.utc)


def reset():
    for c in ("connector_state", "loop_heartbeats", "jobs", "findings"):
        run(db[c].delete_many({}))


# ============ circuit breakers ============

reset()
for i in range(1, ph.BREAKER_THRESHOLD):
    r = run(ph.record_failure(db, "Qualys VMDR", "connection refused"))
    assert r["degraded"] is False, f"tripped early at {i}"
assert run(ph.should_run(db, "Qualys VMDR"))["run"] is True
print(f"PASS: a connector is retried normally for the first {ph.BREAKER_THRESHOLD - 1} failures — "
      "transient errors must not trip the breaker")

r = run(ph.record_failure(db, "Qualys VMDR", "connection refused"))
assert r["degraded"] is True
verdict = run(ph.should_run(db, "Qualys VMDR"))
assert verdict["run"] is False
assert "Circuit breaker open" in verdict["reason"]
assert "connection refused" in verdict["reason"], "the reason must carry the ACTUAL error"
assert verdict["retry_in_seconds"] > 0
print("PASS: after 5 consecutive failures the breaker opens and stops retrying every cycle, and "
      "the reason carries the actual error text — 'it failed' sends you to the logs, 'it failed 5 "
      "times with connection refused' is the answer")

# after the cooldown it retries once, to notice recovery
run(db.connector_state.update_one({"integration": "Qualys VMDR"}, {"$set": {
    "last_failure_at": (now - timedelta(hours=2)).isoformat()}}))
verdict = run(ph.should_run(db, "Qualys VMDR"))
assert verdict["run"] is True and "cooldown elapsed" in verdict["reason"]
print("PASS: a degraded connector is retried once per cooldown — often enough to notice recovery, "
      "rarely enough that a broken integration stops drowning the log")

run(ph.record_success(db, "Qualys VMDR"))
state = run(db.connector_state.find_one({"integration": "Qualys VMDR"}, {"_id": 0}))
assert state["state"] == "ok" and state["consecutive_failures"] == 0
print("PASS: a success clears the failure count and closes the breaker")


# ============ the check that would have caught the outage ============

reset()
from heartbeat import KNOWN_LOOPS
# Every loop reported recently -> healthy
for name in KNOWN_LOOPS:
    run(db.loop_heartbeats.insert_one({
        "name": name, "status": "ok", "last_run_at": now.isoformat()}))
c = run(ph._check_loops(db))
assert c["status"] == "ok"

# Now the event loop blocks: the fast loops stop reporting.
run(db.loop_heartbeats.update_one({"name": "splunk_sync_loop"}, {"$set": {
    "last_run_at": (now - timedelta(hours=6)).isoformat()}}))
c = run(ph._check_loops(db))
assert c["status"] == "failed"
assert c["detail"]["dead"][0]["loop"] == "splunk_sync_loop"
assert "EVENT LOOP BLOCKED" in c["action"]
print("PASS: a loop that stops reporting is detected against its OWN expected interval, and the "
      "remediation points at the log line that names the cause — this is the check that would "
      "have identified the outage in round one instead of round four")

# a loop that never started at all must not look identical to a healthy one
run(db.loop_heartbeats.delete_many({}))
run(db.loop_heartbeats.insert_one({"name": "nightly_loop", "status": "ok",
                                    "last_run_at": now.isoformat()}))
c = run(ph._check_loops(db))
assert c["status"] == "degraded" and c["detail"]["never_ran"]
print("PASS: registered loops that have NEVER run are reported — iterating only the rows that "
      "exist would make a loop that crashed on startup indistinguishable from a healthy one")


# ============ a queue with no worker ============

reset()
@jq.handler("t")
async def _t(d, p, hb):
    return {}

run(jq.enqueue(db, "t", {"n": 1}))
run(db.jobs.update_many({}, {"$set": {
    "enqueued_at": (now - timedelta(hours=2)).isoformat()}}))
c = run(ph._check_queue(db))
assert c["status"] == "failed"
assert "nothing running" in c["summary"]
assert "docker compose ps worker" in c["action"]
print("PASS: jobs queued for two hours with nothing running is reported as a FAILURE naming the "
      "worker container — the silent failure mode of a queue is that it just fills up")


# ============ everything up, nothing arriving ============

reset()
run(db.findings.insert_one({"id": "f1", "last_seen_at": (now - timedelta(days=12)).isoformat()}))
c = run(ph._check_data_freshness(db))
assert c["status"] == "failed"
assert "12 days" in c["summary"]
assert "look healthy while nothing is being ingested" in c["action"]
print("PASS: 'no data in 12 days' is a failure even though nothing errored — every component can "
      "be up while the product is quietly useless, and errors are easy to notice while silence "
      "is not")

run(db.findings.update_one({"id": "f1"}, {"$set": {"last_seen_at": now.isoformat()}}))
assert run(ph._check_data_freshness(db))["status"] == "ok"


# ============ unknown is a problem, not a pass ============

reset()
snap = run(ph.snapshot(db))
statuses = {c["name"]: c["status"] for c in snap["checks"]}
assert statuses["Connectors"] == "unknown"
assert snap["status"] != "ok", "an all-unknown platform must not report healthy"
assert "not the same as 'this is fine'" in snap["note"]
print("PASS: a check that cannot determine its answer counts against overall health — treating "
      "unknown as fine is how a dead feed goes unnoticed for a month")


# ============ the platform's failures become findings ============

reset()
run(db.findings.insert_one({"id": "old", "last_seen_at": (now - timedelta(days=30)).isoformat()}))
result = run(ph.run_self_check(db))
assert result["findings_created"] >= 1
f = run(db.findings.find_one({"canonical_key": "platform:self-check:data-freshness"}, {"_id": 0}))
assert f is not None
assert f["self_check"] is True
assert f["source_tool"] == "Nightwatch self-check"
assert f["severity"] == "High" and f["status"] == "New"
assert f["remediation"]
print("PASS: a platform failure is raised as a FINDING in the same table with the same lifecycle — "
      "so it lands in the queue people already read, not on a status page nobody opens")

# running twice must not duplicate
before = run(db.findings.count_documents({"self_check": True}))
run(ph.run_self_check(db))
assert run(db.findings.count_documents({"self_check": True})) == before
print("PASS: re-running updates the existing self-check finding rather than creating a new one "
      "every hour")

# and it auto-closes when the condition clears
run(db.findings.update_one({"id": "old"}, {"$set": {"last_seen_at": now.isoformat()}}))
result = run(ph.run_self_check(db))
f = run(db.findings.find_one({"canonical_key": "platform:self-check:data-freshness"}, {"_id": 0}))
assert f["status"] == "Fixed validated"
assert "auto-closed" in f["verification_note"]
print("PASS: a self-check finding auto-closes when the check passes again — a platform that raises "
      "its own problems and never clears them trains people to ignore them")


# ============ routes ============

import server, auth_utils
from routes import platform_health as phr
phr.db = db
from fastapi.testclient import TestClient

admin = {"id": "u1", "email": "a@x.com", "role": "admin", "name": "A", "teams": []}
server.app.dependency_overrides[auth_utils.get_current_user] = lambda: admin
client = TestClient(server.app)

run(ph.record_failure(db, "Broken Connector", "TLS handshake failed"))
for _ in range(5):
    run(ph.record_failure(db, "Broken Connector", "TLS handshake failed"))

r = client.get("/api/v1/health/platform")
assert r.status_code == 200
assert r.json()["status"] in ("degraded", "failed")
assert r.json()["summary"]
print("PASS: GET /v1/health/platform returns one status for the whole platform with a summary "
      "naming what is wrong")

r = client.get("/api/v1/health/connectors")
items = r.json()["items"]
assert items[0]["integration"] == "Broken Connector", "degraded connectors must sort first"
assert items[0]["last_error"] == "TLS handshake failed"
print("PASS: the connector list leads with the degraded ones and shows each one's real last error")

r = client.post("/api/v1/health/connectors/Broken Connector/reset")
assert r.status_code == 200
assert run(ph.should_run(db, "Broken Connector"))["run"] is True
print("PASS: a breaker can be reset once the cause is fixed — deliberately manual, since "
      "auto-closing would let a permanently broken integration cycle forever, looking busy while "
      "never working")

r = client.post("/api/v1/health/self-check")
assert r.status_code == 200 and "findings_created" in r.json()
