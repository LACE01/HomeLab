"""Async backups: run in the worker, poll for the result, so a large database
can't 520 through the Cloudflare proxy.

The subtle part is the encrypted-backup passphrase across the async boundary. A
synchronous backup returns it in the HTTP response and never stores it. An async
one can't -- the worker finished before the poll arrives -- so it goes into a
READ-ONCE vault: available exactly once, then gone. It must NEVER end up in the
persisted job result.
"""
import os, sys, asyncio, tempfile
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_backup_async"
os.environ["JWT_SECRET"] = "testsecret"
os.environ["BACKUP_DIR"] = tempfile.mkdtemp()
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_backup_async"]
db = db_module.db

import backup, jobqueue, job_handlers

run = lambda c: asyncio.get_event_loop().run_until_complete(c)


def a(c, m=""): assert c, m


run(db.findings.insert_many([{"id": f"f{i}", "cve": f"CVE-{i}"} for i in range(15)]))


# ============ the route enqueues instead of running inline ============

import server, auth_utils
from routes import backups as backups_route
backups_route.db = db
from fastapi.testclient import TestClient

admin = {"id": "u1", "email": "admin@x.com", "role": "admin", "name": "A", "teams": []}
server.app.dependency_overrides[auth_utils.get_current_user] = lambda: admin
client = TestClient(server.app)

r = client.post("/api/v1/admin/backups", json={"encrypt": False})
a(r.status_code == 200, r.text)
a(r.json()["status"] == "queued" and r.json()["job_id"],
  "the backup must return a job id immediately, not run inline")
print("PASS: POST /v1/admin/backups ENQUEUES and returns a job id immediately — no inline dump that "
      "outlives the Cloudflare 100s proxy timeout")

job_id = r.json()["job_id"]
job = run(db.jobs.find_one({"id": job_id}, {"_id": 0}))
a(job["kind"] == "backup_create")

# run the worker handler (what the worker container does)
async def _hb(progress=None):
    return None
rec = run(job_handlers._backup(db, job["payload"], _hb))
a(rec["documents"] >= 15 and rec["verified"] is True)  # >= because the jobs collection is counted too
a("memory" in rec, "the result should report a memory snapshot for the origin-memory check")
print("PASS: the worker handler performs the real backup and reports a memory snapshot of the "
      "origin — so 'does the box have room' is answerable")


# ============ encrypted async backup: passphrase in a READ-ONCE vault, never the job ============

r = client.post("/api/v1/admin/backups", json={"encrypt": True})
enc_job_id = r.json()["job_id"]
enc_job = run(db.jobs.find_one({"id": enc_job_id}, {"_id": 0}))
enc_rec = run(job_handlers._backup(db, enc_job["payload"], _hb))

a(enc_rec.get("encrypted") is True)
a(enc_rec.get("passphrase_available") is True)
a("passphrase" not in enc_rec, "the passphrase must NOT be in the job result -- it gets persisted")
a("passphrase_notice" not in enc_rec)
print("PASS: an encrypted async backup returns passphrase_available=true but NOT the passphrase — "
      "the job result is persisted, and the passphrase must never be")

# simulate the worker storing the result on the job (jobqueue.complete)
run(jobqueue.complete(db, enc_job_id, enc_rec))
stored_job = run(db.jobs.find_one({"id": enc_job_id}, {"_id": 0}))
# the only passphrase-ish key allowed is the boolean flag, never the value
a("passphrase" not in (stored_job.get("result") or {}),
  "a literal 'passphrase' key is in the persisted job result")
a((stored_job.get("result") or {}).get("passphrase_available") is True)

# the read-once endpoint returns it ONCE
p1 = client.get(f"/api/v1/admin/backups/{enc_rec['id']}/passphrase").json()
a(p1["available"] is True and p1["passphrase"])
captured = p1["passphrase"]
# and now prove the actual VALUE was never in the persisted job row
import json as _json
a(captured not in _json.dumps(stored_job.get("result") or {}),
  "the passphrase VALUE leaked into the persisted job row")
print("PASS: the persisted job row contains only a passphrase_available flag, never the passphrase "
      "value itself")
print("PASS: GET /v1/admin/backups/{id}/passphrase returns the passphrase once")

# ...and it's gone after that
p2 = client.get(f"/api/v1/admin/backups/{enc_rec['id']}/passphrase").json()
a(p2["available"] is False and "shown exactly once" in p2["message"])
a(run(db.backup_secrets.count_documents({"backup_id": enc_rec["id"]})) == 0)
print("PASS: a second fetch returns nothing and the vault entry is deleted — read-once, then gone "
      "from the server")


# ============ the async encrypted backup actually restores with that passphrase ============

from pathlib import Path
disk = Path(os.environ["BACKUP_DIR"], enc_rec["filename"]).read_bytes()
a(backup.is_encrypted(disk))
run(db.findings.delete_many({}))
res = run(backup.restore_backup(db, disk, passphrase=captured))
a(res["documents_restored"] >= 15)  # snapshot also carried jobs/history rows
a(run(db.findings.count_documents({})) == 15)
print("PASS: the encrypted backup produced by the async job restores end-to-end with the "
      "read-once passphrase — the whole flow is sound, not just the plumbing")


# ============ a second in-flight backup dedupes rather than stacking ============

r1 = client.post("/api/v1/admin/backups", json={"encrypt": False})
r2 = client.post("/api/v1/admin/backups", json={"encrypt": False})
# same payload, still queued -> deduped
a(r2.json().get("deduped") is True and r2.json()["job_id"] == r1.json()["job_id"])
print("PASS: clicking Backup twice while one is queued dedupes to the same job rather than running "
      "two full-database dumps at once")


# ============ the run-on-host CLI exists ============

import subprocess
out = subprocess.run([sys.executable, "backup.py", "--help"], capture_output=True, text=True, cwd=".")
a(out.returncode == 0 and "--encrypt" in out.stdout and "no HTTP" in out.stdout)
print("PASS: `python backup.py` runs a backup directly on the host, bypassing HTTP entirely — the "
      "interim unblock for the Cloudflare timeout, immune to the proxy")

server.app.dependency_overrides.clear()
