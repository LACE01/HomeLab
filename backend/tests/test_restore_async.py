"""Async restore: the upload is stashed to the shared volume, the WORKER runs the
restore, and the API polls -- so restoring a large database can't 520 through the
Cloudflare proxy or OOM the API (the mirror of the async-backup fix).

The subtle parts, all asserted here:
  * the route ENQUEUES and returns a job id instead of restoring inline
  * the worker restores from the stashed file and then DELETES it (a stashed
    upload is a full transient copy of the database -- it must not linger)
  * an encrypted restore's passphrase rides a READ-ONCE vault, never the job row
  * destructive-safety holds on the streaming path: a WRONG passphrase fails
    before a single document is deleted
  * the restore is memory-bounded (documents inserted in batches, each
    collection freed as it goes)
"""
import os, sys, asyncio, tempfile, gzip, json
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_restore_async"
os.environ["JWT_SECRET"] = "testsecret"
os.environ["BACKUP_DIR"] = tempfile.mkdtemp()
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_restore_async"]
db = db_module.db

import backup, jobqueue, job_handlers
from pathlib import Path

run = lambda c: asyncio.get_event_loop().run_until_complete(c)
def a(c, m=""): assert c, m

async def _hb(progress=None): return None


import server, auth_utils
from routes import backups as backups_route
backups_route.db = db
from fastapi.testclient import TestClient
admin = {"id": "u1", "email": "admin@x.com", "role": "admin", "name": "A", "teams": []}
server.app.dependency_overrides[auth_utils.get_current_user] = lambda: admin
client = TestClient(server.app)


# ============ make a real (plaintext) backup to restore from ============

run(db.findings.insert_many([{"id": f"f{i}", "cve": f"CVE-{i}"} for i in range(30)]))
run(db.assets.insert_many([{"id": f"a{i}"} for i in range(10)]))
plain = run(backup.create_backup(db, label="to-restore"))
plain_bytes = Path(os.environ["BACKUP_DIR"], plain["filename"]).read_bytes()


# ============ the route ENQUEUES a restore and returns a job id ============

run(db.findings.delete_many({})); run(db.assets.delete_many({}))
r = client.post("/api/v1/admin/backups/restore",
                data={"confirm": "RESTORE"},
                files={"file": ("backup.json.gz", plain_bytes, "application/gzip")})
a(r.status_code == 200, r.text)
a(r.json().get("status") == "queued" and r.json().get("job_id"),
  "restore must enqueue a job and return immediately, not restore inline")
a(run(db.findings.count_documents({})) == 0, "restore ran inline instead of enqueuing")
print("PASS: POST /v1/admin/backups/restore ENQUEUES a job and returns immediately — no inline "
      "restore that outlives the Cloudflare 100s proxy timeout")

job = run(db.jobs.find_one({"id": r.json()["job_id"]}, {"_id": 0}))
a(job["kind"] == "backup_restore")
stashed = job["payload"]["restore_file"]
a(os.path.exists(stashed), "the upload should be stashed on the shared volume for the worker")


# ============ the worker restores from the stashed file, then removes it ============

res = run(job_handlers._restore(db, job["payload"], _hb))
a(res.get("ok") is True and res["documents_restored"] == 40, res)
a(run(db.findings.count_documents({})) == 30 and run(db.assets.count_documents({})) == 10)
a("memory" in res, "the restore should report a memory snapshot")
a(not os.path.exists(stashed), "the stashed upload must be deleted after the restore, not left on disk")
print("PASS: the worker restores from the stashed upload (all 40 docs across 2 collections), reports "
      "a memory snapshot, and deletes the transient upload afterward")


# ============ memory-bounded: inserts happen in batches, collections freed as it goes ============

import inspect
src = inspect.getsource(backup.restore_from_path)
a("batch_size" in src and "collections.pop(" in src,
  "restore must batch inserts and free each collection as it goes")
a(backup.RESTORE_BATCH >= 1, "there is a real batch size")
run(db.findings.delete_many({})); run(db.assets.delete_many({}))
run(db.big.insert_many([{"id": f"b{i}"} for i in range(backup.RESTORE_BATCH * 2 + 5)]))
big = run(backup.create_backup(db, label="big"))
big_bytes = Path(os.environ["BACKUP_DIR"], big["filename"]).read_bytes()
run(db.big.delete_many({}))
tmp = Path(os.environ["BACKUP_DIR"], ".restore-unit.bin"); tmp.write_bytes(big_bytes)
rr = run(backup.restore_from_path(db, str(tmp), batch_size=backup.RESTORE_BATCH))
a(rr["detail"]["big"] == backup.RESTORE_BATCH * 2 + 5)
a(run(db.big.count_documents({})) == backup.RESTORE_BATCH * 2 + 5)
tmp.unlink(missing_ok=True)
print(f"PASS: a collection larger than one batch ({backup.RESTORE_BATCH}) restores fully in batches — "
      "the whole database is never inserted in a single call")


# ============ encrypted restore: passphrase via read-once vault, never the job row ============

run(db.findings.delete_many({}))
run(db.findings.insert_many([{"id": f"f{i}"} for i in range(12)]))
enc = run(backup.create_backup(db, label="enc", encrypt=True))
enc_pw = enc["passphrase"]
enc_bytes = Path(os.environ["BACKUP_DIR"], enc["filename"]).read_bytes()

run(db.findings.delete_many({}))
r2 = client.post("/api/v1/admin/backups/restore",
                 data={"confirm": "RESTORE", "passphrase": enc_pw},
                 files={"file": ("b.enc", enc_bytes, "application/octet-stream")})
a(r2.status_code == 200 and r2.json()["job_id"])
job2 = run(db.jobs.find_one({"id": r2.json()["job_id"]}, {"_id": 0}))
a(enc_pw not in json.dumps(job2["payload"]),
  "the restore passphrase VALUE leaked into the persisted job payload")
a("passphrase" not in job2["payload"], "no literal 'passphrase' key on the job payload")
a(job2["payload"]["has_passphrase"] is True)
print("PASS: an encrypted restore stores only a has_passphrase flag + a vault id on the job — the "
      "passphrase value is never persisted on the job row")

res2 = run(job_handlers._restore(db, job2["payload"], _hb))
a(res2.get("ok") is True and res2["documents_restored"] >= 12, res2)  # snapshot carried other collections too
a(run(db.findings.count_documents({})) == 12)
a(run(db.backup_secrets.count_documents({"backup_id": job2["payload"]["restore_id"]})) == 0)
print("PASS: the worker claims the passphrase once from the vault, restores the encrypted backup, and "
      "the vault entry is gone afterward")


# ============ destructive-safety: a WRONG passphrase deletes nothing ============

run(db.findings.delete_many({}))
run(db.findings.insert_many([{"id": f"live{i}"} for i in range(7)]))
wrong_id = "wrong-restore"
wp = Path(os.environ["BACKUP_DIR"], f".restore-{wrong_id}.bin"); wp.write_bytes(enc_bytes)
run(backup.stash_passphrase(db, wrong_id, "not-the-passphrase"))
res3 = run(job_handlers._restore(db, {"restore_file": str(wp), "restore_id": wrong_id,
                                      "has_passphrase": True}, _hb))
a(res3.get("ok") is False and "passphrase" in res3.get("error", "").lower(),
  f"a wrong passphrase should be a clean terminal error: {res3}")
a(run(db.findings.count_documents({})) == 7,
  "a wrong-passphrase restore deleted live data — decrypt must fail BEFORE the destructive wipe")
a(not os.path.exists(str(wp)), "the stashed upload is cleaned up even on failure")
print("PASS: a restore with the WRONG passphrase fails as a terminal error and deletes NOTHING — the "
      "streaming path preserves the decrypt-before-wipe guarantee, and the stashed upload is cleaned "
      "up even on failure")

# ============ stage-then-swap: a mid-restore failure leaves live data intact ============

run(db.findings.delete_many({}))
run(db.findings.insert_many([{"id": f"keep{i}"} for i in range(9)]))
# hand restore a corrupt archive -> it must fail WITHOUT wiping the 9 live docs
bad = Path(os.environ["BACKUP_DIR"], ".restore-corrupt.bin")
bad.write_bytes(b"this is not a gzip archive at all")
try:
    run(backup.restore_from_path(db, str(bad)))
    a(False, "a corrupt archive should have raised")
except ValueError as e:
    a("valid VulnOps backup" in str(e) or "staging failed" in str(e))
a(run(db.findings.count_documents({})) == 9,
  "a corrupt restore wiped live data — staging must fail before any swap")
# no orphan stage collections left behind
names = run(db.list_collection_names())
a(not any(n.startswith(backup.STAGE_PREFIX) for n in names),
  "a failed restore left temporary stage collections behind")
bad.unlink(missing_ok=True)
print("PASS: a corrupt/failed restore leaves the live database exactly as it was and cleans up its "
      "temp collections — the destructive swap only runs after the whole archive stages successfully")

# and a SUCCESSFUL restore reports it staged-then-swapped
run(db.findings.delete_many({}))
ok_res = run(backup.restore_from_path(db, str(Path(os.environ["BACKUP_DIR"], plain["filename"]))))
a(ok_res.get("staged_then_swapped") is True and ok_res["swapped_collections"] >= 1)
print("PASS: a successful restore stages every collection then atomically swaps them into place")

server.app.dependency_overrides.clear()
print("\nALL ASYNC RESTORE TESTS PASSED")
