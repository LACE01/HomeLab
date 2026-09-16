"""Cross-VM backup transfer: a download carried to another VM must not silently
truncate, and if a truncated/corrupt file is restored the error must SAY so.

The reported symptom -- a backup downloaded from one VM fails to restore on a new
one -- is the classic signature of a download cut short in transit (a large .gz
streamed with no Content-Length through a proxy). These tests lock in the fixes:
a sha256 recorded at creation, download headers that let the client verify the
byte count + hash, and a restore error that names truncation instead of a cryptic
gzip failure."""
import os, sys, asyncio, tempfile
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_backup_dl_integrity"
os.environ["JWT_SECRET"] = "testsecret"
os.environ["BACKUP_DIR"] = tempfile.mkdtemp()
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_backup_dl_integrity"]
db = db_module.db

import backup
from pathlib import Path
run = lambda c: asyncio.get_event_loop().run_until_complete(c)
def a(c, m=""): assert c, m


run(db.findings.insert_many([{"id": f"f{i}", "cve": f"CVE-{i}"} for i in range(25)]))
rec = run(backup.create_backup(db, label="xfer"))
path = Path(os.environ["BACKUP_DIR"], rec["filename"])
disk = path.read_bytes()


# ============ sha256 recorded at creation, matches the file ============

a(rec.get("sha256") and len(rec["sha256"]) == 64, "a sha256 fingerprint must be recorded")
a(rec["sha256"] == backup.sha256_bytes(disk), "the recorded sha256 must match the file on disk")
a(backup.sha256_file(path) == rec["sha256"], "streaming and byte hashing agree")
print("PASS: create_backup records a sha256 that matches the file on disk (the fingerprint that "
      "travels with the backup between VMs)")


# ============ download route serves Content-Length + sha256 headers, from disk ============

import server, auth_utils
from routes import backups as backups_route
backups_route.db = db
from fastapi.testclient import TestClient
admin = {"id": "u1", "email": "a@x.com", "role": "admin", "name": "A", "teams": []}
server.app.dependency_overrides[auth_utils.get_current_user] = lambda: admin
client = TestClient(server.app)

r = client.get(f"/api/v1/admin/backups/{rec['id']}/download")
a(r.status_code == 200, r.text)
a(r.headers.get("content-length") == str(len(disk)), "download must send an exact Content-Length")
a(r.headers.get("x-backup-sha256") == rec["sha256"], "download must send the sha256 header")
a(r.headers.get("content-type") == "application/octet-stream",
  "serve as octet-stream so no proxy re-encodes an already-gzip file")
a(backup.sha256_bytes(r.content) == rec["sha256"], "the downloaded bytes hash to the recorded value")
print("PASS: the download is served from disk with an exact Content-Length, an X-Backup-SHA256 header, "
      "and octet-stream — so a truncated transfer is detectable and nothing re-encodes the file")


# ============ a TRUNCATED download restores with a CLEAR truncation error ============

truncated = disk[: len(disk) // 2]           # simulate a cut-short download
tp = Path(os.environ["BACKUP_DIR"], ".restore-truncated.bin"); tp.write_bytes(truncated)
run(db.findings.delete_many({}))
run(db.findings.insert_many([{"id": f"live{i}"} for i in range(6)]))   # live data to protect
try:
    run(backup.restore_from_path(db, str(tp)))
    a(False, "a truncated backup should have raised")
except ValueError as e:
    msg = str(e)
    a("truncated or corrupted" in msg, f"the error must name truncation/corruption: {msg}")
    a("sha256" in msg and "bytes" in msg, "the error must include the received size + sha256 to compare")
# and the live data is untouched (stage-then-swap never got to swap)
a(run(db.findings.count_documents({})) == 6, "a truncated restore wiped live data")
print("PASS: restoring a truncated file fails with a clear 'truncated or corrupted' error that includes "
      "the received byte count + sha256 to compare against the source VM — and leaves live data intact")
tp.unlink(missing_ok=True)


# ============ the intact file still restores fine ============

full = Path(os.environ["BACKUP_DIR"], ".restore-full.bin"); full.write_bytes(disk)
run(db.findings.delete_many({}))
res = run(backup.restore_from_path(db, str(full)))
a(run(db.findings.count_documents({})) == 25, "the intact backup restored the 25 docs")
full.unlink(missing_ok=True)
print("PASS: the intact, correctly-transferred backup restores cleanly")

server.app.dependency_overrides.clear()
print("\nALL BACKUP DOWNLOAD-INTEGRITY TESTS PASSED")
