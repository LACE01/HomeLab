import os, sys, asyncio, shutil, tempfile, gzip
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_backups_offsite_and_verify"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

# Backups write to disk -- point BACKUP_DIR at a throwaway temp dir for this test
# run so it never touches a real /app/backups volume, and gets cleaned up after.
_tmp_backup_dir = tempfile.mkdtemp(prefix="nightwatch-test-backups-")
os.environ["BACKUP_DIR"] = _tmp_backup_dir

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_backups_offsite_and_verify"]

import server
import auth_utils
from routes import backups as backups_route
backups_route.db = db_module.db

from fastapi.testclient import TestClient

admin_user = {"id": "u1", "email": "admin@x.com", "role": "admin", "name": "Admin", "teams": []}
app = server.app
app.dependency_overrides[auth_utils.get_current_user] = lambda: admin_user
client = TestClient(app)

db = db_module.db


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


import importlib
import backup as backup_module
importlib.reload(backup_module)
backup_module.BACKUP_DIR.mkdir(parents=True, exist_ok=True)

# ============ verify_backup() -- pure unit tests, no filesystem needed ============

good_payload = backup_module.json_util.dumps({
    "created_at": "x", "collections": {"findings": [{"id": "f1"}, {"id": "f2"}], "assets": [{"id": "a1"}]},
}).encode("utf-8")
good_gz = gzip.compress(good_payload)

v1 = backup_module.verify_backup(good_gz)
assert v1["valid"] is True and v1["collections"] == 2 and v1["documents"] == 3
print("PASS: verify_backup() parses a well-formed archive and counts collections/documents correctly")

v2 = backup_module.verify_backup(good_gz, expected_collections=2, expected_documents=3)
assert v2["valid"] is True
print("PASS: verify_backup() passes when counts match what was expected (the actual dump counts)")

v3 = backup_module.verify_backup(good_gz, expected_collections=99)
assert v3["valid"] is False and "Collection count mismatch" in v3["error"]
print("PASS: verify_backup() fails on a collection-count mismatch")

v4 = backup_module.verify_backup(good_gz, expected_documents=99)
assert v4["valid"] is False and "Document count mismatch" in v4["error"]
print("PASS: verify_backup() fails on a document-count mismatch")

v5 = backup_module.verify_backup(b"not even gzip data")
assert v5["valid"] is False and "corrupt or unreadable" in v5["error"]
print("PASS: verify_backup() detects a corrupt/truncated archive instead of raising")

malformed = gzip.compress(backup_module.json_util.dumps({"created_at": "x"}).encode("utf-8"))
v6 = backup_module.verify_backup(malformed)
assert v6["valid"] is False and "collections" in v6["error"]
print("PASS: verify_backup() detects a missing 'collections' key")

# ============ offsite_configured() / offsite_status() ============

os.environ.pop("BACKUP_S3_BUCKET", None)
assert backup_module.offsite_configured() is False
status = backup_module.offsite_status()
assert status["configured"] is False
print("PASS: off-site storage reports unconfigured when BACKUP_S3_BUCKET isn't set")

# ============ create_backup() -- end to end, off-site NOT configured ============

run(db.findings.insert_many([{"id": "f1", "severity": "Critical"}, {"id": "f2", "severity": "High"}]))
run(db.assets.insert_one({"id": "a1", "hostname": "srv-1"}))

record = run(backup_module.create_backup(db, label="test"))
assert record["verified"] is True and record["verification_error"] is None
assert record["offsite_attempted"] is False and record["offsite_ok"] is False
print("PASS: create_backup() runs verification automatically and skips off-site upload when unconfigured")

on_disk = backup_module._safe_path(record["filename"])
assert on_disk.exists()
print("PASS: create_backup() writes the archive to BACKUP_DIR")

# ============ off-site upload -- fake S3 client, no real network/creds ============

class FakeS3Client:
    puts = []
    should_fail = False

    def put_object(self, Bucket, Key, Body):
        if FakeS3Client.should_fail:
            raise RuntimeError("simulated network failure")
        FakeS3Client.puts.append({"Bucket": Bucket, "Key": Key, "Body": Body})


backup_module._s3_client = lambda: FakeS3Client()
os.environ["BACKUP_S3_BUCKET"] = "my-nightwatch-backups"
os.environ["BACKUP_S3_PREFIX"] = "homelab"

assert backup_module.offsite_configured() is True
print("PASS: offsite_configured() reflects BACKUP_S3_BUCKET being set")

result = backup_module.upload_offsite("test-file.json.gz", b"fake-content")
assert result["ok"] is True and result["bucket"] == "my-nightwatch-backups" and result["key"] == "homelab/test-file.json.gz"
assert len(FakeS3Client.puts) == 1 and FakeS3Client.puts[0]["Body"] == b"fake-content"
print("PASS: upload_offsite() uploads to the configured bucket with the configured key prefix")

record2 = run(backup_module.create_backup(db, label="test-with-offsite"))
assert record2["offsite_attempted"] is True and record2["offsite_ok"] is True
assert record2["offsite_key"] == f"homelab/{record2['filename']}"
assert record2["verified"] is True
print("PASS: create_backup() uploads off-site automatically and records both verification AND off-site status")

# --- off-site failure must not affect the local backup's success ---
FakeS3Client.should_fail = True
record3 = run(backup_module.create_backup(db, label="test-offsite-fails"))
assert record3["verified"] is True  # local backup + verification unaffected
assert record3["offsite_attempted"] is True and record3["offsite_ok"] is False
assert "simulated network failure" in record3["offsite_error"]
on_disk3 = backup_module._safe_path(record3["filename"])
assert on_disk3.exists()
print("PASS: an off-site upload failure never blocks or invalidates the local backup itself")
FakeS3Client.should_fail = False

# ============ verify_backup_by_id / upload_offsite_by_id ============

verify_result = run(backup_module.verify_backup_by_id(db, record["id"]))
assert verify_result["valid"] is True
refreshed = run(db.backup_history.find_one({"id": record["id"]}, {"_id": 0}))
assert refreshed["verified"] is True
print("PASS: verify_backup_by_id() re-verifies an existing backup from disk and updates its record")

upload_result = run(backup_module.upload_offsite_by_id(db, record["id"]))
assert upload_result["ok"] is True
refreshed2 = run(db.backup_history.find_one({"id": record["id"]}, {"_id": 0}))
assert refreshed2["offsite_ok"] is True and refreshed2["offsite_key"] == f"homelab/{record['filename']}"
print("PASS: upload_offsite_by_id() retroactively uploads an already-created backup and updates its record")

try:
    run(backup_module.verify_backup_by_id(db, "not-a-real-id"))
    assert False
except ValueError as e:
    assert "not found" in str(e).lower()
print("PASS: verify_backup_by_id() raises a clear error for an unknown backup id")

# ============ routes ============

# reset to unconfigured for the route-level "not configured" checks, then
# re-configure with the fake client for the rest
os.environ.pop("BACKUP_S3_BUCKET", None)
r = client.get("/api/v1/admin/backups/offsite-status")
assert r.status_code == 200 and r.json()["configured"] is False
print("PASS: GET /v1/admin/backups/offsite-status reports unconfigured")

r2 = client.post("/api/v1/admin/backups", json={"label": "via-route"})
assert r2.status_code == 200, r2.text
new_id = r2.json()["id"]
assert r2.json()["verified"] is True
print("PASS: POST /v1/admin/backups creates a backup and the response includes verification status")

r3 = client.get("/api/v1/admin/backups")
assert r3.status_code == 200
items = r3.json()["items"]
assert any(i["id"] == new_id and "verified" in i and "offsite_ok" in i for i in items)
print("PASS: GET /v1/admin/backups exposes verified/offsite fields on every listed backup")

r4 = client.post(f"/api/v1/admin/backups/{new_id}/verify")
assert r4.status_code == 200 and r4.json()["valid"] is True
print("PASS: POST /v1/admin/backups/{id}/verify re-verifies via the route")

r5 = client.post(f"/api/v1/admin/backups/{new_id}/upload-offsite")
assert r5.status_code == 400
print("PASS: POST /v1/admin/backups/{id}/upload-offsite returns 400 when off-site isn't configured")

os.environ["BACKUP_S3_BUCKET"] = "my-nightwatch-backups"
r6 = client.post(f"/api/v1/admin/backups/{new_id}/upload-offsite")
assert r6.status_code == 200 and r6.json()["ok"] is True
print("PASS: POST /v1/admin/backups/{id}/upload-offsite succeeds once off-site is configured")

r7 = client.get("/api/v1/admin/backups/offsite-status")
assert r7.json()["configured"] is True and r7.json()["bucket"] == "my-nightwatch-backups"
print("PASS: GET /v1/admin/backups/offsite-status reflects the now-configured bucket")

r8 = client.post("/api/v1/admin/backups/not-a-real-id/verify")
assert r8.status_code == 404
r9 = client.post("/api/v1/admin/backups/not-a-real-id/upload-offsite")
assert r9.status_code == 404
print("PASS: verify/upload-offsite routes 404 cleanly for an unknown backup id")

# --- cleanup ---
os.environ.pop("BACKUP_S3_BUCKET", None)
os.environ.pop("BACKUP_S3_PREFIX", None)
shutil.rmtree(_tmp_backup_dir, ignore_errors=True)

print("\nALL OFF-SITE BACKUP + RESTORE VERIFICATION TESTS PASSED")
