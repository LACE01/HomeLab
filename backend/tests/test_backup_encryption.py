"""Encrypted backups: a strong passphrase shown once, never stored.

The security property is exact: a backup file stolen from the volume or from
off-site storage is useless without a passphrase that exists only wherever the
operator pasted it. The corollary is equally exact and must be enforced: lose the
passphrase and the backup is unrecoverable, because a recoverable passphrase is
not encryption.
"""
import os, sys, asyncio, json, gzip
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_backup_encryption"
os.environ["JWT_SECRET"] = "testsecret"
import tempfile
os.environ["BACKUP_DIR"] = tempfile.mkdtemp()
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_backup_encryption"]
db = db_module.db

import backup

run = lambda c: asyncio.get_event_loop().run_until_complete(c)


def a(c, m=""): assert c, m


# ============ the crypto primitives ============

pw = backup.generate_passphrase()
a(len(pw) >= 30, "the passphrase must be strong")
a(pw != backup.generate_passphrase(), "each passphrase is unique")
print(f"PASS: generate_passphrase produces a strong, unique one-time passphrase (e.g. {pw[:14]}…)")

payload = gzip.compress(b'{"created_at":"x","collections":{}}' * 500)
env = backup.encrypt_payload(payload, pw)

a(backup.is_encrypted(env) is True)
a(backup.is_encrypted(payload) is False)
a(backup.is_encrypted(b"\\x1f\\x8b\\x08plain") is False)
print("PASS: an encrypted envelope is recognizable, and a plain gzip backup is not mistaken for one")

# the passphrase must not appear anywhere in the file
a(pw.encode() not in env, "the passphrase leaked into the encrypted file")
a(b"collections" not in env, "plaintext leaked past encryption")
print("PASS: the passphrase does not appear in the encrypted file, and the plaintext is not "
      "readable in it")

a(backup.decrypt_payload(env, pw) == payload)
print("PASS: the right passphrase recovers the exact payload")

for wrong in (pw + "x", pw[:-1], "", "totally-wrong"):
    try:
        backup.decrypt_payload(env, wrong)
        raise AssertionError(f"a wrong passphrase {wrong!r} was accepted")
    except ValueError:
        pass
print("PASS: a wrong or empty passphrase is rejected — Fernet authenticates, so a bad key can't "
      "return garbage that a restore would then load")

# tampering is detected (authenticated encryption)
tampered = json.loads(env.decode())
import base64
ct = bytearray(base64.b64decode(tampered["ciphertext"]))
ct[-1] ^= 0x01
tampered["ciphertext"] = base64.b64encode(bytes(ct)).decode()
try:
    backup.decrypt_payload(json.dumps(tampered).encode(), pw)
    raise AssertionError("tampered ciphertext was accepted")
except ValueError as e:
    a("tampered" in str(e) or "Wrong passphrase" in str(e))
print("PASS: a tampered ciphertext is rejected even with the right passphrase — the file is "
      "authenticated, not just scrambled")


# ============ create_backup: encrypted, passphrase shown ONCE ============

run(db.findings.insert_many([{"id": f"f{i}", "cve": f"CVE-{i}"} for i in range(20)]))

rec = run(backup.create_backup(db, label="encrypted test", encrypt=True))
a(rec["encrypted"] is True)
a(rec["filename"].endswith(".json.gz.enc"))
a(rec["verified"] is True, "the plaintext is verified before encryption, so verified stays honest")
a(rec["documents"] == 20)
# the passphrase is in THIS response...
a(rec.get("passphrase"), "the create response must carry the one-time passphrase")
a("shown once" in rec["passphrase_notice"])
created_pw = rec["passphrase"]
print("PASS: an encrypted backup verifies its real doc count (checked before encryption) and "
      "returns the passphrase ONCE in the create response, with a notice that it's shown once")

# ...but NOT in the stored record
stored = run(db.backup_history.find_one({"id": rec["id"]}, {"_id": 0}))
a("passphrase" not in stored, "the passphrase was stored — it must never be")
a(stored["encrypted"] is True)
print("PASS: the passphrase is NOT written to the backup record — it exists only in the one create "
      "response, then nowhere on the server")

# and NOT in the file on disk
from pathlib import Path
disk = Path(os.environ["BACKUP_DIR"], rec["filename"]).read_bytes()
a(created_pw.encode() not in disk)
a(backup.is_encrypted(disk))
print("PASS: the passphrase is not in the file on disk, and the file on disk is the encrypted "
      "envelope (so off-site copies are encrypted at rest too)")


# ============ restore: wrong passphrase fails BEFORE anything is deleted ============

# Put DIFFERENT data in the live DB, then attempt a restore with a wrong passphrase.
run(db.findings.delete_many({}))
run(db.findings.insert_many([{"id": f"live{i}"} for i in range(7)]))
live_before = run(db.findings.count_documents({}))
a(live_before == 7)

try:
    run(backup.restore_backup(db, disk, passphrase="wrong-passphrase"))
    raise AssertionError("restore proceeded with a wrong passphrase")
except ValueError as e:
    a("Wrong passphrase" in str(e))
# THE critical assertion: the destructive restore must not have touched live data
a(run(db.findings.count_documents({})) == 7,
  "a failed decrypt deleted live data — decryption must happen BEFORE the destructive wipe")
print("PASS: a restore with the WRONG passphrase fails before anything is deleted — the "
      "destructive wipe only runs after the file has decrypted and parsed, so a bad passphrase "
      "can't leave you with neither the old data nor the restore")

# a missing passphrase on an encrypted file is a clean error, not a gzip crash
try:
    run(backup.restore_backup(db, disk, passphrase=None))
    raise AssertionError("restore proceeded with no passphrase")
except ValueError as e:
    a("encrypted" in str(e) and "passphrase is required" in str(e))
a(run(db.findings.count_documents({})) == 7)
print("PASS: restoring an encrypted backup with NO passphrase gives a clear 'passphrase required' "
      "error, not a confusing gzip failure, and still doesn't delete anything")


# ============ restore: the correct passphrase works end to end ============

res = run(backup.restore_backup(db, disk, passphrase=created_pw))
a(res["documents_restored"] == 20)
a(run(db.findings.count_documents({})) == 20, "the encrypted backup restored the original 20 docs")
print("PASS: the correct passphrase restores the encrypted backup end to end")


# ============ unencrypted backups still work unchanged ============

run(db.findings.delete_many({}))
run(db.findings.insert_many([{"id": f"p{i}"} for i in range(5)]))
plain = run(backup.create_backup(db, label="plain"))
a(plain["encrypted"] is False and plain["filename"].endswith(".json.gz"))
a("passphrase" not in plain, "an unencrypted backup must not carry a passphrase")
plain_disk = Path(os.environ["BACKUP_DIR"], plain["filename"]).read_bytes()
run(db.findings.delete_many({}))
run(backup.restore_backup(db, plain_disk))   # no passphrase needed
a(run(db.findings.count_documents({})) == 5)
print("PASS: unencrypted backups are unchanged — created without a passphrase and restored without "
      "one, so existing backups and workflows keep working")
