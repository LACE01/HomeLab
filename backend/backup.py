"""Database backup/restore -- pure pymongo/bson, no mongodump/mongorestore binary
needed (recent official Mongo images don't reliably ship the database-tools package,
and this avoids adding it to either container). Dumps every collection to a single
gzip-compressed JSON file using bson.json_util, which round-trips Mongo-native types
(dates, etc.) correctly, then writes to a mounted volume so backups survive the
backend container being recreated -- the container filesystem itself is ephemeral.

Also supports an optional off-site destination (any S3-compatible object store --
AWS S3, MinIO, Backblaze B2, Wasabi, etc., configured entirely via env vars) and a
non-destructive restore-verification pass that runs automatically after every
backup. See upload_offsite()/verify_backup() below for what each actually checks
and why a full restore-drill against a second live database isn't in scope for a
single self-hosted deployment.
"""
import gzip
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from bson import json_util

logger = logging.getLogger("vulnops")

BACKUP_DIR = Path(os.environ.get("BACKUP_DIR", "/app/backups"))
DEFAULT_RETENTION = 14  # keep the last N backups when pruning


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_path(filename: str) -> Path:
    """Rejects path traversal -- filename must resolve to a plain file directly
    inside BACKUP_DIR, nothing above or beside it."""
    candidate = (BACKUP_DIR / filename).resolve()
    base = BACKUP_DIR.resolve()
    if candidate != base and base not in candidate.parents:
        raise ValueError("Invalid backup filename")
    return candidate


# --- Off-site destination (S3-compatible: AWS S3, MinIO, Backblaze B2, Wasabi,
# etc.) -- configured entirely via env vars so a fresh install with none of these
# set just keeps writing local-only backups, same "quietly no-op until
# configured" convention as BACKUP_SCHEDULE_ENABLED and every optional connector
# in this app. Off-site upload is opt-in, never required to use local backups. ---

def offsite_configured() -> bool:
    return bool(os.environ.get("BACKUP_S3_BUCKET"))


def offsite_status() -> dict:
    return {
        "configured": offsite_configured(),
        "bucket": os.environ.get("BACKUP_S3_BUCKET"),
        "endpoint_url": os.environ.get("BACKUP_S3_ENDPOINT_URL") or None,
        "prefix": os.environ.get("BACKUP_S3_PREFIX", "nightwatch-backups"),
    }


def _s3_client():
    import boto3
    kwargs = {}
    if os.environ.get("BACKUP_S3_ENDPOINT_URL"):
        kwargs["endpoint_url"] = os.environ["BACKUP_S3_ENDPOINT_URL"]
    if os.environ.get("BACKUP_S3_REGION"):
        kwargs["region_name"] = os.environ["BACKUP_S3_REGION"]
    if os.environ.get("BACKUP_S3_ACCESS_KEY_ID") and os.environ.get("BACKUP_S3_SECRET_ACCESS_KEY"):
        kwargs["aws_access_key_id"] = os.environ["BACKUP_S3_ACCESS_KEY_ID"]
        kwargs["aws_secret_access_key"] = os.environ["BACKUP_S3_SECRET_ACCESS_KEY"]
    return boto3.client("s3", **kwargs)


def upload_offsite(filename: str, content: bytes) -> dict:
    """Uploads one backup file to the configured S3-compatible bucket. Returns a
    result dict rather than raising -- a network hiccup or misconfigured bucket
    degrades to "off-site upload failed" without ever undoing or blocking the
    local backup itself, which has already succeeded by the time this runs."""
    if not offsite_configured():
        return {"attempted": False, "ok": False, "reason": "not configured"}
    bucket = os.environ["BACKUP_S3_BUCKET"]
    prefix = os.environ.get("BACKUP_S3_PREFIX", "nightwatch-backups").strip("/")
    key = f"{prefix}/{filename}" if prefix else filename
    try:
        client = _s3_client()
        client.put_object(Bucket=bucket, Key=key, Body=content)
        return {"attempted": True, "ok": True, "bucket": bucket, "key": key, "uploaded_at": _now_iso()}
    except Exception as e:
        logger.warning(f"Off-site backup upload failed: {e}")
        return {"attempted": True, "ok": False, "bucket": bucket, "key": key, "error": str(e)}


def verify_backup(content: bytes, expected_collections: int | None = None,
                   expected_documents: int | None = None) -> dict:
    """Restore-verification without touching the live database: decompresses and
    fully parses the archive exactly as restore_backup() would, then (when the
    original dump counts are known) cross-checks that the archive's collection/
    document counts match what was actually dumped.

    This is deliberately NOT a full restore drill against a second, disposable
    database -- provisioning and tearing down a spare Mongo instance safely on
    every backup isn't in scope for a single self-hosted deployment. What it does
    catch is the two failure modes that actually matter for a backup file: "this
    archive is corrupt/truncated" and "this archive doesn't contain what we think
    it does" -- both of which a real restore would otherwise discover the hard
    way, mid-disaster, when it's too late to do anything but panic.
    """
    try:
        raw = gzip.decompress(content)
        data = json_util.loads(raw.decode("utf-8"))
    except Exception as e:
        return {"valid": False, "error": f"Archive is corrupt or unreadable: {e}", "verified_at": _now_iso()}

    collections = data.get("collections")
    if collections is None or not isinstance(collections, dict):
        return {"valid": False, "error": "Missing or malformed 'collections' key", "verified_at": _now_iso()}

    doc_count = sum(len(v) for v in collections.values() if isinstance(v, list))
    result = {"valid": True, "collections": len(collections), "documents": doc_count, "verified_at": _now_iso()}

    if expected_collections is not None and len(collections) != expected_collections:
        result["valid"] = False
        result["error"] = f"Collection count mismatch: archive has {len(collections)}, expected {expected_collections}"
    elif expected_documents is not None and doc_count != expected_documents:
        result["valid"] = False
        result["error"] = f"Document count mismatch: archive has {doc_count}, expected {expected_documents}"
    return result


# ---------------------------------------------------------------------------
# Optional at-rest encryption.
#
# When a backup is encrypted, a strong passphrase is generated server-side, used
# to derive the key, and SHOWN EXACTLY ONCE in the create response. It is never
# stored -- not in the backup record, not on disk, nowhere. That is the security
# property: a backup file stolen from the volume (or from off-site storage) is
# useless without a passphrase that exists only wherever the operator pasted it.
#
# The unavoidable corollary, which the UI must state plainly: lose the passphrase
# and the backup is unrecoverable. There is no reset, because a resettable
# passphrase is not encryption.
ENC_MAGIC = "NIGHTWATCH-ENC-BACKUP"
ENC_VERSION = 1
KDF_ITERATIONS = 600_000   # PBKDF2-HMAC-SHA256, OWASP-recommended floor


def generate_passphrase() -> str:
    """A strong, human-copyable one-time passphrase. Never stored."""
    import secrets
    # ~180 bits. Grouped for legibility when copied by hand.
    raw = secrets.token_urlsafe(30)
    return "-".join(raw[i:i + 6] for i in range(0, len(raw), 6))


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    import base64
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                     iterations=KDF_ITERATIONS)
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


def encrypt_payload(payload: bytes, passphrase: str) -> bytes:
    """Wrap the gzip payload in an authenticated-encryption envelope.

    The envelope is plain JSON (magic, kdf params, salt, ciphertext) so a restore
    can read the header WITHOUT the key and tell the operator 'this is encrypted,
    a passphrase is required' rather than failing with a gzip error.
    """
    import os as _os, base64, json
    from cryptography.fernet import Fernet
    salt = _os.urandom(16)
    token = Fernet(_derive_key(passphrase, salt)).encrypt(payload)
    envelope = {
        "magic": ENC_MAGIC, "version": ENC_VERSION,
        "kdf": "pbkdf2-sha256", "iterations": KDF_ITERATIONS,
        "salt": base64.b64encode(salt).decode(),
        "ciphertext": base64.b64encode(token).decode(),
    }
    return json.dumps(envelope).encode("utf-8")


def is_encrypted(content: bytes) -> bool:
    """Cheap peek: is this an encrypted-backup envelope?"""
    head = content[:64].lstrip()
    if not head.startswith(b"{"):
        return False
    try:
        import json
        return json.loads(content.decode("utf-8", "replace")).get("magic") == ENC_MAGIC
    except Exception:
        return False


def decrypt_payload(content: bytes, passphrase: str) -> bytes:
    """Recover the gzip payload from an encrypted envelope. Raises ValueError on a
    wrong passphrase or tampering (Fernet authenticates, so a modified ciphertext
    is rejected, not silently returned as garbage)."""
    import base64, json
    from cryptography.fernet import Fernet, InvalidToken
    try:
        env = json.loads(content.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"Not an encrypted VulnOps backup: {e}")
    if env.get("magic") != ENC_MAGIC:
        raise ValueError("Not an encrypted VulnOps backup.")
    if not passphrase:
        raise ValueError("This backup is encrypted; a passphrase is required to restore it.")
    salt = base64.b64decode(env["salt"])
    key = _derive_key(passphrase, salt)
    try:
        return Fernet(key).decrypt(base64.b64decode(env["ciphertext"]))
    except InvalidToken:
        raise ValueError("Wrong passphrase, or the backup file has been tampered with.")


async def _stream_gzip_dump(db, collection_names, out_fileobj, ts) -> int:
    """Write gzip(json_util.dumps({"created_at":..,"collections":{name:[docs]}}))
    to out_fileobj ONE document at a time.

    The old create_backup materialized the entire database as Python objects, then
    a single giant JSON string, then a gzip blob -- several full copies of a
    200MB+ database resident at once. That OOM-killed the worker (mem_limit 1536m)
    on a large database and put it in a requeue/crash loop. Streaming keeps peak
    memory to a single document plus the gzip window, regardless of DB size.

    Returns the total number of documents written.
    """
    total_docs = 0
    gz = gzip.GzipFile(fileobj=out_fileobj, mode="wb")
    def w(s: str):
        gz.write(s.encode("utf-8"))
    try:
        w('{"created_at": ')
        w(json_util.dumps(ts))
        w(', "collections": {')
        for ci, name in enumerate(collection_names):
            if ci:
                w(',')
            w(json_util.dumps(name))
            w(': [')
            first = True
            # motor streams the cursor in batches, so only a batch is resident.
            async for doc in db[name].find({}):
                w('' if first else ',')
                w(json_util.dumps(doc))
                first = False
                total_docs += 1
            w(']')
        w('}}')
    finally:
        gz.close()
    return total_docs


def _verify_gzip_file(path: "Path", expected_documents=None, expected_collections=None) -> dict:
    """Integrity-verify a freshly written archive by streaming it through the
    gzip decoder in chunks -- never holding the whole thing in memory. gzip's
    trailing CRC and length are checked as the stream ends, so a truncated or
    corrupt file (disk full, crash mid-write) is caught. The document/collection
    counts are authoritative from the write itself, so they can't disagree with
    what was dumped; this confirms the bytes on disk are sound."""
    try:
        decompressed = 0
        with gzip.open(path, "rb") as fh:
            while True:
                chunk = fh.read(1 << 20)
                if not chunk:
                    break
                decompressed += len(chunk)
        if decompressed == 0:
            return {"valid": False, "error": "Archive decompressed to nothing",
                    "verified_at": _now_iso()}
    except Exception as e:
        return {"valid": False, "error": f"Archive is corrupt or unreadable: {e}",
                "verified_at": _now_iso()}
    return {"valid": True, "collections": expected_collections,
            "documents": expected_documents, "verified_at": _now_iso()}


async def create_backup(db, label: str | None = None, *, encrypt: bool = False) -> dict:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    suffix = ".json.gz.enc" if encrypt else ".json.gz"
    filename = f"vulnops-backup-{ts}{suffix}"
    path = _safe_path(filename)

    collection_names = [c for c in await db.list_collection_names()
                        if c != "backup_history" and not c.startswith(STAGE_PREFIX)]

    # Stream the dump to a temp gzip file on the backup volume, one document at a
    # time -- see _stream_gzip_dump. This is the fix for the worker being
    # OOM-killed (and crash-looping) when backing up a large database inline.
    import tempfile
    tmp = tempfile.NamedTemporaryFile(prefix="vulnops-bak-", suffix=".gz",
                                      dir=str(BACKUP_DIR), delete=False)
    tmp_path = Path(tmp.name)
    try:
        total_docs = await _stream_gzip_dump(db, collection_names, tmp, ts)
        tmp.flush()
        tmp.close()

        # Verify the PLAINTEXT archive round-trips BEFORE we encrypt it (an
        # encrypted file can't be structurally verified without the key), and do
        # it by streaming so verification is memory-bounded too.
        verification = _verify_gzip_file(tmp_path, expected_documents=total_docs,
                                         expected_collections=len(collection_names))

        passphrase = None
        if encrypt:
            passphrase = generate_passphrase()
            gz_bytes = tmp_path.read_bytes()   # the COMPRESSED archive is small
            path.write_bytes(encrypt_payload(gz_bytes, passphrase))
        else:
            os.replace(str(tmp_path), str(path))   # atomic move -- no extra copy
    finally:
        if tmp_path.exists():
            tmp_path.unlink()

    size_bytes = path.stat().st_size

    # Read the file back ONLY when off-site is actually configured -- otherwise
    # we'd pull the whole archive into RAM for nothing (and the archive can be
    # large). This was one of the redundant full-file copies behind the OOM.
    if offsite_configured():
        offsite = upload_offsite(filename, path.read_bytes())
    else:
        offsite = {"attempted": False, "ok": False, "reason": "not configured"}

    record = {
        "id": str(uuid.uuid4()), "filename": filename, "label": label,
        "collections": len(collection_names), "documents": total_docs,
        "size_bytes": size_bytes, "created_at": _now_iso(),
        "encrypted": encrypt,
        "verified": verification["valid"], "verification_error": verification.get("error"),
        "verified_at": verification["verified_at"],
        "offsite_attempted": offsite["attempted"], "offsite_ok": offsite["ok"],
        "offsite_bucket": offsite.get("bucket"), "offsite_key": offsite.get("key"),
        "offsite_error": offsite.get("error"), "offsite_uploaded_at": offsite.get("uploaded_at"),
    }
    await db.backup_history.insert_one(dict(record))
    # The passphrase is returned HERE and only here. It is never stored. Surface
    # it to the caller so the UI can show it once; after this response it is gone
    # from the server forever.
    out = dict(record)
    if passphrase:
        out["passphrase"] = passphrase
        out["passphrase_notice"] = ("Copy this passphrase now. It is shown once and never stored — "
                                     "without it, this backup cannot be restored.")
    return out


async def verify_backup_by_id(db, backup_id: str) -> dict:
    """Re-reads an existing backup off disk and re-runs verification -- useful
    after the fact (e.g. checking an older backup is still intact) without
    needing to create a new one."""
    record = await db.backup_history.find_one({"id": backup_id}, {"_id": 0})
    if not record:
        raise ValueError("Backup not found")
    content = read_backup_file(record["filename"])
    result = verify_backup(content, expected_collections=record.get("collections"), expected_documents=record.get("documents"))
    await db.backup_history.update_one({"id": backup_id}, {"$set": {
        "verified": result["valid"], "verification_error": result.get("error"), "verified_at": result["verified_at"],
    }})
    return result


async def upload_offsite_by_id(db, backup_id: str) -> dict:
    """Manual (re-)upload of an existing backup to the configured off-site
    destination -- used both for a first-time backfill after off-site is
    configured, and to retry one that failed."""
    record = await db.backup_history.find_one({"id": backup_id}, {"_id": 0})
    if not record:
        raise ValueError("Backup not found")
    content = read_backup_file(record["filename"])
    result = upload_offsite(record["filename"], content)
    await db.backup_history.update_one({"id": backup_id}, {"$set": {
        "offsite_attempted": result["attempted"], "offsite_ok": result["ok"],
        "offsite_bucket": result.get("bucket"), "offsite_key": result.get("key"),
        "offsite_error": result.get("error"), "offsite_uploaded_at": result.get("uploaded_at"),
    }})
    return result


async def list_backups(db) -> list:
    records = await db.backup_history.find({}, {"_id": 0}).sort("created_at", -1).to_list(500)
    # Cross-check against what's actually still on disk (a pruned/deleted file
    # shouldn't offer a download link that 404s).
    for r in records:
        r["file_exists"] = _safe_path(r["filename"]).exists() if r.get("filename") else False
    return records


def read_backup_file(filename: str) -> bytes:
    path = _safe_path(filename)
    if not path.exists():
        raise FileNotFoundError(f"Backup file '{filename}' not found on disk")
    return path.read_bytes()


async def restore_backup(db, content: bytes, passphrase: str | None = None) -> dict:
    """DESTRUCTIVE: replaces each collection's contents with what's in the backup.
    Meant for disaster recovery, not merging -- there's no partial/dry-run mode.

    An encrypted backup requires the passphrase that was shown when it was
    created. A wrong or missing passphrase fails cleanly BEFORE anything is
    deleted -- the destructive part only runs once the file has decrypted and
    parsed."""
    if is_encrypted(content):
        content = decrypt_payload(content, passphrase)   # raises ValueError on bad passphrase
    try:
        raw = gzip.decompress(content)
        data = json_util.loads(raw.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"Not a valid VulnOps backup file: {e}")

    collections = data.get("collections")
    if collections is None:
        raise ValueError("Not a valid VulnOps backup file (missing 'collections' key)")

    restored = {}
    for name, docs in collections.items():
        await db[name].delete_many({})
        if docs:
            await db[name].insert_many(docs)
        restored[name] = len(docs)

    return {"collections_restored": len(collections), "documents_restored": sum(restored.values()), "detail": restored}


RESTORE_BATCH = 2000


STAGE_PREFIX = "__restore_stage__"


async def restore_from_path(db, path, passphrase: str | None = None,
                            batch_size: int = RESTORE_BATCH) -> dict:
    """Memory-bounded, STAGE-THEN-SWAP, worker-side restore.

    Two problems this solves, both of which produced the "Restore failed" the
    operator saw with no usable reason:

    1. It ran inline in the 1g API process behind Cloudflare's ~100s proxy
       timeout -- on a large database it OOM'd or 520'd. This runs in the worker,
       frees each collection as it inserts it, and writes in batches.

    2. The old path did delete_many() then insert_many() on the LIVE collection.
       A failure part-way (bad doc, worker killed, disk full) left the database
       half-wiped with no way back -- the worst possible outcome for a restore.
       This stages every collection into a temporary collection FIRST and only
       once the ENTIRE archive has been staged successfully does it swap the
       staged collections into place with an atomic rename. If anything fails
       during staging, the live database is untouched and the temp collections
       are dropped.

    Destructive-safety is therefore total: a wrong/missing passphrase, a corrupt
    file, or a mid-restore error all leave the live data exactly as it was. The
    only destructive step is the final rename-swap, which is fast metadata ops.
    """
    p = Path(path)
    if not p.exists():
        raise ValueError(f"Restore file not found: {path}")
    content = p.read_bytes()
    if is_encrypted(content):
        content = decrypt_payload(content, passphrase)   # raises before anything is staged
    try:
        raw = gzip.decompress(content)
        del content
        data = json_util.loads(raw.decode("utf-8"))
        del raw
    except ValueError:
        raise
    except Exception as e:
        raise ValueError(f"Not a valid VulnOps backup file: {e}")

    collections = data.get("collections")
    if collections is None or not isinstance(collections, dict):
        raise ValueError("Not a valid VulnOps backup file (missing 'collections' key)")

    names = list(collections.keys())
    staged = []          # (stage_name, live_name, count) for names successfully staged
    restored = {}

    async def _drop_stage(stage_name):
        try:
            await db.drop_collection(stage_name)
        except Exception:
            pass

    # ---- STAGE: load every collection into a temp collection; live data untouched ----
    try:
        for name in names:
            docs = collections.pop(name)         # freed from the parsed dict as we go
            stage_name = f"{STAGE_PREFIX}{name}"
            await _drop_stage(stage_name)         # clear any leftover from a prior aborted restore
            n = 0
            for i in range(0, len(docs), batch_size):
                chunk = docs[i:i + batch_size]
                if chunk:
                    await db[stage_name].insert_many(chunk)
                    n += len(chunk)
            staged.append((stage_name, name, n))
            restored[name] = n
            del docs
    except Exception as e:
        # staging failed -> live data is untouched; clean up every temp collection
        for stage_name, _live, _n in staged:
            await _drop_stage(stage_name)
        # also drop the one we were mid-way through, if any
        raise ValueError(f"Restore staging failed before any live data was changed: {e}")

    # ---- SWAP: everything staged OK; rename each temp collection into place ----
    # This is the only step that touches live data, and it's fast metadata ops.
    swapped = 0
    for stage_name, live_name, _n in staged:
        await db[stage_name].rename(live_name, dropTarget=True)
        swapped += 1

    total = sum(restored.values())
    return {"collections_restored": len(names), "documents_restored": total,
            "detail": restored, "staged_then_swapped": True, "swapped_collections": swapped}


async def prune_old_backups(db, retention: int = DEFAULT_RETENTION) -> dict:
    records = await db.backup_history.find({}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    to_prune = records[retention:]
    removed = 0
    for r in to_prune:
        try:
            path = _safe_path(r["filename"])
            if path.exists():
                path.unlink()
        except Exception:
            pass
        await db.backup_history.delete_one({"id": r["id"]})
        removed += 1
    return {"pruned": removed, "kept": min(len(records), retention)}


async def delete_backup(db, backup_id: str) -> None:
    record = await db.backup_history.find_one({"id": backup_id}, {"_id": 0})
    if not record:
        return
    try:
        path = _safe_path(record["filename"])
        if path.exists():
            path.unlink()
    except Exception:
        pass
    await db.backup_history.delete_one({"id": backup_id})


async def backup_loop(db, interval_hours: int = 24, retention: int = DEFAULT_RETENTION):
    """Optional scheduled backup -- only runs if BACKUP_SCHEDULE_ENABLED is set, so a
    fresh install doesn't silently start writing to disk before someone's decided
    where that disk should be (i.e. mounted a real volume for it)."""
    import asyncio
    import logging
    from heartbeat import record_heartbeat
    logger = logging.getLogger("vulnops")
    if os.environ.get("BACKUP_SCHEDULE_ENABLED", "false").lower() not in ("true", "1", "yes"):
        logger.info("Scheduled backups disabled (set BACKUP_SCHEDULE_ENABLED=true to enable)")
        return
    await asyncio.sleep(90)
    while True:
        ok, detail = True, {}
        try:
            record = await create_backup(db, label="scheduled")
            prune_result = await prune_old_backups(db, retention)
            logger.info(
                f"Scheduled backup: {record['filename']} ({record['documents']} docs, "
                f"verified={record['verified']}, offsite_ok={record['offsite_ok']}) — {prune_result}"
            )
            detail = {
                "backup": record["filename"], "documents": record["documents"], "prune": prune_result,
                "verified": record["verified"], "offsite_attempted": record["offsite_attempted"],
                "offsite_ok": record["offsite_ok"],
            }
        except Exception as e:
            logger.exception(f"Scheduled backup failed: {e}")
            ok, detail["error"] = False, str(e)
        await record_heartbeat(db, "backup_loop", "ok" if ok else "error", detail)
        await asyncio.sleep(interval_hours * 3600)


# ---------------------------------------------------------------------------
# Async backups: the passphrase across a job boundary.
#
# A synchronous backup returns the passphrase in its HTTP response and never
# stores it. An ASYNC backup runs in the worker; the passphrase can't ride back
# in the poll response (the worker finished long before the poll arrives) and it
# MUST NOT be written into the job result, which is persisted. So it goes into a
# read-once vault: stored just long enough for the operator to fetch it exactly
# once, then deleted. It's weaker than the sync path (which never persists it),
# so it is auto-expired as a backstop and read-once on retrieval.
# ---------------------------------------------------------------------------
PASSPHRASE_TTL_MINUTES = 30


async def stash_passphrase(db, backup_id: str, passphrase: str) -> None:
    await db.backup_secrets.insert_one({
        "backup_id": backup_id, "passphrase": passphrase, "created_at": _now_iso()})


async def claim_passphrase(db, backup_id: str) -> dict:
    """Return the passphrase ONCE and delete it. After this, it's gone."""
    doc = await db.backup_secrets.find_one_and_delete({"backup_id": backup_id})
    if not doc:
        return {"available": False,
                "message": ("No passphrase is available for this backup. It is shown exactly once "
                             "and is deleted the moment it's retrieved — if this was already viewed, "
                             "or the backup wasn't encrypted, there is nothing to show, and an "
                             "encrypted backup whose passphrase was never captured is unrecoverable.")}
    # opportunistically purge any that were never claimed and have aged out
    from datetime import datetime, timezone, timedelta
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=PASSPHRASE_TTL_MINUTES)).isoformat()
    await db.backup_secrets.delete_many({"created_at": {"$lt": cutoff}})
    return {"available": True, "passphrase": doc["passphrase"]}


def memory_snapshot() -> dict:
    """Best-effort available/used memory, for reporting whether the origin has
    room to run a large backup. Degrades to nothing rather than failing."""
    info = {}
    try:
        import shutil
        # cgroup v2 memory (what the container is actually limited to)
        for path, key in (("/sys/fs/cgroup/memory.max", "limit_bytes"),
                          ("/sys/fs/cgroup/memory.current", "used_bytes")):
            try:
                with open(path) as f:
                    v = f.read().strip()
                    info[key] = None if v == "max" else int(v)
            except Exception:
                pass
        if info.get("limit_bytes") and info.get("used_bytes") is not None:
            info["available_bytes"] = info["limit_bytes"] - info["used_bytes"]
    except Exception:
        pass
    return info


# ---------------------------------------------------------------------------
# Run-on-host interim unblock.
#
#   docker compose exec backend python backup.py            # plain backup
#   docker compose exec backend python backup.py --encrypt  # encrypted; prints passphrase
#
# Bypasses HTTP entirely, so it is immune to the Cloudflare proxy timeout that
# 520'd inline backups. Useful before pulling the async fix, or any time you want
# a backup without touching the UI.
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse, asyncio as _asyncio

    parser = argparse.ArgumentParser(description="Create a database backup directly (no HTTP).")
    parser.add_argument("--encrypt", action="store_true",
                        help="encrypt the backup; the passphrase is printed ONCE — copy it.")
    parser.add_argument("--label", default="host-cli")
    args = parser.parse_args()

    async def _main():
        from db import db
        mem = memory_snapshot()
        if mem.get("available_bytes") is not None:
            print(f"Container memory: {mem['available_bytes'] // (1024*1024)} MB available "
                  f"of {mem.get('limit_bytes', 0) // (1024*1024)} MB limit.")
        print("Creating backup…")
        rec = await create_backup(db, label=args.label, encrypt=args.encrypt)
        print(f"Backup: {rec['filename']}  ({rec['documents']} docs, "
              f"{rec['size_bytes'] // 1024} KB, verified={rec['verified']})")
        if rec.get("passphrase"):
            print()
            print("=" * 60)
            print("PASSPHRASE (shown once, not stored — copy it now):")
            print("   " + rec["passphrase"])
            print("Without it, this backup cannot be restored.")
            print("=" * 60)

    _asyncio.run(_main())
