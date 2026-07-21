"""Secrets/credential leak scanning for self-hosted git repositories.

Detects hardcoded credentials (API keys, tokens, private keys, high-entropy
strings that look like secrets) committed to a git repo's current working
tree, using Yelp's detect-secrets (pip-installable, actively maintained,
plugin-based detector for ~15 well-known credential formats plus entropy
heuristics -- https://github.com/Yelp/detect-secrets).

Scope: scans the repository's current checked-out state (a shallow clone of
one branch), not full git history. A secret that was committed and later
removed in a subsequent commit won't be caught here -- that's a deliberate
limitation, not an oversight: scanning full history safely means deep-cloning
arbitrary (possibly large, possibly private) repositories onto this
container's disk, a meaningfully bigger resource/exposure footprint than the
current-working-tree check most self-hosted setups need day to day.

Findings never store the actual secret value -- detect-secrets itself only
outputs a SHA1 hash of each detected secret (`hashed_secret`), specifically
so a tool built around it (like this one) never becomes a second copy of the
leaked credential sitting in yet another database. Open the file at the
reported line to see the real value; rotate the credential; don't expect to
recover the plaintext from here, because this app never has it.

detect-secrets requires its scan target to be inside a git working tree (it
enumerates files via `git ls-files` internally) -- a natural fit since the
whole point here is scanning a freshly cloned repo anyway, not a fallback
needed for arbitrary file uploads.
"""
import asyncio
import json
import logging
import shutil
import tempfile
import uuid
from datetime import datetime, timezone

logger = logging.getLogger("vulnops")

OPEN_STATES = ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]

# Finding-types detect-secrets can return, bucketed by how likely a match is to
# be a genuine, live credential rather than a heuristic false positive. A
# leaked private key is about as bad as a secret leak gets; generic entropy/
# keyword heuristics are the noisiest (most false-positive-prone) detectors.
# Everything else (AWS/GitHub/Stripe/Slack/Twilio/SendGrid/etc. named
# detectors) defaults to High -- a specific, named-service token format match
# is a much stronger signal than a generic heuristic.
_CRITICAL_TYPES = {"Private Key"}
_MEDIUM_TYPES = {"Base64 High Entropy String", "Hex High Entropy String", "Secret Keyword", "Keyword"}


def _severity_for_type(secret_type: str) -> str:
    if secret_type in _CRITICAL_TYPES:
        return "Critical"
    if secret_type in _MEDIUM_TYPES:
        return "Medium"
    return "High"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _clone_url_with_token(repo_url: str, token: str = None) -> str:
    """Embeds an access token into an HTTPS clone URL for a private repo, the
    same way GitHub/GitLab/Gitea all document (https://oauth2:<token>@host/...)
    -- used only for the one-shot clone subprocess argv, never logged."""
    if not token or not repo_url.startswith("https://"):
        return repo_url
    scheme, rest = repo_url.split("://", 1)
    return f"{scheme}://oauth2:{token}@{rest}"


async def _run(*args, timeout_sec=300, cwd=None):
    proc = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, cwd=cwd,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
    except asyncio.TimeoutError:
        proc.kill()
        raise ValueError(f"'{args[0]}' took longer than {timeout_sec}s and was aborted")
    return proc.returncode, stdout, stderr


async def scan_git_repo(repo_url: str, branch: str = None, token: str = None, timeout_sec: int = 300) -> list:
    """Shallow-clones one branch of a git repo into a throwaway temp directory,
    runs detect-secrets against it, and returns the raw list of
    {filename, type, hashed_secret, line_number, is_verified} hits -- the temp
    clone is always removed afterward, success or failure, so no repository
    content (which may be private) lingers on disk."""
    tmp_dir = tempfile.mkdtemp(prefix="secrets-scan-")
    try:
        clone_url = _clone_url_with_token(repo_url, token)
        clone_args = ["git", "clone", "--depth", "1", "--quiet"]
        if branch:
            clone_args += ["--branch", branch]
        clone_args += [clone_url, tmp_dir]

        rc, _, stderr = await _run(*clone_args, timeout_sec=timeout_sec)
        if rc != 0:
            detail = stderr.decode("utf-8", "replace").strip() or f"git exited with code {rc}"
            if token:
                detail = detail.replace(token, "***")  # never surface the token in an error message
            raise ValueError(f"Couldn't clone '{repo_url}': {detail}")

        rc2, stdout2, stderr2 = await _run("detect-secrets", "scan", ".", timeout_sec=timeout_sec, cwd=tmp_dir)
        if rc2 != 0:
            detail = stderr2.decode("utf-8", "replace").strip() or f"detect-secrets exited with code {rc2}"
            raise ValueError(f"Couldn't scan '{repo_url}': {detail}")
        try:
            data = json.loads(stdout2)
        except Exception as e:
            raise ValueError(f"detect-secrets returned unreadable output for '{repo_url}': {e}")

        results = []
        for filename, hits in (data.get("results") or {}).items():
            for hit in hits:
                results.append({
                    "filename": filename, "type": hit.get("type"),
                    "hashed_secret": hit.get("hashed_secret"), "line_number": hit.get("line_number"),
                    "is_verified": hit.get("is_verified", False),
                })
        return results
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


async def _notify_secret_found(db, repo_url, hit, severity, finding_id):
    from notifier import dispatch
    try:
        await dispatch("secret_leak_found", {
            "repo": repo_url, "secret_type": hit["type"], "filename": hit["filename"],
            "severity": severity, "url": f"/findings/{finding_id}",
        }, db)
    except Exception:
        pass


async def run_repo_scan(db, repo_url: str, branch: str = None, token: str = None,
                         asset_id: str = None, label: str = None) -> dict:
    """Scans one repo, creates/updates/auto-resolves a finding per detected
    secret (keyed by file+type+content-hash so a fixed/rotated/removed secret
    auto-resolves and an unchanged one doesn't duplicate across scans), and
    records scan history keyed by repo_url."""
    now = _now_iso()
    hits = await scan_git_repo(repo_url, branch, token)

    asset = await db.assets.find_one({"id": asset_id}, {"_id": 0}) if asset_id else None
    source_label = (asset or {}).get("hostname") or label or repo_url
    seen_keys = set()
    created = updated = 0

    for hit in hits:
        canonical_key = f"secrets:{repo_url}:{hit['filename']}:{hit['type']}:{hit['hashed_secret']}"
        seen_keys.add(canonical_key)
        severity = _severity_for_type(hit["type"])
        existing = await db.findings.find_one({"canonical_key": canonical_key}, {"_id": 0})
        if existing:
            if existing.get("status") in OPEN_STATES:
                await db.findings.update_one({"id": existing["id"]}, {"$set": {"last_seen_at": now}})
                updated += 1
            continue
        finding = {
            "id": str(uuid.uuid4()), "canonical_key": canonical_key,
            "title": f"Possible {hit['type']} committed in {repo_url} ({hit['filename']})",
            "description": (
                f"detect-secrets flagged a likely {hit['type']} at {hit['filename']}:{hit['line_number']} "
                f"in {repo_url}. The actual value is never stored here (only a one-way hash) -- open the "
                f"file at that line to see it, then rotate the credential and remove it from history."
            ),
            "severity": severity, "status": "New",
            "source_tool": "Secrets Scan (detect-secrets)", "source_tool_type": "Secrets Detection",
            "detection_channel": "Git repository scan",
            "asset_id": asset_id, "asset_hostname": source_label,
            "asset_ip": (asset or {}).get("ip"), "asset_criticality": (asset or {}).get("criticality"),
            "asset_exposure": (asset or {}).get("exposure"),
            "component_name": hit["filename"], "cwe": "CWE-798",
            "first_seen_at": now, "last_seen_at": now, "rti": [],
        }
        await db.findings.insert_one(finding)
        created += 1
        await _notify_secret_found(db, repo_url, hit, severity, finding["id"])

    # Auto-resolve findings from a previous scan of this same repo that no
    # longer appear -- the secret was removed/rotated since.
    prior = await db.findings.find(
        {"detection_channel": "Git repository scan", "status": {"$in": OPEN_STATES}}, {"_id": 0},
    ).to_list(5000)
    resolved = 0
    prefix = f"secrets:{repo_url}:"
    for f in prior:
        key = f.get("canonical_key") or ""
        if key.startswith(prefix) and key not in seen_keys:
            await db.findings.update_one({"id": f["id"]}, {"$set": {
                "status": "Fixed validated", "resolved_at": now,
                "resolution_note": "Secret no longer detected on re-scan (removed/rotated, or the file/line changed).",
            }})
            resolved += 1

    record = {
        "id": repo_url, "repo_url": repo_url, "branch": branch, "label": label, "asset_id": asset_id,
        "secrets_found": len(hits), "findings_created": created, "findings_updated": updated,
        "findings_resolved": resolved, "scanned_at": now,
    }
    await db.secrets_scan_history.update_one({"id": repo_url}, {"$set": record}, upsert=True)
    return record


async def secrets_scan_loop(db, interval_hours: int = 24):
    """Background poll -- scans all enabled watch targets once per interval.
    Gated by the secrets_scan_nightly_check feature flag (default on) -- manual
    "Scan now"/"Scan all" actions from the UI are never gated, only this
    automatic sweep, same convention as the other Scheduled Syncs flags."""
    from heartbeat import record_heartbeat
    from feature_flags import is_enabled
    await asyncio.sleep(65)  # let other startup tasks settle first
    while True:
        ok, detail = True, {}
        try:
            if await is_enabled(db, "secrets_scan_nightly_check"):
                result = await run_all_repo_scans(db)
                logger.info(f"Secrets scan sweep: {result}")
                detail = result
            else:
                detail = {"skipped": "disabled in Settings"}
        except Exception as e:
            logger.exception(f"Secrets scan sweep failed: {e}")
            ok, detail["error"] = False, str(e)
        await record_heartbeat(db, "secrets_scan_loop", "ok" if ok else "error", detail)
        await asyncio.sleep(interval_hours * 3600)


async def run_all_repo_scans(db) -> dict:
    """Scans every enabled watch target. Concurrency-capped and deliberately
    low (3) -- each scan does a real git clone plus a filesystem walk, real
    disk/CPU/network work, not a lightweight DNS/HTTP check."""
    targets = await db.secrets_scan_targets.find({"enabled": True}, {"_id": 0}).to_list(200)
    sem = asyncio.Semaphore(3)

    async def _one(t):
        async with sem:
            try:
                return await run_repo_scan(db, t["repo_url"], t.get("branch"), t.get("token"),
                                            t.get("asset_id"), t.get("label"))
            except Exception as e:
                return {"repo_url": t["repo_url"], "error": str(e)}

    results = await asyncio.gather(*[_one(t) for t in targets])
    scanned = len(results)
    failed = len([r for r in results if "error" in r])
    findings_created = sum(r.get("findings_created", 0) for r in results if "error" not in r)
    return {"scanned": scanned, "failed": failed, "findings_created": findings_created, "synced_at": _now_iso()}
