import os, sys, asyncio, json
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_secrets_scan"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_secrets_scan"]

import server
import auth_utils
from routes import secrets_scan as ss_route
ss_route.db = db_module.db

from fastapi.testclient import TestClient

admin_user = {"id": "u1", "email": "admin@x.com", "role": "admin", "name": "Admin", "teams": []}
app = server.app
app.dependency_overrides[auth_utils.get_current_user] = lambda: admin_user
client = TestClient(app)

db = db_module.db


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


import secrets_scan as ss

# ============ _severity_for_type() -- pure unit tests ============

assert ss._severity_for_type("Private Key") == "Critical"
assert ss._severity_for_type("Base64 High Entropy String") == "Medium"
assert ss._severity_for_type("Secret Keyword") == "Medium"
assert ss._severity_for_type("AWS Access Key") == "High"
assert ss._severity_for_type("GitHub Token") == "High"
assert ss._severity_for_type("Stripe Access Key") == "High"
print("PASS: _severity_for_type() buckets private keys as Critical, named-service tokens as High, generic heuristics as Medium")

# ============ _clone_url_with_token() ============

assert ss._clone_url_with_token("https://github.com/org/repo.git", "tok123") == "https://oauth2:tok123@github.com/org/repo.git"
assert ss._clone_url_with_token("https://github.com/org/repo.git", None) == "https://github.com/org/repo.git"
assert ss._clone_url_with_token("git@github.com:org/repo.git", "tok123") == "git@github.com:org/repo.git"  # SSH URLs unaffected
print("PASS: _clone_url_with_token() embeds a token into an HTTPS URL only, leaves SSH URLs untouched")

# ============ scan_git_repo() -- real subprocess plumbing, fake processes ============

FAKE_DETECT_SECRETS_JSON = json.dumps({
    "results": {
        "config.py": [
            {"type": "AWS Access Key", "filename": "config.py", "hashed_secret": "abc123", "line_number": 4, "is_verified": False},
            {"type": "Secret Keyword", "filename": "config.py", "hashed_secret": "def456", "line_number": 9, "is_verified": False},
        ],
    },
}).encode("utf-8")


class FakeProcess:
    def __init__(self, returncode, stdout=b"", stderr=b""):
        self.returncode = returncode
        self._stdout, self._stderr = stdout, stderr

    async def communicate(self):
        return self._stdout, self._stderr

    def kill(self):
        pass


_call_log = []


async def _fake_exec_ok(*args, **kwargs):
    _call_log.append(args)
    if args[0] == "git":
        return FakeProcess(0)
    if args[0] == "detect-secrets":
        return FakeProcess(0, stdout=FAKE_DETECT_SECRETS_JSON)
    raise AssertionError(f"unexpected command: {args}")


async def _fake_exec_clone_fails(*args, **kwargs):
    if args[0] == "git":
        return FakeProcess(128, stderr=b"fatal: repository 'https://oauth2:supersecrettoken@github.com/org/priv.git/' not found")
    return FakeProcess(0, stdout=b"{}")


_real_create_subprocess_exec = asyncio.create_subprocess_exec

asyncio.create_subprocess_exec = _fake_exec_ok
_call_log.clear()
hits = run(ss.scan_git_repo("https://github.com/org/repo.git"))
assert len(hits) == 2
assert hits[0]["type"] == "AWS Access Key" and hits[0]["hashed_secret"] == "abc123"
assert hits[1]["type"] == "Secret Keyword"
assert _call_log[0][0] == "git" and "clone" in _call_log[0]
assert _call_log[1][0] == "detect-secrets" and "scan" in _call_log[1]
print("PASS: scan_git_repo() clones the repo then runs detect-secrets, returning the parsed hits")

asyncio.create_subprocess_exec = _fake_exec_clone_fails
try:
    run(ss.scan_git_repo("https://github.com/org/priv.git", token="supersecrettoken"))
    assert False
except ValueError as e:
    assert "supersecrettoken" not in str(e)  # token must never leak into an error message
    assert "***" in str(e)
print("PASS: scan_git_repo() surfaces a clone failure as a clear ValueError with the token scrubbed out")

asyncio.create_subprocess_exec = _real_create_subprocess_exec

# ============ run_repo_scan() -- findings lifecycle, monkeypatched scan_git_repo ============

ss.scan_git_repo = lambda repo_url, branch=None, token=None, timeout_sec=300: _async_return([
    {"filename": "config.py", "type": "AWS Access Key", "hashed_secret": "abc123", "line_number": 4, "is_verified": False},
    {"filename": "config.py", "type": "Secret Keyword", "hashed_secret": "def456", "line_number": 9, "is_verified": False},
])


async def _async_return(v):
    return v


result = run(ss.run_repo_scan(db, "https://github.com/org/repo.git"))
assert result["secrets_found"] == 2 and result["findings_created"] == 2
print("PASS: run_repo_scan() creates one finding per detected secret")

aws_finding = run(db.findings.find_one({"canonical_key": "secrets:https://github.com/org/repo.git:config.py:AWS Access Key:abc123"}, {"_id": 0}))
assert aws_finding is not None and aws_finding["severity"] == "High" and aws_finding["cwe"] == "CWE-798"
# canonical_key legitimately embeds the *hash* ("abc123" here) for dedup -- what
# must NEVER appear is a field carrying the real secret value, which this
# pipeline never even receives from detect-secrets in the first place.
assert not any(k in aws_finding for k in ("secret_value", "value", "plaintext_secret"))
print("PASS: findings never contain the actual secret value -- only detect-secrets' own one-way hash is used, for dedup only")

# re-scanning with the exact same hits must not duplicate findings
result2 = run(ss.run_repo_scan(db, "https://github.com/org/repo.git"))
assert result2["findings_created"] == 0 and result2["findings_updated"] == 2
print("PASS: run_repo_scan() doesn't duplicate findings for secrets that are still present on re-scan")

# secret removed/rotated -- the corresponding finding should auto-resolve
ss.scan_git_repo = lambda repo_url, branch=None, token=None, timeout_sec=300: _async_return([
    {"filename": "config.py", "type": "AWS Access Key", "hashed_secret": "abc123", "line_number": 4, "is_verified": False},
])
result3 = run(ss.run_repo_scan(db, "https://github.com/org/repo.git"))
assert result3["findings_resolved"] == 1
secret_keyword_finding = run(db.findings.find_one({"canonical_key": "secrets:https://github.com/org/repo.git:config.py:Secret Keyword:def456"}, {"_id": 0}))
assert secret_keyword_finding["status"] == "Fixed validated"
aws_finding_still_open = run(db.findings.find_one({"canonical_key": "secrets:https://github.com/org/repo.git:config.py:AWS Access Key:abc123"}, {"_id": 0}))
assert aws_finding_still_open["status"] == "New"
print("PASS: run_repo_scan() auto-resolves a finding whose secret is no longer detected, leaving the still-present one open")

# a human closes the AWS finding manually -- re-running while it's STILL present must not reopen it
run(db.findings.update_one({"id": aws_finding_still_open["id"]}, {"$set": {"status": "Fixed validated"}}))
run(ss.run_repo_scan(db, "https://github.com/org/repo.git"))
aws_finding_after = run(db.findings.find_one({"canonical_key": "secrets:https://github.com/org/repo.git:config.py:AWS Access Key:abc123"}, {"_id": 0}))
assert aws_finding_after["status"] == "Fixed validated"
print("PASS: run_repo_scan() never auto-reopens a finding a human already closed, even if the secret is still detected")

# ============ run_all_repo_scans() -- batch runner ============

ss.scan_git_repo = lambda repo_url, branch=None, token=None, timeout_sec=300: _async_return([])
run(db.secrets_scan_targets.insert_many([
    {"id": "t1", "repo_url": "https://github.com/org/repo1.git", "enabled": True, "asset_id": None, "label": None},
    {"id": "t2", "repo_url": "https://github.com/org/repo2.git", "enabled": True, "asset_id": None, "label": None},
    {"id": "t3", "repo_url": "https://github.com/org/repo3.git", "enabled": False, "asset_id": None, "label": None},
]))
batch = run(ss.run_all_repo_scans(db))
assert batch["scanned"] == 2 and batch["failed"] == 0
print("PASS: run_all_repo_scans() only scans enabled targets")


def _flaky(repo_url, branch=None, token=None, timeout_sec=300):
    if repo_url.endswith("repo2.git"):
        raise ValueError("simulated clone timeout")
    return _async_return([])


ss.scan_git_repo = _flaky
batch2 = run(ss.run_all_repo_scans(db))
assert batch2["scanned"] == 2 and batch2["failed"] == 1
print("PASS: run_all_repo_scans() isolates a single target's failure from the rest of the batch")

ss.scan_git_repo = lambda repo_url, branch=None, token=None, timeout_sec=300: _async_return([])

# ============ routes ============

r = client.post("/api/v1/admin/secrets-scan/targets", json={"repo_url": "https://github.com/org/app.git", "token": "realtoken123", "label": "test"})
assert r.status_code == 200, r.text
created = r.json()
assert created["token"] == "•••"  # masked in the response
print("PASS: POST /v1/admin/secrets-scan/targets creates a watch target and masks the token in the response")

r_bad = client.post("/api/v1/admin/secrets-scan/targets", json={"repo_url": "not-a-url"})
assert r_bad.status_code == 400
print("PASS: POST /v1/admin/secrets-scan/targets rejects a repo URL without a recognized scheme")

r2 = client.get("/api/v1/admin/secrets-scan/targets")
assert r2.status_code == 200
listed = next(t for t in r2.json()["items"] if t["id"] == created["id"])
assert listed["token"] == "•••"
print("PASS: GET /v1/admin/secrets-scan/targets masks tokens in the list too")

stored = run(db.secrets_scan_targets.find_one({"id": created["id"]}, {"_id": 0}))
assert stored["token"] == "realtoken123"
print("PASS: the real token is still stored server-side (needed for scheduled re-scans), only masked in API responses")

# scan-now enqueues to the worker rather than cloning the repo inside the API
# process -- a git clone in the request handler is heavy enough to contribute to
# the OOM crash. The route returns a job id; the worker handler does the work.
r3 = client.post(f"/api/v1/admin/secrets-scan/targets/{created['id']}/scan-now")
assert r3.status_code == 200, r3.text
assert r3.json()["status"] == "queued" and r3.json()["job_id"]
print("PASS: POST /v1/admin/secrets-scan/targets/{id}/scan-now ENQUEUES instead of cloning the "
      "repo inline")

import job_handlers as _jh
_job = run(db.jobs.find_one({"id": r3.json()["job_id"]}, {"_id": 0}))
async def _nohb(progress=None):
    return None
run(_jh._secrets(db, _job["payload"], _nohb))
r4 = client.get("/api/v1/admin/secrets-scan/targets")
item = next(t for t in r4.json()["items"] if t["id"] == created["id"])
assert item["latest"] is not None and item["latest"]["repo_url"] == "https://github.com/org/app.git"
print("PASS: the worker handler performs the real scan and records the latest result")

# updating without changing the token (masked placeholder echoed back) must keep the real token
r5 = client.put(f"/api/v1/admin/secrets-scan/targets/{created['id']}", json={
    "repo_url": "https://github.com/org/app.git", "token": "•••", "label": "updated", "enabled": False,
})
assert r5.status_code == 200 and r5.json()["enabled"] is False and r5.json()["token"] == "•••"
stored2 = run(db.secrets_scan_targets.find_one({"id": created["id"]}, {"_id": 0}))
assert stored2["token"] == "realtoken123"
print("PASS: PUT with the masked placeholder token preserves the real stored token instead of overwriting it")

r6 = client.post("/api/v1/admin/secrets-scan/scan-all")
assert r6.status_code == 200, r6.text
print("PASS: POST /v1/admin/secrets-scan/scan-all runs the batch route")

engagement = run(db.engagements.find_one({"scanner": "Secrets Scan (detect-secrets)"}, {"_id": 0}))
assert engagement is not None and engagement["status"] == "completed"
print("PASS: a manual scan-now route records an entry on the Engagements page")

r7 = client.delete(f"/api/v1/admin/secrets-scan/targets/{created['id']}")
assert r7.status_code == 200 and r7.json()["ok"] is True
r8 = client.get("/api/v1/admin/secrets-scan/targets")
assert not any(t["id"] == created["id"] for t in r8.json()["items"])
print("PASS: DELETE /v1/admin/secrets-scan/targets/{id} removes the watch target")

# ============ feature flag + notification template + rbac wiring ============

import feature_flags
assert "secrets_scan_nightly_check" in feature_flags.FLAG_KEYS
print("PASS: secrets_scan_nightly_check is registered in the feature flag registry")

import notifier
assert "secret_leak_found" in notifier.TRIGGERS and "secret_leak_found" in notifier.TEMPLATES
rendered = notifier.TEMPLATES["secret_leak_found"]["subject"].format(secret_type="AWS Access Key", repo="org/app")
assert "AWS Access Key" in rendered and "org/app" in rendered
print("PASS: secret_leak_found notification trigger + template are wired and render correctly")

import rbac
assert any(m["key"] == "/admin/secrets-scan" for m in rbac.MODULE_REGISTRY)
print("PASS: /admin/secrets-scan is registered as an RBAC module key")

print("\nALL SECRETS/CREDENTIAL LEAK SCANNING TESTS PASSED")
