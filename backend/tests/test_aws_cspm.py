import os, sys, asyncio, uuid
from datetime import datetime, timezone, timedelta
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_aws_cspm"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_aws_cspm"]

import server
import auth_utils
from routes import admin as admin_route
from routes import integrations as integrations_route
admin_route.db = db_module.db
integrations_route.db = db_module.db

from fastapi.testclient import TestClient

admin_user = {"id": "u1", "email": "admin@x.com", "role": "admin", "name": "Admin", "teams": []}
app = server.app
app.dependency_overrides[auth_utils.get_current_user] = lambda: admin_user
client = TestClient(app)

db = db_module.db


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


import aws_cspm as cspm

# ============ fake boto3 clients -- one fixture "AWS account" ============

SECURITY_GROUPS = [
    {"GroupId": "sg-open22", "GroupName": "open-ssh", "IpPermissions": [
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
    ]},
    {"GroupId": "sg-open8080", "GroupName": "open-web", "IpPermissions": [
        {"IpProtocol": "tcp", "FromPort": 8080, "ToPort": 8080, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
    ]},
    {"GroupId": "sg-restricted", "GroupName": "restricted", "IpPermissions": [
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]},
    ]},
]

EBS_VOLUMES = [
    {"VolumeId": "vol-unencrypted", "Size": 100, "State": "in-use", "Encrypted": False},
    {"VolumeId": "vol-encrypted", "Size": 50, "State": "in-use", "Encrypted": True},
]

RDS_INSTANCES = [
    {"DBInstanceIdentifier": "prod-db", "Engine": "postgres", "PubliclyAccessible": True},
    {"DBInstanceIdentifier": "internal-db", "Engine": "mysql", "PubliclyAccessible": False},
]

# Mutable knobs so later tests (auto-resolve, error-isolation) can tweak the
# fixture between runs without redefining every fake class.
STATE = {
    "buckets": ["public-bucket", "private-bucket"],
    "root_mfa_enabled": False,
    "trails": [],
    "cloudtrail_raises": False,
}


class FakePaginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **kwargs):
        return list(self._pages)


class FakeSTS:
    def get_caller_identity(self):
        return {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/cspm-scanner"}


class FakeS3:
    def list_buckets(self):
        return {"Buckets": [{"Name": n} for n in STATE["buckets"]]}

    def get_bucket_policy_status(self, Bucket):
        if Bucket == "public-bucket":
            return {"PolicyStatus": {"IsPublic": True}}
        raise Exception("NoSuchBucketPolicy: The bucket policy does not exist")

    def get_bucket_acl(self, Bucket):
        return {"Grants": []}

    def get_public_access_block(self, Bucket):
        raise Exception("NoSuchPublicAccessBlockConfiguration")


class FakeEC2:
    def get_paginator(self, op):
        if op == "describe_security_groups":
            return FakePaginator([{"SecurityGroups": SECURITY_GROUPS}])
        if op == "describe_volumes":
            return FakePaginator([{"Volumes": EBS_VOLUMES}])
        raise ValueError(f"unexpected paginator op {op}")


class FakeIAM:
    def get_account_summary(self):
        return {"SummaryMap": {"AccountMFAEnabled": 1 if STATE["root_mfa_enabled"] else 0}}

    def get_paginator(self, op):
        if op == "list_users":
            return FakePaginator([{"Users": [{"UserName": "alice"}, {"UserName": "bob"}]}])
        raise ValueError(f"unexpected paginator op {op}")

    def get_login_profile(self, UserName):
        if UserName == "alice":
            return {"UserName": "alice"}
        raise Exception("NoSuchEntity: Login profile not found")  # bob has no console access

    def list_mfa_devices(self, UserName):
        return {"MFADevices": []}

    def list_access_keys(self, UserName):
        if UserName == "alice":
            old_date = datetime.now(timezone.utc) - timedelta(days=120)
            return {"AccessKeyMetadata": [{"AccessKeyId": "AKIAOLDKEY123", "Status": "Active", "CreateDate": old_date}]}
        return {"AccessKeyMetadata": []}


class FakeCloudTrail:
    def describe_trails(self, includeShadowTrails=True):
        if STATE["cloudtrail_raises"]:
            raise Exception("AccessDenied: not authorized to perform cloudtrail:DescribeTrails")
        return {"trailList": STATE["trails"]}

    def get_trail_status(self, Name):
        return {"IsLogging": True}


class FakeRDS:
    def get_paginator(self, op):
        if op == "describe_db_instances":
            return FakePaginator([{"DBInstances": RDS_INSTANCES}])
        raise ValueError(f"unexpected paginator op {op}")


def _fake_clients_factory(cfg):
    return {
        "sts": FakeSTS(), "iam": FakeIAM(), "s3": FakeS3(), "ec2": FakeEC2(),
        "rds": FakeRDS(), "cloudtrail": FakeCloudTrail(), "region": cfg.get("region") or "us-east-1",
    }


_real_clients = cspm._clients
cspm._clients = _fake_clients_factory


def _reset():
    run(db.integrations.delete_many({}))
    run(db.findings.delete_many({}))
    run(db.aws_cspm_scan_runs.delete_many({}))
    run(db.import_jobs.delete_many({}))
    run(db.engagements.delete_many({}))
    STATE["buckets"] = ["public-bucket", "private-bucket"]
    STATE["root_mfa_enabled"] = False
    STATE["trails"] = []
    STATE["cloudtrail_raises"] = False


def _seed_integration():
    doc = {"id": str(uuid.uuid4()), "name": "AWS CSPM", "type": "cloud", "status": "not_configured",
           "config": {"region": "us-east-1", "api_key": "AKIATESTKEY", "api_secret": "testsecretkey"},
           "sync_errors": 0}
    run(db.integrations.insert_one(doc))
    return doc


# ============ full scan: one finding per check on the fixture account ============

_reset()
_seed_integration()
result = run(cspm.run_aws_cspm_scan(db))
assert result["status"] == "success"
summary = result["summary"]
assert summary["account_id"] == "123456789012"
assert summary["checks_run"] == 8
assert summary["checks_failed"] == 0
assert summary["created"] == 8, f"expected 8 findings, got {summary['created']}"
print("PASS: run_aws_cspm_scan() runs all 8 checks and creates exactly one finding per fixture misconfiguration")

findings = run(db.findings.find({"detection_channel": "aws_cspm"}, {"_id": 0}).to_list(20))
by_check = {f["aws_check_id"]: f for f in findings}
assert set(by_check.keys()) == {
    "s3_public_bucket", "sg_open_to_world", "iam_root_no_mfa", "iam_user_console_no_mfa",
    "iam_access_key_stale", "cloudtrail_not_enabled", "rds_publicly_accessible", "ebs_unencrypted",
}
print("PASS: exactly the 8 expected check types fired, no extras (e.g. sg-open8080/internal-db/vol-encrypted correctly not flagged)")

assert by_check["s3_public_bucket"]["asset_hostname"] == "public-bucket"
assert by_check["s3_public_bucket"]["severity"] == "Critical"
assert by_check["sg_open_to_world"]["asset_hostname"] == "sg-open22"
assert by_check["sg_open_to_world"]["severity"] == "Critical"  # admin port 22
assert by_check["iam_root_no_mfa"]["severity"] == "Critical"
assert by_check["iam_user_console_no_mfa"]["asset_hostname"] == "alice"
assert by_check["iam_access_key_stale"]["asset_hostname"] == "AKIAOLDKEY123"
assert by_check["rds_publicly_accessible"]["asset_hostname"] == "prod-db"
assert by_check["ebs_unencrypted"]["asset_hostname"] == "vol-unencrypted"
for f in findings:
    assert f["cloud_provider"] == "aws" and f["cloud_account_id"] == "123456789012"
    assert f["source_tool"] == "AWS CSPM"
    assert f["asset_id"] is None  # no formal asset row -- resource name lives in asset_hostname only
print("PASS: each finding is attributed to the correct AWS resource, with cloud_provider/account_id/source_tool set consistently")

runs = run(db.aws_cspm_scan_runs.find({}, {"_id": 0}).to_list(10))
assert len(runs) == 1
jobs = run(db.import_jobs.find({"source_name": "AWS CSPM"}, {"_id": 0}).to_list(10))
assert len(jobs) == 1 and jobs[0]["created_count"] == 8
engagement = run(db.engagements.find_one({"scanner": "AWS CSPM"}, {"_id": 0}))
assert engagement is not None and engagement["status"] == "completed"
print("PASS: a run record + import_jobs entry + Engagements entry are all written")

# ============ auto-resolve: fixing the S3 bucket + enabling root MFA closes those two ============

STATE["buckets"] = ["private-bucket"]  # public-bucket deleted/fixed
STATE["root_mfa_enabled"] = True
result2 = run(cspm.run_aws_cspm_scan(db))
assert result2["summary"]["auto_closed"] == 2
s3_finding = run(db.findings.find_one({"aws_check_id": "s3_public_bucket"}, {"_id": 0}))
mfa_finding = run(db.findings.find_one({"aws_check_id": "iam_root_no_mfa"}, {"_id": 0}))
assert s3_finding["status"] == "Fixed validated"
assert mfa_finding["status"] == "Fixed validated"
assert "auto-closed" in s3_finding["verification_note"]
print("PASS: fixing a misconfiguration in AWS auto-closes its finding on the next full-account sweep")

# ============ reopen semantics ============

STATE["buckets"] = ["public-bucket", "private-bucket"]  # bucket goes public again
result3 = run(cspm.run_aws_cspm_scan(db))
s3_finding2 = run(db.findings.find_one({"aws_check_id": "s3_public_bucket"}, {"_id": 0}))
assert s3_finding2["status"] == "Reopened"
assert s3_finding2["reopened_count"] == 1
print("PASS: a closed finding whose misconfiguration reappears is reopened, not silently left closed")

# ============ one failing check doesn't take down the whole scan ============

_reset()
_seed_integration()
STATE["cloudtrail_raises"] = True
result4 = run(cspm.run_aws_cspm_scan(db))
assert result4["status"] == "success"  # 1 of 8 checks failing shouldn't fail the whole run
assert result4["summary"]["checks_failed"] == 1
assert result4["errors"][0]["stage"] == "_check_cloudtrail"
cloudtrail_finding = run(db.findings.find_one({"aws_check_id": "cloudtrail_not_enabled"}, {"_id": 0}))
assert cloudtrail_finding is None  # the check errored, it never ran to completion
print("PASS: a permissions error on one check (e.g. missing cloudtrail:DescribeTrails) is isolated -- the other 7 checks still run and the scan is still reported as a success")
STATE["cloudtrail_raises"] = False

# ============ clean failure modes ============

_reset()
doc = {"id": str(uuid.uuid4()), "name": "AWS CSPM", "type": "cloud", "status": "not_configured",
       "config": {"region": "us-east-1"}, "sync_errors": 0}
run(db.integrations.insert_one(doc))
try:
    run(cspm.run_aws_cspm_scan(db))
    assert False, "should have raised"
except RuntimeError as e:
    assert "missing access key" in str(e).lower()
print("PASS: missing access key/secret raises a clear error before any AWS calls are attempted")

_reset()
try:
    run(cspm.run_aws_cspm_scan(db))
    assert False, "should have raised"
except RuntimeError as e:
    assert "not found" in str(e)
print("PASS: scanning with no AWS CSPM integration configured at all raises clearly")

# ============ routes ============

_reset()
_seed_integration()
r = client.post("/api/v1/admin/aws-cspm/scan/run")
assert r.status_code == 200, r.text
assert r.json()["status"] == "running"
print("PASS: POST /v1/admin/aws-cspm/scan/run starts a background scan and returns immediately")


async def _wait_for_run():
    for _ in range(50):
        await asyncio.sleep(0.05)
        d = await db.aws_cspm_scan_runs.find_one({}, {"_id": 0})
        if d and d.get("status") != "running":
            return d
    return await db.aws_cspm_scan_runs.find_one({}, {"_id": 0})


final = run(_wait_for_run())
assert final is not None and final["status"] == "success"
print("PASS: the background scan job completes and replaces the 'running' placeholder row")

r2 = client.get("/api/v1/admin/aws-cspm/scan/runs")
assert r2.status_code == 200 and len(r2.json()["items"]) >= 1
print("PASS: GET /v1/admin/aws-cspm/scan/runs lists past run history")

run(db.aws_cspm_scan_runs.insert_one({"id": "already-running-1", "status": "running", "ran_at": cspm._now_iso(), "summary": {}, "errors": []}))
r3 = client.post("/api/v1/admin/aws-cspm/scan/run")
assert r3.status_code == 200 and r3.json()["id"] == "already-running-1"
run(db.aws_cspm_scan_runs.delete_one({"id": "already-running-1"}))
print("PASS: triggering a scan while one is already running returns the in-progress job instead of starting a duplicate")

# ============ /v1/integrations/{id}/test + PATCH status-lift (AWS has no "endpoint") ============

_reset()
integration = _seed_integration()
r4 = client.post(f"/api/v1/integrations/{integration['id']}/test")
assert r4.status_code == 200, r4.text
assert "123456789012" in r4.json()["message"]
print("PASS: POST /v1/integrations/{id}/test authenticates via STS GetCallerIdentity for AWS CSPM (no generic endpoint check applied)")

_reset()
doc2 = {"id": str(uuid.uuid4()), "name": "AWS CSPM", "type": "cloud", "status": "not_configured", "config": {}, "sync_errors": 0}
run(db.integrations.insert_one(doc2))
r5 = client.patch(f"/api/v1/integrations/{doc2['id']}", json={"region": "us-west-2", "api_key": "AKIANEW", "api_secret": "secretnew"})
assert r5.status_code == 200
saved = run(db.integrations.find_one({"id": doc2["id"]}, {"_id": 0}))
assert saved["status"] == "healthy"  # lifted despite no "endpoint" ever being set
assert saved["config"]["region"] == "us-west-2"
print("PASS: PATCH /v1/integrations/{id} lifts AWS CSPM's status to healthy on region+key pair alone, with no endpoint field required")

# ============ feature flag + seed wiring ============

import feature_flags
assert "aws_cspm_nightly_scan" in feature_flags.FLAG_KEYS
print("PASS: aws_cspm_nightly_scan is registered in the feature flag registry")

import seed
assert any(s["name"] == "AWS CSPM" for s in seed.SCANNERS)
print("PASS: 'AWS CSPM' integration card is seeded")

cspm._clients = _real_clients

print("\nALL AWS CSPM CONNECTOR TESTS PASSED")
