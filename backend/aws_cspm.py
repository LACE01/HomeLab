"""AWS Cloud Security Posture Management (CSPM) -- a focused, opinionated set of
misconfiguration checks against one connected AWS account, using read-only IAM
credentials. Scoped deliberately to AWS only for this first pass (not Azure/GCP
too) -- see the task tracker note this was built under for why; nothing about
the shape here is AWS-specific enough to block adding another cloud later.

This is this app's OWN scanner (boto3 read calls + rule evaluation), not a
wrapper around AWS Security Hub/Config -- so it works on any account, including
ones with Security Hub never enabled, at the cost of being a narrower rule set
than a mature CSPM product. Eight checks are implemented, chosen as the most
commonly-flagged, highest-signal misconfigurations across the services a typical
small-to-mid AWS account actually uses -- this is NOT AWS Config Rules/Security
Hub-equivalent coverage (that's hundreds of rules across dozens of services):

  1. S3 buckets publicly accessible (Block Public Access + bucket policy/ACL)
  2. Security groups with an inbound rule open to 0.0.0.0/0 or ::/0
  3. Root account has no MFA device
  4. IAM users with console access but no MFA device
  5. IAM access keys older than 90 days (no rotation)
  6. No CloudTrail trail visible from the configured region that is actively logging
  7. RDS instances marked publicly accessible
  8. Unencrypted EBS volumes

Scope limits, explicit: EC2/RDS/EBS checks only look at the ONE region the
integration is configured for (add another Integrations row per region to cover
more -- this app doesn't yet auto-fan-out across all enabled regions in a
single account). IAM and S3 are genuinely global/region-agnostic AWS APIs, so
those two checks always cover the whole account regardless of the configured
region.

Every check function is plain synchronous boto3 (list/describe/get calls)
called directly from inside `run_aws_cspm_scan` (an `async def`) -- the same
"small, infrequent, bounded" trade-off backup.py's off-site S3 upload already
makes in this codebase, not wrapped in `asyncio.to_thread`/an executor. A CSPM
sweep is a handful of read-only list/describe calls once an hour at most, not
a hot path worth the added complexity.

Findings here don't have a natural 1:1 asset the way a host-based finding
does (a public S3 bucket or an IAM user isn't an "asset" in this app's
inventory sense) -- same design choice domain_email_security.py and
secrets_scan.py already made: `asset_hostname` carries a human-readable
resource identifier (bucket name, security group ID, IAM user name, etc.)
and no db.assets row is created or required. Risk scoring (compute_risk/
compute_sla_days, which need a real asset's criticality/exposure) is skipped
for the same reason -- these findings carry a severity but no risk_score.
"""
import asyncio
import logging
import uuid
from datetime import datetime, timezone, timedelta

logger = logging.getLogger("vulnops.aws_cspm")

OPEN_STATES = ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]

SENSITIVE_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
                    1433: "MSSQL", 6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch"}
ADMIN_PORTS = {22, 3389}
STALE_KEY_DAYS = 90


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _get_integration(db) -> dict | None:
    return await db.integrations.find_one({"name": "AWS CSPM"}, {"_id": 0})


def _clients(cfg: dict) -> dict:
    import boto3
    kwargs = {}
    if cfg.get("api_key") and cfg.get("api_secret"):
        kwargs["aws_access_key_id"] = cfg["api_key"]
        kwargs["aws_secret_access_key"] = cfg["api_secret"]
    region = cfg.get("region") or "us-east-1"
    session = boto3.Session(region_name=region, **kwargs)
    return {
        "sts": session.client("sts"),
        "iam": session.client("iam"),
        "s3": session.client("s3"),
        "ec2": session.client("ec2"),
        "rds": session.client("rds"),
        "cloudtrail": session.client("cloudtrail"),
        "region": region,
    }


def _finding_stub(check_id: str, resource_type: str, resource_id: str, title: str,
                   description: str, severity: str, remediation: str, region: str | None,
                   cwe: str | None = None, arn: str | None = None) -> dict:
    return {
        "check_id": check_id, "resource_type": resource_type, "resource_id": resource_id,
        "title": title, "description": description, "severity": severity,
        "remediation": remediation, "region": region, "cwe": cwe, "arn": arn,
    }


# --------------------------- individual checks ---------------------------
# Each returns (list_of_finding_stubs, error_or_None) -- a permissions gap on one
# check (e.g. a least-privilege role missing cloudtrail:DescribeTrails) must never
# take down the other seven.

def _check_s3_public_buckets(clients: dict) -> tuple[list, str | None]:
    s3 = clients["s3"]
    out = []
    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except Exception as e:
        return [], f"list_buckets: {e}"

    for b in buckets:
        name = b["Name"]
        is_public = False
        reason = None
        try:
            status = s3.get_bucket_policy_status(Bucket=name)
            if status.get("PolicyStatus", {}).get("IsPublic"):
                is_public, reason = True, "bucket policy grants public access"
        except Exception:
            pass  # no policy at all is common and not itself an error
        if not is_public:
            try:
                acl = s3.get_bucket_acl(Bucket=name)
                for grant in acl.get("Grants", []):
                    uri = (grant.get("Grantee") or {}).get("URI", "")
                    if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                        is_public, reason = True, "bucket ACL grants access to all/authenticated users"
                        break
            except Exception:
                pass
        if is_public:
            try:
                pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                if all(pab.get(k) for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")):
                    is_public = False  # fully blocked at the account/bucket level despite the policy/ACL
            except Exception:
                pass  # no Block Public Access config at all -- stays flagged
        if is_public:
            out.append(_finding_stub(
                "s3_public_bucket", "s3_bucket", name,
                f"S3 bucket \"{name}\" is publicly accessible",
                f"Bucket \"{name}\" {reason} and Block Public Access is not fully enabled for it.",
                "Critical",
                "Enable S3 Block Public Access for this bucket (or the whole account), and remove the public bucket policy/ACL grant unless the bucket is intentionally public (e.g. static website hosting).",
                None, cwe="CWE-284",
            ))
    return out, None


def _check_security_groups_open(clients: dict) -> tuple[list, str | None]:
    ec2 = clients["ec2"]
    region = clients["region"]
    out = []
    try:
        paginator = ec2.get_paginator("describe_security_groups")
        groups = []
        for page in paginator.paginate():
            groups.extend(page.get("SecurityGroups", []))
    except Exception as e:
        return [], f"describe_security_groups: {e}"

    for sg in groups:
        for perm in sg.get("IpPermissions", []):
            open_ranges = [r["CidrIp"] for r in perm.get("IpRanges", []) if r.get("CidrIp") in ("0.0.0.0/0",)]
            open_ranges += [r["CidrIpv6"] for r in perm.get("Ipv6Ranges", []) if r.get("CidrIpv6") in ("::/0",)]
            if not open_ranges:
                continue
            from_port, to_port = perm.get("FromPort"), perm.get("ToPort")
            is_all_traffic = perm.get("IpProtocol") == "-1"
            hit_ports = [] if is_all_traffic else [
                p for p in SENSITIVE_PORTS if from_port is not None and to_port is not None and from_port <= p <= to_port
            ]
            if not is_all_traffic and not hit_ports:
                continue  # open to the world, but only on a non-sensitive port -- not flagged in this v1 scope
            severity = "Critical" if is_all_traffic or any(p in ADMIN_PORTS for p in hit_ports) else "High"
            port_desc = "all ports/protocols" if is_all_traffic else ", ".join(f"{SENSITIVE_PORTS[p]} ({p})" for p in hit_ports)
            out.append(_finding_stub(
                "sg_open_to_world", "security_group", sg["GroupId"],
                f"Security group \"{sg.get('GroupName', sg['GroupId'])}\" is open to the internet",
                f"Security group {sg['GroupId']} ({sg.get('GroupName')}) allows inbound traffic from anywhere ({', '.join(open_ranges)}) on {port_desc}.",
                severity,
                "Restrict this rule's source to specific known IP ranges (e.g. a VPN or office CIDR), or remove it and use a bastion/SSM Session Manager instead of direct exposure.",
                region, cwe="CWE-284",
            ))
    return out, None


def _check_iam_root_mfa(clients: dict) -> tuple[list, str | None]:
    iam = clients["iam"]
    try:
        summary = iam.get_account_summary().get("SummaryMap", {})
    except Exception as e:
        return [], f"get_account_summary: {e}"
    if summary.get("AccountMFAEnabled") == 0:
        return [_finding_stub(
            "iam_root_no_mfa", "iam_root", "root-account",
            "AWS account root user has no MFA device",
            "The root user for this AWS account can sign in with only a password -- no multi-factor authentication is configured.",
            "Critical",
            "Sign in as root and enable a hardware or virtual MFA device immediately (IAM -> root user -> Security credentials). The root user should also not be used for day-to-day work at all.",
            None, cwe="CWE-308",
        )], None
    return [], None


def _check_iam_user_mfa(clients: dict) -> tuple[list, str | None]:
    iam = clients["iam"]
    out = []
    try:
        paginator = iam.get_paginator("list_users")
        users = []
        for page in paginator.paginate():
            users.extend(page.get("Users", []))
    except Exception as e:
        return [], f"list_users: {e}"

    for u in users:
        username = u["UserName"]
        try:
            iam.get_login_profile(UserName=username)  # raises NoSuchEntity if no console access
        except Exception:
            continue  # no console access at all -- MFA not applicable to this user
        try:
            mfa = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
        except Exception as e:
            continue
        if not mfa:
            out.append(_finding_stub(
                "iam_user_console_no_mfa", "iam_user", username,
                f"IAM user \"{username}\" has console access but no MFA",
                f"IAM user {username} can sign in to the AWS Console with just a password -- no MFA device is registered.",
                "High",
                f"Have {username} register an MFA device (IAM -> Users -> {username} -> Security credentials), or enforce it account-wide via an IAM policy condition requiring aws:MultiFactorAuthPresent.",
                None, cwe="CWE-308",
            ))
    return out, None


def _check_iam_stale_access_keys(clients: dict, max_age_days: int = STALE_KEY_DAYS) -> tuple[list, str | None]:
    iam = clients["iam"]
    out = []
    try:
        paginator = iam.get_paginator("list_users")
        users = []
        for page in paginator.paginate():
            users.extend(page.get("Users", []))
    except Exception as e:
        return [], f"list_users: {e}"

    cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)
    for u in users:
        username = u["UserName"]
        try:
            keys = iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
        except Exception:
            continue
        for k in keys:
            if k.get("Status") != "Active":
                continue
            created = k.get("CreateDate")
            if created and created.replace(tzinfo=timezone.utc) < cutoff:
                age_days = (datetime.now(timezone.utc) - created.replace(tzinfo=timezone.utc)).days
                out.append(_finding_stub(
                    "iam_access_key_stale", "iam_access_key", k["AccessKeyId"],
                    f"IAM access key for \"{username}\" hasn't been rotated in {age_days} days",
                    f"Access key {k['AccessKeyId']} for user {username} was created {age_days} days ago (created {created.date()}) and is still active.",
                    "Medium",
                    f"Rotate this access key: create a new one, update whatever uses {k['AccessKeyId']}, then deactivate and delete the old one. Consider IAM roles instead of long-lived keys where possible.",
                    None,
                ))
    return out, None


def _check_cloudtrail(clients: dict) -> tuple[list, str | None]:
    ct = clients["cloudtrail"]
    region = clients["region"]
    try:
        trails = ct.describe_trails(includeShadowTrails=True).get("trailList", [])
    except Exception as e:
        return [], f"describe_trails: {e}"

    if not trails:
        return [_finding_stub(
            "cloudtrail_not_enabled", "cloudtrail", "account",
            "No CloudTrail trail is configured",
            f"No CloudTrail trail is visible from region {region} for this account -- API activity is not being logged at all.",
            "High",
            "Create a multi-region CloudTrail trail delivering to a dedicated, access-restricted S3 bucket, and enable log file validation.",
            region, cwe="CWE-778",
        )], None

    for t in trails:
        name = t.get("Name")
        try:
            status = ct.get_trail_status(Name=t.get("TrailARN") or name)
        except Exception:
            continue
        if status.get("IsLogging"):
            return [], None  # at least one actively-logging trail is enough to consider this check passed

    return [_finding_stub(
        "cloudtrail_not_enabled", "cloudtrail", "account",
        "CloudTrail exists but no trail is actively logging",
        f"{len(trails)} CloudTrail trail(s) exist but none currently has logging enabled.",
        "High",
        "Enable logging on an existing trail (CloudTrail console -> trail -> Start logging), or create a new multi-region trail.",
        region, cwe="CWE-778",
    )], None


def _check_rds_public(clients: dict) -> tuple[list, str | None]:
    rds = clients["rds"]
    region = clients["region"]
    out = []
    try:
        paginator = rds.get_paginator("describe_db_instances")
        instances = []
        for page in paginator.paginate():
            instances.extend(page.get("DBInstances", []))
    except Exception as e:
        return [], f"describe_db_instances: {e}"

    for db_inst in instances:
        if db_inst.get("PubliclyAccessible"):
            out.append(_finding_stub(
                "rds_publicly_accessible", "rds_instance", db_inst["DBInstanceIdentifier"],
                f"RDS instance \"{db_inst['DBInstanceIdentifier']}\" is publicly accessible",
                f"RDS instance {db_inst['DBInstanceIdentifier']} ({db_inst.get('Engine')}) has PubliclyAccessible=true and can be reached directly from the internet if its security group allows it.",
                "Critical",
                "Set PubliclyAccessible to false (Modify -> Connectivity), and connect to it only from within the VPC (e.g. via a bastion or VPN).",
                region, cwe="CWE-284",
            ))
    return out, None


def _check_ebs_unencrypted(clients: dict) -> tuple[list, str | None]:
    ec2 = clients["ec2"]
    region = clients["region"]
    out = []
    try:
        paginator = ec2.get_paginator("describe_volumes")
        volumes = []
        for page in paginator.paginate():
            volumes.extend(page.get("Volumes", []))
    except Exception as e:
        return [], f"describe_volumes: {e}"

    for v in volumes:
        if not v.get("Encrypted"):
            out.append(_finding_stub(
                "ebs_unencrypted", "ebs_volume", v["VolumeId"],
                f"EBS volume \"{v['VolumeId']}\" is not encrypted",
                f"EBS volume {v['VolumeId']} ({v.get('Size')} GiB, {v.get('State')}) has no encryption at rest.",
                "Medium",
                "Create an encrypted snapshot of this volume and a new encrypted volume from it (existing volumes can't be encrypted in-place), then swap it in during a maintenance window. Enable \"Encryption by default\" for this region so new volumes are encrypted automatically.",
                region, cwe="CWE-311",
            ))
    return out, None


CHECKS = [
    _check_s3_public_buckets,
    _check_security_groups_open,
    _check_iam_root_mfa,
    _check_iam_user_mfa,
    _check_iam_stale_access_keys,
    _check_cloudtrail,
    _check_rds_public,
    _check_ebs_unencrypted,
]


async def _notify_cspm_finding(db, stub: dict, account_id: str, finding_id: str):
    from notifier import dispatch
    try:
        await dispatch("aws_cspm_finding", {
            "title": stub["title"], "severity": stub["severity"], "account_id": account_id,
            "resource_id": stub["resource_id"], "url": f"/findings/{finding_id}",
        }, db)
    except Exception:
        pass


async def run_aws_cspm_scan(db) -> dict:
    """Runs every check against the configured AWS account, upserts/auto-resolves
    findings, writes a run + import_jobs + Engagements record."""
    integration = await _get_integration(db)
    if not integration:
        raise RuntimeError("AWS CSPM integration not found")
    cfg = integration.get("config") or {}
    if not (cfg.get("api_key") and cfg.get("api_secret")):
        raise RuntimeError("AWS CSPM integration missing access key ID / secret access key")

    started_at = _now_iso()
    clients = _clients(cfg)

    try:
        account_id = clients["sts"].get_caller_identity()["Account"]
    except Exception as e:
        errors = [{"stage": "auth", "error": str(e)}]
        return await _record_run(db, "failed", {"started_at": started_at, "checks_run": 0,
                                                  "created": 0, "updated": 0, "failed": 1}, errors, None)

    all_stubs: list[dict] = []
    errors: list = []
    for check_fn in CHECKS:
        try:
            stubs, err = check_fn(clients)
        except Exception as e:
            stubs, err = [], str(e)
        if err:
            errors.append({"stage": check_fn.__name__, "error": err})
        all_stubs.extend(stubs)

    created = updated = 0
    seen_keys = set()
    now = _now_iso()
    for stub in all_stubs:
        canonical = f"aws-cspm:{account_id}:{stub['check_id']}:{stub['resource_id']}"
        seen_keys.add(canonical)
        existing = await db.findings.find_one({"canonical_key": canonical}, {"_id": 0})
        base = {
            "title": stub["title"], "description": stub["description"], "severity": stub["severity"],
            "remediation": stub["remediation"], "cwe": stub.get("cwe"),
            "source_tool": "AWS CSPM", "source_tool_type": "Cloud Security Posture Management",
            "detection_channel": "aws_cspm",
            "asset_hostname": stub["resource_id"], "asset_id": None,
            "cloud_provider": "aws", "cloud_account_id": account_id,
            "cloud_region": stub.get("region"), "aws_resource_type": stub["resource_type"],
            "aws_check_id": stub["check_id"],
            "last_seen_at": now,
        }
        if existing:
            new_status = existing["status"]
            reopened = existing.get("reopened_count", 0)
            if existing["status"] in ("Fixed validated", "Mitigated", "Closed administratively"):
                new_status = "Reopened"
                reopened += 1
            base["status"] = new_status
            base["reopened_count"] = reopened
            base["first_seen_at"] = existing["first_seen_at"]
            base["canonical_key"] = canonical
            await db.findings.update_one({"id": existing["id"]}, {"$set": base})
            updated += 1
        else:
            finding = {
                "id": str(uuid.uuid4()), "canonical_key": canonical,
                "first_seen_at": now, "reopened_count": 0,
                "status": "New", "validation_status": "pending",
                "rti": [], "tags": ["aws", "cspm"],
                **base,
            }
            await db.findings.insert_one(finding)
            created += 1
            if stub["severity"] in ("Critical", "High"):
                await _notify_cspm_finding(db, stub, account_id, finding["id"])

    # Auto-resolve: this is a full-account sweep every run (unlike Tenable's
    # partial-batch-of-scans case), so absence really does mean "no longer true".
    prior = await db.findings.find(
        {"detection_channel": "aws_cspm", "cloud_account_id": account_id, "status": {"$in": OPEN_STATES}},
        {"_id": 0},
    ).to_list(5000)
    resolved = 0
    for f in prior:
        if f.get("canonical_key") not in seen_keys:
            await db.findings.update_one({"id": f["id"]}, {"$set": {
                "status": "Fixed validated", "last_changed_at": _now_iso(),
                "verification_status": "passed",
                "verification_note": "No longer detected on the most recent AWS CSPM scan of this account -- auto-closed.",
            }})
            resolved += 1

    summary = {
        "started_at": started_at, "account_id": account_id, "region": clients["region"],
        "checks_run": len(CHECKS), "checks_failed": len(errors),
        "findings_found": len(all_stubs), "created": created, "updated": updated,
        "auto_closed": resolved,
    }
    status = "success" if len(errors) < len(CHECKS) else "failed"
    await db.integrations.update_one(
        {"id": integration["id"]},
        {"$set": {"status": "healthy" if status == "success" else "degraded",
                  "last_sync_at": _now_iso(),
                  "sync_errors": 0 if status == "success" else (integration.get("sync_errors", 0) + 1)}},
    )
    from routes.common import record_engagement
    await record_engagement(
        db, name=f"AWS CSPM scan — {started_at[:10]}", scanner="AWS CSPM",
        scan_type="scheduled", scan_method="api",
        status="completed" if status == "success" else "failed",
        assets_scanned=1, findings_created=created, findings_updated=updated,
        started_at=started_at, error="; ".join(str(e.get("error")) for e in errors[:3]) if errors else None,
    )
    return await _record_run(db, status, summary, errors, account_id)


async def _record_run(db, status: str, summary: dict, errors: list, account_id: str | None):
    doc = {
        "id": str(uuid.uuid4()), "ran_at": _now_iso(), "status": status,
        "summary": summary, "errors": errors[:50],
    }
    await db.aws_cspm_scan_runs.insert_one(dict(doc))
    await db.import_jobs.insert_one({
        "id": doc["id"], "source_name": "AWS CSPM", "mode": "live_sync", "status": status,
        "request_id": f"awscspm_{doc['id'][:12]}",
        "started_at": summary.get("started_at", doc["ran_at"]), "finished_at": doc["ran_at"],
        "created_count": summary.get("created", 0), "updated_count": summary.get("updated", 0),
        "deduplicated_count": summary.get("updated", 0), "failed_count": summary.get("checks_failed", 0),
        "retry_count": 0, "errors": errors[:50],
    })
    return doc


async def aws_cspm_poll_loop(db, interval_hours: int = 24):
    """Background poll -- skips silently if AWS CSPM isn't configured. Gated by
    the aws_cspm_nightly_scan feature flag; manual "Scan now" is never gated."""
    from heartbeat import record_heartbeat
    from feature_flags import is_enabled
    await asyncio.sleep(35)
    while True:
        ok, detail = True, {}
        try:
            integration = await _get_integration(db)
            cfg = (integration or {}).get("config") or {}
            configured = bool(cfg.get("api_key") and cfg.get("api_secret"))
            if configured and await is_enabled(db, "aws_cspm_nightly_scan"):
                logger.info("AWS CSPM poll: running scan")
                run = await run_aws_cspm_scan(db)
                logger.info(f"AWS CSPM poll done: {run.get('summary')}")
                detail["summary"] = run.get("summary")
            elif not configured:
                detail["skipped"] = "not configured"
            else:
                detail["skipped"] = "disabled in Settings"
        except Exception as e:
            logger.exception(f"AWS CSPM poll error: {e}")
            ok, detail["error"] = False, str(e)
        await record_heartbeat(db, "aws_cspm_poll_loop", "ok" if ok else "error", detail)
        await asyncio.sleep(interval_hours * 3600)
