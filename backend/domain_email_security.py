"""Email domain authentication monitoring: SPF, DKIM, DMARC.

Checks whether a domain has properly configured email-authentication records,
which make it much harder for an attacker to send phishing/BEC mail that
appears to come "From:" that domain. Mirrors cert_monitor.py's overall shape --
periodic DNS lookup -> per-check severity classification -> finding
create/update/auto-resolve keyed by a canonical_key -> notification dispatch on
new findings -> background loop with heartbeat -> concurrency-capped batch
runner over a db.domain_watch_targets collection -- but unlike a TLS cert
(one pass/fail per hostname:port), a domain's email-auth posture has three
independent axes (SPF, DKIM, DMARC) that can each be broken on their own, so
each gets its own finding rather than collapsing to a single severity.

Uses dnspython (already pinned in requirements.txt) for TXT record lookups.
SPF and DMARC are both discoverable via one well-known DNS query each (the
domain's own root TXT record, and the TXT record at _dmarc.<domain>,
respectively). DKIM has no equivalent universal discovery mechanism -- a
domain's DKIM selector is an arbitrary name chosen by whatever mail
provider/ESP it uses, and that name isn't published anywhere in DNS itself.
So the DKIM check here is necessarily a best-effort probe against a list of
selector names commonly used by major providers (Google Workspace, Microsoft
365, SendGrid, Mailchimp/Mandrill, Amazon SES, Zoho) -- it can prove DKIM
*is* configured, but can never definitively prove it's absent, and that
distinction is carried through into the result/finding text rather than
glossed over.
"""
import uuid
from datetime import datetime, timezone

import dns.resolver


def _now():
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now().isoformat()


def _txt_strings(name: str) -> list:
    """Resolves a TXT record set for `name` and returns each record as one
    flattened string. A single TXT record can be split across multiple quoted
    segments by DNS -- dnspython represents that as multiple entries in
    rdata.strings that must be concatenated back together, not treated as
    separate records. Returns [] for NXDOMAIN/no-answer rather than raising,
    since "no TXT record here" is itself a meaningful, common result."""
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=8.0)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    out = []
    for rdata in answers:
        out.append("".join(
            s.decode("utf-8", "replace") if isinstance(s, bytes) else s
            for s in rdata.strings
        ))
    return out


def check_spf(domain: str) -> dict:
    """Looks up the domain's root TXT records and picks out any SPF record(s)."""
    records = [r for r in _txt_strings(domain) if r.lower().startswith("v=spf1")]
    record = records[0] if records else None
    all_mechanism = None
    if record:
        for mech in ("-all", "~all", "?all", "+all"):
            if mech in record:
                all_mechanism = mech
                break
    return {
        "present": bool(records), "record": record, "record_count": len(records),
        "all_mechanism": all_mechanism, "checked_at": _now_iso(),
    }


def check_dmarc(domain: str) -> dict:
    """Looks up _dmarc.<domain>'s TXT record and parses its tag=value pairs."""
    records = [r for r in _txt_strings(f"_dmarc.{domain}") if r.lower().startswith("v=dmarc1")]
    record = records[0] if records else None
    policy = rua = ruf = pct = None
    if record:
        tags = {}
        for part in record.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                tags[k.strip().lower()] = v.strip()
        policy, rua, ruf, pct = tags.get("p"), tags.get("rua"), tags.get("ruf"), tags.get("pct")
    return {
        "present": bool(records), "record": record, "policy": policy,
        "rua": rua, "ruf": ruf, "pct": pct, "checked_at": _now_iso(),
    }


# Common DKIM selector names used by major mail providers/ESPs -- see module
# docstring for why this is a best-effort list rather than a definitive lookup.
COMMON_DKIM_SELECTORS = [
    "google", "selector1", "selector2",  # Google Workspace; Microsoft 365
    "k1", "k2",                          # Mailchimp / Mandrill
    "s1", "s2",                          # SendGrid
    "dkim", "mail", "default", "smtp", "mx",
    "amazonses", "zoho",
]


def check_dkim(domain: str, selectors: list = None) -> dict:
    """Best-effort DKIM probe -- tries each candidate selector's DNS name and
    keeps any that resolve to something that looks like a DKIM key record."""
    selectors = selectors or COMMON_DKIM_SELECTORS
    found = []
    for sel in selectors:
        for r in _txt_strings(f"{sel}._domainkey.{domain}"):
            low = r.lower()
            if "v=dkim1" in low or "p=" in low:
                found.append(sel)
                break
    return {
        "found_selectors": found, "checked_selectors": selectors,
        "best_effort": True, "checked_at": _now_iso(),
    }


def classify(spf: dict, dmarc: dict, dkim: dict) -> list:
    """Returns a list of (check_type, severity, reason) tuples, one per issue
    actually found -- zero, one, two, or all three of SPF/DMARC/DKIM can be
    flagged independently for the same domain."""
    issues = []

    if not spf.get("present"):
        issues.append(("spf", "High",
            "No SPF record found -- receiving mail servers have no way to verify that a "
            "message claiming to be from this domain actually came from an authorized "
            "sending server, making the domain trivial to spoof in phishing/BEC mail."))
    elif spf.get("record_count", 0) > 1:
        issues.append(("spf", "High",
            f"Multiple SPF records found ({spf['record_count']}) -- this is an RFC 7208 "
            "violation, and many mail servers will treat it as a permanent SPF failure "
            "for ALL legitimate mail from this domain, not just spoofed mail."))
    elif spf.get("all_mechanism") in (None, "+all"):
        issues.append(("spf", "Medium",
            "SPF record doesn't end in a -all/~all mechanism (or explicitly allows +all) -- "
            "it fails to tell receiving servers to reject or quarantine mail that fails "
            "the SPF check."))

    if not dmarc.get("present"):
        issues.append(("dmarc", "High",
            "No DMARC record found -- there's no policy telling mail receivers what to do "
            "with messages that fail SPF/DKIM, and no aggregate reporting visibility into "
            "who is currently sending mail as this domain (including spoofing attempts)."))
    elif dmarc.get("policy") == "none":
        issues.append(("dmarc", "Medium",
            "DMARC policy is p=none (monitor-only) -- mail that fails SPF/DKIM alignment is "
            "still delivered as normal rather than rejected or quarantined."))
    elif not dmarc.get("rua"):
        issues.append(("dmarc", "Low",
            "DMARC has no rua aggregate-reporting address configured -- you won't receive "
            "the daily/weekly reports that show who is sending mail as this domain."))

    if not dkim.get("found_selectors"):
        issues.append(("dkim", "Low",
            "No DKIM record found under any commonly-used selector name. This is a "
            "best-effort check only -- a nonstandard selector wouldn't be detected by it -- "
            "so treat this as a prompt to verify manually with your mail provider, not "
            "definitive proof DKIM is unconfigured."))

    return issues


async def _notify_domain_issue(db, domain, check_type, severity, reason, finding_id):
    from notifier import dispatch
    try:
        await dispatch("email_auth_issue", {
            "domain": domain, "check_type": check_type.upper(), "severity": severity,
            "reason": reason, "url": f"/findings/{finding_id}",
        }, db)
    except Exception:
        pass


OPEN_STATES = ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]


async def run_domain_check(db, domain: str, asset_id: str = None, label: str = None) -> dict:
    """Checks one domain's SPF/DKIM/DMARC, upserts the result into
    domain_email_security, and creates/updates/auto-resolves up to three
    independent findings (one per check type) based on current status.
    Idempotent -- re-running just updates the existing records/findings."""
    now = _now_iso()

    try:
        spf = check_spf(domain)
    except Exception as e:
        spf = {"present": False, "error": str(e), "checked_at": now}
    try:
        dmarc = check_dmarc(domain)
    except Exception as e:
        dmarc = {"present": False, "error": str(e), "checked_at": now}
    try:
        dkim = check_dkim(domain)
    except Exception as e:
        dkim = {"found_selectors": [], "error": str(e), "checked_at": now}

    issues = classify(spf, dmarc, dkim)
    issues_by_type = {check_type: (severity, reason) for check_type, severity, reason in issues}

    result = {
        "id": domain, "domain": domain, "asset_id": asset_id, "label": label,
        "spf": spf, "dmarc": dmarc, "dkim": dkim,
        "issues": [{"check": t, "severity": s, "reason": r} for t, s, r in issues],
        "checked_at": now,
    }
    await db.domain_email_security.update_one({"id": domain}, {"$set": result}, upsert=True)

    asset = await db.assets.find_one({"id": asset_id}, {"_id": 0}) if asset_id else None
    for check_type in ("spf", "dmarc", "dkim"):
        canonical_key = f"email-auth:{domain}:{check_type}"
        existing = await db.findings.find_one({"canonical_key": canonical_key}, {"_id": 0})
        issue = issues_by_type.get(check_type)

        if issue:
            severity, reason = issue
            if existing and existing.get("status") in OPEN_STATES:
                await db.findings.update_one({"id": existing["id"]}, {"$set": {
                    "severity": severity, "description": reason, "last_seen_at": now,
                }})
            elif not existing:
                finding = {
                    "id": str(uuid.uuid4()), "canonical_key": canonical_key,
                    "title": f"Email authentication issue ({check_type.upper()}) -- {domain}",
                    "description": reason, "severity": severity, "status": "New",
                    "source_tool": "Email Auth Monitor", "source_tool_type": "Domain Security Monitoring",
                    "detection_channel": "Scheduled DNS check",
                    "asset_id": asset_id, "asset_hostname": (asset or {}).get("hostname") or domain,
                    "asset_ip": (asset or {}).get("ip"), "asset_criticality": (asset or {}).get("criticality"),
                    "asset_exposure": (asset or {}).get("exposure"), "protocol": "tcp", "service": "smtp",
                    "first_seen_at": now, "last_seen_at": now,
                    "rti": [], "cwe": "CWE-290" if check_type in ("spf", "dmarc") else None,
                }
                await db.findings.insert_one(finding)
                await _notify_domain_issue(db, domain, check_type, severity, reason, finding["id"])
            # If it exists but was already fixed/accepted, leave it alone -- a human
            # closed it and a re-check shouldn't silently reopen it.
        elif existing and existing.get("status") in OPEN_STATES:
            await db.findings.update_one({"id": existing["id"]}, {"$set": {
                "status": "Fixed validated", "resolved_at": now,
                "resolution_note": f"{check_type.upper()} check passed on re-scan.",
            }})

    return result


async def domain_email_monitor_loop(db, interval_hours: int = 24):
    """Background poll -- checks all enabled watch targets once per interval.
    Gated by the email_auth_nightly_check feature flag (default on) -- manual
    "Check now"/"Check all" actions from the UI are never gated, only this
    automatic sweep, same convention as the other Scheduled Syncs flags."""
    import asyncio
    import logging
    from heartbeat import record_heartbeat
    from feature_flags import is_enabled
    logger = logging.getLogger("vulnops")
    await asyncio.sleep(50)  # let other startup tasks settle first
    while True:
        ok, detail = True, {}
        try:
            if await is_enabled(db, "email_auth_nightly_check"):
                result = await run_all_domain_checks(db)
                logger.info(f"Email auth check: {result}")
                detail = result
            else:
                detail = {"skipped": "disabled in Settings"}
        except Exception as e:
            logger.exception(f"Email auth check failed: {e}")
            ok, detail["error"] = False, str(e)
        await record_heartbeat(db, "domain_email_monitor_loop", "ok" if ok else "error", detail)
        await asyncio.sleep(interval_hours * 3600)


async def run_all_domain_checks(db) -> dict:
    """Runs every enabled watch target once. Each check is a handful of
    lightweight DNS lookups (not a scan), so unlike Nmap there's no need to
    serialize them -- but concurrency is still capped to avoid hammering a
    resolver with many domains' worth of lookups at once."""
    import asyncio
    targets = await db.domain_watch_targets.find({"enabled": True}, {"_id": 0}).to_list(500)
    sem = asyncio.Semaphore(10)

    async def _one(t):
        async with sem:
            try:
                return await run_domain_check(db, t["domain"], t.get("asset_id"), t.get("label"))
            except Exception as e:
                return {"domain": t["domain"], "error": str(e)}

    results = await asyncio.gather(*[_one(t) for t in targets])
    checked = len(results)
    issues = len([r for r in results if r.get("issues")])
    return {"checked": checked, "issues": issues, "synced_at": _now_iso()}
