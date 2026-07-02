"""TLS certificate expiry monitoring.

Connects to configured hostname:port targets over TLS and reads the leaf certificate
-- even if it's expired, self-signed, or fails hostname validation, since detecting
exactly those conditions is the point. Uses stdlib ssl/socket for the connection and
the already-pinned `cryptography` package (no new dependency -- it's already required
by pyjwt/auth) to parse certificate fields, since Python's ssl.getpeercert() only
returns parsed fields when verify_mode=CERT_REQUIRED, which would hide the exact
certs we most want to catch.
"""
import socket
import ssl
import uuid
from datetime import datetime, timezone

from cryptography import x509

WARN_DAYS = 30
CRITICAL_DAYS = 7


def _now():
    return datetime.now(timezone.utc)


def _now_iso():
    return _now().isoformat()


def _as_utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def check_cert(hostname: str, port: int = 443, timeout: float = 8.0) -> dict:
    """Connects to hostname:port and returns parsed leaf-certificate fields. Raises
    ValueError for network-level failures (DNS, connection refused, TLS handshake
    failure, timeout) -- those get surfaced as their own finding, distinct from a
    cert that connects fine but is expired/untrusted."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                der = ssock.getpeercert(binary_form=True)
                tls_version = ssock.version()
    except Exception as e:
        raise ValueError(f"Couldn't connect / complete TLS handshake: {e}")

    if not der:
        raise ValueError("Server didn't present a certificate")

    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception as e:
        raise ValueError(f"Couldn't parse certificate: {e}")

    not_after = _as_utc(getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after)
    not_before = _as_utc(getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before)
    days_left = (not_after - _now()).days

    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_names = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        san_names = []

    hostname_matches = hostname in san_names or any(
        n.startswith("*.") and hostname.endswith(n[1:]) for n in san_names
    )
    trust_valid, trust_error = _verify_trust(hostname, port, timeout)

    return {
        "hostname": hostname, "port": port,
        "subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
        "not_before": not_before.isoformat(), "not_after": not_after.isoformat(),
        "days_until_expiry": days_left,
        "san": san_names, "hostname_matches_san": hostname_matches,
        "self_signed": cert.issuer == cert.subject,
        "trust_valid": trust_valid, "trust_error": trust_error,
        "tls_version": tls_version, "checked_at": _now_iso(),
    }


def _verify_trust(hostname: str, port: int, timeout: float) -> tuple:
    """Separate connection with real verification enabled, purely to determine
    whether the cert is trusted by the system CA store -- doesn't affect whether we
    were able to read the cert's expiry above."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname):
                pass
        return True, None
    except ssl.SSLCertVerificationError as e:
        return False, str(e.verify_message if hasattr(e, "verify_message") else e)
    except Exception as e:
        return False, str(e)


def classify(days_until_expiry: int, trust_valid: bool, trust_error: str | None) -> tuple:
    """Returns (severity, reason) or (None, None) if nothing's wrong. Expiry always
    wins over trust issues in severity since a cert that's about to lapse causes an
    outage; an untrusted-but-valid cert (e.g. internal CA) is a lower, steady concern."""
    if days_until_expiry < 0:
        return "Critical", f"Certificate expired {abs(days_until_expiry)} day(s) ago"
    if days_until_expiry <= CRITICAL_DAYS:
        return "Critical", f"Certificate expires in {days_until_expiry} day(s)"
    if days_until_expiry <= WARN_DAYS:
        return "High", f"Certificate expires in {days_until_expiry} day(s)"
    if not trust_valid:
        return "Medium", f"Certificate isn't trusted by the system CA store: {trust_error or 'validation failed'}"
    return None, None


async def run_cert_check(db, hostname: str, port: int = 443, asset_id: str | None = None,
                          label: str | None = None) -> dict:
    """Checks one target, upserts the result into tls_certificates, and creates/
    clears a finding based on current status. Idempotent -- re-running just updates
    the existing record and finding rather than duplicating them."""
    import asyncio
    now = _now_iso()
    key = f"{hostname}:{port}"
    try:
        # check_cert does blocking socket/TLS I/O (up to two ~8s handshakes) -- run it
        # off the event loop thread so one slow/unreachable host doesn't stall the
        # entire API for everyone else while it times out.
        info = await asyncio.get_running_loop().run_in_executor(None, check_cert, hostname, port)
        info.update({"id": key, "asset_id": asset_id, "label": label, "reachable": True, "error": None})
        severity, reason = classify(info["days_until_expiry"], info["trust_valid"], info["trust_error"])
    except ValueError as e:
        info = {
            "id": key, "hostname": hostname, "port": port, "asset_id": asset_id, "label": label,
            "reachable": False, "error": str(e), "checked_at": now,
            "days_until_expiry": None, "trust_valid": None,
        }
        severity, reason = "High", f"TLS check failed: {e}"

    await db.tls_certificates.update_one({"id": key}, {"$set": info}, upsert=True)

    canonical_key = f"tls-cert:{key}"
    existing = await db.findings.find_one({"canonical_key": canonical_key}, {"_id": 0})
    open_states = ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]

    if severity:
        if existing and existing.get("status") in open_states:
            await db.findings.update_one({"id": existing["id"]}, {"$set": {
                "severity": severity, "description": reason, "last_seen_at": now,
            }})
        elif not existing:
            asset = await db.assets.find_one({"id": asset_id}, {"_id": 0}) if asset_id else None
            finding = {
                "id": str(uuid.uuid4()), "canonical_key": canonical_key,
                "title": f"TLS certificate issue -- {hostname}:{port}",
                "description": reason, "severity": severity, "status": "New",
                "source_tool": "TLS Cert Monitor", "source_tool_type": "Certificate Monitoring",
                "detection_channel": "Scheduled TLS check",
                "asset_id": asset_id, "asset_hostname": (asset or {}).get("hostname") or hostname,
                "asset_ip": (asset or {}).get("ip"), "asset_criticality": (asset or {}).get("criticality"),
                "asset_exposure": (asset or {}).get("exposure"), "port": port, "protocol": "tcp",
                "service": "https", "first_seen_at": now, "last_seen_at": now,
                "rti": [], "cwe": "CWE-295" if not (info.get("trust_valid")) else None,
            }
            await db.findings.insert_one(finding)
        # If it exists but was already fixed/accepted, leave it alone -- don't reopen
        # automatically; a human closed it and a re-check shouldn't silently override that.
    elif existing and existing.get("status") in open_states:
        # Cert is healthy again (renewed) -- auto-resolve, mirroring the Nmap
        # port-based verification pattern instead of leaving a stale finding open.
        await db.findings.update_one({"id": existing["id"]}, {"$set": {
            "status": "Fixed validated", "resolved_at": now,
            "resolution_note": "Certificate renewed / TLS check passed on re-scan.",
        }})

    return info


async def cert_monitor_loop(db, interval_hours: int = 24):
    """Background poll -- checks all enabled watch targets once per interval."""
    import asyncio
    import logging
    logger = logging.getLogger("vulnops")
    await asyncio.sleep(45)  # let other startup tasks settle first
    while True:
        try:
            result = await run_all_cert_checks(db)
            logger.info(f"TLS cert check: {result}")
        except Exception as e:
            logger.exception(f"TLS cert check failed: {e}")
        await asyncio.sleep(interval_hours * 3600)


async def run_all_cert_checks(db) -> dict:
    """Runs every enabled watch target once. Checks are independent, lightweight TLS
    handshakes (not a scan), so unlike Nmap there's no need to serialize them --
    but we still cap concurrency to avoid hammering a lot of hosts at once."""
    import asyncio
    targets = await db.cert_watch_targets.find({"enabled": True}, {"_id": 0}).to_list(500)
    sem = asyncio.Semaphore(10)

    async def _one(t):
        async with sem:
            try:
                return await run_cert_check(db, t["hostname"], t.get("port", 443), t.get("asset_id"), t.get("label"))
            except Exception as e:
                return {"hostname": t["hostname"], "port": t.get("port", 443), "error": str(e)}

    results = await asyncio.gather(*[_one(t) for t in targets])
    checked = len(results)
    issues = len([r for r in results if r.get("days_until_expiry") is not None and r["days_until_expiry"] <= WARN_DAYS or r.get("reachable") is False])
    return {"checked": checked, "issues": issues, "synced_at": _now_iso()}
