"""External Attack Surface Management (EASM) -- passive discovery of internet-facing
hostnames you might not have in inventory yet.

Uses crt.sh (public Certificate Transparency log search, no API key, run by Sectigo)
to enumerate every hostname that's ever had a public TLS certificate issued for a
domain, then resolves each one over DNS to see what's still live. This never touches
the target directly beyond a standard DNS lookup -- it's index lookups against public
CT logs plus DNS, not a scan -- so unlike the Nmap module there's no authorization
gate here; discovering that a subdomain *exists* in public records isn't scanning it.

Deliberately doesn't auto-create assets or findings from what it finds: a stale/
decommissioned subdomain showing up in CT log history is common and noisy. Instead
candidates land in a review queue and a human promotes the real ones into inventory.
"""
import asyncio
import re
import socket
import uuid
from datetime import datetime, timezone

import httpx

CRTSH_URL = "https://crt.sh/"
HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def query_crtsh(domain: str, timeout: float = 45.0, retries: int = 3) -> list:
    """Hostnames found in CT logs for `domain` (itself plus subdomains).

    Item 35: this used to be a bespoke crt.sh client here, a second one in cti.py,
    and a third about to appear in External Checks. It now delegates to the shared
    ct_service, which adds exponential backoff with jitter, a certspotter fallback
    when crt.sh is down, recognition of crt.sh's HTML-with-a-200 maintenance page,
    and -- importantly -- treats an empty result as CLEAN rather than an error.
    Errors carry the FULL upstream message instead of a truncated one.

    Also fixes a latent crash: the old loop could fall through without ever
    assigning `rows`, raising UnboundLocalError instead of a useful message."""
    from ct_service import fetch_certificates, CTError
    domain = domain.strip().lower().lstrip(".")
    try:
        certs = await fetch_certificates(domain, attempts=retries, timeout=timeout)
    except CTError as e:
        raise ValueError(str(e))

    names = set()
    for row in certs or []:
        raw = row.get("name_value") or ""
        for line in raw.split("\n"):
            name = line.strip().lower().lstrip("*.")
            if not name or name == domain:
                continue
            if not name.endswith("." + domain) and name != domain:
                continue
            if not HOSTNAME_RE.match(name):
                continue
            names.add(name)
    names.add(domain)
    return sorted(names)


def _resolve(hostname: str) -> str | None:
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None


async def resolve_hostname(hostname: str) -> str | None:
    """DNS resolution is blocking stdlib I/O -- offload it so a slow/hanging
    resolver on one name doesn't stall the whole scan or the API."""
    return await asyncio.get_running_loop().run_in_executor(None, _resolve, hostname)


async def run_easm_scan(db, domain: str, concurrency: int = 20) -> dict:
    hostnames = await query_crtsh(domain)

    existing_assets = await db.assets.find(
        {"hostname": {"$in": hostnames}}, {"_id": 0, "hostname": 1}
    ).to_list(len(hostnames) + 1)
    already_tracked = {a["hostname"] for a in existing_assets}

    existing_candidates = await db.easm_candidates.find(
        {"hostname": {"$in": hostnames}}, {"_id": 0}
    ).to_list(len(hostnames) + 1)
    candidate_by_host = {c["hostname"]: c for c in existing_candidates}

    to_resolve = [h for h in hostnames if h not in already_tracked]
    sem = asyncio.Semaphore(concurrency)

    async def _one(hostname):
        async with sem:
            ip = await resolve_hostname(hostname)
            return hostname, ip

    resolved = await asyncio.gather(*[_one(h) for h in to_resolve])

    now = _now_iso()
    new_count = live_count = 0
    for hostname, ip in resolved:
        live = ip is not None
        if live:
            live_count += 1
        existing = candidate_by_host.get(hostname)
        if existing:
            # Already reviewed (promoted/dismissed) -- just refresh liveness, don't
            # resurrect a dismissed one back into the "new" queue.
            await db.easm_candidates.update_one({"id": existing["id"]}, {"$set": {
                "resolved_ip": ip, "live": live, "last_seen_at": now,
            }})
        else:
            await db.easm_candidates.insert_one({
                "id": str(uuid.uuid4()), "hostname": hostname, "domain": domain,
                "resolved_ip": ip, "live": live, "status": "new",
                "first_seen_at": now, "last_seen_at": now,
            })
            new_count += 1

    await db.easm_domains.update_one({"domain": domain}, {"$set": {
        "last_scanned_at": now, "last_result": {
            "hostnames_found": len(hostnames), "already_tracked": len(already_tracked),
            "new_candidates": new_count, "live": live_count,
        },
    }})

    return {
        "domain": domain, "hostnames_found": len(hostnames), "already_tracked": len(already_tracked),
        "new_candidates": new_count, "live": live_count, "synced_at": now,
    }


async def sync_internet_facing_for_asset(db, asset_id: str, exposure: str) -> int:
    """Keeps findings.internet_facing in sync with the asset's current exposure.
    Findings cache this flag at creation time for query performance, so when an
    asset gets (re)classified as internet-facing after the fact -- e.g. EASM proves
    a hostname that was only ever internally scanned actually has a public
    certificate -- its existing findings need to be updated too, or the Exposure
    dashboard silently undercounts them forever."""
    internet_facing = exposure in ("internet", "external")
    result = await db.findings.update_many(
        {"asset_id": asset_id, "internet_facing": {"$ne": internet_facing}},
        {"$set": {"internet_facing": internet_facing}},
    )
    return result.modified_count


async def promote_candidate(db, candidate_id: str, user_email: str) -> dict:
    cand = await db.easm_candidates.find_one({"id": candidate_id}, {"_id": 0})
    if not cand:
        raise ValueError("Candidate not found")
    existing_asset = await db.assets.find_one({"hostname": cand["hostname"]}, {"_id": 0})
    if existing_asset:
        update = {"status": "promoted", "promoted_asset_id": existing_asset["id"]}
        # crt.sh surfacing this hostname is real evidence it's internet-reachable --
        # if it was only ever tracked as internal/unknown before, upgrade it now
        # rather than discarding that signal just because the asset already existed.
        if existing_asset.get("exposure") not in ("internet", "external"):
            await db.assets.update_one({"id": existing_asset["id"]}, {"$set": {"exposure": "internet"}})
            await sync_internet_facing_for_asset(db, existing_asset["id"], "internet")
            existing_asset["exposure"] = "internet"
        from criticality import recompute_asset_criticality
        await recompute_asset_criticality(db, existing_asset["id"])
        await db.easm_candidates.update_one({"id": candidate_id}, {"$set": update})
        return existing_asset

    asset = {
        "id": str(uuid.uuid4()), "hostname": cand["hostname"], "ip": cand.get("resolved_ip"),
        "fqdn": cand["hostname"], "environment": "unknown", "criticality": "medium",
        "exposure": "internet", "platform": "unknown", "operating_system": "unknown",
        # No OS fingerprint exists yet at EASM discovery time (cert-transparency hit,
        # not an active scan) so classify_asset_type() would always be inconclusive
        # here -- "server" is the reasonable default for an internet-facing host
        # found this way; an Nmap/Nikto scan against it later can refine this.
        "asset_type": "server", "owner_team": "Unassigned", "product_id": None, "product_name": None,
        "tags": ["easm", "discovered"], "status": "active", "created_at": _now_iso(),
        "ownership_confidence": 0.2,
        "ownership_rationale": f"Discovered via EASM (certificate transparency logs for {cand.get('domain')}), "
                                 "promoted from the review queue -- not yet confirmed by an active scan.",
    }
    await db.assets.insert_one(asset)
    from criticality import recompute_asset_criticality
    await recompute_asset_criticality(db, asset["id"])
    await db.easm_candidates.update_one({"id": candidate_id}, {"$set": {
        "status": "promoted", "promoted_asset_id": asset["id"], "promoted_by": user_email, "promoted_at": _now_iso(),
    }})
    asset.pop("_id", None)
    return asset


async def dismiss_candidate(db, candidate_id: str, reason: str | None = None) -> None:
    await db.easm_candidates.update_one({"id": candidate_id}, {"$set": {
        "status": "dismissed", "dismiss_reason": reason, "dismissed_at": _now_iso(),
    }})


async def easm_scan_loop(db, interval_hours: int = 24):
    """Background poll -- runs all enabled watch domains once per interval."""
    import logging
    from heartbeat import record_heartbeat
    logger = logging.getLogger("vulnops")
    await asyncio.sleep(60)  # let other startup tasks settle first
    while True:
        ok, detail = True, {"domains_scanned": 0, "domains_failed": 0, "domains_clean": 0, "failures": []}
        try:
            domains = await db.easm_domains.find({"enabled": True}, {"_id": 0}).to_list(200)
            for d in domains:
                try:
                    result = await run_easm_scan(db, d["domain"])
                    logger.info(f"EASM scan: {result}")
                    detail["domains_scanned"] += 1
                    # Item 35: a domain whose CT search legitimately returns
                    # nothing is HEALTHY (zero results), not a failure. This used
                    # to be indistinguishable from a real error on Ops Health.
                    if not result.get("hostnames_found"):
                        detail["domains_clean"] += 1
                except Exception as e:
                    logger.exception(f"EASM scan failed for {d['domain']}: {e}")
                    ok = False
                    detail["domains_failed"] += 1
                    # Keep the actual reason on the heartbeat itself -- not just in
                    # stdout -- so the Ops Health page can show WHY a domain failed
                    # without needing container log access. Item 35: the message is
                    # no longer truncated, so a crt.sh outage reads as a crt.sh
                    # outage rather than a mystery.
                    detail["failures"].append({"domain": d["domain"], "error": str(e)})
        except Exception as e:
            logger.exception(f"EASM loop error: {e}")
            ok, detail["error"] = False, str(e)
        await record_heartbeat(db, "easm_scan_loop", "ok" if ok else "error", detail)
        await asyncio.sleep(interval_hours * 3600)
