"""Nmap XML importer -- parses `nmap -oX` output (stdlib xml.etree, no extra dependency)
and turns it into asset enrichment plus, where warranted, new findings.

This is a *passive import*, not active scanning: VulnOps never runs nmap itself or
reaches out to a network. You run the scan yourself (or via your own cron/CI) and
upload the resulting XML, the same way the CISA Web Scan XLSX importer already works.
That keeps the container's privileges and network reach unchanged, and keeps scan
authorization squarely in your hands.

What it does with the data:
  1. Enrichment -- every asset gets open_ports / detected_os / nmap_last_scan_at,
     surfaced on the Asset Detail page.
  2. Exposure verification -- if you tell it the scan's vantage point was "external"
     (run from outside your network) and it finds a host reachable with open ports,
     that's real confirmation the asset belongs in the "internet-facing" bucket. If the
     asset's own record disagrees, that's flagged as a mismatch for the Exposure
     dashboard instead of silently trusting whichever one was entered first.
  3. Risky-port findings -- a curated list of services that are a real problem when
     reachable from the internet (Telnet, unauthenticated Redis/Mongo/Elasticsearch,
     exposed RDP/SMB/DB ports, etc.) get turned into findings when the scan shows them
     open on an internet-facing host. Internal-network exposure of the same ports is
     normal infrastructure and is not flagged -- this only fires for real attack surface.
  4. New-port findings -- a port that appears for the first time since the previous scan
     on an internet-facing/externally-scanned host gets a lower-severity "new exposure"
     finding, since a newly opened port on an internet-facing box is worth a look even
     if it isn't on the risky list.
  5. Verification evidence -- see nightly.check_single_verification, which now also
     accepts "the port this finding was about is confirmed closed by a scan run after
     the fix" as proof a fix landed, for any finding that has a `port` recorded.
"""
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from scoring import compute_risk, compute_sla_days

RISKY_PORTS = {
    23: ("Telnet", "Critical", "Cleartext remote administration protocol -- credentials and traffic are unencrypted."),
    21: ("FTP", "High", "Cleartext file transfer protocol -- credentials are sent unencrypted unless FTPS is enforced."),
    445: ("SMB", "High", "Windows file sharing exposed to the internet is a common ransomware/worm entry point."),
    3389: ("RDP", "High", "Remote Desktop exposed to the internet is a top initial-access vector for ransomware."),
    3306: ("MySQL", "High", "Database port reachable from the internet -- should sit behind a VPN/bastion, not exposed directly."),
    5432: ("PostgreSQL", "High", "Database port reachable from the internet -- should sit behind a VPN/bastion, not exposed directly."),
    1433: ("MSSQL", "High", "Database port reachable from the internet -- should sit behind a VPN/bastion, not exposed directly."),
    27017: ("MongoDB", "Critical", "MongoDB is frequently found with no authentication when exposed -- a classic mass-scan/ransom target."),
    6379: ("Redis", "Critical", "Redis has no authentication by default -- internet exposure is a frequent source of real breaches."),
    9200: ("Elasticsearch", "Critical", "Elasticsearch has no authentication by default in many deployments -- internet exposure leaks entire indices."),
    5900: ("VNC", "High", "VNC remote access exposed to the internet, often with weak or no authentication."),
    2049: ("NFS", "Medium", "Network file sharing exposed to the internet can leak or allow tampering with file data."),
    111: ("RPCbind", "Medium", "RPC portmapper exposed to the internet is commonly abused for reflection/amplification and service enumeration."),
    23389: ("RDP (alt)", "High", "Remote Desktop on a non-standard port is still Remote Desktop -- still a top ransomware entry vector."),
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _text(el, tag, attr=None, default=None):
    if el is None:
        return default
    child = el.find(tag)
    if child is None:
        return default
    return child.get(attr) if attr else (child.text or default)


def _parse_host(host_el) -> dict:
    status = host_el.find("status")
    state = status.get("state") if status is not None else "unknown"

    ip = None
    for addr in host_el.findall("address"):
        if addr.get("addrtype") in ("ipv4", "ipv6"):
            ip = addr.get("addr")
            break

    hostname = None
    hostnames_el = host_el.find("hostnames")
    if hostnames_el is not None:
        hn = hostnames_el.find("hostname")
        if hn is not None:
            hostname = hn.get("name")

    os_guess = None
    os_el = host_el.find("os")
    if os_el is not None:
        best = None
        best_acc = -1
        for match in os_el.findall("osmatch"):
            try:
                acc = int(match.get("accuracy", "0"))
            except ValueError:
                acc = 0
            if acc > best_acc:
                best_acc = acc
                best = match.get("name")
        if best and best_acc >= 80:
            os_guess = best

    ports = []
    ports_el = host_el.find("ports")
    if ports_el is not None:
        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            service_el = port_el.find("service")
            ports.append({
                "port": int(port_el.get("portid")),
                "protocol": port_el.get("protocol", "tcp"),
                "service": service_el.get("name") if service_el is not None else None,
                "product": service_el.get("product") if service_el is not None else None,
                "version": service_el.get("version") if service_el is not None else None,
            })

    return {"ip": ip, "hostname": hostname, "state": state, "os_guess": os_guess, "ports": ports}


def parse_nmap_xml(content: bytes) -> list:
    """Returns a list of parsed hosts. Raises ValueError on malformed XML."""
    try:
        root = ET.fromstring(content)
    except ET.ParseError as e:
        raise ValueError(f"Not valid Nmap XML: {e}")
    if root.tag != "nmaprun":
        raise ValueError("Doesn't look like an Nmap XML file (root element isn't <nmaprun>)")
    hosts = []
    for host_el in root.findall("host"):
        parsed = _parse_host(host_el)
        if parsed["state"] == "up" and (parsed["ip"] or parsed["hostname"]):
            hosts.append(parsed)
    return hosts


async def _find_or_create_asset(db, ip: str | None, hostname: str | None) -> dict:
    asset = None
    if ip:
        asset = await db.assets.find_one({"ip": ip}, {"_id": 0})
    if not asset and hostname:
        asset = await db.assets.find_one({"hostname": hostname}, {"_id": 0})
    if asset:
        return asset
    label = hostname or ip
    asset = {
        "id": str(uuid.uuid4()), "hostname": label, "ip": ip, "fqdn": hostname if hostname != label else None,
        "environment": "unknown", "criticality": "medium", "exposure": "internal",
        "platform": "unknown", "operating_system": "unknown", "asset_type": "server",
        "owner_team": "Unassigned", "product_id": None, "product_name": None,
        "tags": ["nmap"], "status": "active", "created_at": _now_iso(),
        "ownership_confidence": 0.3,
        "ownership_rationale": "Auto-created from an Nmap scan import (no existing asset matched by IP/hostname).",
    }
    await db.assets.insert_one(asset)
    return asset


async def _dedup_finding(db, asset_id: str, port: int, title: str) -> bool:
    """True if an equivalent Nmap-sourced finding is already open for this asset/port,
    so re-uploading the same (or a follow-up) scan doesn't create duplicates."""
    existing = await db.findings.find_one({
        "asset_id": asset_id, "port": port, "source_tool": "Nmap", "title": title,
        "status": {"$nin": ["Fixed validated", "Closed administratively", "False positive"]},
    })
    return existing is not None


async def _create_port_finding(db, asset: dict, port_info: dict, severity: str, title: str,
                                description: str, cwe: str = "CWE-284") -> bool:
    if await _dedup_finding(db, asset["id"], port_info["port"], title):
        return False
    now = _now_iso()
    finding = {
        "id": str(uuid.uuid4()), "canonical_key": f"nmap:{asset['id']}:{port_info['port']}:{title}",
        "source_tool": "Nmap", "source_observation_id": f"nmap-{asset['id']}-{port_info['port']}",
        "source_native_id": None, "qid": None, "plugin_id": None,
        "title": title, "description": description, "severity": severity,
        "cve": None, "cwe": cwe, "cvss_score": None, "cvss_vector": None,
        "epss_score": 0, "kev_flag": False, "rti": [],
        "port": port_info["port"], "protocol": port_info.get("protocol", "tcp"),
        "service": port_info.get("service"), "service_product": port_info.get("product"),
        "service_version": port_info.get("version"),
        "remediation": "Restrict this service to a VPN/bastion or internal-only network segment, or disable it if unused.",
        "asset_id": asset["id"], "asset_hostname": asset["hostname"], "asset_ip": asset.get("ip"),
        "asset_criticality": asset["criticality"], "asset_exposure": asset["exposure"],
        "asset_environment": asset["environment"], "asset_os": asset.get("operating_system"),
        "internet_facing": True, "owner_team": asset.get("owner_team"),
        "ownership_confidence": asset.get("ownership_confidence", 0.3),
        "product_id": asset.get("product_id"), "product_name": asset.get("product_name"),
        "status": "New", "validation_status": "pending", "reopened_count": 0,
        "first_seen_at": now, "last_seen_at": now, "last_changed_at": now, "imported_at": now,
        "detection_channel": "nmap_import", "tags": asset.get("tags", []),
        "compliance_scope": [], "advisory_links": [], "exploit_references": [],
        "patch_available": None,
    }
    sla_days = compute_sla_days(severity, asset["criticality"])
    try:
        due_dt = datetime.fromisoformat(now.replace("Z", "+00:00"))
    except Exception:
        due_dt = datetime.now(timezone.utc)
    from datetime import timedelta
    finding["sla_days"] = sla_days
    finding["due_at"] = (due_dt + timedelta(days=sla_days)).isoformat()
    risk = compute_risk(finding, asset)
    finding["risk_score"] = risk["score"]
    finding["risk_breakdown"] = risk["breakdown"]
    await db.findings.insert_one(finding)
    return True


async def import_nmap_xml(db, content: bytes, vantage: str = "internal", source_label: str | None = None) -> dict:
    if vantage not in ("internal", "external"):
        vantage = "internal"
    hosts = parse_nmap_xml(content)
    started = _now_iso()

    assets_touched = 0
    findings_created = 0
    exposure_confirmed = 0
    exposure_mismatches = 0

    for h in hosts:
        asset = await _find_or_create_asset(db, h["ip"], h["hostname"])
        prev_ports = {p["port"] for p in asset.get("open_ports") or []}
        new_ports = {p["port"] for p in h["ports"]}
        newly_appeared = new_ports - prev_ports if asset.get("nmap_last_scan_at") else set()

        patch: dict = {
            "open_ports": h["ports"], "nmap_last_scan_at": started, "nmap_vantage": vantage,
        }
        if h["os_guess"]:
            patch["detected_os"] = h["os_guess"]

        # Exposure verification -- only meaningful when the scan was actually run from
        # outside the network; an internal scan finding a host "up" tells you nothing
        # about internet reachability.
        if vantage == "external" and h["ports"]:
            currently_marked_internet = asset.get("exposure") in ("internet", "external")
            patch["exposure_verified_at"] = started
            if currently_marked_internet:
                patch["exposure_mismatch"] = False
                exposure_confirmed += 1
            else:
                patch["exposure_mismatch"] = True
                patch["exposure_mismatch_note"] = (
                    f"An external-vantage Nmap scan found this host reachable with "
                    f"{len(h['ports'])} open port(s), but it's recorded as exposure="
                    f"'{asset.get('exposure')}'.")
                exposure_mismatches += 1

        await db.assets.update_one({"id": asset["id"]}, {"$set": patch})
        asset = {**asset, **patch}
        assets_touched += 1

        is_internet_context = vantage == "external" or asset.get("exposure") in ("internet", "external")
        if is_internet_context:
            for p in h["ports"]:
                if p["port"] in RISKY_PORTS:
                    svc_label, severity, why = RISKY_PORTS[p["port"]]
                    title = f"Exposed {svc_label} service (port {p['port']}) reachable from the internet"
                    created = await _create_port_finding(
                        db, asset, p, severity, title,
                        description=f"{why} Detected via Nmap ({p.get('product') or p.get('service') or 'unknown service'} "
                                    f"{p.get('version') or ''}).".strip(),
                    )
                    if created:
                        findings_created += 1
                elif p["port"] in newly_appeared:
                    title = f"New port opened since last scan: {p['port']}/{p.get('protocol','tcp')} ({p.get('service') or 'unknown'})"
                    created = await _create_port_finding(
                        db, asset, p, "Low", title,
                        description=f"This port was not open on the previous Nmap scan of this host and is now reachable "
                                    f"{'from the internet' if vantage == 'external' else '(internal scan -- confirm intent)'}. "
                                    f"Could be an intended change or a misconfiguration worth a quick look.",
                        cwe="CWE-1008",
                    )
                    if created:
                        findings_created += 1

    await db.import_jobs.insert_one({
        "id": str(uuid.uuid4()), "source_name": "Nmap", "status": "success",
        "started_at": started, "finished_at": _now_iso(),
        "created_count": findings_created, "updated_count": assets_touched, "deduplicated_count": 0,
        "label": source_label or f"Nmap scan ({vantage})",
    })

    return {
        "hosts_parsed": len(hosts), "assets_touched": assets_touched,
        "findings_created": findings_created, "vantage": vantage,
        "exposure_confirmed": exposure_confirmed, "exposure_mismatches": exposure_mismatches,
    }
