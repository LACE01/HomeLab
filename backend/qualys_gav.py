"""Qualys Global AssetView / CyberSecurity Asset Management (GAV/CSAM) enrichment --
pulls the rich per-host inventory GAV/CSAM exposes that the classic VM API
(qualys_sync.py) never does at all: structured hardware (manufacturer/model/
category, not just the combined `hardware.fullName` string), structured OS detail
(publisher/version/edition/architecture/lifecycle+EOL), installed software per host
(WITH a real `publisher` field -- not a substring guess), processor/memory/BIOS
identity, Qualys's own business-context fields (owner/department/environment/
criticality score), physical location, Cloud Agent/sensor status, open ports,
disk volumes, and network interfaces. That's a genuinely separate Qualys module
from the VM API we already use, with its own auth flow and its own licensing --
some subscriptions don't include it, so every call here is written to fail with a
clear, specific reason rather than a generic timeout/500, since "is this even
licensed" is the first thing to check when it doesn't work.

Auth: GAV/CSAM sits behind the Qualys API Gateway, which uses a short-lived JWT
instead of the classic API's HTTP Basic auth -- POST username/password to
{gateway}/auth and use the returned token as a Bearer header for an hour. The gateway
host is the same platform pod as the VM API endpoint already configured under
Integrations -> Qualys VMDR, just on the `gateway.` subdomain instead of `qualysapi.`
(e.g. qualysapi.qg2.apps.qualys.com -> gateway.qg2.apps.qualys.com) -- that mapping is
Qualys's documented convention across all of their platform pods, so it's derived
automatically rather than needing a second endpoint field in the UI. If a given
subscription's gateway happens to live somewhere else, the error message says so
explicitly so it's a one-line fix rather than a silent no-op.

Per-host software feeds vendor candidate detection (vendor_management.py's
suggest_vendors()) AND the Asset Detail page's "Installed Software" panel
(routes/inventory.py's GET /v1/assets/{id}/software) -- both were originally built
only against Microsoft Defender for Endpoint's per-device sync and hardcoded that
source name; they now accept any source in vendor_management.DEVICE_SOFTWARE_SOURCES,
which includes this module's "qualys_device" rows too. This is what makes an
account with Qualys configured (but no Defender for Endpoint) actually populate the
Vendor & Third-Party Risk page's approval queue and asset software lists -- before
this, that queue stayed empty for a Qualys-only deployment no matter how much real
software Qualys had already inventoried, because nothing ever wrote to
db.software_inventory except Defender.
"""
import logging
from datetime import datetime, timezone

import httpx

logger = logging.getLogger("vulnops.qualys_gav")

# Fields requested from GAV/CSAM's asset search API beyond the original hardware/
# lastLoggedOnUser pull -- see https://docs.qualys.com/en/csam/api/asset_host_data/
# get_host_details_of_specific_asset.htm for the full response shape each of these
# tokens expands into (operatingSystem, hardware, software, processor, volume,
# networkInterface, openPort, agent, sensor, tagList, criticality,
# businessInformation, lastLocation all documented there).
_INCLUDE_FIELDS = (
    "id,assetName,dnsName,netbiosName,address,operatingSystem,hardware,"
    "lastLoggedOnUser,software,processor,volume,networkInterface,openPort,"
    "agent,sensor,tagList,criticality,businessInformation,lastLocation,"
    "totalMemory,cpuCount,biosSerialNumber,biosAssetTag,timeZone,lastBoot"
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _derive_gateway_base(vm_endpoint: str) -> str:
    """qualysapi.qg2.apps.qualys.com -> gateway.qg2.apps.qualys.com (Qualys's own
    documented pod-URL convention -- same pattern for qg1/qg2/qg3/qg4/us2/us3/eu1/etc.)."""
    return vm_endpoint.replace("qualysapi.", "gateway.").rstrip("/")


async def _get_gav_token(gateway_base: str, username: str, password: str) -> str:
    url = f"{gateway_base}/auth"
    try:
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.post(
                url,
                data={"username": username, "password": password, "token": "true"},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
    except httpx.HTTPError as e:
        raise RuntimeError(
            f"Could not reach the Qualys Gateway API at {gateway_base} to authenticate for "
            f"asset hardware/software/last-logged-in-user data: {e}. If your account's Qualys "
            f"platform pod uses a different gateway hostname than this guess, let me know the "
            f"real one."
        )
    if r.status_code == 404:
        raise RuntimeError(
            f"Qualys Gateway API not found at {gateway_base} (404). This URL is guessed from your "
            f"configured Qualys VM endpoint by swapping 'qualysapi.' for 'gateway.' -- if your "
            f"platform pod doesn't follow that convention, tell me the real gateway URL."
        )
    if r.status_code in (401, 403):
        raise RuntimeError(
            f"Qualys Gateway API rejected these credentials ({r.status_code}). Either the "
            f"username/password under Integrations -> Qualys VMDR aren't valid for gateway auth, "
            f"or this account doesn't have API access to Global AssetView/CSAM -- that's a separate "
            f"licensed module from the VM API this app already uses successfully."
        )
    if r.status_code != 200:
        raise RuntimeError(f"Qualys Gateway auth failed: HTTP {r.status_code}: {r.text[:200]}")
    token = r.text.strip()
    if not token or len(token) < 20:
        raise RuntimeError(f"Qualys Gateway auth returned an unexpected response (not a JWT): {r.text[:200]}")
    return token


async def _fetch_gav_assets(gateway_base: str, token: str, page_size: int = 300, max_pages: int = 50) -> list:
    """POST /rest/2.0/search/am/asset, paginated. Returns a flat list of asset dicts
    with just the fields we actually use, trimmed from Qualys's much larger payload."""
    url = f"{gateway_base}/rest/2.0/search/am/asset"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    out = []
    last_id = 0
    for _ in range(max_pages):
        # id-based paging -- ask for the next batch of asset IDs greater than the
        # highest one seen so far, restricted to host-type assets.
        body = {"filter": f"id > {last_id} and assetType:HOST"}
        try:
            async with httpx.AsyncClient(timeout=90) as c:
                r = await c.post(url, params={"pageSize": page_size, "includeFields": _INCLUDE_FIELDS},
                                  headers=headers, json=body)
        except httpx.HTTPError as e:
            raise RuntimeError(f"Could not reach Qualys GAV/CSAM asset search: {e}")
        if r.status_code in (401, 403):
            raise RuntimeError(
                f"Qualys GAV/CSAM asset search returned {r.status_code} -- your account's token was "
                f"accepted at login but was denied here, which usually means the Global AssetView/"
                f"CSAM module itself isn't included in this subscription."
            )
        if r.status_code == 404:
            raise RuntimeError(
                f"Qualys GAV/CSAM asset search endpoint not found (404) at {url} -- this module may "
                f"not be enabled for this account/pod."
            )
        if r.status_code != 200:
            raise RuntimeError(f"Qualys GAV/CSAM asset search failed: HTTP {r.status_code}: {r.text[:300]}")
        try:
            data = r.json()
        except Exception:
            raise RuntimeError(f"Qualys GAV/CSAM asset search returned non-JSON: {r.text[:200]}")
        assets = (data.get("assetListData") or {}).get("asset") or data.get("assets") or []
        if isinstance(assets, dict):
            assets = [assets]
        if not assets:
            break
        out.extend(assets)
        try:
            last_id = max(int(a.get("id") or a.get("assetId") or 0) for a in assets)
        except (TypeError, ValueError):
            break
        if len(assets) < page_size:
            break
    return out


def _ms_to_iso(ms) -> str | None:
    """Qualys reports several timestamps (lastVMScan, agent.lastCheckedIn, etc.) as
    epoch milliseconds, 0 meaning 'never' -- normalize both away to None/ISO."""
    try:
        ms = int(ms or 0)
    except (TypeError, ValueError):
        return None
    if ms <= 0:
        return None
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat()


def _parse_gav_asset(ga: dict) -> dict:
    """Flattens one GAV/CSAM asset payload into the flat field set we actually
    store on db.assets, plus the separate list of per-host software entries
    (returned alongside, not merged in, since those become their own
    db.software_inventory rows rather than asset fields)."""
    hw = ga.get("hardware") or {}
    os_ = ga.get("operatingSystem") or {}
    proc = ga.get("processor") or {}
    agent = ga.get("agent") or {}
    sensor = ga.get("sensor") or {}
    crit = ga.get("criticality") or {}
    biz = ga.get("businessInformation") or {}
    loc = ga.get("lastLocation") or {}
    os_lifecycle = os_.get("lifecycle") or {}

    tags = [t.get("tagName") for t in ((ga.get("tagList") or {}).get("tag") or []) if t.get("tagName")]
    open_ports = [
        {"port": p.get("port"), "protocol": p.get("protocol"), "service": p.get("detectedService")}
        for p in ((ga.get("openPortListData") or {}).get("openPort") or [])[:100]
    ]
    volumes = [
        {"name": v.get("name"), "size_bytes": v.get("size"), "free_bytes": v.get("free")}
        for v in ((ga.get("volumeListData") or {}).get("volume") or [])[:50]
    ]
    network_interfaces = [
        {"interface": ni.get("interfaceName") or None, "mac": ni.get("macAddress"),
         "ipv4": ni.get("addressIpV4"), "ipv6": ni.get("addressIpV6")}
        for ni in ((ga.get("networkInterfaceListData") or {}).get("networkInterface") or [])[:50]
    ]
    software = [
        {
            "vendor": (s.get("publisher") or "").strip() or None,
            "name": (s.get("productName") or s.get("fullName") or "").strip(),
            "version": s.get("version"),
            "category": s.get("category"),
            "lifecycle_stage": (s.get("lifecycle") or {}).get("stage"),
        }
        for s in ((ga.get("softwareListData") or {}).get("software") or [])
        if (s.get("productName") or s.get("fullName"))
    ]

    fields = {
        "hardware_info": (hw.get("fullName") or "").strip() or None,
        "hardware_manufacturer": hw.get("manufacturer") or None,
        "hardware_model": hw.get("model") or None,
        "hardware_category": hw.get("category") or None,
        "os_publisher": os_.get("publisher") or None,
        "os_product_name": os_.get("productName") or None,
        "os_version": os_.get("version") or None,
        "os_edition": os_.get("edition") or None,
        "os_architecture": os_.get("architecture") or None,
        "os_lifecycle_stage": os_lifecycle.get("stage") or None,
        "os_eol_date": os_lifecycle.get("eolDate") or None,
        "os_eos_date": os_lifecycle.get("eosDate") or None,
        "processor_description": (proc.get("description") or "").strip() or None,
        "cpu_count": ga.get("cpuCount") or proc.get("numCPUs") or None,
        "total_memory_mb": ga.get("totalMemory") or None,
        "bios_serial_number": ga.get("biosSerialNumber") or None,
        "bios_asset_tag": ga.get("biosAssetTag") or None,
        "last_logged_on_user": (ga.get("lastLoggedOnUser") or "").strip() or None,
        "qualys_criticality_score": crit.get("score"),
        "qualys_business_info": {k: v for k, v in {
            "company": biz.get("company"), "department": biz.get("department"),
            "owned_by": biz.get("ownedBy"), "environment": biz.get("environment"),
            "managed_by": biz.get("managedBy"), "support_group": biz.get("supportGroup"),
        }.items() if v} or None,
        "qualys_location": {k: v for k, v in {
            "city": loc.get("city"), "state": loc.get("state"), "country": loc.get("country"),
        }.items() if v} or None,
        "qualys_tags": tags or None,
        "open_ports": open_ports or None,
        "volumes": volumes or None,
        "network_interfaces": network_interfaces or None,
        "agent_version": agent.get("version") or None,
        "agent_last_checked_in": _ms_to_iso(agent.get("lastCheckedIn")),
        "last_vm_scan_at": _ms_to_iso(sensor.get("lastVMScan")),
    }
    # Drop keys with no real value so a patch never overwrites a previously-known
    # good field with a null just because this particular sync source didn't see it.
    fields = {k: v for k, v in fields.items() if v not in (None, "", [], {})}
    return {"fields": fields, "software": software}


async def sync_qualys_asset_inventory(db) -> dict:
    """Best-effort pass matching GAV/CSAM host records to our existing assets (by IP,
    hostname, or Qualys host ID -- whichever matches), stamping the full flattened
    field set from _parse_gav_asset onto each match, and upserting a
    db.software_inventory row per installed-software entry (source="qualys_device",
    vendor taken directly from Qualys's own `publisher` field -- real data, not a
    keyword guess) so vendor detection and the Asset Detail software panel both pick
    it up. Doesn't create new assets -- this only enriches ones the VM sync (or
    another source) already created."""
    integration = await db.integrations.find_one({"name": "Qualys VMDR"}, {"_id": 0})
    cfg = (integration or {}).get("config") or {}
    endpoint, username, password = cfg.get("endpoint"), cfg.get("username"), cfg.get("api_key")
    if not endpoint or not username or not password:
        raise RuntimeError("Qualys VMDR integration isn't configured (endpoint/username/api_key) -- "
                            "GAV/CSAM reuses those same credentials.")

    gateway_base = _derive_gateway_base(endpoint)
    token = await _get_gav_token(gateway_base, username, password)
    gav_assets = await _fetch_gav_assets(gateway_base, token)

    now = _now_iso()
    matched = 0
    software_synced = 0
    for ga in gav_assets:
        parsed = _parse_gav_asset(ga)
        fields, software = parsed["fields"], parsed["software"]

        hostname = ga.get("dnsName") or ga.get("netbiosName") or ga.get("assetName")
        ip = ga.get("address")
        qualys_host_id = ga.get("id") or ga.get("assetId")
        match_filter = {"$or": [f for f in [
            {"hostname": hostname} if hostname else None,
            {"ip": ip} if ip else None,
            {"qualys_host_id": str(qualys_host_id)} if qualys_host_id else None,
        ] if f]}
        if not match_filter["$or"]:
            continue
        asset = await db.assets.find_one(match_filter, {"_id": 0, "id": 1})
        if not asset:
            continue

        if fields:
            await db.assets.update_one({"id": asset["id"]}, {"$set": {**fields, "gav_synced_at": now}})
            matched += 1

        for sw in software:
            name = sw["name"]
            if not name:
                continue
            vendor = sw["vendor"]
            if not vendor:
                # Qualys's own publisher field is blank for a small minority of
                # entries (typically generic/unbranded components) -- fall back to
                # the same curated keyword heuristic finding-title detection
                # already uses, rather than silently dropping the entry. Only
                # written when a confident match exists; otherwise skipped, since
                # a wrong vendor guess is worse than no entry at all.
                from vendor_management import SOFTWARE_VENDOR_KEYWORDS
                haystack = name.lower()
                vendor = next((v for needle, v in SOFTWARE_VENDOR_KEYWORDS if needle in haystack), None)
            if not vendor:
                continue
            await db.software_inventory.update_one(
                {"source": "qualys_device", "asset_id": asset["id"], "vendor": vendor, "name": name},
                {"$set": {
                    "vendor": vendor, "name": name, "version": sw.get("version"),
                    "asset_id": asset["id"], "source": "qualys_device", "synced_at": now,
                }},
                upsert=True,
            )
            software_synced += 1

    return {"gav_assets_seen": len(gav_assets), "assets_enriched": matched, "software_entries_synced": software_synced}
