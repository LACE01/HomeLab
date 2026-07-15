"""Microsoft Defender for Endpoint EDR connector -- pulls real device inventory and
installed-software inventory, closing the gap vendor_management.py's own docstring
calls out explicitly: "this app has no dedicated per-asset software inventory (no
agent-based installed-application feed)". Matches devices to existing assets by
hostname (case-insensitive, comparing just the first label of computerDnsName against
the first label of asset.hostname -- the same "no shared foreign key, match on the
best available field" approach the Shodan/Censys connectors already use for IPs).

Auth: client-credentials via msgraph.py, scope
https://api.security.microsoft.com/.default -- this is Defender for Endpoint's OWN
token audience, separate from Microsoft Graph (a Graph token will NOT work against
these endpoints, and vice versa). Required application permission on the app
registration: Machine.Read.All and Software.Read.All under the "WindowsDefenderATP" /
"Microsoft Defender ATP" API resource specifically -- NOT Microsoft Graph. Granting
the Graph versions of similarly-named permissions by mistake is the most common way
this connector ends up authenticated but still getting 403s on every call.

API endpoints used (base https://api.security.microsoft.com), confirmed against
Microsoft's current public API docs but NOT verified against a live tenant in this
sandbox (no test tenant available here) -- treat the first real sync as a smoke test,
same caveat msgraph.py's docstring gives for every connector built on top of it:
  GET /api/machines                            -- device inventory
  GET /api/Software                             -- org-wide software inventory
                                                    (feeds vendor candidate detection)
  GET /api/machines/SoftwareInventoryByMachine   -- per-device installed software
                                                    (links a SPECIFIC asset to a
                                                    SPECIFIC vendor)
All three return the same OData {"value": [...], "@odata.nextLink": ...} shape Graph
uses, so msgraph.py's graph_get_paginated works unchanged against them.
"""
import logging
from datetime import datetime, timezone

from msgraph import get_client_credentials_token, graph_get_paginated

logger = logging.getLogger("vulnops.defender")

DEFENDER_SCOPE = "https://api.security.microsoft.com/.default"
RISK_ORDER = {"None": 0, "Informational": 0, "Low": 1, "Medium": 2, "High": 3}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hostname_key(name: str) -> str:
    return (name or "").strip().lower().split(".")[0]


async def sync_defender(db, max_pages: int = 30) -> dict:
    integration = await db.integrations.find_one({"name": "Microsoft Defender for Endpoint"}, {"_id": 0})
    cfg = (integration or {}).get("config") or {}
    base = (cfg.get("endpoint") or "https://api.security.microsoft.com").rstrip("/")

    token = await get_client_credentials_token(db, "Microsoft Defender for Endpoint", DEFENDER_SCOPE)

    machines = await graph_get_paginated(token, f"{base}/api/machines", max_pages=max_pages)

    assets = await db.assets.find({}, {"_id": 0, "id": 1, "hostname": 1}).to_list(50000)
    asset_by_key: dict = {}
    for a in assets:
        k = _hostname_key(a.get("hostname"))
        if k:
            asset_by_key[k] = a

    now_iso = _now_iso()
    devices_matched = 0
    high_risk = 0
    device_id_to_asset_id: dict = {}
    for m in machines:
        dns_name = m.get("computerDnsName")
        risk = m.get("riskScore") or "None"
        exposure = m.get("exposureLevel") or "None"
        if RISK_ORDER.get(risk, 0) >= RISK_ORDER["High"]:
            high_risk += 1
        asset = asset_by_key.get(_hostname_key(dns_name))
        if not asset:
            continue
        device_id_to_asset_id[m.get("id")] = asset["id"]
        await db.assets.update_one({"id": asset["id"]}, {"$set": {
            "defender_device_id": m.get("id"),
            "defender_risk_score": risk,
            "defender_exposure_level": exposure,
            "defender_health_status": m.get("healthStatus"),
            "defender_os_platform": m.get("osPlatform"),
            "defender_agent_version": m.get("agentVersion"),
            "defender_last_seen_at": m.get("lastSeen"),
            "defender_synced_at": now_iso,
        }})
        devices_matched += 1

    # Org-wide software inventory -- feeds vendor candidate detection (see
    # vendor_management.py's suggest_vendors()). Best-effort: a missing
    # Software.Read.All grant shouldn't take down device sync, which is the more
    # valuable half of this connector on its own.
    software_rows = []
    try:
        software_rows = await graph_get_paginated(token, f"{base}/api/Software", max_pages=max_pages)
    except Exception as e:
        logger.warning(f"Defender org-wide software inventory fetch failed (continuing with device data only): {e}")

    software_synced = 0
    for s in software_rows:
        vendor = (s.get("vendor") or "").strip()
        name = (s.get("name") or "").strip()
        if not vendor or not name:
            continue
        await db.software_inventory.update_one(
            {"source": "defender_org", "vendor": vendor, "name": name},
            {"$set": {
                "vendor": vendor, "name": name,
                "exposed_machines": s.get("exposedMachines", 0),
                "weaknesses": s.get("weaknesses", 0),
                "asset_id": None, "source": "defender_org", "synced_at": now_iso,
            }},
            upsert=True,
        )
        software_synced += 1

    # Per-device software -- links a SPECIFIC asset to a SPECIFIC vendor (rather than
    # "this vendor's software exists somewhere in the org"), the precision the
    # org-wide list above can't provide on its own.
    per_machine_rows = []
    try:
        per_machine_rows = await graph_get_paginated(token, f"{base}/api/machines/SoftwareInventoryByMachine", max_pages=max_pages)
    except Exception as e:
        logger.warning(f"Defender per-machine software inventory fetch failed (continuing without per-asset software linkage): {e}")

    per_machine_synced = 0
    for row in per_machine_rows:
        device_id = row.get("id") or row.get("deviceId")
        asset_id = device_id_to_asset_id.get(device_id)
        if not asset_id:
            continue
        vendor = (row.get("softwareVendor") or "").strip()
        name = (row.get("softwareName") or "").strip()
        if not vendor or not name:
            continue
        await db.software_inventory.update_one(
            {"source": "defender_device", "asset_id": asset_id, "vendor": vendor, "name": name},
            {"$set": {
                "vendor": vendor, "name": name, "version": row.get("softwareVersion"),
                "asset_id": asset_id, "source": "defender_device", "synced_at": now_iso,
            }},
            upsert=True,
        )
        per_machine_synced += 1

    if high_risk > 0:
        try:
            from notifier import dispatch
            await dispatch("edr_high_risk_device_found", {"count": high_risk, "url": "/assets"}, db)
        except Exception:
            logger.exception("edr_high_risk_device_found dispatch failed")

    return {
        "devices_seen": len(machines), "devices_matched_to_assets": devices_matched,
        "high_risk_devices": high_risk,
        "org_software_products_synced": software_synced,
        "per_device_software_links_synced": per_machine_synced,
        "synced_at": now_iso,
    }
