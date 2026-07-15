"""Microsoft Intune managed-device sync -- pulls real compliance/patch state per
device via Microsoft Graph, distinct from this app's existing manual "patches
applied" tracking (nightly.py's sweep_patch_completions, which only fires once every
finding in a patch group is independently confirmed resolved through vulnerability
scan data -- Intune's complianceState is a direct MDM signal, not inferred from
scan re-runs, and the two are complementary rather than redundant).

Auth: client-credentials via msgraph.py, scope https://graph.microsoft.com/.default
(same audience as Entra ID -- see entra_sync.py -- since Intune device management is
itself a Graph API surface, not a separate product API like Defender for Endpoint).
Required application permission on the app registration: DeviceManagementManagedDevices.
Read.All, and the tenant needs an active Intune license (Graph returns an error
without one, surfaced as-is rather than guessed at).

Not verified against a live tenant in this sandbox -- see msgraph.py's docstring for
what an AADSTS error usually means if the first real sync fails.
"""
import logging
from datetime import datetime, timezone

from msgraph import get_client_credentials_token, graph_get_paginated

logger = logging.getLogger("vulnops.intune")

GRAPH_SCOPE = "https://graph.microsoft.com/.default"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hostname_key(name: str) -> str:
    return (name or "").strip().lower().split(".")[0]


async def sync_intune(db, max_pages: int = 30) -> dict:
    integration = await db.integrations.find_one({"name": "Microsoft Intune"}, {"_id": 0})
    cfg = (integration or {}).get("config") or {}
    base = (cfg.get("endpoint") or "https://graph.microsoft.com/v1.0").rstrip("/")

    token = await get_client_credentials_token(db, "Microsoft Intune", GRAPH_SCOPE)

    devices = await graph_get_paginated(
        token, f"{base}/deviceManagement/managedDevices",
        params={
            "$select": "id,deviceName,operatingSystem,osVersion,complianceState,"
                       "managementState,lastSyncDateTime,isEncrypted,jailBroken,userPrincipalName",
            "$top": "999",
        },
        max_pages=max_pages,
    )

    assets = await db.assets.find({}, {"_id": 0, "id": 1, "hostname": 1}).to_list(50000)
    asset_by_key = {_hostname_key(a.get("hostname")): a for a in assets if _hostname_key(a.get("hostname"))}

    now_iso = _now_iso()
    matched = 0
    noncompliant = 0
    compliance_counts: dict = {}
    for d in devices:
        state = d.get("complianceState") or "unknown"
        compliance_counts[state] = compliance_counts.get(state, 0) + 1
        if state == "noncompliant":
            noncompliant += 1
        asset = asset_by_key.get(_hostname_key(d.get("deviceName")))
        if not asset:
            continue
        await db.assets.update_one({"id": asset["id"]}, {"$set": {
            "intune_device_id": d.get("id"),
            "intune_compliance_state": state,
            "intune_management_state": d.get("managementState"),
            "intune_os": d.get("operatingSystem"),
            "intune_os_version": d.get("osVersion"),
            "intune_encrypted": bool(d.get("isEncrypted")),
            "intune_last_check_in_at": d.get("lastSyncDateTime"),
            "intune_primary_user": d.get("userPrincipalName"),
            "intune_synced_at": now_iso,
        }})
        matched += 1

    return {
        "devices_seen": len(devices), "devices_matched_to_assets": matched,
        "noncompliant_devices": noncompliant, "compliance_state_counts": compliance_counts,
        "synced_at": now_iso,
    }


async def get_patch_compliance_summary(db) -> dict:
    """Aggregate view for a Patch Compliance panel -- how many managed assets are
    compliant vs. not, and what OS version spread looks like across them. Only counts
    assets that have actually been matched to an Intune device (intune_device_id
    set); assets Intune has never seen aren't "noncompliant", they're just unmanaged,
    which is its own distinct and worth-surfacing state."""
    assets = await db.assets.find(
        {"intune_device_id": {"$exists": True, "$ne": None}},
        {"_id": 0, "id": 1, "hostname": 1, "intune_compliance_state": 1, "intune_os_version": 1,
         "intune_last_check_in_at": 1},
    ).to_list(50000)
    by_state: dict = {}
    by_os_version: dict = {}
    for a in assets:
        state = a.get("intune_compliance_state") or "unknown"
        by_state[state] = by_state.get(state, 0) + 1
        ov = a.get("intune_os_version") or "unknown"
        by_os_version[ov] = by_os_version.get(ov, 0) + 1
    total_assets = await db.assets.count_documents({})
    return {
        "total_managed": len(assets),
        "total_assets": total_assets,
        "unmanaged": max(0, total_assets - len(assets)),
        "by_compliance_state": by_state,
        "by_os_version": by_os_version,
        "noncompliant_assets": [
            {"id": a["id"], "hostname": a.get("hostname"), "last_check_in_at": a.get("intune_last_check_in_at")}
            for a in assets if (a.get("intune_compliance_state") or "unknown") == "noncompliant"
        ][:100],
    }
