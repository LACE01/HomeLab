"""Best-effort server vs workstation classification from the OS string an asset
was discovered with. Every asset importer (Qualys VM sync, Nmap, EASM, generic
integration import) was hardcoding asset_type="server" regardless of what OS
was actually detected -- Nikto/CISA web-app importers were the only ones that
set something else ("web_application"/"web_app"), which is why a fleet with a
mix of servers and end-user Windows workstations showed up as 100% "server" in
the UI. This mirrors the same substring-matching approach criticality.py's rule
engine already uses against the same OS-ish fields (operating_system,
detected_os, platform).

This is heuristic, not authoritative: an admin can always override an
individual asset's type (see routes/inventory.py's PATCH endpoint), and the
bulk recompute endpoint only touches assets that haven't been manually locked.
"""
from typing import Optional

TYPES = ["server", "workstation", "web_application", "network_device", "other"]

# Checked first -- these substrings are unambiguous "this is a server" signals
# even though some (e.g. "windows server") would otherwise get caught by a
# naive "windows" match.
SERVER_OS_HINTS = [
    "windows server", "hyper-v", "esxi", "vmware esxi", "vmware vsphere",
]

# Desktop/laptop OS editions -- anything matching here is a workstation, not a
# server, regardless of how the asset was originally imported.
WORKSTATION_OS_HINTS = [
    "windows 11", "windows 10", "windows 8.1", "windows 8", "windows 7", "windows vista", "windows xp",
    "mac os", "macos", "os x", "chrome os", "chromeos",
    "ubuntu desktop", "fedora workstation",
]

NETWORK_DEVICE_HINTS = [
    "ios-xe", "cisco ios", "junos", "fortios", "panos", "routeros",
]

# Common Linux/Unix distro names that don't literally contain the word "linux"
# (e.g. "Ubuntu 22.04.3 LTS") -- checked after the workstation hints above, so
# "Ubuntu Desktop" still classifies as a workstation, not a server.
LINUX_DISTRO_HINTS = [
    "ubuntu", "debian", "centos", "red hat", "rhel", "fedora", "suse", "opensuse",
    "oracle linux", "amazon linux", "rocky linux", "alma linux", "alpine",
]


def classify_asset_type(operating_system: Optional[str] = None, detected_os: Optional[str] = None,
                         platform: Optional[str] = None) -> Optional[str]:
    """Returns a best-guess asset_type ("server"/"workstation"/"network_device"),
    or None if the available OS strings are inconclusive (e.g. all empty, or
    "unknown") -- callers decide their own fallback in that case, since a fresh
    import and a bulk-recompute-existing-asset want different defaults."""
    haystack = " ".join(s for s in [operating_system, detected_os, platform] if s).lower().strip()
    if not haystack or haystack == "unknown":
        return None

    for hint in NETWORK_DEVICE_HINTS:
        if hint in haystack:
            return "network_device"
    for hint in SERVER_OS_HINTS:
        if hint in haystack:
            return "server"
    for hint in WORKSTATION_OS_HINTS:
        if hint in haystack:
            return "workstation"
    if any(hint in haystack for hint in LINUX_DISTRO_HINTS) or "linux" in haystack or "unix" in haystack or "bsd" in haystack:
        # A generic Linux/Unix string with no "server" or desktop-distro hint --
        # in a fleet scanned by Qualys/Nmap this is overwhelmingly a server, so
        # that's the safe default rather than leaving it unclassified.
        return "server"
    return None


async def recompute_all_asset_types(db) -> dict:
    """Bulk backfill for existing assets that were created before this
    classifier existed (or before an importer had OS info yet). Skips assets
    with asset_type_locked=True (manual override) and ones whose asset_type is
    already something an importer sets deliberately (web_application/web_app),
    since those aren't OS-based classifications this function should touch."""
    checked = changed = skipped_locked = skipped_inconclusive = 0
    async for asset in db.assets.find(
        {}, {"_id": 0, "id": 1, "asset_type": 1, "asset_type_locked": 1,
             "operating_system": 1, "detected_os": 1, "platform": 1}
    ):
        checked += 1
        if asset.get("asset_type_locked"):
            skipped_locked += 1
            continue
        if asset.get("asset_type") in ("web_application", "web_app"):
            continue  # set deliberately by the Nikto/CISA importers, not OS-based
        guess = classify_asset_type(asset.get("operating_system"), asset.get("detected_os"), asset.get("platform"))
        if guess is None:
            skipped_inconclusive += 1
            continue
        if guess != asset.get("asset_type"):
            await db.assets.update_one({"id": asset["id"]}, {"$set": {"asset_type": guess}})
            changed += 1
    return {"checked": checked, "changed": changed, "skipped_locked": skipped_locked, "skipped_inconclusive": skipped_inconclusive}
