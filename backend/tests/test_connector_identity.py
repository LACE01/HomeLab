"""The connectors must actually USE identity resolution.

entity_resolution.py being correct is worth nothing if the connectors keep doing
`asset_by_key[_hostname_key(name)]`. This drives the real sync functions against
fake Graph responses shaped like the live API, and asserts the join lands.

The scenario is the one that was silently failing: Qualys created the asset from
a short scan-target name, Defender reports an FQDN, Intune reports the short name
plus a serial. Under string matching, Defender matched nothing.
"""
import os, sys, asyncio, types
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_connector_identity"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_connector_identity"]
db = db_module.db

import entity_resolution as er
import defender_sync, intune_sync

run = lambda c: asyncio.get_event_loop().run_until_complete(c)

# The asset as Qualys would have created it: short name only.
run(db.assets.insert_one({
    "id": "asset-1", "hostname": "laptop-7", "ip": "10.1.2.3", "status": "active",
    "qualys_host_id": "Q-1001", "operating_system": "Windows 10",
}))
run(er.record_identifiers(db, "asset-1", er.identifiers_from(
    {"hostname": "laptop-7", "ip": "10.1.2.3", "qualys_host_id": "Q-1001"}), "qualys"))

run(db.integrations.insert_many([
    {"id": "i-def", "name": "Microsoft Defender for Endpoint", "type": "edr", "enabled": True,
     "config": {"tenant_id": "t", "client_id": "c", "client_secret": "s"}},
    {"id": "i-int", "name": "Microsoft Intune", "type": "mdm", "enabled": True,
     "config": {"tenant_id": "t", "client_id": "c", "client_secret": "s"}},
]))


# ---- fake Microsoft Graph -------------------------------------------------
DEFENDER_MACHINES = [{
    "id": "D-77",
    # An FQDN. This is the field Defender actually returns, and it never equalled
    # the short hostname the asset was created with.
    "computerDnsName": "LAPTOP-7.corp.eaglecounty.us",
    "aadDeviceId": "aad-guid-42",
    "macAddress": "AA:BB:CC:11:22:33",
    "lastIpAddress": "10.1.2.3",
    "riskScore": "High", "exposureLevel": "Medium", "healthStatus": "Active",
    "osPlatform": "Windows10", "agentVersion": "10.8", "lastSeen": "2026-07-29T00:00:00Z",
}]

INTUNE_DEVICES = [{
    "id": "I-99", "deviceName": "LAPTOP-7", "operatingSystem": "Windows",
    "osVersion": "10.0.19045", "complianceState": "noncompliant",
    "managementState": "managed", "lastSyncDateTime": "2026-07-29T00:00:00Z",
    "isEncrypted": True, "jailBroken": "False", "userPrincipalName": "luis@example.com",
    "serialNumber": "SN-LAPTOP-7", "azureADDeviceId": "aad-guid-42",
    "wiFiMacAddress": "AA:BB:CC:11:22:33", "ethernetMacAddress": None,
}]


async def fake_token(*a, **kw):
    return "token"


captured_select = {}


async def fake_paginated(token, url, params=None, max_pages=None, **kw):
    captured_select[url] = (params or {}).get("$select", "")
    if "managedDevices" in url:
        return list(INTUNE_DEVICES)
    return []


# Both modules do `from msgraph import ...`, so the names to replace live on the
# modules themselves, not on msgraph.
async def fake_defender_paginated(token, url, params=None, max_pages=None, **kw):
    captured_select[url] = (params or {}).get("$select", "")
    if "/api/machines" in url and "Software" not in url:
        return list(DEFENDER_MACHINES)
    return []


defender_sync.get_client_credentials_token = fake_token
defender_sync.graph_get_paginated = fake_defender_paginated
intune_sync.get_client_credentials_token = fake_token
intune_sync.graph_get_paginated = fake_paginated


# ============ Defender: the FQDN now lands on the short-named asset ============

result = run(defender_sync.sync_defender(db))
assert result.get("devices_matched_to_assets") == 1, result
assert result.get("devices_unmatched") == 0, result
asset = run(db.assets.find_one({"id": "asset-1"}, {"_id": 0}))
assert asset["defender_device_id"] == "D-77"
assert asset["defender_risk_score"] == "High"
print("PASS: Defender's FQDN 'LAPTOP-7.corp.eaglecounty.us' now lands on the asset Qualys created "
      "as 'laptop-7' — under string matching this silently matched nothing")

# no duplicate asset was invented
assert run(db.assets.count_documents({})) == 1
print("PASS: matching an existing asset does not create a second one")

# and Defender's identifiers are now on the asset, so the NEXT sync is a strong-key hit
ident = run(er.identity_of(db, "asset-1"))
kinds = {i["kind"] for i in ident["identifiers"]}
assert {"defender_device_id", "aad_device_id", "mac", "fqdn"} <= kinds, kinds
assert "defender" in ident["sources"] and "qualys" in ident["sources"]
print("PASS: the asset accumulated Defender's strong identifiers, so subsequent syncs resolve on "
      "the device GUID instead of re-deriving identity from a name every time")


# ============ Intune: asks Graph for the identity fields at all ============

run(intune_sync.sync_intune(db))
select = next(v for k, v in captured_select.items() if "managedDevices" in k)
for field in ("serialNumber", "azureADDeviceId", "wiFiMacAddress", "ethernetMacAddress"):
    assert field in select, f"Intune does not request {field}; without it there is no strong key"
print("PASS: the Intune query now requests serial/Entra-GUID/MAC — the strong keys. It previously "
      "asked only for a short device name, which is the weak key that made matching unreliable")

asset = run(db.assets.find_one({"id": "asset-1"}, {"_id": 0}))
assert asset["intune_device_id"] == "I-99", asset.get("intune_device_id")
assert asset["intune_compliance_state"] == "noncompliant"
print("PASS: Intune resolves to the same single asset — three sources (Qualys, Defender, Intune) "
      "now agree on one machine instead of describing three")

assert run(db.assets.count_documents({})) == 1
ident = run(er.identity_of(db, "asset-1"))
assert set(ident["sources"]) == {"qualys", "defender", "intune"}
assert any(i["kind"] == "serial" and i["values"] == ["sn-laptop-7"] for i in ident["identifiers"])
print("PASS: one asset, three sources, and a hardware serial now on record — from here the machine "
      "is identifiable even if every name it goes by changes")


# ============ the shared identity is what makes the joins possible ============

# This is the whole point of Tier 0: a question that could not be answered before
# because the three sources were three unrelated records.
asset = run(db.assets.find_one({"id": "asset-1"}, {"_id": 0}))
assert asset["defender_risk_score"] == "High" and asset["intune_compliance_state"] == "noncompliant"
print("PASS: 'a high-EDR-risk machine that is also out of compliance' is now a single asset record "
      "rather than a correlation nobody could make — this is the join Tier 1 is built on")
