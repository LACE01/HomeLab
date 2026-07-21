import os, sys, asyncio, uuid
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_qualys_gav"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_qualys_gav"]

import server
import auth_utils
from routes import inventory as inventory_route
inventory_route.db = db_module.db

from fastapi.testclient import TestClient

admin_user = {"id": "u1", "email": "admin@x.com", "role": "admin", "name": "Admin", "teams": []}
app = server.app
app.dependency_overrides[auth_utils.get_current_user] = lambda: admin_user
client = TestClient(app)

db = db_module.db


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


import qualys_gav as gav
import vendor_management as vm

# ============ pure helpers ============

assert gav._derive_gateway_base("https://qualysapi.qg2.apps.qualys.com") == "https://gateway.qg2.apps.qualys.com"
assert gav._derive_gateway_base("https://qualysapi.qg2.apps.qualys.com/") == "https://gateway.qg2.apps.qualys.com"
print("PASS: _derive_gateway_base swaps qualysapi. for gateway. and strips a trailing slash")

assert gav._ms_to_iso(0) is None
assert gav._ms_to_iso(None) is None
assert gav._ms_to_iso(1700000000000) is not None and gav._ms_to_iso(1700000000000).startswith("2023-")
print("PASS: _ms_to_iso treats 0/None as 'never' and converts real epoch-ms otherwise")

# ============ _parse_gav_asset -- realistic fixture modeled on Qualys's own
# documented "Get Host Details of Specific Asset" example response ============

FIXTURE_ASSET = {
    "id": 69169700,
    "assetName": "web01",
    "dnsName": "web01.corp.local",
    "netbiosName": "WEB01",
    "address": "10.0.0.5",
    "lastLoggedOnUser": "jdoe",
    "cpuCount": 4,
    "totalMemory": 16384,
    "biosSerialNumber": "SN123456",
    "biosAssetTag": "ASSET-01",
    "operatingSystem": {
        "publisher": "Canonical", "productName": "Ubuntu", "version": "22.04",
        "edition": "Server", "architecture": "64-Bit",
        "lifecycle": {"stage": "Current", "eolDate": None, "eosDate": "2027-04-01T00:00:00.000Z"},
    },
    "hardware": {
        "fullName": "Dell Inc. PowerEdge R640", "manufacturer": "Dell Inc.",
        "model": "PowerEdge R640", "category": "Server Hardware / Rack Server",
    },
    "processor": {"description": "Intel Xeon Silver 4210", "numCPUs": 4},
    "agent": {"version": "5.2.1", "lastCheckedIn": 1700000000000},
    "sensor": {"lastVMScan": 1700000500000},
    "criticality": {"score": 4},
    "businessInformation": {"company": "Acme", "department": "IT", "ownedBy": "Jane",
                             "environment": "Production", "managedBy": "Jane", "supportGroup": "Infra"},
    "lastLocation": {"city": "Austin", "state": "TX", "country": "United States"},
    "tagList": {"tag": [{"tagName": "web-tier"}, {"tagName": "pci-scope"}]},
    "openPortListData": {"openPort": [
        {"port": 443, "protocol": "TCP", "detectedService": "HTTPS"},
        {"port": 22, "protocol": "TCP", "detectedService": "SSH"},
    ]},
    "volumeListData": {"volume": [{"name": "/", "size": 107374182400, "free": 53687091200}]},
    "networkInterfaceListData": {"networkInterface": [
        {"interfaceName": "eth0", "macAddress": "00:11:22:33:44:55", "addressIpV4": "10.0.0.5", "addressIpV6": None},
    ]},
    "softwareListData": {"software": [
        {"productName": "Google Chrome", "fullName": "Google Chrome 115.0", "publisher": "Google",
         "version": "115.0.5790.110", "category": "Web Browser", "lifecycle": {"stage": "Current"}},
        {"productName": "OpenSSH", "fullName": "OpenBSD OpenSSH Server 8.9", "publisher": "OpenBSD",
         "version": "8.9", "category": "Access Software", "lifecycle": {"stage": "Current"}},
        # No publisher at all -- exercises the SOFTWARE_VENDOR_KEYWORDS fallback path
        {"productName": "7-Zip", "fullName": "7-Zip 21.07", "publisher": "",
         "version": "21.07", "category": "Utility", "lifecycle": {"stage": "Current"}},
        # No publisher AND no keyword match -- should be dropped, not guessed wrong
        {"productName": "SomeInternalTool", "fullName": "SomeInternalTool 1.0", "publisher": None,
         "version": "1.0", "category": "Other", "lifecycle": {"stage": "Current"}},
    ]},
}

parsed = gav._parse_gav_asset(FIXTURE_ASSET)
fields, software = parsed["fields"], parsed["software"]

assert fields["hardware_info"] == "Dell Inc. PowerEdge R640"
assert fields["hardware_manufacturer"] == "Dell Inc."
assert fields["hardware_model"] == "PowerEdge R640"
assert fields["os_publisher"] == "Canonical"
assert fields["os_version"] == "22.04"
assert fields["os_edition"] == "Server"
assert fields["os_lifecycle_stage"] == "Current"
assert fields["os_eos_date"] == "2027-04-01T00:00:00.000Z"
assert fields["cpu_count"] == 4
assert fields["total_memory_mb"] == 16384
assert fields["bios_serial_number"] == "SN123456"
assert fields["qualys_criticality_score"] == 4
assert fields["qualys_business_info"]["owned_by"] == "Jane"
assert fields["qualys_business_info"]["environment"] == "Production"
assert fields["qualys_location"]["city"] == "Austin"
assert set(fields["qualys_tags"]) == {"web-tier", "pci-scope"}
assert fields["open_ports"] == [{"port": 443, "protocol": "TCP", "service": "HTTPS"}, {"port": 22, "protocol": "TCP", "service": "SSH"}]
assert fields["volumes"][0]["name"] == "/"
assert fields["network_interfaces"][0]["ipv4"] == "10.0.0.5"
assert fields["agent_version"] == "5.2.1"
assert fields["agent_last_checked_in"] is not None
assert fields["last_vm_scan_at"] is not None
print("PASS: _parse_gav_asset flattens hardware/OS/business/location/tags/ports/volumes/network-interfaces correctly")

by_name = {s["name"]: s for s in software}
assert by_name["Google Chrome"]["vendor"] == "Google"
assert by_name["OpenSSH"]["vendor"] == "OpenBSD"
assert by_name["Google Chrome"]["version"] == "115.0.5790.110"
assert by_name["7-Zip"]["vendor"] is None  # publisher blank at parse time -- filled in later by the keyword fallback in sync_qualys_asset_inventory
assert by_name["SomeInternalTool"]["vendor"] is None
print("PASS: _parse_gav_asset extracts real per-software publisher as vendor, leaves blank ones for the sync step's fallback")

# A field with no real value anywhere shouldn't appear in the flattened dict at all
# (so a patch never clobbers a previously-known value with None).
sparse = gav._parse_gav_asset({"id": 1, "assetName": "bare-host"})
assert sparse["fields"] == {}
assert sparse["software"] == []
print("PASS: an asset with no hardware/OS/software data at all produces an empty fields dict, not a dict full of Nones")

# ============ sync_qualys_asset_inventory -- full integration with faked httpx ============

class FakeResponse:
    def __init__(self, json_data=None, text="", status_code=200):
        self._json = json_data
        self.text = text
        self.status_code = status_code

    def json(self):
        return self._json


class FakeAsyncClient:
    def __init__(self, *a, **kw):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, url, **kw):
        if url.endswith("/auth"):
            return FakeResponse(text="a" * 40, status_code=200)
        if url.endswith("/rest/2.0/search/am/asset"):
            body = kw.get("json") or {}
            last_id = 0
            if "id > " in body.get("filter", ""):
                last_id = int(body["filter"].split("id > ")[1].split(" ")[0])
            if last_id == 0:
                return FakeResponse({"assetListData": {"asset": [FIXTURE_ASSET]}}, status_code=200)
            return FakeResponse({"assetListData": {"asset": []}}, status_code=200)
        raise AssertionError(f"Unexpected POST {url}")


import httpx
_real_httpx_async_client = httpx.AsyncClient
httpx.AsyncClient = FakeAsyncClient


def _reset():
    run(db.integrations.delete_many({}))
    run(db.assets.delete_many({}))
    run(db.software_inventory.delete_many({}))
    run(db.vendors.delete_many({}))


def _seed_qualys_integration():
    run(db.integrations.insert_one({
        "id": str(uuid.uuid4()), "name": "Qualys VMDR", "type": "infrastructure",
        "status": "healthy", "sync_errors": 0,
        "config": {"endpoint": "https://qualysapi.qg2.apps.qualys.com", "username": "svc", "api_key": "pw123"},
    }))


_reset()
_seed_qualys_integration()
run(db.assets.insert_one({"id": "asset-1", "hostname": "web01.corp.local", "ip": "10.0.0.5", "tags": []}))
result = run(gav.sync_qualys_asset_inventory(db))
assert result["gav_assets_seen"] == 1
assert result["assets_enriched"] == 1
assert result["software_entries_synced"] == 3  # Chrome, OpenSSH, 7-Zip -- the unresolvable one is dropped
print("PASS: sync_qualys_asset_inventory() matches the existing asset by hostname and reports the right counts")

asset = run(db.assets.find_one({"id": "asset-1"}, {"_id": 0}))
assert asset["hardware_manufacturer"] == "Dell Inc."
assert asset["os_publisher"] == "Canonical"
assert asset["qualys_criticality_score"] == 4
assert asset["gav_synced_at"] is not None
print("PASS: the matched asset is patched with the flattened GAV fields")

sw_rows = run(db.software_inventory.find({"asset_id": "asset-1"}, {"_id": 0}).to_list(20))
by_name2 = {r["name"]: r for r in sw_rows}
assert by_name2["Google Chrome"]["vendor"] == "Google"
assert by_name2["Google Chrome"]["source"] == "qualys_device"
assert by_name2["OpenSSH"]["vendor"] == "OpenBSD"
assert by_name2["7-Zip"]["vendor"] == "7-Zip"  # resolved via SOFTWARE_VENDOR_KEYWORDS fallback
assert "SomeInternalTool" not in by_name2  # no publisher + no keyword match -- correctly dropped, not guessed
print("PASS: db.software_inventory rows use the real Qualys publisher field as vendor, with a keyword fallback only when confident, and never a wrong guess")

# ============ generalized filters actually pick up qualys_device rows ============

# suggest_vendors() -- the exact bug this whole fix addresses
run(db.findings.delete_many({}))
run(db.assets.delete_many({}))
run(db.software_inventory.delete_many({}))
run(db.vendors.delete_many({}))
run(db.assets.insert_one({"id": "asset-2", "hostname": "app01", "tags": []}))
run(db.software_inventory.insert_one({
    "source": "qualys_device", "asset_id": "asset-2", "vendor": "Google", "name": "Google Chrome", "version": "115.0",
}))
suggestions = run(vm.suggest_vendors(db))
names = {s["name"] for s in suggestions}
assert "Google" in names
google = next(s for s in suggestions if s["name"] == "Google")
assert google["asset_count"] == 1
assert "device_software_inventory" in google["source"]
print("PASS: suggest_vendors() now surfaces a vendor detected purely from Qualys-sourced software_inventory (the exact gap reported: empty vendor approval queue on a Qualys-only deployment)")

# _linked_assets() structural matching via qualys_device rows
run(db.vendors.insert_one({"id": "v-google", "name": "Google", "category": "Software", "match_terms": [], "status": "active"}))
vendor = run(db.vendors.find_one({"id": "v-google"}, {"_id": 0}))
assets, structural_ids = run(vm._linked_assets(db, vendor))
assert "asset-2" in structural_ids
print("PASS: _linked_assets() treats a qualys_device software row as real structural evidence, same as Defender's")

# GET /v1/assets/{id}/software -- route-level generalization
run(db.software_inventory.insert_one({
    "source": "defender_device", "asset_id": "asset-2", "vendor": "Mozilla", "name": "Firefox", "version": "115.0",
}))
r = client.get("/api/v1/assets/asset-2/software")
assert r.status_code == 200
vendors_seen = {item["vendor"] for item in r.json()["items"]}
assert vendors_seen == {"Google", "Mozilla"}
assert r.json()["total"] == 2
print("PASS: GET /v1/assets/{id}/software returns rows from BOTH defender_device and qualys_device sources together")

httpx.AsyncClient = _real_httpx_async_client

print("\nALL QUALYS GAV/CSAM + DEVICE-SOFTWARE-SOURCE TESTS PASSED")
