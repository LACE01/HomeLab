import os, sys, asyncio, datetime as dt
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_eol_tracking"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_eol_tracking"]

import server
import auth_utils
from routes import eol_tracking as eol_route
eol_route.db = db_module.db

from fastapi.testclient import TestClient
import httpx

admin_user = {"id": "u1", "email": "admin@x.com", "role": "admin", "name": "Admin", "teams": []}
app = server.app
app.dependency_overrides[auth_utils.get_current_user] = lambda: admin_user
client = TestClient(app)

db = db_module.db


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


import eol_tracking as eol

today = dt.datetime.now(dt.timezone.utc).date()


def _iso(d):
    return d.isoformat()


# ============ classify_eol() -- pure unit tests, dual legacy/v1 field names ============

still_supported = {"cycle": "22.04", "eol": False}
sev, reason = eol.classify_eol(still_supported)
assert sev is None
print("PASS: classify_eol() treats eol=False as still supported (no issue)")

eol_true_no_date = {"cycle": "6", "eol": True}
sev2, reason2 = eol.classify_eol(eol_true_no_date)
assert sev2 == "High" and "no specific date" in reason2
print("PASS: classify_eol() flags eol=True (EOL with no published date) as High")

past_recent = {"cycle": "20.04", "eol": _iso(today - dt.timedelta(days=30))}
sev3, reason3 = eol.classify_eol(past_recent)
assert sev3 == "High" and "30 day(s) ago" in reason3
print("PASS: classify_eol() flags a recently-passed EOL date as High")

past_long = {"cycle": "18.04", "eol": _iso(today - dt.timedelta(days=400))}
sev4, reason4 = eol.classify_eol(past_long)
assert sev4 == "Critical"
print("PASS: classify_eol() escalates to Critical once EOL was over a year ago")

upcoming = {"cycle": "24.04", "eol": _iso(today + dt.timedelta(days=45))}
sev5, reason5 = eol.classify_eol(upcoming)
assert sev5 == "Medium" and "in 45 day(s)" in reason5
print("PASS: classify_eol() flags an EOL within the 90-day warning window as Medium")

far_future = {"cycle": "26.04", "eol": _iso(today + dt.timedelta(days=400))}
sev6, reason6 = eol.classify_eol(far_future)
assert sev6 is None
print("PASS: classify_eol() reports no issue for an EOL date far in the future")

# v1 schema uses `release` instead of `cycle` -- must be read identically
v1_entry = {"release": "9", "eol": _iso(today - dt.timedelta(days=10))}
assert eol._cycle_of(v1_entry) == "9"
sev7, _ = eol.classify_eol(v1_entry)
assert sev7 == "High"
print("PASS: classify_eol()/_cycle_of() handle the v1 API's 'release' field name identically to legacy 'cycle'")

# ============ parse_os_to_product_cycle() -- auto-detection heuristics ============

assert eol.parse_os_to_product_cycle("Ubuntu 20.04.3 LTS") == ("ubuntu", "20.04")
assert eol.parse_os_to_product_cycle("Debian GNU/Linux 11 (bullseye)") == ("debian", "11")
assert eol.parse_os_to_product_cycle("CentOS Linux 7") == ("centos", "7")
assert eol.parse_os_to_product_cycle("Red Hat Enterprise Linux 8") == ("rhel", "8")
assert eol.parse_os_to_product_cycle("Microsoft Windows Server 2019 Standard") is None
assert eol.parse_os_to_product_cycle("macOS 14.5 Sonoma") is None
assert eol.parse_os_to_product_cycle("") is None
print("PASS: parse_os_to_product_cycle() maps Ubuntu/Debian/CentOS/RHEL confidently and leaves Windows/macOS/unknown alone")

# ============ fetch_product_cycles() / run_eol_check() -- fake HTTP, no real network ============

class FakeResponse:
    def __init__(self, status_code, json_data=None):
        self.status_code = status_code
        self._json = json_data if json_data is not None else []

    def json(self):
        return self._json


class FakeAsyncClient:
    responses_by_url = {}

    def __init__(self, *a, **kw):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url, **kw):
        if url not in FakeAsyncClient.responses_by_url:
            return FakeResponse(404, {})
        return FakeAsyncClient.responses_by_url[url]


_real_async_client = httpx.AsyncClient
httpx.AsyncClient = FakeAsyncClient

FakeAsyncClient.responses_by_url = {
    "https://endoflife.date/api/ubuntu.json": FakeResponse(200, [
        {"cycle": "22.04", "eol": _iso(today + dt.timedelta(days=1000)), "latest": "22.04.4", "lts": True},
        {"cycle": "18.04", "eol": _iso(today - dt.timedelta(days=100)), "latest": "18.04.6", "lts": True},
    ]),
}

cycles = run(eol.fetch_product_cycles("ubuntu"))
assert len(cycles) == 2
print("PASS: fetch_product_cycles() parses a well-formed product response")

try:
    run(eol.fetch_product_cycles("not-a-real-product"))
    assert False
except ValueError as e:
    assert "Unknown product" in str(e)
print("PASS: fetch_product_cycles() raises a clear ValueError for a 404 (unknown product)")

result = run(eol.run_eol_check(db, "ubuntu", "18.04"))
assert result["eol"] == _iso(today - dt.timedelta(days=100))
print("PASS: run_eol_check() finds the matching cycle and stores the raw status")

finding = run(db.findings.find_one({"canonical_key": "eol:ubuntu:18.04"}, {"_id": 0}))
assert finding is not None and finding["severity"] == "High" and finding["status"] == "New"
assert finding["component_name"] == "ubuntu" and finding["component_version"] == "18.04"
print("PASS: run_eol_check() creates a finding for an EOL'd cycle")

result2 = run(eol.run_eol_check(db, "ubuntu", "22.04"))
assert result2["eol"] == _iso(today + dt.timedelta(days=1000))
no_finding = run(db.findings.find_one({"canonical_key": "eol:ubuntu:22.04"}, {"_id": 0}))
assert no_finding is None
print("PASS: run_eol_check() creates no finding for a cycle that's comfortably supported")

try:
    run(eol.run_eol_check(db, "ubuntu", "99.04"))
    assert False
except ValueError as e:
    assert "not found" in str(e) or "available cycles" in str(e)
print("PASS: run_eol_check() raises a clear error when the requested cycle doesn't exist for the product")

# --- auto-resolve: cycle 18.04 becomes supported again (simulating a corrected watch) ---
FakeAsyncClient.responses_by_url["https://endoflife.date/api/ubuntu.json"] = FakeResponse(200, [
    {"cycle": "18.04", "eol": False, "latest": "18.04.6", "lts": True},
])
run(eol.run_eol_check(db, "ubuntu", "18.04"))
refreshed_finding = run(db.findings.find_one({"canonical_key": "eol:ubuntu:18.04"}, {"_id": 0}))
assert refreshed_finding["status"] == "Fixed validated"
print("PASS: run_eol_check() auto-resolves a finding once the underlying cycle is no longer flagged")

# ============ run_all_eol_checks() / scan_assets_for_eol() ============

FakeAsyncClient.responses_by_url = {
    "https://endoflife.date/api/ubuntu.json": FakeResponse(200, [
        {"cycle": "18.04", "eol": _iso(today - dt.timedelta(days=5)), "latest": "18.04.6"},
        {"cycle": "20.04", "eol": _iso(today + dt.timedelta(days=1000)), "latest": "20.04.6"},
    ]),
    "https://endoflife.date/api/debian.json": FakeResponse(200, [
        {"cycle": "11", "eol": _iso(today + dt.timedelta(days=1000)), "latest": "11.9"},
    ]),
}

run(db.assets.insert_many([
    {"id": "a1", "hostname": "web-1", "os": "Ubuntu 18.04.6 LTS"},
    {"id": "a2", "hostname": "web-2", "os": "Debian GNU/Linux 11 (bullseye)"},
    {"id": "a3", "hostname": "dc-1", "os": "Microsoft Windows Server 2019 Standard"},  # not auto-detected
]))
# clear any watch targets left over from earlier direct run_eol_check() calls
run(db.eol_watch_targets.delete_many({}))

scan_result = run(eol.scan_assets_for_eol(db))
assert scan_result["assets_scanned"] == 3
assert scan_result["os_strings_matched"] == 2  # Windows Server correctly excluded
assert scan_result["watch_targets_added"] == 2
print("PASS: scan_assets_for_eol() auto-detects Ubuntu/Debian assets, skips Windows, and adds watch targets for exactly the detected ones")

targets = run(db.eol_watch_targets.find({}, {"_id": 0}).to_list(10))
assert any(t["product"] == "ubuntu" and t["cycle"] == "18.04" and t["source"] == "auto" for t in targets)
assert any(t["product"] == "debian" and t["cycle"] == "11" and t["source"] == "auto" for t in targets)
print("PASS: auto-added watch targets are tagged source=auto")

# re-scanning must not duplicate the same auto-detected targets
scan_result2 = run(eol.scan_assets_for_eol(db))
assert scan_result2["watch_targets_added"] == 0
targets_after = run(db.eol_watch_targets.find({}, {"_id": 0}).to_list(10))
assert len(targets_after) == len(targets)
print("PASS: re-running scan_assets_for_eol() never creates duplicate watch targets")

batch = run(eol.run_all_eol_checks(db))
assert batch["checked"] == 2
assert batch["issues"] == 1  # only ubuntu 18.04 is actually EOL
print("PASS: run_all_eol_checks() checks every enabled target and counts only the real issues")

httpx.AsyncClient = _real_async_client

# ============ routes ============

httpx.AsyncClient = FakeAsyncClient
r = client.post("/api/v1/admin/eol/targets", json={"product": "Ubuntu", "cycle": "20.04", "label": "test"})
assert r.status_code == 200, r.text
created = r.json()
assert created["product"] == "ubuntu"  # lowercased
print("PASS: POST /v1/admin/eol/targets creates a manual watch target and normalizes the product to lowercase")

r_bad = client.post("/api/v1/admin/eol/targets", json={"product": "", "cycle": ""})
assert r_bad.status_code == 400
print("PASS: POST /v1/admin/eol/targets rejects an empty product/cycle")

r2 = client.get("/api/v1/admin/eol/targets")
assert r2.status_code == 200
assert any(t["id"] == created["id"] for t in r2.json()["items"])
print("PASS: GET /v1/admin/eol/targets lists watch targets")

r3 = client.post(f"/api/v1/admin/eol/targets/{created['id']}/check-now")
assert r3.status_code == 200, r3.text
print("PASS: POST /v1/admin/eol/targets/{id}/check-now runs a real check through the route")

r4 = client.get("/api/v1/admin/eol/targets")
item = next(t for t in r4.json()["items"] if t["id"] == created["id"])
assert item["latest"] is not None and item["latest"]["product"] == "ubuntu"
print("PASS: GET /v1/admin/eol/targets merges each target with its latest check result")

r5 = client.put(f"/api/v1/admin/eol/targets/{created['id']}", json={"product": "ubuntu", "cycle": "20.04", "enabled": False})
assert r5.status_code == 200 and r5.json()["enabled"] is False
print("PASS: PUT /v1/admin/eol/targets/{id} updates a watch target")

r6 = client.post("/api/v1/admin/eol/check-all")
assert r6.status_code == 200, r6.text
print("PASS: POST /v1/admin/eol/check-all runs the batch route")

r7 = client.post("/api/v1/admin/eol/scan-assets")
assert r7.status_code == 200, r7.text
assert "assets_scanned" in r7.json()
print("PASS: POST /v1/admin/eol/scan-assets runs the auto-detect route")

r8 = client.delete(f"/api/v1/admin/eol/targets/{created['id']}")
assert r8.status_code == 200 and r8.json()["ok"] is True
r9 = client.get("/api/v1/admin/eol/targets")
assert not any(t["id"] == created["id"] for t in r9.json()["items"])
print("PASS: DELETE /v1/admin/eol/targets/{id} removes the watch target")

httpx.AsyncClient = _real_async_client

# ============ feature flag + notification template + rbac wiring ============

import feature_flags
assert "eol_nightly_check" in feature_flags.FLAG_KEYS
print("PASS: eol_nightly_check is registered in the feature flag registry")

import notifier
assert "eol_software_issue" in notifier.TRIGGERS and "eol_software_issue" in notifier.TEMPLATES
rendered = notifier.TEMPLATES["eol_software_issue"]["subject"].format(product="ubuntu", cycle="18.04")
assert "ubuntu" in rendered and "18.04" in rendered
print("PASS: eol_software_issue notification trigger + template are wired and render correctly")

import rbac
assert any(m["key"] == "/admin/eol-tracking" for m in rbac.MODULE_REGISTRY)
print("PASS: /admin/eol-tracking is registered as an RBAC module key")

print("\nALL END-OF-LIFE SOFTWARE TRACKING TESTS PASSED")
