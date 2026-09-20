"""Admin-tunable numeric settings: list/validate/set, live effect on the dashboard
cache (TTL=0 disables it), persistence, and boot re-apply."""
import os, sys, asyncio
from datetime import datetime, timezone, timedelta
os.environ.update(MONGO_URL="x", DB_NAME="t", JWT_SECRET="x")
sys.path.insert(0, ".")
from mongomock_motor import AsyncMongoMockClient
import db as dbm; dbm.client=AsyncMongoMockClient(); dbm.db=dbm.client["t"]; db=dbm.db
import server, auth_utils, app_settings
from routes import common as common
from fastapi.testclient import TestClient
run=lambda x: asyncio.get_event_loop().run_until_complete(x)
def a(c,m=""): assert c,m
now=datetime.now(timezone.utc)
admin={"id":"u1","email":"a@x.com","role":"admin","name":"A","teams":[],"team":None}
server.app.dependency_overrides[auth_utils.get_current_user]=lambda: admin
c=TestClient(server.app)

items={i["key"]:i for i in c.get("/api/v1/settings/tunables").json()["items"]}
a("dashboard_cache_ttl_seconds" in items and "saved_search_alert_interval_minutes" in items, "both tunables listed")
a(items["dashboard_cache_ttl_seconds"]["value"]==30 and items["saved_search_alert_interval_minutes"]["value"]==60, "defaults surfaced")
a(all(k in items["dashboard_cache_ttl_seconds"] for k in ("min","max","unit","label","description")), "registry metadata present")
print("PASS: tunables list with defaults + bounds metadata")

a(c.patch("/api/v1/settings/tunables/dashboard_cache_ttl_seconds", json={"value":9999}).status_code==400, "over-max rejected")
a(c.patch("/api/v1/settings/tunables/dashboard_cache_ttl_seconds", json={"value":-1}).status_code==400, "under-min rejected")
a(c.patch("/api/v1/settings/tunables/nope", json={"value":1}).status_code==400, "unknown key rejected")
print("PASS: out-of-range and unknown-key writes rejected (400)")

a(c.patch("/api/v1/settings/tunables/dashboard_cache_ttl_seconds", json={"value":0}).status_code==200, "set 0 ok")
a(common._DASH_TTL_OVERRIDE["seconds"]==0, "override pushed to live process immediately")
run(db.findings.insert_one({"id":"f1","severity":"Critical","status":"New","owner_team":"C","asset_id":"h1","due_at":now-timedelta(days=1),"first_seen_at":now-timedelta(days=5)}))
b1=c.get("/api/v1/dashboards/executive").text
run(db.findings.insert_one({"id":"f2","severity":"High","status":"New","owner_team":"C","asset_id":"h2","due_at":now-timedelta(days=1),"first_seen_at":now-timedelta(days=5)}))
b2=c.get("/api/v1/dashboards/executive").text
a(b1!=b2, "TTL=0 disables cache -> each call recomputes")
print("PASS: TTL=0 disables the dashboard cache live")

a(c.patch("/api/v1/settings/tunables/saved_search_alert_interval_minutes", json={"value":10}).status_code==200, "set interval ok")
a(run(app_settings.get_setting(db,"saved_search_alert_interval_minutes"))==10, "interval persisted + read back")
common.set_dashboard_ttl_override(None)
run(app_settings.apply_persisted_settings(db))
a(common._DASH_TTL_OVERRIDE["seconds"]==0, "boot re-apply restores stored TTL override")
print("PASS: values persist and are re-applied at boot")

print("\nALL TUNABLE SETTINGS TESTS PASSED")
