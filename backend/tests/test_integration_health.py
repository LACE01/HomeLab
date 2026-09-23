"""#69: integration health is DERIVED honestly from last_sync age (not the stale
stored status), and stale/failed/never-synced connectors raise alerts."""
import os, sys, asyncio
from datetime import datetime, timezone, timedelta
os.environ.update(MONGO_URL="x", DB_NAME="t", JWT_SECRET="x")
sys.path.insert(0, ".")
from mongomock_motor import AsyncMongoMockClient
import db as dbm; dbm.client=AsyncMongoMockClient(); dbm.db=dbm.client["t"]; db=dbm.db
import server, auth_utils
from routes import integrations as ig
from fastapi.testclient import TestClient
run=lambda x: asyncio.get_event_loop().run_until_complete(x)
def a(c,m=""): assert c,m
now=datetime.now(timezone.utc); iso=lambda d:d.isoformat()

run(db.integrations.insert_many([
  {"id":"q","name":"Qualys","enabled":True,"status":"healthy","sync_errors":0,"last_sync_at":iso(now-timedelta(minutes=30)),"config":{"endpoint":"x","api_key":"y"}},
  {"id":"s","name":"Splunk","enabled":True,"status":"healthy","sync_errors":0,"last_sync_at":iso(now-timedelta(days=75)),"config":{"endpoint":"x","api_key":"y"}},  # 75d stale but stored HEALTHY
  {"id":"w","name":"Wazuh","enabled":True,"status":"degraded","sync_errors":4,"last_error":"auth failed","last_sync_at":iso(now-timedelta(days=80)),"config":{"endpoint":"x","api_key":"y"}},
  {"id":"n","name":"Tenable","enabled":True,"status":"healthy","sync_errors":0,"config":{"endpoint":"x","api_key":"y"}},  # never synced
  {"id":"nc","name":"OpenCTI","enabled":False,"status":"not_configured","config":{}},
]))
admin={"id":"u1","email":"a@x.com","role":"admin","name":"A","teams":[],"team":None}
server.app.dependency_overrides[auth_utils.get_current_user]=lambda: admin
c=TestClient(server.app)
items={i["id"]:i for i in c.get("/api/v1/integrations").json()["items"]}
a(items["q"]["health"]["health"]=="healthy", f"fresh -> healthy: {items['q']['health']}")
a(items["s"]["health"]["health"]=="stale", f"75d old -> stale despite stored HEALTHY: {items['s']['health']}")
a(items["w"]["health"]["health"]=="failed", f"errors+old -> failed: {items['w']['health']}")
a(items["n"]["health"]["health"]=="never_synced", f"never synced flagged: {items['n']['health']}")
a(items["nc"]["health"]["health"]=="not_configured", "disabled/unconfigured stays not_configured")
a(items["s"]["health"]["last_error"] is None and items["w"]["health"]["last_error"]=="auth failed", "last_error surfaced")
print("PASS: derived health is staleness-aware (stale/failed/never_synced/healthy/not_configured)")

r=run(ig.check_integration_staleness(db))
a(r["flagged"]==3, f"stale + failed + never_synced alerted (got {r})")
a(run(db.notifications_outbox.count_documents({"kind":"integration_stale"}))==3, "3 outbox alerts written")
# deduped per day
r2=run(ig.check_integration_staleness(db))
a(r2["flagged"]==0, "second run same day is deduped")
print("PASS: stale/failed/never-synced connectors alert (deduped per day)")
print("\nALL INTEGRATION HEALTH TESTS PASSED")
