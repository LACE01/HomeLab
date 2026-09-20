"""Regression: dashboard endpoints must not 500 when finding/event timestamps are
native BSON datetimes (real Mongo) instead of ISO strings. Previously
`f["due_at"] < now_iso()` compared a datetime to a string -> TypeError -> 500."""
import os, sys, asyncio
from datetime import datetime, timezone, timedelta
os.environ.update(MONGO_URL="x", DB_NAME="t", JWT_SECRET="x")
sys.path.insert(0, ".")
from mongomock_motor import AsyncMongoMockClient
import db as dbm; dbm.client=AsyncMongoMockClient(); dbm.db=dbm.client["t"]; db=dbm.db
import server, auth_utils
from fastapi.testclient import TestClient
run=lambda x: asyncio.get_event_loop().run_until_complete(x)
def a(c,m=""): assert c,m
now=datetime.now(timezone.utc)

run(db.findings.insert_many([
 {"id":"f1","title":"A","cve":"CVE-1","severity":"Critical","status":"New","owner_team":"Coms","kev_flag":True,
  "asset_id":"h1","due_at":now-timedelta(days=3),"first_seen_at":now-timedelta(days=40),"reopened_count":0},
 {"id":"f2","title":"B","cve":"CVE-2","severity":"High","status":"Fixed validated","owner_team":"Coms",
  "asset_id":"h1","due_at":now+timedelta(days=3),"first_seen_at":now-timedelta(days=10),"last_changed_at":now-timedelta(days=1)},
 {"id":"f3","title":"C","severity":"Medium","status":"New","owner_team":"IT","asset_id":"h2",
  "due_at":(now-timedelta(days=1)).isoformat(),"first_seen_at":(now-timedelta(days=5)).isoformat()},
]))
run(db.security_events.insert_many([
 {"id":"e1","status":"acknowledged","created_at":now-timedelta(hours=5),"acknowledged_at":now-timedelta(hours=4)},
 {"id":"e2","status":"closed","created_at":now-timedelta(hours=8),"closed_at":now-timedelta(hours=2)},
]))
admin={"id":"u1","email":"a@x.com","role":"admin","name":"A","teams":[],"team":None}
server.app.dependency_overrides[auth_utils.get_current_user]=lambda: admin
c=TestClient(server.app)
for ep in ["analyst","manager","executive","exposure","operational","teams-leaderboard","soc"]:
    r=c.get(f"/api/v1/dashboards/{ep}")
    a(r.status_code==200, f"{ep} returned {r.status_code}: {r.text[:160]}")
    print(f"PASS: /dashboards/{ep} handles native-datetime findings/events (200)")
print("\nALL DASHBOARD DATETIME TESTS PASSED")
