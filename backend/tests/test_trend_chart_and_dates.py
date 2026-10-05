"""#16: the per-host vulnerabilities-over-time chart must count findings whose
timestamps are native BSON datetimes (previously silently dropped -> "No findings"),
and stay correct for string timestamps. Plus the shared parse_dt helper and the
exception/report sites that used to 500 on datetime-typed fields."""
import os, sys, asyncio
from datetime import datetime, timezone, timedelta, date
os.environ.update(MONGO_URL="x", DB_NAME="t", JWT_SECRET="x")
sys.path.insert(0, ".")
from mongomock_motor import AsyncMongoMockClient
import db as dbm; dbm.client=AsyncMongoMockClient(); dbm.db=dbm.client["t"]; db=dbm.db
import server, auth_utils
from routes.common import parse_dt
from fastapi.testclient import TestClient
run=lambda x: asyncio.get_event_loop().run_until_complete(x)
def a(c,m=""): assert c,m
now=datetime.now(timezone.utc)

a(parse_dt("2026-01-02T03:04:05Z").tzinfo is not None)
a(parse_dt(datetime(2026,1,2)).tzinfo is not None, "naive datetime -> aware")
a(parse_dt(date(2026,1,2)).year==2026 and parse_dt(None) is None and parse_dt("junk") is None)
print("PASS: parse_dt handles ISO strings, aware/naive datetimes, dates, junk")

run(db.findings.insert_many([
 {"id":"dt","asset_id":"h1","severity":"High","status":"New",
  "first_seen_at":now-timedelta(days=20),"last_seen_at":now-timedelta(days=1)},          # native datetimes
 {"id":"st","asset_id":"h1","severity":"Critical","status":"Fixed validated",
  "first_seen_at":(now-timedelta(days=10)).isoformat(),"last_seen_at":(now-timedelta(days=5)).isoformat()},
]))
admin={"id":"u1","email":"a@x.com","role":"admin","name":"A","teams":[],"team":None}
server.app.dependency_overrides[auth_utils.get_current_user]=lambda: admin
c=TestClient(server.app)
r=c.get("/api/v1/charts/findings-timeseries",params={"asset_id":"h1","days":30}).json()
a(r["total"]==2, f"datetime-typed finding no longer dropped: total={r['total']}")
today=r["series"][-1]; d7=r["series"][-8]
a(today.get("High")==1 and today.get("Critical",0)==0, f"today: open High present, fixed Critical gone: {today}")
a(d7.get("Critical")==1, f"7 days ago the fixed Critical was still present: {d7}")
w=c.get("/api/v1/charts/findings-timeseries",params={"asset_id":"h1","days":90,"granularity":"week"}).json()
a(w["total"]==2 and w["series"][-1].get("High")==1)
print("PASS: #16 per-host chart counts datetime- and string-typed findings (day + week)")

# exceptions list with a datetime expires_at must not 500
run(db.exceptions.insert_one({"id":"e1","status":"active","finding_id":"dt","expires_at":now+timedelta(days=10),
                               "requested_at":now.isoformat(),"approval_chain":[]}))
rr=c.get("/api/v1/exceptions")
a(rr.status_code==200, f"exceptions list with datetime expires_at: {rr.status_code} {rr.text[:150]}")
e=[x for x in rr.json()["items"] if x["id"]=="e1"][0]
a(e["days_until_expiry"] in (9,10), e.get("days_until_expiry"))
print("PASS: exceptions list computes expiry from a native datetime (was a 500)")
print("\nALL TREND-CHART + DATE TESTS PASSED")
