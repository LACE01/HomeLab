"""#60/#72/#74 (+66): ONE canonical 'open' definition (routes.common.OPEN_STATUSES)
drives every list, KPI, host count and campaign scope. Each symptom from the backlog
is pinned here, plus a static guard against re-introducing literal status lists."""
import os, sys, re, asyncio, pathlib
from datetime import datetime, timezone, timedelta
os.environ.update(MONGO_URL="x", DB_NAME="t", JWT_SECRET="x")
sys.path.insert(0, ".")
from mongomock_motor import AsyncMongoMockClient
import db as dbm; dbm.client=AsyncMongoMockClient(); dbm.db=dbm.client["t"]; db=dbm.db
import server, auth_utils
from routes import common as common
from fastapi.testclient import TestClient
run=lambda x: asyncio.get_event_loop().run_until_complete(x)
def a(c,m=""): assert c,m
now=datetime.now(timezone.utc); iso=lambda d:d.isoformat()

# static guard: no module may define its own literal open list again
lit=re.compile(r'\[\s*["\']New["\'],\s*["\']Needs triage["\'],\s*["\']Valid["\'],\s*["\']Reopened["\']')
offenders=[str(p) for p in pathlib.Path(".").rglob("*.py")
           if not str(p).startswith("tests/") and str(p)!="routes/common.py"
           and any(lit.search(l) and "REMAINING_OPEN" not in l for l in p.read_text().splitlines())]
a(not offenders, f"literal open-status lists re-introduced in: {offenders}")
print("PASS: no literal open-status lists outside routes/common.py (canonical source enforced)")

common._DASH_TTL_OVERRIDE["seconds"]=0   # no dashboard cache in tests
fs=[
 {"id":"o1","title":"Open KEV","severity":"Critical","status":"New","kev_flag":True,"asset_id":"h1","asset_hostname":"h1","owner_team":"T","first_seen_at":iso(now-timedelta(days=3)),"risk_score":90},
 {"id":"o2","title":"Open pending","severity":"High","status":"Fixed pending validation","kev_flag":True,"asset_id":"h1","asset_hostname":"h1","owner_team":"T","first_seen_at":iso(now-timedelta(days=60)),"risk_score":70},
 {"id":"r1","title":"Fixed KEV","severity":"Critical","status":"Fixed validated","kev_flag":True,"asset_id":"h1","asset_hostname":"h1","owner_team":"T","first_seen_at":iso(now-timedelta(days=90)),"risk_score":95},
 {"id":"r2","title":"Mitigated","severity":"Critical","status":"Mitigated","kev_flag":False,"asset_id":"h1","asset_hostname":"h1","owner_team":"T","first_seen_at":iso(now-timedelta(days=5)),"risk_score":50},
]
run(db.findings.insert_many(fs)); run(db.assets.insert_one({"id":"h1","hostname":"h1"}))
admin={"id":"u1","email":"a@x.com","role":"admin","name":"A","teams":[],"team":None}
server.app.dependency_overrides[auth_utils.get_current_user]=lambda: admin
c=TestClient(server.app)

# #60: KEV view (no status of its own) must exclude resolved
ids={f["id"] for f in c.get("/api/v1/findings",params={"view":"kev"}).json()["items"]}
a(ids=={"o1","o2"}, f"KEV view lists only open KEV findings, not Fixed-validated: {ids}")
ids_all={f["id"] for f in c.get("/api/v1/findings").json()["items"]}
a(ids_all=={"o1","o2"}, f"All Open excludes Fixed validated + Mitigated: {ids_all}")
ids_inc={f["id"] for f in c.get("/api/v1/findings",params={"include_resolved":"true"}).json()["items"]}
a(ids_inc=={"o1","o2","r1","r2"}, "include_resolved toggle still shows history")
print("PASS: #60 views + default list are open-only; include_resolved toggle shows history")

# #60: NEW(30d) uses first_seen_at (scanner findings have no created_at)
an=c.get("/api/v1/dashboards/analyst",params={"range":"30d"}).json()
a(an["new_findings"]==1 and an["open_findings"]==2, f"NEW(30d)=1 (o1), open=2: {an['new_findings']},{an['open_findings']}")
print("PASS: #60 NEW(30d) counts open findings first seen in-window (was always 0)")

# #72: host header = current open, history separate
hf=c.get("/api/v1/assets/h1/findings").json()
a(hf["open_count"]==2 and hf["resolved_count"]==2 and hf["total_count"]==4, hf)
a(hf["items"][0]["is_open"] and hf["items"][1]["is_open"], "open findings sort first")
print("PASS: #72 host returns current-open (2) vs lifetime (4)")

# #74: create == preview (no crude severity union)
flt={"severity":["Critical"],"view":"kev"}
pv=c.post("/api/v1/remediation-campaigns/preview",json={"findings_filter":flt}).json()
cr=c.post("/api/v1/remediation-campaigns",json={"name":"t","findings_filter":flt}).json()
a(pv["total"]==1 and len(cr["finding_ids"])==1 and cr["finding_ids"]==["o1"],
  f"preview {pv['total']} vs generated {len(cr['finding_ids'])} {cr['finding_ids']}")
print("PASS: #74 campaign generates exactly what the preview showed")
print("\nALL CANONICAL OPEN-STATUS TESTS PASSED")
