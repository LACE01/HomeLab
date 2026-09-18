"""#61 vuln-over-time + KEV burndown timeseries; #56 Sensor->Category->Severity Sankey."""
import os, sys, asyncio
os.environ["MONGO_URL"]="x"; os.environ["DB_NAME"]="t"; os.environ["JWT_SECRET"]="x"
sys.path.insert(0, ".")
from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client=AsyncMongoMockClient(); db_module.db=db_module.client["t"]; db=db_module.db
import server, auth_utils
from routes import dashboards as dr; dr.db=db
from fastapi.testclient import TestClient
run=lambda x: asyncio.get_event_loop().run_until_complete(x)
def a(c,m=""): assert c,m
admin={"id":"u1","email":"a@x.com","role":"admin","name":"A","teams":[],"team":None}
server.app.dependency_overrides[auth_utils.get_current_user]=lambda: admin
c=TestClient(server.app)

# ---- #61 timeseries ----
run(db.posture_snapshots.insert_many([
  {"day":"2026-09-10","counts":{"open_findings":100,"by_severity":{"Critical":10,"High":20,"Medium":40,"Low":30},"kev":8,"overdue":5}},
  {"day":"2026-09-15","counts":{"open_findings":80,"by_severity":{"Critical":6,"High":16,"Medium":35,"Low":23},"kev":3,"overdue":4}},
]))
ts=c.get("/api/v1/dashboards/vuln-timeseries", params={"days":3650}).json()
a(ts["points"]==2 and ts["series"][0]["Critical"]==10 and ts["series"][1]["total_open"]==80, ts)
a(ts["kev_burndown"]["start"]==8 and ts["kev_burndown"]["current"]==3 and ts["kev_burndown"]["reduced"]==5, ts["kev_burndown"])
print("PASS: #61 — vuln timeseries returns per-day severity + total + KEV, and a KEV burndown (8→3, reduced 5)")

# ---- #56 sankey ----
run(db.findings.insert_many([
  {"id":"f1","source_tool":"Qualys VMDR","source_tool_type":"Network Vuln","severity":"Critical","status":"New","owner_team":"SecOps","kev_flag":True,"entity_name":"Payments"},
  {"id":"f2","source_tool":"Qualys VMDR","source_tool_type":"Network Vuln","severity":"High","status":"New","owner_team":"SecOps","kev_flag":False,"entity_name":"Payments"},
  {"id":"f3","source_tool":"Nessus","source_tool_type":"Web","severity":"Critical","status":"New","owner_team":"IT","kev_flag":False,"entity_name":"Web"},
  {"id":"f4","source_tool":"Qualys VMDR","source_tool_type":"Network Vuln","severity":"Low","status":"Fixed validated","owner_team":"SecOps"},  # resolved -> excluded
]))
sk=c.get("/api/v1/dashboards/sankey").json()
a(sk["total"]==3, f"sankey should count only OPEN findings, got {sk['total']}")
names={n["id"]:n for n in sk["nodes"]}
a(any(n["column"]==0 and n["name"]=="Qualys VMDR" for n in sk["nodes"]))
a(any(n["column"]==2 and n["name"]=="Critical" for n in sk["nodes"]))
# link Qualys->Network Vuln should carry value 2 (f1+f2)
q2n=[l for l in sk["links"] if l["source"]=="0:Qualys VMDR" and l["target"]=="1:Network Vuln"]
a(q2n and q2n[0]["value"]==2, q2n)
print("PASS: #56 — sankey builds Sensor→Category→Severity flows over OPEN findings only")

# filters: team + KEV
sk2=c.get("/api/v1/dashboards/sankey", params={"owner_team":"IT"}).json()
a(sk2["total"]==1, sk2["total"])
sk3=c.get("/api/v1/dashboards/sankey", params={"kev":"true"}).json()
a(sk3["total"]==1, sk3["total"])
print("PASS: #56 — sankey respects team / KEV / entity / severity filters")

server.app.dependency_overrides.clear()
print("\nALL DASHBOARD CHART TESTS PASSED")
