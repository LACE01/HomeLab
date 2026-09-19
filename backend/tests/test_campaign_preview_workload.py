"""Scope preview, per-assignee workload, scope templates, weekly chart rollup."""
import os, sys, asyncio
from datetime import datetime, timezone, timedelta
os.environ["MONGO_URL"]="x"; os.environ["DB_NAME"]="t"; os.environ["JWT_SECRET"]="x"
sys.path.insert(0, ".")
from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client=AsyncMongoMockClient(); db_module.db=db_module.client["t"]; db=db_module.db
import server, auth_utils
from routes import findings as fr; fr.db=db
from routes import dashboards as dr; dr.db=db
from routes import remediation_campaigns as rr; rr.db=db
from fastapi.testclient import TestClient
run=lambda x: asyncio.get_event_loop().run_until_complete(x)
def a(c,m=""): assert c,m
now=datetime.now(timezone.utc)
admin={"id":"u1","email":"a@x.com","role":"admin","name":"A","teams":[],"team":None}
server.app.dependency_overrides[auth_utils.get_current_user]=lambda: admin
c=TestClient(server.app)

run(db.findings.insert_many([
  {"id":"f1","title":"A","cve":"CVE-1","severity":"Critical","status":"New","owner_team":"SecOps","kev_flag":True,"risk_score":90,"asset_hostname":"h1"},
  {"id":"f2","title":"B","cve":"CVE-2","severity":"High","status":"New","owner_team":"SecOps","risk_score":70,"asset_hostname":"h1"},
  {"id":"f3","title":"C","cve":"CVE-3","severity":"Low","status":"Fixed validated","owner_team":"SecOps","risk_score":10,"asset_hostname":"h2"},
]))

# ---- preview ----
# via filter (hides resolved by default -> open scope)
pv=c.post("/api/v1/remediation-campaigns/preview", json={"findings_filter":{"owner_team":"SecOps"}}).json()
a(pv["total"]==2 and pv["to_patch"]==2 and pv["sample"][0]["id"]=="f1", pv)
# via explicit ids incl a resolved one -> already_resolved counted
pv2=c.post("/api/v1/remediation-campaigns/preview", json={"finding_ids":["f1","f2","f3"]}).json()
a(pv2["total"]==3 and pv2["to_patch"]==2 and pv2["already_resolved"]==1 and pv2["by_severity"].get("Critical")==1, pv2)
print("PASS: preview returns total, to-patch vs already-resolved, severity breakdown, and a risk-sorted sample")

# ---- workload ----
c.post("/api/v1/remediation-campaigns", json={"name":"c1","finding_ids":["f1","f2"],"assignees":["tech@x.com"],"due_date":(now-timedelta(days=1)).isoformat()})
c.post("/api/v1/remediation-campaigns", json={"name":"c2","finding_ids":["f1"],"assignees":["tech@x.com","tech2@x.com"]})
wl={w["assignee"]:w for w in c.get("/api/v1/remediation-campaigns/workload").json()["items"]}
a(wl["tech@x.com"]["campaigns"]==2 and wl["tech@x.com"]["overdue_campaigns"]==1 and wl["tech@x.com"]["open"]>=1, wl)
print("PASS: workload aggregates per-assignee campaigns / open / overdue across campaigns")

# ---- scope templates ----
r=c.post("/api/v1/remediation-campaigns/scope-templates", json={"name":"PCI criticals","filter":{"severity":["Critical"],"tags":["pci"]}})
a(r.status_code==200)
tpls=c.get("/api/v1/remediation-campaigns/scope-templates").json()["items"]
a(len(tpls)==1 and tpls[0]["filter"]["tags"]==["pci"])
c.delete(f"/api/v1/remediation-campaigns/scope-templates/{tpls[0]['id']}")
a(len(c.get('/api/v1/remediation-campaigns/scope-templates').json()['items'])==0)
print("PASS: scope templates save / list / delete (per user)")

# ---- weekly granularity ----
run(db.posture_snapshots.insert_many([
  {"day":"2026-09-14","counts":{"open_findings":100,"by_severity":{"Critical":5},"kev":3}},  # Mon
  {"day":"2026-09-16","counts":{"open_findings":80,"by_severity":{"Critical":4},"kev":2}},   # Wed same wk
]))
run(db.patches_applied.insert_many([{"resolved_at":"2026-09-14T10:00Z"},{"resolved_at":"2026-09-16T10:00Z"}]))
wk=c.get("/api/v1/dashboards/vuln-timeseries", params={"days":3650,"granularity":"week"}).json()["series"]
wkrow=[r for r in wk if r["day"]=="2026-09-14"]
a(wkrow and wkrow[0]["total_open"]==80 and wkrow[0]["patched"]==2, wk)  # latest open in week, summed patches
print("PASS: weekly granularity rolls up (latest open per week, summed patches)")

server.app.dependency_overrides.clear()
print("\nALL PREVIEW/WORKLOAD/TEMPLATE TESTS PASSED")
