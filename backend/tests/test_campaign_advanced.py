"""Recurring campaigns, escalation ladder, CSV export/report, bulk-reassign, spike explain."""
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
import remediation_campaigns as rc
from fastapi.testclient import TestClient
run=lambda x: asyncio.get_event_loop().run_until_complete(x)
def a(c,m=""): assert c,m
now=datetime.now(timezone.utc)
admin={"id":"u1","email":"a@x.com","role":"admin","name":"A","teams":[],"team":None}
server.app.dependency_overrides[auth_utils.get_current_user]=lambda: admin
c=TestClient(server.app)

run(db.findings.insert_many([
  {"id":"f1","title":"OpenSSL","cve":"CVE-1","qid":"38170","severity":"Critical","status":"New","owner_team":"SecOps","asset_hostname":"h1","first_seen_at":"2026-08-18T02:00:00Z"},
  {"id":"f2","title":"Apache","cve":"CVE-2","severity":"High","status":"Reopened","owner_team":"SecOps","asset_hostname":"h1","last_changed_at":"2026-08-18T05:00:00Z"},
]))

# ---- recurring: create + run-now ----
rec=c.post("/api/v1/remediation-campaigns/recurring", json={"name_template":"Monthly patch {month}","scope":{"severity":["Critical","High"]},"cadence":"monthly","due_days":30,"assignees":["tech@x.com"]}).json()
a(rec["id"] and rec["next_run_at"])
rn=c.post(f"/api/v1/remediation-campaigns/recurring/{rec['id']}/run-now").json()
a(rn["findings"]==2 and rn["campaign_id"], rn)
camp=c.get(f"/api/v1/remediation-campaigns/{rn['campaign_id']}").json()
a("Monthly patch" in camp["name"])
print("PASS: recurring definition creates a campaign on run-now (name expands {month}, scope resolved)")
# nightly-style due run creates another when next_run_at is past
run(db.remediation_recurring.update_one({"id":rec["id"]},{"$set":{"next_run_at":(now-timedelta(days=1)).isoformat()}}))
async def _resolver(flt): return await rr._ids_from_findings_filter(admin, flt)
res=run(rc.run_due_recurring(db,_resolver))
a(res["count"]==1, res)
print("PASS: run_due_recurring auto-creates a campaign when a definition is due (nightly)")

# ---- CSV export + report ----
cid=rn["campaign_id"]
csvr=c.get(f"/api/v1/remediation-campaigns/{cid}/export.csv")
a(csvr.status_code==200 and "Title,CVE,QID" in csvr.content.decode() and "OpenSSL" in csvr.content.decode())
rep=c.get(f"/api/v1/remediation-campaigns/{cid}/report").json()
a(rep["progress"]["total"]>=1 and "timeline" in rep and "groups" in rep)
print("PASS: campaign CSV export + leadership report payload work")

# ---- bulk reassign within campaign ----
c.post(f"/api/v1/remediation-campaigns/{cid}/bulk-assign", json={"finding_ids":["f1"],"assignee":"newtech@x.com"})
a(run(db.findings.find_one({"id":"f1"}))["assigned_to"]=="newtech@x.com")
act=c.get(f"/api/v1/remediation-campaigns/{cid}").json()["activity"]
a(any(e["action"]=="reassigned" for e in act))
print("PASS: bulk-reassign sets assigned_to on selected findings + logs activity")

# ---- escalation ladder ----
run(db.users.insert_one({"email":"mgr@x.com","role":"manager","name":"M"}))
ov=c.post("/api/v1/remediation-campaigns", json={"name":"way overdue","finding_ids":["f1"],"due_date":(now-timedelta(days=30)).isoformat()}).json()
esc=c.post("/api/v1/remediation-campaigns/escalate").json()
a(esc["escalated"]>=1, esc)
a(run(db.notifications_outbox.count_documents({"kind":"campaign_escalated","recipient":"mgr@x.com"}))>=1, "manager got the escalation")
print("PASS: overdue-by->threshold escalates to managers/admins (separate from the assignee nudge)")

# ---- explain the spike ----
sp=c.get("/api/v1/dashboards/findings-changed-on-day", params={"day":"2026-08-18"}).json()
a(sp["created_count"]==1 and sp["reopened_count"]==1, sp)
a(sp["created"][0]["id"]=="f1" and sp["reopened"][0]["id"]=="f2")
print("PASS: findings-changed-on-day explains a spike (1 created + 1 reopened on that day)")

# ============ regression: due_at / first_seen_at as native datetime (BSON date) ----
# real Mongo stores dates as datetimes, not ISO strings; priority_score must not 500
run(db.findings.insert_one({"id":"dt1","title":"native date","severity":"High","status":"New",
  "owner_team":"SecOps","asset_id":"hd","asset_hostname":"hd",
  "due_at": now - timedelta(days=1), "first_seen_at": now - timedelta(days=40)}))
dc=c.post("/api/v1/remediation-campaigns", json={"name":"native dates","finding_ids":["dt1"]}).json()
det=c.get(f"/api/v1/remediation-campaigns/{dc['id']}")
a(det.status_code==200, det.text)
a(det.json()["findings"][0]["priority_score"] > 0, det.json()["findings"][0])
print("PASS: campaign detail handles native-datetime due_at/first_seen_at without 500 (the reported bug)")

server.app.dependency_overrides.clear()
print("\nALL CAMPAIGN ADVANCED TESTS PASSED")
