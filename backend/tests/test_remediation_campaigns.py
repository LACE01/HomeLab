"""#62 Remediation Campaign / Patch Tracker: progress auto-driven by finding status;
patched/complete/overdue/regression signals."""
import os, sys, asyncio
from datetime import datetime, timezone, timedelta
os.environ["MONGO_URL"]="x"; os.environ["DB_NAME"]="t"; os.environ["JWT_SECRET"]="x"
sys.path.insert(0, ".")
from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client=AsyncMongoMockClient(); db_module.db=db_module.client["t"]; db=db_module.db
import server, auth_utils
from routes import remediation_campaigns as rr; rr.db=db
import remediation_campaigns as rc
from fastapi.testclient import TestClient
run=lambda x: asyncio.get_event_loop().run_until_complete(x)
def a(c,m=""): assert c,m
now=datetime.now(timezone.utc)
admin={"id":"u1","email":"a@x.com","role":"admin","name":"A","teams":[],"team":None}
server.app.dependency_overrides[auth_utils.get_current_user]=lambda: admin
c=TestClient(server.app)

# 3 findings: 1 open, 1 patched, 1 reopened (regression)
run(db.findings.insert_many([
  {"id":"f1","title":"A","severity":"Critical","status":"New","owner_team":"SecOps","kev_flag":True,"cve":"CVE-1"},
  {"id":"f2","title":"B","severity":"High","status":"Fixed validated","owner_team":"SecOps","cve":"CVE-2"},
  {"id":"f3","title":"C","severity":"High","status":"Reopened","owner_team":"SecOps","cve":"CVE-3"},
]))

# ---- create from a filter (snapshot to ids) ----
r=c.post("/api/v1/remediation-campaigns", json={
  "name":"Sept patch push","owner_team":"SecOps","due_date":(now-timedelta(days=1)).isoformat(),
  "filter":{"owner_team":"SecOps"}})
a(r.status_code==200, r.text)
camp=r.json(); cid=camp["id"]
a(set(camp["finding_ids"])=={"f1","f2","f3"}, camp["finding_ids"])
print("PASS: #62 — a campaign snapshots its members from a filter (all SecOps findings)")

# ---- progress auto-driven from current status ----
d=c.get(f"/api/v1/remediation-campaigns/{cid}").json()
p=d["progress"]
a(p["total"]==3 and p["patched"]==1 and p["open"]==2, p)   # f1 New + f3 Reopened are open
a(p["regressions"]==1, "f3 Reopened is a regression")
a(p["percent_complete"]==33, p["percent_complete"])
a(p["overdue"] is True, "past due and not complete -> overdue")
a(p["complete"] is False)
print("PASS: #62 — progress is computed live from finding status (1/3 patched, 1 regression, overdue)")

# ---- patch the rest -> auto complete, no longer overdue ----
run(db.findings.update_many({"id":{"$in":["f1","f3"]}}, {"$set":{"status":"Fixed validated"}}))
p2=c.get(f"/api/v1/remediation-campaigns/{cid}").json()["progress"]
a(p2["percent_complete"]==100 and p2["complete"] is True and p2["overdue"] is False and p2["regressions"]==0, p2)
print("PASS: #62 — when the scanner marks the rest fixed, the campaign auto-completes (100%, not overdue)")

# ---- alerts roll-up ----
# make a second overdue campaign with a regression
run(db.findings.insert_one({"id":"g1","title":"D","severity":"High","status":"Reopened","owner_team":"IT"}))
c.post("/api/v1/remediation-campaigns", json={"name":"IT laggards","due_date":(now-timedelta(days=2)).isoformat(),"finding_ids":["g1"]})
al=c.get("/api/v1/remediation-campaigns/alerts").json()
a(any(x["name"]=="IT laggards" for x in al["overdue"]))
a(any(x["name"]=="IT laggards" for x in al["regressions"]))
a(any(x["name"]=="Sept patch push" for x in al["newly_complete"]))
print("PASS: #62 — cross-campaign alerts surface overdue, regressions, and newly-complete")

# ---- empty campaign is rejected ----
r=c.post("/api/v1/remediation-campaigns", json={"name":"empty","filter":{"owner_team":"NoSuchTeam"}})
a(r.status_code==400, "an empty campaign should be rejected")
print("PASS: #62 — a campaign that would match nothing is rejected")

server.app.dependency_overrides.clear()
print("\nALL REMEDIATION CAMPAIGN TESTS PASSED")
