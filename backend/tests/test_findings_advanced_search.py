"""#58 advanced search: field-scoped operators (qid:/cve:/owner:/source:/entity:),
SLA/age/entity/confidence filters, and per-user saved views."""
import os, sys, asyncio
from datetime import datetime, timezone, timedelta
os.environ["MONGO_URL"]="x"; os.environ["DB_NAME"]="t"; os.environ["JWT_SECRET"]="x"
sys.path.insert(0, ".")
from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client=AsyncMongoMockClient(); db_module.db=db_module.client["t"]; db=db_module.db
import server, auth_utils
from routes import findings as fr; fr.db=db
from fastapi.testclient import TestClient
run=lambda x: asyncio.get_event_loop().run_until_complete(x)
def a(c,m=""): assert c,m
now=datetime.now(timezone.utc)

run(db.findings.insert_many([
  {"id":"f1","cve":"CVE-2024-1","qid":"38170","title":"OpenSSL","severity":"Critical","status":"New",
   "owner_team":"SecOps","source_tool":"Qualys VMDR","entity_name":"Payments","risk_score":90,
   "due_at":(now-timedelta(days=2)).isoformat(),"first_seen_at":(now-timedelta(days=40)).isoformat(),
   "ownership_confidence":0.9},
  {"id":"f2","cve":"CVE-2024-2","qid":"38171","title":"Apache","severity":"High","status":"New",
   "owner_team":"IT","source_tool":"Nessus","entity_name":"Web","risk_score":70,
   "due_at":(now+timedelta(days=10)).isoformat(),"first_seen_at":(now-timedelta(days=3)).isoformat(),
   "ownership_confidence":0.2},
]))
admin={"id":"u1","email":"a@x.com","role":"admin","name":"A","teams":[],"team":None}
server.app.dependency_overrides[auth_utils.get_current_user]=lambda: admin
c=TestClient(server.app)
def ids(params): 
    r=c.get("/api/v1/findings", params=params); a(r.status_code==200, r.text)
    return {i["id"] for i in r.json()["items"]}

# ---- field operators ----
a(ids({"q":"qid:38170"})=={"f1"}); a(ids({"q":"cve:CVE-2024-2"})=={"f2"})
a(ids({"q":"owner:SecOps"})=={"f1"}); a(ids({"q":"source:Nessus"})=={"f2"})
a(ids({"q":"entity:Payments"})=={"f1"})
print("PASS: #58 — field operators qid:/cve:/owner:/source:/entity: each scope the search")
# operator + free text together
a(ids({"q":"owner:SecOps OpenSSL"})=={"f1"})
print("PASS: #58 — an operator combines with free text (owner:SecOps OpenSSL)")

# ---- SLA / age / entity / confidence ----
a(ids({"sla":"overdue"})=={"f1"}, "overdue = past due date")
a(ids({"sla":"within"})=={"f2"})
a(ids({"age_days":"30"})=={"f1"}, "age_days>=30 keeps the 40-day-old finding")
a(ids({"confidence":"low"})=={"f2"}, "low ownership confidence")
a(ids({"confidence":"high"})=={"f1"})
a(ids({"entity":"Web"})=={"f2"})
print("PASS: #58 — SLA, age, entity, and confidence-owner filters all work")

# ---- saved views (per user) ----
r=c.post("/api/v1/findings/views", json={"name":"My criticals","filters":{"severities":["Critical"],"kevOnly":True}})
a(r.status_code==200 and r.json()["id"], r.text)
vid=r.json()["id"]
lst=c.get("/api/v1/findings/views").json()["items"]
a(len(lst)==1 and lst[0]["name"]=="My criticals" and lst[0]["filters"]["kevOnly"] is True)
print("PASS: #58 — a saved view stores the filter state and lists back for the user")
# another user doesn't see it
other={"id":"u2","email":"b@x.com","role":"admin","name":"B","teams":[],"team":None}
server.app.dependency_overrides[auth_utils.get_current_user]=lambda: other
a(len(c.get("/api/v1/findings/views").json()["items"])==0, "saved views are per-user")
print("PASS: #58 — saved views are per-user (another user sees none)")
# delete
server.app.dependency_overrides[auth_utils.get_current_user]=lambda: admin
c.delete(f"/api/v1/findings/views/{vid}")
a(len(c.get("/api/v1/findings/views").json()["items"])==0)
print("PASS: #58 — a saved view can be deleted")

server.app.dependency_overrides.clear()
print("\nALL ADVANCED-SEARCH TESTS PASSED")
