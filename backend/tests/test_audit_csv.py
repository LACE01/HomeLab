"""Audit-log CSV export: both /admin/audit-log.csv and /admin/login-audit.csv return
proper CSV, normalize the two activity_log document shapes, and honor filters."""
import os, sys, asyncio
os.environ.update(MONGO_URL="x", DB_NAME="t", JWT_SECRET="x")
sys.path.insert(0, ".")
from mongomock_motor import AsyncMongoMockClient
import db as dbm; dbm.client=AsyncMongoMockClient(); dbm.db=dbm.client["t"]; db=dbm.db
import server, auth_utils
from fastapi.testclient import TestClient
run=lambda x: asyncio.get_event_loop().run_until_complete(x)
def a(c,m=""): assert c,m

run(db.activity_log.insert_many([
 {"id":"a1","actor":"admin@x.com","action":"status_change","entity_type":"finding","entity_id":"f1","details":"New->Valid","timestamp":"2026-09-18T10:00:00+00:00"},
 {"id":"a2","finding_id":"f2","detail":"note added","created_at":"2026-09-19T10:00:00+00:00"},  # alt shape
]))
run(db.login_audit.insert_many([
 {"id":"l1","email":"u@x.com","success":True,"ip":"10.0.0.1","user_agent":"Chrome","timestamp":"2026-09-19T09:00:00+00:00"},
 {"id":"l2","email":"bad@x.com","success":False,"ip":"10.0.0.2","reason":"bad password","timestamp":"2026-09-19T09:05:00+00:00"},
]))
admin={"id":"u1","email":"a@x.com","role":"admin","name":"A","teams":[],"team":None}
server.app.dependency_overrides[auth_utils.get_current_user]=lambda: admin
c=TestClient(server.app)

r=c.get("/api/v1/admin/audit-log.csv")
a(r.status_code==200 and r.headers["content-type"].startswith("text/csv"), "activity csv content-type")
a("attachment; filename=audit-log.csv" in r.headers.get("content-disposition",""), "activity filename")
lines=r.text.strip().splitlines()
a(lines[0]=="timestamp,actor,action,entity_type,entity_id,details", "activity header")
a(any("note added" in l and "f2" in l for l in lines), "alt-shape doc normalized (finding_id->entity_id)")
a(lines[1].startswith("2026-09-19"), "sorted newest-first")
print("PASS: activity audit CSV normalizes both doc shapes, sorted, correct headers")

r2=c.get("/api/v1/admin/login-audit.csv", params={"success": False})
a(r2.status_code==200, "login csv ok")
l2=r2.text.strip().splitlines()
a(l2[0].startswith("timestamp,email,success,ip"), "login header")
a(len(l2)==2 and "bad@x.com" in l2[1], "success=false filter applied (only the failed attempt)")
print("PASS: login-audit CSV honors filters + correct headers")

print("\nALL AUDIT CSV TESTS PASSED")
