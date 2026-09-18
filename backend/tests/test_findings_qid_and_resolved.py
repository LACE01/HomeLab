"""#2 QID search actually works (string OR int storage); #60 resolved findings are
hidden by default and don't inflate the open counts."""
import os, sys, asyncio
os.environ["MONGO_URL"]="x"; os.environ["DB_NAME"]="t"; os.environ["JWT_SECRET"]="x"
sys.path.insert(0, ".")
from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client=AsyncMongoMockClient(); db_module.db=db_module.client["t"]; db=db_module.db
import server, auth_utils
from routes import findings as fr; fr.db=db
from fastapi.testclient import TestClient
admin={"id":"u1","email":"a@x.com","role":"admin","name":"A","teams":[],"team":None}
server.app.dependency_overrides[auth_utils.get_current_user]=lambda: admin
c=TestClient(server.app); run=lambda x: asyncio.get_event_loop().run_until_complete(x)
def a(cnd,m=""): assert cnd,m

run(db.findings.insert_many([
  {"id":"f1","title":"OpenSSL","qid":"38170","severity":"Critical","status":"New","risk_score":90,"kev_flag":True},
  {"id":"f2","title":"Apache","qid":11111,"severity":"High","status":"New","risk_score":70},        # int qid
  {"id":"f3","title":"Old fixed","qid":"22222","severity":"Critical","status":"Fixed validated","risk_score":80,"kev_flag":True},
  {"id":"f4","title":"Mitigated","qid":"33333","severity":"High","status":"Mitigated","risk_score":60},
]))

# ---- #2 QID search ----
a([i["id"] for i in c.get("/api/v1/findings", params={"q":"38170"}).json()["items"]]==["f1"])
a([i["id"] for i in c.get("/api/v1/findings", params={"q":"11111"}).json()["items"]]==["f2"], "int-stored QID must be searchable")
print("PASS: #2 — QID search returns the finding whether the QID is stored as a string or an int")

# ---- #60 default hides resolved ----
ids = {i["id"] for i in c.get("/api/v1/findings").json()["items"]}
a(ids == {"f1","f2"}, f"default list should be open-only, got {ids}")
print("PASS: #60 — the default findings list hides resolved/fixed items (only open f1, f2)")

# show resolved on demand
ids2 = {i["id"] for i in c.get("/api/v1/findings", params={"include_resolved":"true"}).json()["items"]}
a(ids2 == {"f1","f2","f3","f4"}, ids2)
print("PASS: #60 — include_resolved=true shows the resolved items too")

# explicitly filtering by a resolved status still works
ids3 = {i["id"] for i in c.get("/api/v1/findings", params={"status":"Fixed validated"}).json()["items"]}
a(ids3 == {"f3"}, ids3)
print("PASS: #60 — explicitly selecting a resolved status returns those findings")

# ---- #60 counts are open-scoped (no inflation) ----
st = c.get("/api/v1/findings/stats").json()
a(st["by_severity"].get("Critical",0)==1, f"open Critical should be 1 (f3 is resolved), got {st['by_severity']}")
a(st["by_severity_all"].get("Critical",0)==2, "the all-inclusive breakdown still counts both criticals")
a(st["open_total"]==2 and st["total"]==4)
a(st["kev"]==1, "KEV headline is open-scoped: f1 open KEV counts, f3 resolved KEV does not")
print("PASS: #60 — severity/KEV headline counts are open-scoped; resolved findings no longer inflate them")

server.app.dependency_overrides.clear()
print("\nALL QID + RESOLVED-LIFECYCLE TESTS PASSED")
