"""#57 team-scoped CSV export + #59 flexible export (column picker + scope)."""
import os, sys, asyncio, csv, io
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

run(db.findings.insert_many([
  {"id":"f1","cve":"CVE-1","qid":"38170","title":"A","severity":"Critical","status":"New","risk_score":90,"kev_flag":True,"owner_team":"SecOps","asset_hostname":"h1"},
  {"id":"f2","cve":"CVE-2","qid":"38171","title":"B","severity":"High","status":"New","risk_score":70,"owner_team":"IT","asset_hostname":"h2"},
  {"id":"f3","cve":"CVE-3","qid":"38172","title":"C","severity":"Low","status":"Fixed validated","risk_score":10,"owner_team":"SecOps","asset_hostname":"h3"},
]))

def as_admin():
    server.app.dependency_overrides[auth_utils.get_current_user]=lambda: {"id":"u1","email":"a@x.com","role":"admin","name":"A","teams":[],"team":None}
def as_analyst_team(team):
    server.app.dependency_overrides[auth_utils.get_current_user]=lambda: {"id":"u2","email":"an@x.com","role":"analyst","name":"An","teams":[team],"team":team}

as_admin(); c=TestClient(server.app)

def parse(resp):
    a(resp.status_code==200, resp.text)
    rows=list(csv.reader(io.StringIO(resp.content.decode())))
    return rows[0], rows[1:]

# ---- default columns + filtered scope (open only) ----
hdr, rows = parse(c.get("/api/v1/findings/export"))
a("CVE" in hdr and "QID" in hdr and "Owner Team" in hdr)
a({r[hdr.index("CVE")] for r in rows} == {"CVE-1","CVE-2"}, "export respects the hide-resolved default")
print("PASS: #59 — default export uses the default columns and respects the open-only default")

# ---- column picker: only chosen columns, in order ----
hdr2, rows2 = parse(c.get("/api/v1/findings/export", params=[("columns","title"),("columns","severity")]))
a(hdr2==["Title","Severity"], hdr2)
print("PASS: #59 — column picker exports exactly the chosen columns, in order")

# ---- scope=all includes resolved ----
_, rows_all = parse(c.get("/api/v1/findings/export", params={"scope":"all"}))
a(len(rows_all)==3, "scope=all exports everything the user can see, including resolved")
print("PASS: #59 — scope=all exports all findings (incl. resolved)")

# ---- scope=selected exports only the given ids ----
hdr3, rows3 = parse(c.get("/api/v1/findings/export", params=[("scope","selected"),("ids","f2"),("columns","cve")]))
a([r[0] for r in rows3]==["CVE-2"], rows3)
print("PASS: #59 — scope=selected exports only the selected ids")

# ---- team filter (#57): owner_team narrows the export ----
_, rows_team = parse(c.get("/api/v1/findings/export", params={"owner_team":"IT"}))
a({r[0] for r in rows_team}=={"CVE-2"} or all("IT" in r for r in []) , None)  # placeholder; check via CVE col below
hdr_t, rows_t = parse(c.get("/api/v1/findings/export", params={"owner_team":"IT"}))
a({r[hdr_t.index("CVE")] for r in rows_t}=={"CVE-2"})
print("PASS: #57 — owner_team filter narrows the export to that team")

# ---- team SCOPING (#57): an analyst only exports their team's findings ----
as_analyst_team("SecOps"); c2=TestClient(server.app)
hdr_s, rows_s = parse(c2.get("/api/v1/findings/export", params={"scope":"all"}))
a({r[hdr_s.index("Owner Team")] for r in rows_s} == {"SecOps"}, "analyst export must be team-scoped")
print("PASS: #57 — export is team-scoped: an analyst can only export their own team's findings")

server.app.dependency_overrides.clear()
print("\nALL FINDINGS EXPORT TESTS PASSED")
