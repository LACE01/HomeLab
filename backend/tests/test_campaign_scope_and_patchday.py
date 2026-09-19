"""Scope picker autocomplete + list filters (no exact typing) and the
patches-on-day drill-through for the dashboard chart."""
import os, sys, asyncio
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
admin={"id":"u1","email":"a@x.com","role":"admin","name":"A","teams":[],"team":None}
server.app.dependency_overrides[auth_utils.get_current_user]=lambda: admin
c=TestClient(server.app)

run(db.findings.insert_many([
  {"id":"f1","title":"Microsoft Windows Security Update","cve":"CVE-2026-0296","qid":"38170","severity":"Critical","status":"New","asset_hostname":"compix","owner_team":"SecOps"},
  {"id":"f2","title":"Apache Struts RCE","cve":"CVE-2026-0299","qid":11111,"severity":"High","status":"New","asset_hostname":"web-1","owner_team":"IT"},
  {"id":"f3","title":"Microsoft Edge Update","cve":"CVE-2026-0300","qid":"38171","severity":"Medium","status":"New","asset_hostname":"compix","owner_team":"SecOps"},
]))

# ---- suggest (autocomplete) ----
a(set(c.get("/api/v1/findings/suggest",params={"field":"cve","q":"CVE-2026-029"}).json()["items"])>={"CVE-2026-0296","CVE-2026-0299"})
a("38170" in c.get("/api/v1/findings/suggest",params={"field":"qid","q":"3817"}).json()["items"])
a("compix" in c.get("/api/v1/findings/suggest",params={"field":"hostname","q":"comp"}).json()["items"])
a(any("Microsoft" in x for x in c.get("/api/v1/findings/suggest",params={"field":"title","q":"micro"}).json()["items"]))
print("PASS: /findings/suggest autocompletes cve / qid / hostname / title (no exact typing needed)")

# ---- list filters resolve exact picks ----
def ids(params):
    return {i["id"] for i in c.get("/api/v1/findings", params=params).json()["items"]}
# campaign resolver takes the filter dict with lists:
q=run(rr._ids_from_findings_filter(admin, {"cve":["CVE-2026-0296","CVE-2026-0299"]}))
a(set(q)=={"f1","f2"}, q)
q2=run(rr._ids_from_findings_filter(admin, {"qid":["38170","11111"]}))
a(set(q2)=={"f1","f2"}, q2)   # int-stored qid matched too
q3=run(rr._ids_from_findings_filter(admin, {"hostname":["compix"]}))
a(set(q3)=={"f1","f3"}, q3)
print("PASS: campaign scope resolves multi-select CVE / QID (incl int) / Device picks to the right findings")

# ---- build a campaign straight from picked values ----
camp=c.post("/api/v1/remediation-campaigns", json={"name":"picked","findings_filter":{"cve":["CVE-2026-0296"],"hostname":["compix"]}}).json()
a(set(camp["finding_ids"])=={"f1"}, camp["finding_ids"])   # cve AND hostname
print("PASS: a campaign can be built from picked CVE + Device without exact-match typing")

# ---- patches-on-day drill-through ----
run(db.patches_applied.insert_many([
  {"asset_hostname":"compix","title":"Windows Update","cves":["CVE-2026-0296"],"finding_ids":["f1"],"finding_count":1,"resolved_at":"2026-08-18T10:00:00Z"},
  {"asset_hostname":"web-1","title":"Struts","cves":["CVE-2026-0299"],"finding_ids":["f2"],"finding_count":1,"resolved_at":"2026-08-18T12:00:00Z"},
  {"asset_hostname":"x","title":"other","finding_ids":["z"],"finding_count":1,"resolved_at":"2026-08-19T09:00:00Z"},
]))
r=c.get("/api/v1/dashboards/patches-on-day",params={"day":"2026-08-18"}).json()
a(r["count"]==2 and r["findings_patched"]==2 and {g["asset_hostname"] for g in r["groups"]}=={"compix","web-1"}, r)
print("PASS: patches-on-day returns exactly what got patched on that date (host/title/CVEs/finding ids)")

server.app.dependency_overrides.clear()
print("\nALL SCOPE + PATCH-DAY TESTS PASSED")
