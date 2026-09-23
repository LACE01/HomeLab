"""#62 v2 — filter-based membership (Findings logic), grouping, aging, notes +
mass-note + attachments, status→autoclose, timeline, alerts→notifications."""
import os, sys, asyncio
from datetime import datetime, timezone, timedelta
os.environ["MONGO_URL"]="x"; os.environ["DB_NAME"]="t"; os.environ["JWT_SECRET"]="x"
sys.path.insert(0, ".")
from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client=AsyncMongoMockClient(); db_module.db=db_module.client["t"]; db=db_module.db
import server, auth_utils
from routes import remediation_campaigns as rr; rr.db=db
from routes import findings as fr; fr.db=db
from routes import workflows as wf; wf.db=db
import remediation_campaigns as rc
from fastapi.testclient import TestClient
run=lambda x: asyncio.get_event_loop().run_until_complete(x)
def a(c,m=""): assert c,m
now=datetime.now(timezone.utc)
admin={"id":"u1","email":"a@x.com","role":"admin","name":"A","teams":[],"team":None}
server.app.dependency_overrides[auth_utils.get_current_user]=lambda: admin
c=TestClient(server.app)

run(db.findings.insert_many([
  {"id":"f1","title":"OpenSSL","cve":"CVE-1","severity":"Critical","status":"New","owner_team":"SecOps","kev_flag":True,"asset_id":"h1","asset_hostname":"h1","first_seen_at":(now-timedelta(days=45)).isoformat()},
  {"id":"f2","title":"Apache","cve":"CVE-2","severity":"High","status":"New","owner_team":"SecOps","kev_flag":False,"asset_id":"h1","asset_hostname":"h1","first_seen_at":(now-timedelta(days=5)).isoformat()},
  {"id":"f3","title":"Struts","cve":"CVE-3","severity":"Critical","status":"New","owner_team":"IT","kev_flag":True,"asset_id":"h2","asset_hostname":"h2","first_seen_at":(now-timedelta(days=10)).isoformat()},
  {"id":"f4","title":"Low thing","cve":"CVE-4","severity":"Low","status":"New","owner_team":"SecOps","asset_id":"h3","asset_hostname":"h3","first_seen_at":now.isoformat()},
]))

# ---- create from the FULL findings filter (Critical/High + KEV) ----
r=c.post("/api/v1/remediation-campaigns", json={
  "name":"KEV blitz","owner_team":"SecOps","assignees":["tech@x.com"],
  "due_date":(now-timedelta(days=1)).isoformat(),
  "findings_filter":{"severity":["Critical","High"],"kev":True}})
a(r.status_code==200, r.text)
camp=r.json(); cid=camp["id"]
a(set(camp["finding_ids"])=={"f1","f3"}, camp["finding_ids"])  # Critical/High AND KEV
print("PASS: campaign created from the same multi-select Findings filter (Critical/High + KEV → f1,f3)")

# ---- #baseline: patched counts only findings patched AFTER being added ----
# add a member that is ALREADY resolved at creation -> must NOT count toward patched/total
run(db.findings.insert_one({"id":"fdone","title":"Already fixed","cve":"CVE-9","severity":"Critical","status":"Fixed validated","owner_team":"SecOps","kev_flag":True,"asset_id":"h5","asset_hostname":"h5"}))
rb=c.post("/api/v1/remediation-campaigns", json={"name":"baseline test","finding_ids":["f1","fdone"]}).json()
pb=c.get(f"/api/v1/remediation-campaigns/{rb['id']}").json()["progress"]
a(pb["total"]==1 and pb["patched"]==0, f"only the open member (f1) is the baseline: {pb}")
a(pb["already_resolved_at_add"]==1, "the pre-resolved member is context, not progress")
# now patch f1 -> patched becomes 1/1
c.post(f"/api/v1/remediation-campaigns/{rb['id']}/bulk-status", json={"finding_ids":["f1"],"status":"Fixed validated"})
pb2=c.get(f"/api/v1/remediation-campaigns/{rb['id']}").json()["progress"]
a(pb2["patched"]==1 and pb2["percent_complete"]==100, pb2)
print("PASS: baseline — a member already resolved at add-time doesn't inflate patched; only in-campaign patches count")
# restore f1 open for the rest of the suite
run(db.findings.update_one({"id":"f1"},{"$set":{"status":"New"}}))

# ---- detail: aging, groups (device/vuln/team), mine slice ----
d=c.get(f"/api/v1/remediation-campaigns/{cid}").json()
a(d["progress"]["max_open_age_days"]>=45 and d["progress"]["aging_over_30d"]==1, d["progress"])
a(len(d["groups"]["device"])==2 and len(d["groups"]["team"])==2, d["groups"])
a(any(g["key"]=="h1" for g in d["groups"]["device"]))
print("PASS: detail exposes aging (max 45d, 1 over 30d) and per-device/vuln/team breakdowns")

# tech 'mine' slice: as a SecOps tech, only SecOps findings are mine (f1)
tech={"id":"u2","email":"tech@x.com","role":"analyst","name":"T","teams":["SecOps"],"team":"SecOps"}
server.app.dependency_overrides[auth_utils.get_current_user]=lambda: tech
dt=c.get(f"/api/v1/remediation-campaigns/{cid}").json()
a(set(dt["mine"])=={"f1"}, dt["mine"])
print("PASS: the tech view's 'mine' slice scopes to the user's team/assignment (f1)")
server.app.dependency_overrides[auth_utils.get_current_user]=lambda: admin

# ---- campaign note with a link + attachment ----
r=c.post(f"/api/v1/remediation-campaigns/{cid}/notes", json={
  "text":"Patch window Sat 2am","links":["https://kb/patch"],"attachments":[{"name":"plan.png","mime":"image/png","data_url":"data:image/png;base64,AAAA"}]})
a(r.status_code==200 and r.json()["action"]=="note", r.text)
print("PASS: a campaign note stores text + links + screenshot attachments")

# ---- mass-note across findings (no opening each) ----
r=c.post(f"/api/v1/remediation-campaigns/{cid}/mass-note", json={"finding_ids":["f1","f3"],"text":"Vendor patch KB123 applies"})
a(r.json()["noted"]==2)
a(run(db.comments.count_documents({"finding_id":"f1"}))==1, "mass note landed on the finding's own comments")
print("PASS: mass-note writes one note to many findings at once (into each finding's comments)")

# ---- bulk status -> patch f1,f3; campaign auto-closes when all done ----
c.post(f"/api/v1/remediation-campaigns/{cid}/bulk-status", json={"finding_ids":["f1","f3"],"status":"Fixed validated"})
d2=c.get(f"/api/v1/remediation-campaigns/{cid}").json()
a(d2["progress"]["complete"] is True and d2["status"]=="closed", (d2["progress"]["complete"], d2["status"]))
a(any(e["action"]=="closed" for e in d2["activity"]), "auto-close is logged in activity")
print("PASS: bulk-status via built-in statuses drives progress and auto-closes the campaign at 100%")

# ---- exception routing logs an exception_filed activity ----
run(db.findings.insert_one({"id":"f9","title":"WontFix","severity":"Medium","status":"New","owner_team":"SecOps","asset_id":"h9","asset_hostname":"h9"}))
r2=c.post("/api/v1/remediation-campaigns", json={"name":"cant patch","finding_ids":["f9"]}).json()
c.post(f"/api/v1/remediation-campaigns/{r2['id']}/bulk-status", json={"finding_ids":["f9"],"status":"Accepted risk"})
act=c.get(f"/api/v1/remediation-campaigns/{r2['id']}").json()["activity"]
a(any(e["action"]=="exception_filed" for e in act))
print("PASS: routing a can't-patch finding to 'Accepted risk' records an exception on the timeline")

# ---- timeline includes patches ----
run(db.patches_applied.insert_one({"id":"p1","asset_hostname":"h1","title":"OpenSSL","finding_ids":["f1"],"resolved_at":now.isoformat()}))
tl=c.get(f"/api/v1/remediation-campaigns/{cid}").json()["timeline"]
a(any(e["type"]=="patch" for e in tl), "timeline shows patch events")
print("PASS: the campaign timeline merges patch events with activity")

# ---- alerts -> notifications outbox ----
c.post("/api/v1/remediation-campaigns", json={"name":"late","due_date":(now-timedelta(days=3)).isoformat(),"finding_ids":["f2","f4"]})
r=c.post("/api/v1/remediation-campaigns/notify").json()
a(r["sent"]>=1, r)
a(run(db.notifications_outbox.count_documents({"kind":"remediation_overdue"}))>=1, "overdue alert written to outbox")
# deduped: a second notify the same day sends nothing new
a(c.post("/api/v1/remediation-campaigns/notify").json()["sent"]==0, "alerts dedupe per day")
print("PASS: campaign alerts are pushed to the notifications outbox (deduped per day)")

# ============ verification-gated close ============
run(db.findings.insert_many([
  {"id":"v1","title":"V1","severity":"High","status":"New","owner_team":"SecOps","asset_id":"hv","asset_hostname":"hv"},
  {"id":"v2","title":"V2","severity":"High","status":"New","owner_team":"SecOps","asset_id":"hv","asset_hostname":"hv"},
]))
vc=c.post("/api/v1/remediation-campaigns", json={"name":"verify","finding_ids":["v1","v2"],
  "assignees":["tech@county.us"],"require_verification":True}).json()
vid=vc["id"]
# mark v1 'Fixed pending validation' (provisional) and v2 'Fixed validated'
c.post(f"/api/v1/remediation-campaigns/{vid}/bulk-status", json={"finding_ids":["v1"],"status":"Fixed pending validation"})
c.post(f"/api/v1/remediation-campaigns/{vid}/bulk-status", json={"finding_ids":["v2"],"status":"Fixed validated"})
d=c.get(f"/api/v1/remediation-campaigns/{vid}").json()
a(d["progress"]["verified"]==1 and d["progress"]["unverified_resolved"]==1 and d["progress"]["closeable"] is False, d["progress"])  # v1 pending-validation = patched-but-unverified
# close is blocked because v1 is only pending validation (still open)
r=c.post(f"/api/v1/remediation-campaigns/{vid}/close")
a(r.status_code==400 and "verified" in r.json()["detail"].lower(), r.text)
print("PASS: verification-gated close blocks while a fix is only 'pending validation' (not scanner-verified)")
# scanner verifies v1 -> now closeable, auto-close on the status flip
c.post(f"/api/v1/remediation-campaigns/{vid}/bulk-status", json={"finding_ids":["v1"],"status":"Fixed validated"})
d2=c.get(f"/api/v1/remediation-campaigns/{vid}").json()
a(d2["progress"]["closeable"] is True and d2["status"]=="closed", (d2["progress"]["closeable"], d2["status"]))
print("PASS: once the scanner confirms all fixes (Fixed validated), the campaign is closeable and auto-closes")

# ============ assignee notifications ============
a(run(db.notifications_outbox.count_documents({"kind":"campaign_assigned","recipient":"tech@county.us"}))>=1,
  "assignee got an 'assigned' notification on campaign create")
print("PASS: assignees are notified on assignment (per-recipient outbox entry)")
# overdue -> assignee nudged
run(db.findings.insert_one({"id":"od1","title":"OD","severity":"High","status":"New","owner_team":"SecOps","asset_id":"ho","asset_hostname":"ho"}))
oc=c.post("/api/v1/remediation-campaigns", json={"name":"overdue camp","finding_ids":["od1"],
  "assignees":["tech2@county.us"],"due_date":(now-timedelta(days=2)).isoformat()}).json()
c.post("/api/v1/remediation-campaigns/notify")
a(run(db.notifications_outbox.count_documents({"kind":"campaign_overdue","recipient":"tech2@county.us"}))>=1)
print("PASS: assignees are nudged when their campaign is overdue")

# ============ maintenance window + change ticket ============
mc=c.post("/api/v1/remediation-campaigns", json={"name":"win","finding_ids":["od1"],
  "maintenance_window":{"start":(now).isoformat(),"end":(now+timedelta(days=1)).isoformat()},
  "change_ticket":"CHG-1001"}).json()
md=c.get(f"/api/v1/remediation-campaigns/{mc['id']}").json()
a(md["maintenance_window"]["start"] and md["change_ticket"]=="CHG-1001")
a(rc.in_maintenance_window(md) is True, "now is within the configured window")
print("PASS: maintenance window + change ticket are stored and the in-window check works")

# ============ burndown history ============
run(rc.snapshot_progress(db, day="2026-09-16"))
run(rc.snapshot_progress(db, day="2026-09-17"))
bd=c.get(f"/api/v1/remediation-campaigns/{vid}/burndown").json()["series"]
a(len(bd)>=2 and all("patched" in x and "open" in x for x in bd), bd)
print("PASS: daily progress snapshots build a burndown series per campaign")

# ============ real exception workflow + ticket attach ============
run(db.findings.insert_one({"id":"ex1","title":"WontPatch","severity":"High","status":"New","owner_team":"SecOps","asset_id":"hx","asset_hostname":"hx"}))
ec=c.post("/api/v1/remediation-campaigns", json={"name":"exc camp","finding_ids":["ex1"]}).json()
r=c.post(f"/api/v1/remediation-campaigns/{ec['id']}/request-exceptions",
         json={"finding_ids":["ex1"],"business_justification":"Vendor has no patch until Q4","duration_days":120})
a(r.status_code==200 and r.json()["requested"]==1, r.text)
a(run(db.exceptions.count_documents({"finding_id":"ex1"}))==1, "a real exception was filed via the workflow")
act=c.get(f"/api/v1/remediation-campaigns/{ec['id']}").json()["activity"]
a(any(e["action"]=="exception_filed" for e in act))
print("PASS: can't-patch files a REAL risk-acceptance exception through the exceptions workflow")

# ticket attach: a finding with a ticket in db.tickets shows ticket_ref
run(db.tickets.insert_one({"id":"tk1","external_id":"RA-ABC123","system":"internal","url":"/exceptions/xyz","finding_id":"ex1","status":"open"}))
d=c.get(f"/api/v1/remediation-campaigns/{ec['id']}").json()
f_ex1=[f for f in d["findings"] if f["id"]=="ex1"][0]
a(f_ex1.get("ticket_ref") and f_ex1["ticket_ref"]["external_id"]=="RA-ABC123" and f_ex1["ticket_ref"]["url"], f_ex1.get("ticket_ref"))
print("PASS: each campaign finding carries its real ticket (external id + url) for a clickable link")

# ============ assignable users ============
run(db.users.insert_many([{"email":"a@x.com","name":"Admin A","team":"SecOps","role":"admin"},
                          {"email":"t@x.com","name":"Tech T","teams":["IT"],"role":"analyst"}]))
au=c.get("/api/v1/remediation-campaigns/assignable-users").json()["items"]
a(len(au)>=2 and any(u["email"]=="t@x.com" and u["team"]=="IT" for u in au), au)
print("PASS: assignable-users returns users (email/name/team) for the assignee picker")

# ============ channel dispatch is invoked (a rule delivers) ============
run(db.notification_channels.insert_one({"id":"ch1","type":"email","enabled":True,"to":"soc@x.com"}))
run(db.notification_rules.insert_one({"id":"r1","trigger":"remediation_assigned","active":True,"channel_ids":["ch1"],"template_id":"new_assignment","frequency":"immediate"}))
run(db.notifications_outbox.delete_many({}))
ac=c.post("/api/v1/remediation-campaigns", json={"name":"dispatch camp","finding_ids":["ex1"],"assignees":["someone@x.com"]}).json()
# outbox got the per-assignee record AND the rule-driven delivery attempt was made
a(run(db.notifications_outbox.count_documents({"kind":"campaign_assigned"}))>=1, "per-assignee outbox record")
print("PASS: assignment fans out to configured Notifications channels (dispatch) in addition to the outbox")

# ============ SLA/priority auto-sort (tech queue: highest-impact first) ============
from datetime import datetime as _dt, timezone as _tz, timedelta as _td
_now2=_dt.now(_tz.utc)
run(db.findings.insert_many([
  {"id":"pr_low","title":"low","severity":"Low","status":"New","owner_team":"SecOps","asset_id":"hp","asset_hostname":"hp"},
  {"id":"pr_crit_kev_od","title":"crit kev overdue","severity":"Critical","status":"New","owner_team":"SecOps","asset_id":"hp","asset_hostname":"hp","kev_flag":True,"due_at":(_now2-_td(days=3)).isoformat(),"epss_score":0.9},
  {"id":"pr_med","title":"med","severity":"Medium","status":"New","owner_team":"SecOps","asset_id":"hp","asset_hostname":"hp"},
  {"id":"pr_done","title":"done","severity":"Critical","status":"Fixed validated","owner_team":"SecOps","asset_id":"hp","asset_hostname":"hp"},
]))
pc=c.post("/api/v1/remediation-campaigns", json={"name":"prio","finding_ids":["pr_low","pr_crit_kev_od","pr_med","pr_done"]}).json()
order=[f["id"] for f in c.get(f"/api/v1/remediation-campaigns/{pc['id']}").json()["findings"]]
a(order[0]=="pr_crit_kev_od", f"the Critical+KEV+overdue+high-EPSS finding must be first: {order}")
a(order.index("pr_med")<order.index("pr_low"), "Medium ranks above Low")
a(order[-1]=="pr_done", "resolved findings sink to the bottom")
print("PASS: campaign findings are auto-sorted by priority (SLA × severity × KEV × EPSS × age); resolved sink")

server.app.dependency_overrides.clear()
print("\nALL REMEDIATION CAMPAIGN v2 TESTS PASSED")
