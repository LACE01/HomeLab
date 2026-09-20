"""Overview extras for the campaign detail: admin `overview` block (risk composition,
tickets, exceptions, velocity/ETA, regressions) and the tech `my` block (scoped stats,
priority queue, batch-by-device). All derived from findings already loaded + one cheap
exceptions read."""
import os, sys, asyncio
from datetime import datetime, timezone, timedelta
os.environ.update(MONGO_URL="x", DB_NAME="t", JWT_SECRET="x")
sys.path.insert(0, ".")
from mongomock_motor import AsyncMongoMockClient
import db as dbm; dbm.client=AsyncMongoMockClient(); dbm.db=dbm.client["t"]; db=dbm.db
import remediation_campaigns as rc
run=lambda x: asyncio.get_event_loop().run_until_complete(x)
def a(c,m=""): assert c,m
now=datetime.now(timezone.utc)

run(db.findings.insert_many([
 {"id":"f1","title":"OpenSSL","cve":"CVE-1","severity":"Critical","status":"New","owner_team":"Coms","kev_flag":True,"epss_score":0.9,"asset_id":"h1","asset_hostname":"mac-pro","assigned_to":"tech@x","due_at":(now-timedelta(days=2)).isoformat(),"first_seen_at":(now-timedelta(days=40)).isoformat()},
 {"id":"f2","title":"Apache","cve":"CVE-2","severity":"High","status":"New","owner_team":"Coms","kev_flag":False,"asset_id":"h1","asset_hostname":"mac-pro","assigned_to":"tech@x","due_at":(now+timedelta(days=3)).isoformat(),"first_seen_at":(now-timedelta(days=5)).isoformat()},
 {"id":"f3","title":"SMB","cve":"CVE-3","severity":"Medium","status":"Fixed validated","owner_team":"Coms","asset_id":"h2","asset_hostname":"compix","assigned_to":"tech@x"},
 {"id":"f4","title":"Reopened","cve":"CVE-4","severity":"High","status":"Reopened","owner_team":"Coms","asset_id":"h2","asset_hostname":"compix"},
]))
run(db.exceptions.insert_many([
  {"id":"e1","finding_id":"f1","status":"pending_approval"},
  {"id":"e2","finding_id":"f2","status":"active"},
]))
camp=run(rc.create_campaign(db,name="Coms",description="",owner_team="Coms",
        due_date=(now+timedelta(days=10)).isoformat(),finding_ids=["f1","f2","f3","f4"],require_verification=True))
run(db.remediation_campaigns.update_one({"id":camp["id"]},{"$set":{"created_at":(now-timedelta(days=7)).isoformat()}}))
run(db.findings.update_one({"id":"f2"},{"$set":{"status":"Fixed validated"}}))  # 1 patched-since-add

d=run(rc.campaign_detail(db,camp["id"],for_user={"email":"tech@x","teams":["Coms"]}))
ov=d["overview"]; my=d["my"]

# risk composition over OPEN baseline (f1 open critical/kev/epss, f4 reopened high)
a(ov["risk"]["severity"]["Critical"]==1 and ov["risk"]["severity"]["High"]==1, "severity split over open")
a(ov["risk"]["kev_open"]==1, "kev open counted")
a(ov["risk"]["high_epss_open"]==1, "epss>=0.5 open counted")
a(ov["risk"]["overdue_open"]==1, "overdue open counted")
print("PASS: risk composition scoped to open baseline")

a(ov["exceptions"]=={"pending":1,"active":1,"denied":0,"total":2}, "exceptions rolled up by status")
a(ov["tickets"]["with_ticket"]+ov["tickets"]["without_ticket"]==ov["risk"]["open_total"], "ticket coverage covers open")
print("PASS: exceptions + ticket coverage")

# velocity: 1 patched over 7 days => ~1/wk; 1 still open => ETA ~1 week out; deadline 10d => on track
a(ov["velocity"]["patched_per_week"]==1.0, "velocity per week")
a(ov["velocity"]["eta"] is not None and ov["velocity"]["days_to_due"] in (9,10), "eta + days_to_due computed")
a(ov["velocity"]["on_track"] in (True,False), "on_track decided when deadline+velocity known")
print("PASS: velocity + projected close + on-track")

a([r["id"] for r in ov["regressions"]]==["f4"], "regressions list = reopened members")
print("PASS: regressions surfaced")

# my block (tech@x owns all four by assignment/team)
a(my["total"]==4 and my["patched"]==2 and my["open"]==2, "my scoped counts (full set, not capped)")
a(my["overdue"]==1, "my overdue")
a([q["id"] for q in my["queue"]][0]=="f1", "queue sorted by priority, f1 first")
a(any(x["host"]=="mac-pro" for x in my["by_device"]), "batch-by-device present")
print("PASS: my-work stats, priority queue, batch-by-device")

print("\nALL CAMPAIGN OVERVIEW TESTS PASSED")
