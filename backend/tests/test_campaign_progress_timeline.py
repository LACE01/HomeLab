"""#66/#64: the campaign 'Patched' signal counts applied fixes including
'Fixed pending validation' (the root cause of the tile saying 2 while 15 were
fixed); the timeline is built from that SAME per-finding signal and flags
pre-creation backlog; the burndown spans the full window; velocity gives a real
ETA, never a bogus far-future date."""
import os, sys, asyncio
from datetime import datetime, timezone, timedelta
os.environ.update(MONGO_URL="x", DB_NAME="t", JWT_SECRET="x")
sys.path.insert(0, ".")
from mongomock_motor import AsyncMongoMockClient
import db as dbm; dbm.client=AsyncMongoMockClient(); dbm.db=dbm.client["t"]; db=dbm.db
import remediation_campaigns as rc
run=lambda x: asyncio.get_event_loop().run_until_complete(x)
def a(c,m=""): assert c,m
now=datetime.now(timezone.utc); iso=lambda d:d.isoformat(); created=now-timedelta(days=10)

fs=[]
for i in range(3):
    fs.append({"id":f"pend{i}","title":f"T{i}","cve":f"CVE-P{i}","severity":"High","status":"Fixed pending validation",
               "asset_id":f"h{i}","asset_hostname":f"host{i}","last_changed_at":iso(now-timedelta(days=2)),
               "first_seen_at":iso(created-timedelta(days=5))})
fs.append({"id":"val1","title":"V","cve":"CVE-V","severity":"Critical","status":"Fixed validated",
           "asset_id":"hv","asset_hostname":"hostv","last_changed_at":iso(now-timedelta(days=1)),
           "first_seen_at":iso(created-timedelta(days=5))})
for i in range(2):
    fs.append({"id":f"open{i}","title":f"O{i}","cve":f"CVE-O{i}","severity":"Medium","status":"New",
               "asset_id":f"ho{i}","asset_hostname":f"hosto{i}","first_seen_at":iso(created-timedelta(days=5))})
for i in range(2):
    fs.append({"id":f"pre{i}","title":f"PR{i}","cve":f"CVE-PR{i}","severity":"Low","status":"Fixed validated",
               "asset_id":f"hp{i}","asset_hostname":f"hostp{i}","last_changed_at":iso(created-timedelta(days=3)),
               "first_seen_at":iso(created-timedelta(days=20))})
run(db.findings.insert_many(fs))
baseline=[f["id"] for f in fs if not f["id"].startswith("pre")]
camp=run(rc.create_campaign(db,name="Coms",description="",owner_team="Coms",
        due_date=iso(now+timedelta(days=20)), finding_ids=[f["id"] for f in fs], require_verification=True))
run(db.remediation_campaigns.update_one({"id":camp["id"]},{"$set":{"created_at":iso(created),"baseline_open_ids":baseline}}))

d=run(rc.campaign_detail(db,camp["id"],for_user={"email":"a@x.com","role":"admin","teams":["Coms"]}))
p=d["progress"]
a(p["total"]==6, "baseline denominator = open-at-creation only")
a(p["patched"]==4, f"patched includes pending-validation (got {p['patched']})")
a(p["verified"]==1 and p["open"]==2 and p["already_resolved_at_add"]==2)
print("PASS: patched counts applied fixes incl. pending-validation; baseline denominator right")

patch_events=[e for e in d["timeline"] if e["type"]=="patch"]
a(sum(1 for e in patch_events if not e["pre_creation"])==4, "4 active patches (reconciles with tile)")
a(sum(1 for e in patch_events if e["pre_creation"])==2, "2 pre-creation backlog events flagged")
print("PASS: timeline uses same signal as tile + flags pre-creation backlog")

vel=d["overview"]["velocity"]
a(vel["eta"] is not None and vel["eta_note"] is None, "real ETA, no bogus note")
print("PASS: velocity ETA is real, not a bogus far-future date")

# a stalled campaign (0 patched) must NOT project a bogus date
c2=run(rc.create_campaign(db,name="Stalled",description="",owner_team="Coms",
       due_date=iso(now+timedelta(days=5)), finding_ids=["open0","open1"], require_verification=True))
run(db.remediation_campaigns.update_one({"id":c2["id"]},{"$set":{"created_at":iso(created),"baseline_open_ids":["open0","open1"]}}))
d2=run(rc.campaign_detail(db,c2["id"],for_user={"email":"a@x.com","role":"admin","teams":["Coms"]}))
v2=d2["overview"]["velocity"]
a(v2["eta"] is None and v2["eta_note"]=="no patches yet", f"stalled -> no bogus ETA (got {v2})")
print("PASS: stalled campaign reports 'no patches yet' instead of a bogus 'Jan 2028'")

bd=run(rc.burndown(db,camp["id"]))
a(len(bd)>=2 and bd[0].get("synthetic") and bd[-1].get("live") and bd[-1]["patched"]==4)
print("PASS: burndown spans created_at -> now with a real 0->4 slope")
print("\nALL CAMPAIGN PROGRESS/TIMELINE TESTS PASSED")
