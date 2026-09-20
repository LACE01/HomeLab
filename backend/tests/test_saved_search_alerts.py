"""Saved-search alerting: enabling a saved view baselines to now (never alerts on the
existing backlog), then alerts the owner exactly once per newly-appearing match, using
the same filter builder the Findings list uses."""
import os, sys, asyncio
from datetime import datetime, timezone, timedelta
os.environ.update(MONGO_URL="x", DB_NAME="t", JWT_SECRET="x")
sys.path.insert(0, ".")
from mongomock_motor import AsyncMongoMockClient
import db as dbm; dbm.client=AsyncMongoMockClient(); dbm.db=dbm.client["t"]; db=dbm.db
import saved_search_alerts as ssa
run=lambda x: asyncio.get_event_loop().run_until_complete(x)
def a(c,m=""): assert c,m
now=datetime.now(timezone.utc)

run(db.users.insert_one({"id":"u1","email":"admin@x.com","role":"admin"}))
# backlog Critical finding (exists BEFORE the alert is enabled)
run(db.findings.insert_one({"id":"old","title":"Old","cve":"CVE-OLD","severity":"Critical","status":"New",
    "asset_id":"h1","first_seen_at":(now-timedelta(days=2)).isoformat()}))
# saved view watching Critical, alert enabled with checkpoint = now
run(db.saved_findings_views.insert_one({"id":"v1","owner":"admin@x.com","name":"Crit watch",
    "filters":{"severities":["Critical"]},"alert_enabled":True,
    "alert_enabled_at":now.isoformat(),"alert_last_checked_at":now.isoformat()}))

# Run 1: only the backlog exists; nothing NEW since checkpoint -> no alert
r1=run(ssa.check_saved_search_alerts(db, now=(now+timedelta(minutes=1)).isoformat()))
a(r1["views_with_new"]==0 and r1["notified"]==0, f"backlog must not alert: {r1}")
a(run(db.notifications_outbox.count_documents({"recipient":"admin@x.com"}))==0, "no outbox from backlog")
print("PASS: enabling baselines to now -- existing backlog does NOT alert")

# A NEW Critical finding appears after the checkpoint
run(db.findings.insert_one({"id":"new","title":"New","cve":"CVE-NEW","severity":"Critical","status":"New",
    "asset_id":"h2","first_seen_at":(now+timedelta(minutes=5)).isoformat()}))
# A NEW but NON-matching (High) finding -- must be ignored by the Critical filter
run(db.findings.insert_one({"id":"high","title":"High","cve":"CVE-HI","severity":"High","status":"New",
    "asset_id":"h3","first_seen_at":(now+timedelta(minutes=6)).isoformat()}))

r2=run(ssa.check_saved_search_alerts(db, now=(now+timedelta(minutes=10)).isoformat()))
a(r2["views_with_new"]==1 and r2["notified"]==1, f"one new match should alert: {r2}")
ob=run(db.notifications_outbox.find({"recipient":"admin@x.com"},{"_id":0}).to_list(10))
a(len(ob)==1 and ob[0]["kind"]=="saved_search_match", "one outbox notification written")
a("CVE-NEW" in ob[0]["body"] and "CVE-HI" not in ob[0]["body"], "alert names the matching new finding, not the non-matching one")
print("PASS: alerts on the new matching finding only (filter respected)")

# Run 3: checkpoint advanced -> the same finding is NOT alerted again
r3=run(ssa.check_saved_search_alerts(db, now=(now+timedelta(minutes=15)).isoformat()))
a(r3["views_with_new"]==0, "no double-alert after checkpoint advances")
a(run(db.notifications_outbox.count_documents({"recipient":"admin@x.com"}))==1, "still exactly one notification")
print("PASS: checkpoint prevents double-alerting the same finding")

print("\nALL SAVED-SEARCH ALERT TESTS PASSED")
