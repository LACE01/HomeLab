"""A rescan must not wipe enrichment. The Qualys/Tenable upserts used to $set their
new-finding defaults (epss 0, kev False, rti [], KB-only CWE) onto EXISTING findings,
erasing KEV/EPSS/exploit flags (and dropping risk) every sync and nulling NVD CWEs
(which broke the CWE->ATT&CK chain, #33). Also covers the #32 log-binned histogram."""
import os, sys, asyncio, random
os.environ.update(MONGO_URL="x", DB_NAME="t", JWT_SECRET="x")
sys.path.insert(0, ".")
from mongomock_motor import AsyncMongoMockClient
import db as dbm; dbm.client=AsyncMongoMockClient(); dbm.db=dbm.client["t"]; db=dbm.db
import qualys_sync as qs
run=lambda x: asyncio.get_event_loop().run_until_complete(x)
def a(c,m=""): assert c,m

det={"qid":"105170","severity":"3","type":"Confirmed","status":"Active","hostname":"srv1.ecg.local",
     "ip":"10.0.0.9","os":"Windows Server 2019","qualys_host_id":"77","first_found":"2026-08-01T00:00:00Z",
     "last_found":"2026-09-30T00:00:00Z"}
kb={"105170":{"title":"Example RCE","cve":"CVE-2024-1111","cvss":5.3}}   # KB has no CWE
run(qs._upsert_finding(db, det, kb, {}))
f=run(db.findings.find_one({"qid":"105170"},{"_id":0}))
risk_before_enrich=f["risk_score"]
# enrichment runs (KEV/EPSS/Exploit-DB/NVD)
run(db.findings.update_one({"id":f["id"]},{"$set":{"kev_flag":True,"epss_score":0.72,"rti":["public_exploit","active_attacks"],
    "exploit_references":[{"edb_id":"1"}],"cwe":"CWE-78","cvss_vector":"AV:N/AC:L"}}))
from scoring import compute_risk
asset=run(db.assets.find_one({"id":f["asset_id"]},{"_id":0}))
enriched=run(db.findings.find_one({"id":f["id"]},{"_id":0}))
run(db.findings.update_one({"id":f["id"]},{"$set":{"risk_score":compute_risk(enriched,asset)["score"]}}))
risk_enriched=run(db.findings.find_one({"id":f["id"]},{"_id":0}))["risk_score"]

# hourly rescan of the same detection
out=run(qs._upsert_finding(db, det, kb, {}))
g=run(db.findings.find_one({"id":f["id"]},{"_id":0}))
a(out=="updated", out)
a(g["kev_flag"] is True and g["epss_score"]==0.72, f"KEV/EPSS survived rescan: {g['kev_flag']},{g['epss_score']}")
a(set(g["rti"])=={"public_exploit","active_attacks"} and g["exploit_references"], "exploit flags survived")
a(g["cwe"]=="CWE-78" and g["cvss_vector"]=="AV:N/AC:L", "NVD CWE/vector not nulled by KB-only data")
a(g["risk_score"]==risk_enriched and risk_enriched>risk_before_enrich, f"risk stays enriched ({g['risk_score']} vs {risk_enriched})")
print("PASS: rescan preserves KEV/EPSS/exploit flags, NVD CWE, and the enriched risk score")

from scoring_v2 import empirical_percentile
random.seed(3)
cohort=[round(random.choice([0.01]*6+[random.uniform(0.002,0.05)]*3+[random.uniform(0.1,0.9)])*1.3,4) for _ in range(400)]
r=empirical_percentile(0.4, cohort)
a(r["scale"]=="log" and sum(1 for c in r["distribution"] if c)>=12, "log bins spread a skewed cohort")
from collections import Counter
most_common_exact=Counter(cohort).most_common(1)[0][1]
a(max(r["distribution"])<=most_common_exact+max(5,len(cohort)//20), "only genuinely identical scores pile into one bar")
a(r["buckets"][r["my_bucket"]]["from"]<=0.4<=r["buckets"][r["my_bucket"]]["to"]*1.0001, "my_bucket contains my score")
a(empirical_percentile(0.01,[0.01]*5)["uniform"] is True)
print("PASS: #32 histogram spreads an EPSS-skewed cohort; my bucket correct; uniform cohort flagged")
print("\nALL RESCAN/HISTOGRAM TESTS PASSED")
