"""#71: Qualys ingestion completeness. The sync must pull status New (freshly found
detections), keep Confirmed+Potential by default, COUNT anything it filters, flag
truncation, and the completeness diff must explain every missing (host, QID)."""
import os, sys, asyncio
os.environ.update(MONGO_URL="x", DB_NAME="t", JWT_SECRET="x")
sys.path.insert(0, ".")
from mongomock_motor import AsyncMongoMockClient
import db as dbm; dbm.client=AsyncMongoMockClient(); dbm.db=dbm.client["t"]; db=dbm.db
import qualys_sync as qs
run=lambda x: asyncio.get_event_loop().run_until_complete(x)
def a(c,m=""): assert c,m

def xml(dets, more=False):
    rows="".join(f"<DETECTION><QID>{q}</QID><TYPE>{t}</TYPE><SEVERITY>{sv}</SEVERITY><STATUS>{st}</STATUS></DETECTION>"
                 for q,t,sv,st in dets)
    warn = "<WARNING><URL>https://x/api?id_min=999</URL></WARNING>" if more else ""
    return (f"<HOST_LIST_VM_DETECTION_OUTPUT><RESPONSE><HOST_LIST><HOST><ID>1</ID><IP>10.0.0.5</IP>"
            f"<DNS>host1.ecg.local</DNS><DETECTION_LIST>{rows}</DETECTION_LIST></HOST></HOST_LIST>{warn}"
            f"</RESPONSE></HOST_LIST_VM_DETECTION_OUTPUT>").encode()

# parser: default keeps Confirmed+Potential, counts Info drops
stats={}
dets,_=qs._parse_detections(xml([("377734","Potential","3","New"),("90126","Info","2","Active"),("100","Confirmed","5","Active")]),
                            qs.DEFAULT_INCLUDE_TYPES, stats)
a({d["qid"] for d in dets}=={"377734","100"}, f"Potential kept, Info filtered: {dets}")
a(stats["dropped_by_type"]=={"Info":1}, f"drop counted: {stats}")
print("PASS: Confirmed+Potential kept by default; Info drops are COUNTED, not silent")

# fetch default now requests status New
import inspect
src=inspect.getsource(qs.run_qualys_sync)
a('"New,Active,Re-Opened"' in src, "sync default statuses include New")
print("PASS: sync default statuses include 'New' (freshly found detections no longer skipped)")

# completeness diff with mocked fetch + an integration row
run(db.integrations.insert_one({"id":"q","name":"Qualys VMDR","config":{"endpoint":"https://q","username":"u","api_key":"p"}}))
run(db.findings.insert_one({"id":"f","source_tool":"Qualys VMDR","qid":"100","asset_hostname":"host1.ecg.local"}))
async def fake_fetch(*a_, **k):
    return xml([("100","Confirmed","5","Active"),("377734","Potential","3","New"),
                ("90126","Info","2","Active"),("555","Confirmed","4","Fixed"),("777","Confirmed","4","Active")])
qs._fetch_qualys_detections=fake_fetch
rep=run(qs.qualys_completeness_check(db))
r=rep["missing_by_reason"]
a(r.get("filtered_type_Info")==1, f"90126 explained as Info-filtered: {r}")
a(r.get("status_fixed")==1, "Fixed detection explained, not a gap")
a(r.get("not_ingested")==2, f"377734 (Potential, now in scope but not yet ingested) + 777 = real gaps: {r}")
a(rep["real_gaps"]==2 and rep["qualys_detections"]==5)
print("PASS: full diff labels every missing pair (type-filtered / fixed / real gap)")

rep2=run(qs.qualys_completeness_check(db, qids=["377734","90126","42"]))
a(rep2["per_qid"]["377734"]["types"]==["Potential"] and rep2["per_qid"]["377734"]["db_findings"]==0)
a(rep2["per_qid"]["42"]["qualys_hosts"]==0 and "note" in rep2["per_qid"]["42"])
print("PASS: targeted QID check reports per-QID Qualys hosts vs DB findings")
print("\nALL QUALYS COMPLETENESS TESTS PASSED")
