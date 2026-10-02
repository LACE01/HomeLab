"""#21: identical notes posted CONCURRENTLY (Enter + click / double-click) land once
on every notes surface; a genuinely new note still posts. #27: the compensating-
controls block is enforced next to the risk verdict even for stored templates that
predate it, and the docx flags residual<inherent with no controls documented."""
import os, sys, asyncio, io
os.environ.update(MONGO_URL="x", DB_NAME="t", JWT_SECRET="x")
sys.path.insert(0, ".")
from mongomock_motor import AsyncMongoMockClient
import db as dbm; dbm.client=AsyncMongoMockClient(); dbm.db=dbm.client["t"]; db=dbm.db
from routes.common import dedupe_post, now_iso
run=lambda x: asyncio.get_event_loop().run_until_complete(x)
def a(c,m=""): assert c,m

async def race(text):
    async def one():
        async def _ins():
            await asyncio.sleep(0.05)          # widen the race window like a slow insert
            d={"id":os.urandom(4).hex(),"finding_id":"f1","author":"u@x","text":text,"created_at":now_iso()}
            await db.comments.insert_one(dict(d)); return d
        return await dedupe_post(db.comments, {"finding_id":"f1"}, "u@x", text, _ins)
    return await asyncio.gather(one(), one(), one())

res=run(race("Patched via GPO"))
a(run(db.comments.count_documents({"text":"Patched via GPO"}))==1, "3 concurrent identical posts -> 1 row")
a(sum(1 for _,dup in res if dup)==2, "the other two are recognized as duplicates")
print("PASS: concurrent identical submits insert exactly once (race closed)")
run(race("A different note"))
a(run(db.comments.count_documents({"finding_id":"f1"}))==2, "a genuinely new note still posts")
print("PASS: distinct note text still posts normally")

# every notes endpoint is wired to the shared guard
import pathlib
for f,needle in [("routes/findings.py","dedupe_post(db.comments, {\"finding_id\""),
                 ("routes/risk_register.py","dedupe_post(db.comments, {\"risk_id\""),
                 ("routes/workflows.py","dedupe_post(db.comments, {\"exception_id\""),
                 ("routes/incident_response.py","dedupe_post(db.ir_case_events"),
                 ("routes/remediation_campaigns.py","dedupe_post(db.remediation_campaign_activity"),
                 ("routes/security_reviews.py","dedupe_post(db.security_review_notes")]:
    a(needle in pathlib.Path(f).read_text(), f"{f} uses the shared guard")
print("PASS: all six notes/comments endpoints use the shared race-safe guard")

# #27 layout enforcement
from report_templates import resolve_layout, _block
old_tmpl={"blocks":[_block("header"), _block("risk_verdict"), _block("decision")]}   # pre-item-27 template
lay=[b["type"] for b in resolve_layout(old_tmpl, shared=False)]
a(lay.index("compensating_controls")==lay.index("risk_verdict")+1, f"controls injected after verdict: {lay}")
hid={"blocks":[_block("header"), _block("risk_verdict"), {**_block("compensating_controls"),"visible":False}]}
a("compensating_controls" in [b["type"] for b in resolve_layout(hid, shared=True)], "hidden controls block re-enforced")
print("PASS: #27 controls block enforced beside the verdict, incl. pre-existing/edited templates")

from security_review_docx import _residual_below_inherent
a(_residual_below_inherent({"inherent_risk":{"score":20},"residual_risk":{"score":6}}))
a(not _residual_below_inherent({"inherent_risk":{"score":6},"residual_risk":{"score":6}}))
print("PASS: #27 docx detects an unjustified residual reduction")
print("\nALL NOTES-DEDUPE + CONTROLS TESTS PASSED")
