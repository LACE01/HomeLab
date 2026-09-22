"""Streaming-restore parser: every document in a VulnOps gzip-JSON archive must
round-trip through scripts/stream_restore.stream_docs() without materializing the
whole archive. Exercises the tokenizer's hard cases (strings containing commas /
quotes / braces / escapes, nested objects/arrays, dates, ObjectIds, empty
collections)."""
import os, sys, gzip, io, datetime
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))
from bson import json_util, ObjectId
import stream_restore as sr
def a(c, m=""): assert c, m

docs = {
  "findings": [
    {"_id": ObjectId(), "id": "f1",
     "title": 'Weird, title with "quotes" and {braces} [brackets]',
     "due_at": datetime.datetime(2026, 9, 1, 12, 0, 0),
     "nested": {"a": [1, 2, {"b": "c,d"}]}, "n": 3.14, "ok": True, "z": None},
    {"_id": ObjectId(), "id": "f2", "title": "escaped \\\\ and quote \\\" inside", "arr": []},
  ],
  "assets": [{"_id": ObjectId(), "id": "a1", "hostname": "host,with,commas", "tags": ["x", "y]z"]}],
  "empty_col": [],
}

buf = io.BytesIO(); gz = gzip.GzipFile(fileobj=buf, mode="wb")
def w(s): gz.write(s.encode("utf-8"))
w('{"created_at": '); w(json_util.dumps(datetime.datetime(2026, 9, 21))); w(', "collections": {')
for ci, (name, dl) in enumerate(docs.items()):
    if ci: w(',')
    w(json_util.dumps(name)); w(': [')
    first = True
    for d in dl:
        w('' if first else ','); w(json_util.dumps(d)); first = False
    w(']')
w('}}'); gz.close()

got = {}
for name, doc in sr.stream_docs(gzip.GzipFile(fileobj=io.BytesIO(buf.getvalue()), mode="rb")):
    got.setdefault(name, []).append(doc)

a(set(got) == {"findings", "assets"}, f"empty collection should yield nothing; got {set(got)}")
for name, dl in docs.items():
    if not dl: continue
    a(len(got.get(name, [])) == len(dl), f"{name} count mismatch")
    for orig, parsed in zip(dl, got[name]):
        a(json_util.dumps(orig, sort_keys=True) == json_util.dumps(parsed, sort_keys=True),
          f"doc mismatch in {name}")
print("PASS: streaming parser round-trips all docs (commas/quotes/braces/escapes/dates/ObjectId)")
print("\nALL STREAM RESTORE TESTS PASSED")
