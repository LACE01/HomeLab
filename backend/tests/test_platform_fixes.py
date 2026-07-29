"""Items 32-34: score-distribution histogram binning, MITRE ATT&CK mapping
population + coverage indicator, and the live database-size endpoint."""
import os, sys, asyncio, uuid
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_platform_fixes"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_platform_fixes"]

import server
import auth_utils
from routes import findings as findings_route
from routes import backups as backups_route
findings_route.db = db_module.db
backups_route.db = db_module.db

from fastapi.testclient import TestClient

admin_user = {"id": "u1", "email": "admin@x.com", "role": "admin", "name": "Admin", "teams": []}
app = server.app
app.dependency_overrides[auth_utils.get_current_user] = lambda: admin_user
client = TestClient(app)
db = db_module.db


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# =========================================================================
# Item 32 -- score distribution histogram
# =========================================================================

from scoring_v2 import empirical_percentile

# A realistic cohort: KRI scores cluster in a narrow band. The OLD binning
# divided by max(cohort), which pushed nearly everything into one bucket --
# exactly the "only one visible bar" symptom.
cohort = [0.30, 0.31, 0.32, 0.33, 0.34, 0.35, 0.36, 0.37, 0.38, 0.39, 0.41, 0.42, 0.55, 0.61]
r = empirical_percentile(0.36, cohort)
nonzero = [b for b in r["buckets"] if b["count"] > 0]
assert len(nonzero) >= 4, f"a clustered cohort must spread across several bars, got {len(nonzero)}"
assert len(r["buckets"]) == 20
assert sum(b["count"] for b in r["buckets"]) == len(cohort), "every finding must land in exactly one bucket"
print("PASS: histogram bins over the fixed 0-1 KRI domain, so a clustered cohort renders as multiple bars (was one)")

# bucket ranges are contiguous and labelled for tooltips
assert r["buckets"][0]["from"] == 0.0 and r["buckets"][0]["to"] == 0.05
assert r["buckets"][19]["to"] == 1.0
assert all(r["buckets"][i]["to"] == r["buckets"][i + 1]["from"] for i in range(19))
print("PASS: each bucket carries a contiguous from/to range and a count for per-bar tooltips")

# my_bucket is computed server-side (the frontend used an unrelated formula)
assert r["my_bucket"] == 7, r["my_bucket"]          # 0.36 * 20 = 7.2 -> bucket 7
assert r["buckets"][r["my_bucket"]]["from"] <= 0.36 < r["buckets"][r["my_bucket"]]["to"]
assert r["cohort_size"] == len(cohort)
assert r["cohort_min"] == 0.3 and r["cohort_max"] == 0.61
print("PASS: the viewer's own bucket, cohort size, and cohort range come from the server")

# edge cases
empty = empirical_percentile(0.5, [])
assert empty["buckets"] == [] and empty["my_bucket"] is None
top = empirical_percentile(1.0, [1.0])
assert top["my_bucket"] == 19, "a perfect score must land in the last bucket, not out of range"
print("PASS: empty cohorts and a maximum score are handled without index errors")


# =========================================================================
# Item 33 -- MITRE ATT&CK mapping
# =========================================================================

from mitre_mapping import normalize_cwe, mitre_for_cwe, apply_mitre_mapping, mapping_coverage

# The actual root cause: Qualys hands back a BARE number.
assert normalize_cwe(89) == "CWE-89"
assert normalize_cwe("89") == "CWE-89"
assert normalize_cwe("CWE-89") == "CWE-89"
assert normalize_cwe("cwe-89") == "CWE-89"
assert normalize_cwe("CWE-89, CWE-79") == "CWE-89"
assert normalize_cwe(["CWE-22"]) == "CWE-22"
assert normalize_cwe("NVD-CWE-noinfo") is None      # NVD placeholder, not a real CWE
assert normalize_cwe("NVD-CWE-Other") is None
assert normalize_cwe("") is None and normalize_cwe(None) is None
print("PASS: CWE normalization accepts bare numbers, prefixed ids, lists, and rejects NVD placeholders")

assert mitre_for_cwe("89")["technique_id"] == "T1190", "a bare Qualys CWE must now resolve -- this was the bug"
assert mitre_for_cwe("CWE-89")["technique_id"] == "T1190"
assert mitre_for_cwe("CWE-99999") is None
print("PASS: a bare-number CWE now resolves to an ATT&CK technique (previously every Qualys finding missed)")

f = apply_mitre_mapping({"id": "f1", "cwe": "89"})
assert f["mitre_tactic"] == "Initial Access"
assert "T1190" in f["mitre_technique"]
assert f["mitre_mapping_source"] == "heuristic"
# an analyst-set mapping is never overwritten
f2 = apply_mitre_mapping({"id": "f2", "cwe": "89", "mitre_tactic": "Impact", "mitre_technique": "Custom"})
assert f2["mitre_tactic"] == "Impact"
# falls back to alternative fields some importers use
f3 = apply_mitre_mapping({"id": "f3", "cwe": None, "cwes": ["CWE-79"]})
assert f3.get("mitre_technique_id") == "T1190"
print("PASS: apply_mitre_mapping populates from normalized CWEs, respects analyst overrides, and checks alt fields")

cov = mapping_coverage({"89": 10, "CWE-79": 5, "CWE-99999": 3, None: 7})
assert cov["findings_total"] == 25
assert cov["findings_mapped"] == 15
assert cov["findings_without_cwe"] == 7
assert cov["coverage_pct_of_all"] == 60.0
assert cov["coverage_pct_of_cwe_bearing"] == 83.3
assert cov["top_unmapped"][0] == {"cwe": "CWE-99999", "count": 3}
assert cov["table_size"] > 40
print("PASS: mapping_coverage separates 'no CWE at all' from 'CWE not in the table' and ranks the biggest gaps")

# --- API: coverage endpoint + backfill ---
run(db.findings.delete_many({}))
run(db.findings.insert_many([
    {"id": "a", "cwe": "89", "status": "New", "severity": "High"},          # bare -> mappable after normalize
    {"id": "b", "cwe": "CWE-79", "status": "Valid", "severity": "High"},
    {"id": "c", "cwe": "NVD-CWE-noinfo", "status": "New", "severity": "Medium"},
    {"id": "d", "cwe": None, "status": "New", "severity": "Low"},
    {"id": "e", "cwe": "CWE-99999", "status": "New", "severity": "Low"},
    {"id": "f", "cwe": "89", "status": "Fixed validated", "severity": "High"},  # closed, excluded
]))
r = client.get("/api/v1/mitre/coverage")
assert r.status_code == 200
cov = r.json()
assert cov["findings_total"] == 5, "closed findings must be excluded from coverage"
assert cov["findings_mapped"] == 2                  # 89 + CWE-79
assert cov["findings_without_cwe"] == 1
print("PASS: /v1/mitre/coverage reports live backlog coverage, excluding closed findings")

r = client.post("/api/v1/mitre/backfill-cwe")
assert r.status_code == 200
# a + f ("89" -> "CWE-89") and c ("NVD-CWE-noinfo" -> None). The backfill
# deliberately repairs CLOSED findings too -- they still feed history/reporting.
assert r.json()["updated"] == 3
assert run(db.findings.find_one({"id": "a"}, {"_id": 0}))["cwe"] == "CWE-89"
assert run(db.findings.find_one({"id": "c"}, {"_id": 0}))["cwe"] is None
# idempotent
r = client.post("/api/v1/mitre/backfill-cwe")
assert r.json()["updated"] == 0
print("PASS: the backfill canonicalizes already-stored CWEs, clears NVD placeholders, and is idempotent")

# --- ingest normalizes going forward ---
from qualys_sync import _norm_cwe
assert _norm_cwe("89") == "CWE-89" and _norm_cwe(None) is None
print("PASS: Qualys knowledgebase ingest normalizes CWE at write time, so new findings map immediately")


# =========================================================================
# Item 34 -- live database size
# =========================================================================

run(db.assets.insert_many([{"id": f"a{i}", "hostname": f"h{i}"} for i in range(7)]))
r = client.get("/api/v1/admin/backups/db-size")
assert r.status_code == 200
payload = r.json()
d = payload["database"]
assert d["collection_count"] >= 2
assert d["document_count"] >= 12                     # 6 findings + 7 assets
names = {c["name"] for c in payload["collections"]}
assert "assets" in names and "findings" in names
assets_row = next(c for c in payload["collections"] if c["name"] == "assets")
assert assets_row["documents"] == 7
assert payload["generated_at"]
# mongomock has no dbStats -- the endpoint must degrade to exact counts, not 500
assert d["source"] in ("dbStats", "counted")
print("PASS: /v1/admin/backups/db-size reports document + collection counts with a per-collection breakdown, "
      "degrading to exact counts when byte-level stats aren't available")
