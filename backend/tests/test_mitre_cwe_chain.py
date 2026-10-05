"""#33 -- the CWE -> ATT&CK data chain: Tenable now reads the CWE, the
coverage indicator reports where the chain breaks, and the admin repair
propagates CWE across findings sharing a CVE."""
import asyncio, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("MONGO_URL", "x"); os.environ.setdefault("DB_NAME", "t"); os.environ.setdefault("JWT_SECRET", "x")

from tenable_sync import _plugin_cwe
assert _plugin_cwe({"cwe": "89"}) == "CWE-89"
assert _plugin_cwe({"xref": ["IAVA:2020-A-1", "CWE:79"]}) == "CWE-79"
assert _plugin_cwe({"xref": "CWE:22"}) == "CWE-22"
assert _plugin_cwe({"xref": ["IAVA:2020-A-1"]}) is None
assert _plugin_cwe({}) is None
print("PASS: Tenable plugin attributes yield a canonical CWE (attribute or xref)")

from mitre_mapping import coverage_from_findings
rows = [
    {"id": "a", "cwe": "CWE-89", "title": "x"},
    {"id": "b", "cwe": "89", "title": "x"},
    {"id": "c", "cwe": "CWE-99999", "title": "x"},
    {"id": "d", "cwe": None, "title": "nothing"},
]
cov = coverage_from_findings(rows)
ch = cov["cwe_chain"]
assert ch["with_cwe"] == 3 and ch["with_cwe_pct"] == 75.0, ch
assert ch["cwe_mapped"] == 2 and ch["cwe_mapped_pct"] == 66.7, ch
assert ch["top_unmapped_cwes"] == [{"cwe": "CWE-99999", "count": 1}], ch
print("PASS: coverage indicator splits 'no CWE at ingest' from 'CWE not in table'")

from mongomock_motor import AsyncMongoMockClient
import routes.findings as rf
import aggregate_cache

async def main():
    db = AsyncMongoMockClient()["t"]
    rf.db = db
    await db.findings.insert_many([
        {"id": "1", "cve": "CVE-2024-1", "cwe": "CWE-89"},
        {"id": "2", "cve": "CVE-2024-1", "cwe": None},
        {"id": "3", "cve": "CVE-2024-1"},
        {"id": "4", "cve": "CVE-2024-2", "cwe": "79"},
        {"id": "5", "cve": "CVE-2024-3", "cwe": None},
    ])
    async def _noop(*a, **k): return None
    aggregate_cache.invalidate = _noop
    r = await rf.mitre_backfill_cwe(user={"role": "admin"})
    assert r["updated"] == 1, r            # "79" -> "CWE-79"
    assert r["propagated_by_cve"] == 2, r  # ids 2 and 3
    got = {d["id"]: d.get("cwe") async for d in db.findings.find({}, {"_id": 0})}
    assert got == {"1": "CWE-89", "2": "CWE-89", "3": "CWE-89", "4": "CWE-79", "5": None}, got
    r2 = await rf.mitre_backfill_cwe(user={"role": "admin"})
    assert r2["updated"] == 0 and r2["propagated_by_cve"] == 0, r2
    print("PASS: repair normalizes, propagates by CVE, and is idempotent")

asyncio.run(main())
