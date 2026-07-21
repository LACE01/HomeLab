import os, sys, asyncio
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_pci_dss_compliance"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_pci_dss_compliance"]

import server
import auth_utils
from routes import compliance as compliance_route
compliance_route.db = db_module.db

from fastapi.testclient import TestClient

admin_user = {"id": "u1", "email": "admin@x.com", "role": "admin", "name": "Admin", "teams": []}
app = server.app
app.dependency_overrides[auth_utils.get_current_user] = lambda: admin_user
client = TestClient(app)

db = db_module.db


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


import compliance

assert len(compliance.PCI_DSS_REQUIREMENTS) == 12
assert compliance.PCI_DSS_REQUIREMENTS["PCI-9"].startswith("Restrict Physical Access")
print("PASS: all 12 PCI-DSS v4.0 requirements are cataloged")

# --- open findings across a few categories, including one PCI-mapped and one not ---
run(db.findings.insert_many([
    # network_security -> PCI-1, via nmap source + port
    {"id": "f1", "severity": "Critical", "status": "New", "source_tool": "Nmap", "port": 445, "title": "Open port"},
    # crypto_pki -> PCI-3, PCI-4, via TLS Cert Monitor
    {"id": "f2", "severity": "High", "status": "New", "source_tool": "TLS Cert Monitor", "title": "Weak cipher"},
    # asset_inventory -> no PCI mapping at all (deliberately, per the file's own conservative mapping)
    {"id": "f3", "severity": "Medium", "status": "New", "source_tool": "EASM", "title": "New subdomain discovered"},
]))

summary = run(compliance.compute_compliance_summary(db))
assert "pci_dss_requirements" in summary and "pci_dss_coverage_pct" in summary and "unmapped_clean_pci_dss" in summary
print("PASS: compute_compliance_summary returns PCI-DSS fields alongside the existing CIS/NIST ones")

by_id = {c["id"]: c for c in summary["pci_dss_requirements"]}
assert by_id["PCI-1"]["status"] == "gap" and by_id["PCI-1"]["critical"] == 1
print("PASS: PCI-1 (Network Security Controls) correctly reflects the Critical Nmap finding as a gap")

assert by_id["PCI-3"]["status"] == "at_risk" and by_id["PCI-4"]["status"] == "at_risk"
assert by_id["PCI-3"]["high"] == 1 and by_id["PCI-4"]["high"] == 1
print("PASS: a single crypto finding correctly rolls up into BOTH PCI-3 and PCI-4 (multi-requirement category mapping)")

# PCI-9 (physical access) has zero mapped categories -- must show as unmapped, not "clean" with a misleading 0
assert "PCI-9" not in by_id
unmapped_ids = {c["id"] for c in summary["unmapped_clean_pci_dss"]}
assert "PCI-9" in unmapped_ids
print("PASS: PCI-9 (physical access -- no signal in this app) is correctly reported as unmapped, not falsely 'clean'")

assert summary["pci_dss_coverage_pct"] is not None and 0 <= summary["pci_dss_coverage_pct"] <= 100
print(f"PASS: pci_dss_coverage_pct computes a sane percentage ({summary['pci_dss_coverage_pct']}%)")

# Existing CIS/NIST behavior must be completely unaffected by adding PCI-DSS
assert any(c["id"] == "CIS-13" for c in summary["controls"])
assert summary["coverage_pct"] is not None
print("PASS: existing CIS Controls coverage is unaffected by the PCI-DSS addition")

# --- drill-down for a PCI requirement ---
drill = run(compliance.get_control_findings(db, "PCI-1"))
assert drill["total"] == 1 and drill["items"][0]["id"] == "f1"
assert drill["name"] == compliance.PCI_DSS_REQUIREMENTS["PCI-1"]
print("PASS: get_control_findings drills into a PCI-* requirement id and returns the right findings")

drill_cis = run(compliance.get_control_findings(db, "CIS-12"))
assert drill_cis["total"] == 1 and drill_cis["items"][0]["id"] == "f1"
print("PASS: get_control_findings still works correctly for CIS-* ids (not broken by the PCI addition)")

drill_unknown = run(compliance.get_control_findings(db, "PCI-99"))
assert drill_unknown["total"] == 0 and drill_unknown["items"] == []
print("PASS: get_control_findings handles an unknown control id gracefully")

# --- operational controls carry pci_dss tags ---
ops = run(compliance.compute_operational_controls(db))
mfa_ctrl = next(c for c in ops if c["id"] == "mfa")
assert mfa_ctrl["pci_dss"] == ["PCI-8"]
backup_ctrl = next(c for c in ops if c["id"] == "backup_continuity")
assert backup_ctrl["pci_dss"] == []
print("PASS: operational controls carry pci_dss requirement tags (or an empty list where there's genuinely no mapping)")

# --- routes ---
r = client.get("/api/v1/compliance/summary")
assert r.status_code == 200, r.text
body = r.json()
assert "pci_dss_requirements" in body and "operational_controls" in body
op_by_id = {c["id"]: c for c in body["operational_controls"]}
assert "pci_dss" in op_by_id["mfa"]
print("PASS: GET /v1/compliance/summary includes PCI-DSS data end to end")

r2 = client.get("/api/v1/compliance/controls/PCI-1/findings")
assert r2.status_code == 200 and r2.json()["total"] == 1
print("PASS: GET /v1/compliance/controls/PCI-1/findings route works")

r3 = client.get("/api/v1/reports/pdf/compliance")
assert r3.status_code == 200, r3.text
assert r3.headers.get("content-type") == "application/pdf"
assert r3.content[:4] == b"%PDF" and len(r3.content) > 500
print("PASS: GET /v1/reports/pdf/compliance renders a real PDF including the new PCI-DSS section without error")

print("\nALL PCI-DSS COMPLIANCE MAPPING TESTS PASSED")
