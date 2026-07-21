import os, sys, asyncio
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_scheduled_reports"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_scheduled_reports"]

import server
import auth_utils
from routes import scheduled_reports as sr_route
sr_route.db = db_module.db

from fastapi.testclient import TestClient

admin_user = {"id": "u1", "email": "admin@x.com", "role": "admin", "name": "Admin", "teams": []}
app = server.app
app.dependency_overrides[auth_utils.get_current_user] = lambda: admin_user
client = TestClient(app)

db = db_module.db


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# --- reports.py refactor: Response now carries raw bytes directly ---
import reports

run(db.findings.insert_many([
    {"id": "f1", "severity": "Critical", "status": "New", "risk_score": 90, "asset_hostname": "srv-1",
     "asset_id": "a1", "first_seen_at": "2026-07-01T00:00:00+00:00", "cve": "CVE-2026-1"},
    {"id": "f2", "severity": "High", "status": "New", "risk_score": 60, "asset_hostname": "srv-2",
     "asset_id": "a2", "first_seen_at": "2026-07-05T00:00:00+00:00", "cve": "CVE-2026-2"},
]))

resp_pdf = run(reports.run_prebuilt(db, "open_by_severity", "pdf"))
assert resp_pdf is not None
assert isinstance(resp_pdf.body, bytes) and len(resp_pdf.body) > 100
assert resp_pdf.media_type == "application/pdf"
assert resp_pdf.body[:4] == b"%PDF"
print("PASS: run_prebuilt PDF response now exposes real PDF bytes via .body (not just a streaming wrapper)")

resp_csv = run(reports.run_prebuilt(db, "open_by_severity", "csv"))
assert isinstance(resp_csv.body, (bytes, str))
csv_bytes = resp_csv.body if isinstance(resp_csv.body, bytes) else resp_csv.body.encode()
assert b"severity" in csv_bytes and b"Critical" in csv_bytes
assert resp_csv.media_type == "text/csv"
print("PASS: run_prebuilt CSV response exposes real CSV bytes via .body")

# ============ scheduled_reports.py ============
import scheduled_reports as sr

created = run(sr.create_scheduled_report(db, {
    "name": "Weekly Critical Report", "source": "prebuilt", "report_id": "open_by_severity",
    "fmt": "pdf", "frequency": "weekly", "recipients": ["ciso@example.com", " soc@example.com "],
}, actor="admin@x.com"))
assert created["recipients"] == ["ciso@example.com", "soc@example.com"]  # trimmed
assert created["enabled"] is True and created["last_sent_at"] is None
print("PASS: create_scheduled_report validates and stores a prebuilt schedule, trims recipient whitespace")

try:
    run(sr.create_scheduled_report(db, {
        "name": "Bad", "source": "prebuilt", "report_id": "not_a_real_report",
        "frequency": "weekly", "recipients": ["a@b.com"],
    }, actor="admin@x.com"))
    assert False
except ValueError as e:
    assert "Unknown report_id" in str(e)
print("PASS: create_scheduled_report rejects an unknown prebuilt report_id")

try:
    run(sr.create_scheduled_report(db, {
        "name": "Bad freq", "source": "prebuilt", "report_id": "open_by_severity",
        "frequency": "biannually", "recipients": ["a@b.com"],
    }, actor="admin@x.com"))
    assert False
except ValueError as e:
    assert "frequency must be" in str(e)
print("PASS: create_scheduled_report rejects an invalid frequency")

try:
    run(sr.create_scheduled_report(db, {
        "name": "No recipients", "source": "prebuilt", "report_id": "open_by_severity",
        "frequency": "daily", "recipients": [],
    }, actor="admin@x.com"))
    assert False
except ValueError as e:
    assert "recipient" in str(e)
print("PASS: create_scheduled_report rejects an empty recipient list")

custom_schedule = run(sr.create_scheduled_report(db, {
    "name": "Daily custom by owner", "source": "custom",
    "custom_config": {"group_by": "owner_team", "metric": "count", "filters": {}},
    "fmt": "csv", "frequency": "daily", "recipients": ["team@example.com"],
}, actor="admin@x.com"))
print("PASS: create_scheduled_report also accepts a custom-builder config")

# --- send_scheduled_report_now (simulated email -- no SMTP_HOST/RESEND_API_KEY set in this test env) ---
result = run(sr.send_scheduled_report_now(db, created["id"]))
assert result["ok"] is True
assert result["sent_to"] == ["ciso@example.com", "soc@example.com"]
assert result["filename"].endswith(".pdf")
print("PASS: send_scheduled_report_now generates the real report and 'sends' it (simulated, no mail server configured) to every recipient")

refreshed = run(sr.get_scheduled_report(db, created["id"]))
assert refreshed["last_sent_at"] is not None
print("PASS: last_sent_at is updated after a successful send")

result_custom = run(sr.send_scheduled_report_now(db, custom_schedule["id"]))
assert result_custom["ok"] is True and result_custom["filename"].endswith(".csv")
print("PASS: a custom-builder scheduled report also generates and sends correctly")

# --- update / delete ---
updated = run(sr.update_scheduled_report(db, created["id"], {"enabled": False}))
assert updated["enabled"] is False
print("PASS: update_scheduled_report can disable a schedule")

deleted = run(sr.delete_scheduled_report(db, custom_schedule["id"]))
assert deleted is True
assert run(sr.get_scheduled_report(db, custom_schedule["id"])) is None
print("PASS: delete_scheduled_report removes the schedule")

# --- run_due_scheduled_reports cadence logic ---
run(db.scheduled_reports.update_one({"id": created["id"]}, {"$set": {"enabled": True}}))
sweep1 = run(sr.run_due_scheduled_reports(db))
assert sweep1["schedules_checked"] == 1
assert sweep1["sent"] == 0  # just sent above, well within the weekly window -- not due again
print("PASS: run_due_scheduled_reports skips a schedule that was just sent (not yet due)")

# force it to look overdue by backdating last_sent_at well past the weekly window
import datetime as dt
old_ts = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=10)).isoformat()
run(db.scheduled_reports.update_one({"id": created["id"]}, {"$set": {"last_sent_at": old_ts}}))
sweep2 = run(sr.run_due_scheduled_reports(db))
assert sweep2["sent"] == 1
print("PASS: run_due_scheduled_reports sends a schedule once its cadence window has elapsed")

# never-sent schedule is due immediately
never_sent = run(sr.create_scheduled_report(db, {
    "name": "Monthly compliance snapshot", "source": "prebuilt", "report_id": "open_exceptions",
    "frequency": "monthly", "recipients": ["compliance@example.com"],
}, actor="admin@x.com"))
sweep3 = run(sr.run_due_scheduled_reports(db))
assert any(True for _ in [1])  # sanity no-op
just = run(sr.get_scheduled_report(db, never_sent["id"]))
assert just["last_sent_at"] is not None
print("PASS: a never-sent schedule fires on its first due-check, same as digest rules")

# ============ routes ============
r = client.get("/api/v1/reports/scheduled")
assert r.status_code == 200, r.text
assert len(r.json()["items"]) >= 2
print("PASS: GET /v1/reports/scheduled lists schedules")

r2 = client.post("/api/v1/reports/scheduled", json={
    "name": "Route-created", "source": "prebuilt", "report_id": "top_risk_assets",
    "fmt": "csv", "frequency": "daily", "recipients": ["x@example.com"],
})
assert r2.status_code == 200, r2.text
new_id = r2.json()["id"]
print("PASS: POST /v1/reports/scheduled creates a schedule via the API")

r3 = client.post(f"/api/v1/reports/scheduled/{new_id}/send-now")
assert r3.status_code == 200, r3.text
assert r3.json()["ok"] is True
print("PASS: POST /v1/reports/scheduled/{id}/send-now sends immediately regardless of cadence")

r4 = client.patch(f"/api/v1/reports/scheduled/{new_id}", json={"enabled": False})
assert r4.status_code == 200 and r4.json()["enabled"] is False
print("PASS: PATCH /v1/reports/scheduled/{id} updates a schedule")

r5 = client.delete(f"/api/v1/reports/scheduled/{new_id}")
assert r5.status_code == 200 and r5.json()["ok"] is True
r6 = client.delete(f"/api/v1/reports/scheduled/{new_id}")
assert r6.status_code == 404
print("PASS: DELETE /v1/reports/scheduled/{id} removes it, 404s on a repeat delete")

print("\nALL SCHEDULED REPORT TESTS PASSED")
