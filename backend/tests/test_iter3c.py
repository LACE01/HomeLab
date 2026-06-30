"""Iteration 3c tests:
- P0 fix verification: nightly-rescore endpoints + cwe-prevalence (must NOT return 404)
- Time-range filter on dashboards
- User preferences GET/PUT
- Findings grouping endpoint
"""
import os
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "https://remediationhub.preview.emergentagent.com").rstrip("/")
ADMIN_EMAIL = "luisarce731@outlook.com"
ADMIN_PASSWORD = "vz7NOHcP64WRBEOg3C2I"


@pytest.fixture(scope="module")
def admin_client():
    s = requests.Session()
    s.headers.update({"Content-Type": "application/json"})
    r = s.post(f"{BASE_URL}/api/auth/login",
               json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
               timeout=15)
    assert r.status_code == 200, f"login failed: {r.status_code} {r.text}"
    tok = r.json()["token"]
    s.headers.update({"Authorization": f"Bearer {tok}"})
    return s


# --------------------------- P0 FIX VERIFICATION ---------------------------
class TestP0Fixes:
    def test_nightly_rescore_run_returns_200(self, admin_client):
        r = admin_client.post(f"{BASE_URL}/api/v1/admin/nightly-rescore/run", timeout=60)
        assert r.status_code == 200, f"expected 200 got {r.status_code} - body: {r.text[:300]}"
        body = r.json()
        assert isinstance(body, dict)

    def test_nightly_rescore_runs_list(self, admin_client):
        r = admin_client.get(f"{BASE_URL}/api/v1/admin/nightly-rescore/runs", timeout=15)
        assert r.status_code == 200, r.text[:300]
        data = r.json()
        assert "items" in data
        assert isinstance(data["items"], list)
        # After we triggered a run in previous test, expect at least 1 item
        assert len(data["items"]) >= 1, "rescore runs history should have at least 1 entry"

    def test_cwe_prevalence(self, admin_client):
        r = admin_client.get(f"{BASE_URL}/api/v1/cwe-prevalence", timeout=15)
        assert r.status_code == 200, r.text[:300]
        data = r.json()
        assert "items" in data
        if data["items"]:
            it = data["items"][0]
            for k in ("cwe", "weight", "count", "sample_title"):
                assert k in it, f"missing key {k} in cwe-prevalence item"


# --------------------------- Time-range ---------------------------
class TestTimeRange:
    def test_analyst_7d(self, admin_client):
        r = admin_client.get(f"{BASE_URL}/api/v1/dashboards/analyst", params={"range": "7d"}, timeout=15)
        assert r.status_code == 200, r.text[:300]
        d = r.json()
        assert d["range"] == "7d"
        assert d["range_days"] == 7

    def test_analyst_30d_default(self, admin_client):
        r = admin_client.get(f"{BASE_URL}/api/v1/dashboards/analyst", timeout=15)
        assert r.status_code == 200
        d = r.json()
        assert d["range"] == "30d"
        assert d["range_days"] == 30

    def test_new_findings_varies_by_window(self, admin_client):
        r7 = admin_client.get(f"{BASE_URL}/api/v1/dashboards/analyst", params={"range": "7d"}, timeout=15).json()
        r365 = admin_client.get(f"{BASE_URL}/api/v1/dashboards/analyst", params={"range": "12mo"}, timeout=15).json()
        # 12-month new findings count should be >= 7-day (larger window)
        assert r365["new_findings"] >= r7["new_findings"]

    def test_executive_custom_range(self, admin_client):
        r = admin_client.get(
            f"{BASE_URL}/api/v1/dashboards/executive",
            params={"range": "custom",
                    "start": "2026-04-01T00:00:00Z",
                    "end": "2026-06-30T23:59:59Z"},
            timeout=15,
        )
        assert r.status_code == 200, r.text[:300]
        d = r.json()
        assert d["range"] == "custom"

    def test_manager_invalid_range_does_not_crash(self, admin_client):
        r = admin_client.get(f"{BASE_URL}/api/v1/dashboards/manager", params={"range": "foo"}, timeout=15)
        assert r.status_code == 200, r.text[:300]
        d = r.json()
        # On unknown range, range_days must be None (per parse_time_range)
        assert d.get("range_days") in (None, 0) or d["range_days"] is None
        # snapshots should still be present (no filter applied)
        assert "snapshots" in d


# --------------------------- User Preferences ---------------------------
class TestPreferences:
    def test_get_default_prefs(self, admin_client):
        r = admin_client.get(f"{BASE_URL}/api/v1/me/preferences", timeout=15)
        assert r.status_code == 200, r.text[:300]
        prefs = r.json()
        assert "dashboard" in prefs
        assert "range" in prefs["dashboard"]
        assert "tiles" in prefs["dashboard"]
        assert "findings" in prefs
        assert "group_by" in prefs["findings"]
        assert "view_mode" in prefs["findings"]
        # default range
        # don't lock to '30d' in case user previously set it, but ensure it's a string
        assert isinstance(prefs["dashboard"]["range"], str)

    def test_put_prefs_persist(self, admin_client):
        body = {"prefs": {"dashboard": {"range": "90d", "tiles": {"stat-kev": False}}}}
        r = admin_client.put(f"{BASE_URL}/api/v1/me/preferences", json=body, timeout=15)
        assert r.status_code == 200, r.text[:300]
        merged = r.json()
        assert merged["dashboard"]["range"] == "90d"
        assert merged["dashboard"]["tiles"]["stat-kev"] is False
        # default tile that wasn't touched should remain True (deep merge)
        assert merged["dashboard"]["tiles"]["stat-open"] is True

        # GET again to verify persistence
        r2 = admin_client.get(f"{BASE_URL}/api/v1/me/preferences", timeout=15).json()
        assert r2["dashboard"]["range"] == "90d"
        assert r2["dashboard"]["tiles"]["stat-kev"] is False

        # Reset back to defaults for cleanliness
        admin_client.put(f"{BASE_URL}/api/v1/me/preferences",
                         json={"prefs": {"dashboard": {"range": "30d", "tiles": {"stat-kev": True}}}},
                         timeout=15)


# --------------------------- Findings grouping ---------------------------
class TestFindingsGroups:
    def test_group_by_cve_by_vulnerability(self, admin_client):
        r = admin_client.get(
            f"{BASE_URL}/api/v1/findings-groups",
            params={"group_by": "cve", "view_mode": "by_vulnerability"},
            timeout=20,
        )
        assert r.status_code == 200, r.text[:300]
        d = r.json()
        assert d["group_by"] == "cve"
        assert d["view_mode"] == "by_vulnerability"
        assert isinstance(d.get("groups"), list)
        if d["groups"]:
            g = d["groups"][0]
            for k in ("key", "count", "asset_count", "max_risk", "severities", "kev", "sample_title"):
                assert k in g, f"missing field {k} in group: {g}"

    def test_group_by_severity(self, admin_client):
        r = admin_client.get(
            f"{BASE_URL}/api/v1/findings-groups",
            params={"group_by": "severity"},
            timeout=15,
        )
        assert r.status_code == 200, r.text[:300]
        d = r.json()
        assert d["group_by"] == "severity"
        assert isinstance(d["groups"], list)
        sev_keys = {g["key"] for g in d["groups"] if g.get("key")}
        # at least one of the expected severities should appear
        assert sev_keys & {"Critical", "High", "Medium", "Low", "Info", "—"}

    def test_group_by_invalid_rejected(self, admin_client):
        r = admin_client.get(
            f"{BASE_URL}/api/v1/findings-groups",
            params={"group_by": "garbage"},
            timeout=10,
        )
        assert r.status_code == 422, f"expected 422 got {r.status_code}: {r.text[:200]}"
