"""Iteration 9 tests: Teams CRUD, findings groups (by_asset/by_vulnerability),
bulk-owner, OpenCTI CF Access error, integration config patch."""
import os
import uuid
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "https://remediationhub.preview.emergentagent.com").rstrip("/")
ADMIN_EMAIL = "luisarce731@outlook.com"
ADMIN_PASSWORD = "vz7NOHcP64WRBEOg3C2I"


@pytest.fixture(scope="session")
def admin_token():
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}, timeout=20)
    assert r.status_code == 200, f"login failed: {r.status_code} {r.text[:200]}"
    body = r.json()
    return body.get("access_token") or body["token"]


@pytest.fixture(scope="session")
def H(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


# --- Auth basic ---
def test_auth_me(H):
    r = requests.get(f"{BASE_URL}/api/auth/me", headers=H, timeout=15)
    assert r.status_code == 200
    me = r.json()
    assert me["email"] == ADMIN_EMAIL
    assert me["role"] == "admin"


# --- Teams CRUD ---
def test_teams_list_returns_formal_and_implicit(H):
    r = requests.get(f"{BASE_URL}/api/v1/admin/teams", headers=H, timeout=20)
    assert r.status_code == 200
    items = r.json()["items"]
    assert isinstance(items, list) and len(items) > 0
    # check both implicit and formal teams exist
    names = [t["name"] for t in items]
    assert len(names) == len(set(names)), f"Duplicate team names: {names}"
    implicit_count = sum(1 for t in items if t.get("implicit"))
    formal_count = sum(1 for t in items if not t.get("implicit"))
    print(f"teams: {formal_count} formal, {implicit_count} implicit")
    # implicit teams must have id=None
    for t in items:
        if t.get("implicit"):
            assert t.get("id") is None


def test_teams_full_crud(H):
    unique_name = f"TEST_Team_{uuid.uuid4().hex[:8]}"
    # CREATE
    r = requests.post(f"{BASE_URL}/api/v1/admin/teams", headers=H,
                      json={"name": unique_name, "color": "#10b981", "description": "test"}, timeout=20)
    assert r.status_code == 200, r.text
    created = r.json()
    assert created["name"] == unique_name
    assert created["color"] == "#10b981"
    tid = created["id"]

    # Duplicate -> 409
    r2 = requests.post(f"{BASE_URL}/api/v1/admin/teams", headers=H,
                       json={"name": unique_name}, timeout=20)
    assert r2.status_code == 409

    # Verify in list
    r3 = requests.get(f"{BASE_URL}/api/v1/admin/teams", headers=H, timeout=20)
    assert any(t["name"] == unique_name for t in r3.json()["items"])

    # PATCH (rename)
    new_name = unique_name + "_RENAMED"
    r4 = requests.patch(f"{BASE_URL}/api/v1/admin/teams/{tid}", headers=H,
                        json={"name": new_name, "color": "#10b981"}, timeout=20)
    assert r4.status_code == 200, r4.text

    r5 = requests.get(f"{BASE_URL}/api/v1/admin/teams", headers=H, timeout=20)
    assert any(t["name"] == new_name for t in r5.json()["items"])

    # DELETE
    r6 = requests.delete(f"{BASE_URL}/api/v1/admin/teams/{tid}", headers=H, timeout=20)
    assert r6.status_code == 200
    r7 = requests.get(f"{BASE_URL}/api/v1/admin/teams", headers=H, timeout=20)
    assert not any(t.get("id") == tid for t in r7.json()["items"])


def test_teams_members_propagation(H):
    """Adding/removing members updates user.team field."""
    users = requests.get(f"{BASE_URL}/api/v1/admin/users", headers=H, timeout=15).json()["items"]
    # Pick a non-admin user to safely move (or use any user other than self)
    candidates = [u for u in users if u["email"] != ADMIN_EMAIL]
    if not candidates:
        pytest.skip("no other users to test member assignment")
    test_user = candidates[0]
    original_team = test_user.get("team")

    unique_name = f"TEST_MemberTeam_{uuid.uuid4().hex[:6]}"
    r = requests.post(f"{BASE_URL}/api/v1/admin/teams", headers=H,
                      json={"name": unique_name, "members": [test_user["id"]]}, timeout=20)
    assert r.status_code == 200
    tid = r.json()["id"]

    users2 = requests.get(f"{BASE_URL}/api/v1/admin/users", headers=H, timeout=15).json()["items"]
    moved = next(u for u in users2 if u["id"] == test_user["id"])
    assert moved.get("team") == unique_name, f"user.team not updated, got {moved.get('team')}"

    # Remove member via PATCH
    r2 = requests.patch(f"{BASE_URL}/api/v1/admin/teams/{tid}", headers=H,
                       json={"name": unique_name, "members": []}, timeout=20)
    assert r2.status_code == 200
    users3 = requests.get(f"{BASE_URL}/api/v1/admin/users", headers=H, timeout=15).json()["items"]
    cleared = next(u for u in users3 if u["id"] == test_user["id"])
    assert cleared.get("team") in (None, ""), f"team not cleared, got {cleared.get('team')}"

    # restore original if non-null
    if original_team:
        requests.patch(f"{BASE_URL}/api/v1/admin/users/{test_user['id']}", headers=H,
                       json={"team": original_team}, timeout=15)

    # cleanup
    requests.delete(f"{BASE_URL}/api/v1/admin/teams/{tid}", headers=H, timeout=15)


# --- Findings groups: by_asset / by_vulnerability ---
def test_findings_groups_by_cve(H):
    r = requests.get(f"{BASE_URL}/api/v1/findings-groups",
                     params={"group_by": "cve", "view_mode": "by_vulnerability", "limit": 100},
                     headers=H, timeout=30)
    assert r.status_code == 200
    data = r.json()
    assert data["group_by"] == "cve"
    assert data["view_mode"] == "by_vulnerability"
    assert isinstance(data["groups"], list)
    assert len(data["groups"]) > 0
    g0 = data["groups"][0]
    assert "key" in g0 and "count" in g0 and "max_risk" in g0
    assert "asset_count" in g0  # by_vulnerability includes asset_count
    print(f"by_vulnerability returned {len(data['groups'])} CVE groups")


def test_findings_groups_by_asset(H):
    r = requests.get(f"{BASE_URL}/api/v1/findings-groups",
                     params={"group_by": "asset", "view_mode": "by_asset", "limit": 100},
                     headers=H, timeout=30)
    assert r.status_code == 200
    data = r.json()
    assert data["group_by"] == "asset"
    assert len(data["groups"]) > 0
    print(f"by_asset returned {len(data['groups'])} asset groups; top key={data['groups'][0]['key']}")


# --- Bulk owner ---
def test_bulk_owner_admin_can_set(H):
    # get one finding id
    r = requests.get(f"{BASE_URL}/api/v1/findings", params={"limit": 1}, headers=H, timeout=15)
    items = r.json()["items"]
    if not items:
        pytest.skip("no findings")
    fid = items[0]["id"]
    original = items[0].get("owner_team")

    test_team = f"TEST_BulkOwn_{uuid.uuid4().hex[:6]}"
    r2 = requests.post(f"{BASE_URL}/api/v1/findings/bulk-owner", headers=H,
                      json={"ids": [fid], "owner_team": test_team}, timeout=15)
    assert r2.status_code == 200
    assert r2.json()["updated"] == 1

    # verify
    g = requests.get(f"{BASE_URL}/api/v1/findings/{fid}", headers=H, timeout=10).json()
    assert g["owner_team"] == test_team
    assert g["ownership_confidence"] == 1.0

    # restore
    if original:
        requests.post(f"{BASE_URL}/api/v1/findings/bulk-owner", headers=H,
                      json={"ids": [fid], "owner_team": original}, timeout=15)


# --- Findings list count (admin sees all) ---
def test_findings_total_count(H):
    r = requests.get(f"{BASE_URL}/api/v1/findings", params={"limit": 1}, headers=H, timeout=20)
    assert r.status_code == 200
    total = r.json()["total"]
    assert total > 1000, f"expected ~6855, got {total}"
    print(f"findings total = {total}")


# --- OpenCTI / threat intel: CF Access error message ---
def test_threat_intel_returns_actionable_cf_message(H):
    r = requests.get(f"{BASE_URL}/api/v1/threat-intel/CVE-2025-55315", headers=H, timeout=30)
    assert r.status_code == 200
    data = r.json()
    # Either not configured OR configured with an actionable error mentioning Cloudflare Access
    if data.get("configured"):
        err = data.get("error", "") or ""
        # Expect an actionable message, NOT the cryptic 'Expecting value' JSON parse
        assert "Expecting value" not in err, f"got cryptic JSON parse error: {err}"
        if err:
            assert ("Cloudflare Access" in err or "service token" in err.lower()
                    or "redirect" in err.lower() or "HTTP" in err), f"unexpected error: {err}"
        print(f"threat-intel response: configured={data['configured']} error={err[:120]}")
    else:
        print("OpenCTI not configured (skipped CF message check)")


# --- Integration config patch ---
def test_integration_config_patch(H):
    r = requests.get(f"{BASE_URL}/api/v1/integrations", headers=H, timeout=15)
    assert r.status_code == 200
    integrations = r.json().get("items", [])
    octi = next((i for i in integrations if "OpenCTI" in i.get("name", "")), None)
    if not octi:
        pytest.skip("OpenCTI integration not present")

    # PATCH a benign key in config
    sentinel = f"TEST_{uuid.uuid4().hex[:6]}"
    r2 = requests.patch(f"{BASE_URL}/api/v1/admin/integrations/{octi['id']}/config", headers=H,
                       json={"config": {"test_marker": sentinel}}, timeout=15)
    assert r2.status_code == 200
    # Verify persisted
    r3 = requests.get(f"{BASE_URL}/api/v1/integrations", headers=H, timeout=10)
    octi2 = next(i for i in r3.json()["items"] if i["id"] == octi["id"])
    assert octi2["config"].get("test_marker") == sentinel
    # cleanup not strictly required (extra benign key)
