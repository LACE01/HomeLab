"""Backend tests for Integrations PATCH/Test endpoints and key masking."""
import os
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "https://remediationhub.preview.emergentagent.com").rstrip("/")


def _login(email, password):
    r = requests.post(f"{BASE_URL}/api/auth/login", json={"email": email, "password": password}, timeout=20)
    assert r.status_code == 200, f"Login failed for {email}: {r.status_code} {r.text}"
    body = r.json()
    return body.get("access_token") or body.get("token")


@pytest.fixture(scope="module")
def admin_token():
    return _login("admin@vulnops.io", "admin123")


@pytest.fixture(scope="module")
def analyst_token():
    return _login("analyst@vulnops.io", "analyst123")


@pytest.fixture(scope="module")
def integrations(admin_token):
    r = requests.get(f"{BASE_URL}/api/v1/integrations", headers={"Authorization": f"Bearer {admin_token}"}, timeout=20)
    assert r.status_code == 200, r.text
    items = r.json()["items"]
    assert isinstance(items, list) and len(items) > 0, "Expected at least one integration"
    return items


# ---------------- GET list masking ----------------
class TestListMasking:
    def test_list_returns_items(self, admin_token):
        r = requests.get(f"{BASE_URL}/api/v1/integrations", headers={"Authorization": f"Bearer {admin_token}"}, timeout=20)
        assert r.status_code == 200
        body = r.json()
        assert "items" in body
        assert len(body["items"]) > 0

    def test_no_plaintext_api_secret(self, admin_token, integrations):
        # After configuring secrets, verify they're never returned in plaintext on subsequent GETs
        for i in integrations:
            cfg = i.get("config") or {}
            secret = cfg.get("api_secret")
            if secret:
                assert secret == "•••" or "•••" in secret, f"api_secret leaked: {secret}"


# ---------------- PATCH ----------------
class TestPatchIntegration:
    def test_admin_can_patch(self, admin_token, integrations):
        target = integrations[0]
        payload = {
            "endpoint": "https://qualysapi.qualys.com",
            "api_key": "my_test_key_xyz",
            "auth_type": "api_key",
        }
        r = requests.patch(
            f"{BASE_URL}/api/v1/integrations/{target['id']}",
            json=payload,
            headers={"Authorization": f"Bearer {admin_token}"},
            timeout=20,
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body.get("ok") is True

        # Verify persistence via GET — endpoint stored as-is, api_key masked
        r2 = requests.get(f"{BASE_URL}/api/v1/integrations", headers={"Authorization": f"Bearer {admin_token}"}, timeout=20)
        item = next(x for x in r2.json()["items"] if x["id"] == target["id"])
        assert item["config"]["endpoint"] == "https://qualysapi.qualys.com"
        masked = item["config"]["api_key"]
        assert "•••" in masked, f"api_key not masked in GET: {masked}"
        assert "my_test_key_xyz" not in masked
        # Expected like 'my_t•••_xyz'
        assert masked.startswith("my_t") and masked.endswith("_xyz")

    def test_analyst_forbidden(self, analyst_token, integrations):
        target = integrations[0]
        r = requests.patch(
            f"{BASE_URL}/api/v1/integrations/{target['id']}",
            json={"endpoint": "https://evil.example.com"},
            headers={"Authorization": f"Bearer {analyst_token}"},
            timeout=20,
        )
        assert r.status_code == 403, f"Expected 403 for non-admin, got {r.status_code}: {r.text}"


# ---------------- Test endpoint ----------------
class TestTestEndpoint:
    def test_test_returns_400_without_config(self, admin_token, integrations):
        # Use the LAST integration (one not patched in TestPatchIntegration)
        target = integrations[-1]
        # First clear its config to ensure unconfigured state
        requests.patch(
            f"{BASE_URL}/api/v1/integrations/{target['id']}",
            json={"endpoint": "", "api_key": ""},
            headers={"Authorization": f"Bearer {admin_token}"},
            timeout=20,
        )
        # Empty strings get filtered (exclude_none, but empty strings pass through)
        # Force unset via direct PATCH with explicit "" — server treats "" as falsy in cfg.get checks
        r = requests.post(
            f"{BASE_URL}/api/v1/integrations/{target['id']}/test",
            headers={"Authorization": f"Bearer {admin_token}"},
            timeout=20,
        )
        assert r.status_code == 400, f"Expected 400, got {r.status_code}: {r.text}"
        assert "Missing" in (r.json().get("detail") or "")

    def test_test_returns_200_after_configure(self, admin_token, integrations):
        target = integrations[0]
        # Ensure configured
        requests.patch(
            f"{BASE_URL}/api/v1/integrations/{target['id']}",
            json={"endpoint": "https://qualysapi.qualys.com", "api_key": "my_test_key_xyz"},
            headers={"Authorization": f"Bearer {admin_token}"},
            timeout=20,
        )
        r = requests.post(
            f"{BASE_URL}/api/v1/integrations/{target['id']}/test",
            headers={"Authorization": f"Bearer {admin_token}"},
            timeout=20,
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body.get("ok") is True
        assert "verified" in (body.get("message") or "").lower()
        assert target["name"] in body["message"]

        # Verify status flipped to healthy
        r2 = requests.get(f"{BASE_URL}/api/v1/integrations", headers={"Authorization": f"Bearer {admin_token}"}, timeout=20)
        item = next(x for x in r2.json()["items"] if x["id"] == target["id"])
        assert item["status"] == "healthy"

    def test_test_analyst_forbidden(self, analyst_token, integrations):
        target = integrations[0]
        r = requests.post(
            f"{BASE_URL}/api/v1/integrations/{target['id']}/test",
            headers={"Authorization": f"Bearer {analyst_token}"},
            timeout=20,
        )
        assert r.status_code == 403
