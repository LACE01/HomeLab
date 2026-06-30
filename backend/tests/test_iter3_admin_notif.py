"""Iteration 3a backend tests — single super admin, user CRUD, notification engine."""
import os
import uuid
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL") or os.environ.get(
    "FRONTEND_BACKEND_URL"
)
if not BASE_URL:
    # fallback to /app/frontend/.env
    with open("/app/frontend/.env") as fh:
        for line in fh:
            if line.startswith("REACT_APP_BACKEND_URL="):
                BASE_URL = line.split("=", 1)[1].strip()
                break
BASE_URL = BASE_URL.rstrip("/")

ADMIN_EMAIL = "luisarce731@outlook.com"
ADMIN_PASS = "vz7NOHcP64WRBEOg3C2I"


@pytest.fixture(scope="module")
def admin_token():
    r = requests.post(
        f"{BASE_URL}/api/auth/login",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASS},
        timeout=15,
    )
    assert r.status_code == 200, f"super admin login failed: {r.status_code} {r.text}"
    data = r.json()
    assert "token" in data
    assert data["user"]["role"] == "admin"
    return data["token"]


@pytest.fixture(scope="module")
def admin_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}", "Content-Type": "application/json"}


# ---------- Demo accounts removed ----------
class TestDemoAccountsRemoved:
    def test_demo_admin_login_fails(self):
        r = requests.post(
            f"{BASE_URL}/api/auth/login",
            json={"email": "admin@vulnops.io", "password": "admin123"},
            timeout=15,
        )
        assert r.status_code == 401

    def test_only_super_admin_seeded(self, admin_headers):
        r = requests.get(f"{BASE_URL}/api/v1/admin/users", headers=admin_headers, timeout=15)
        assert r.status_code == 200
        items = r.json()["items"]
        emails = {u["email"] for u in items}
        # Super admin must be present
        assert ADMIN_EMAIL in emails
        # None of the legacy demo accounts should remain
        for legacy in [
            "admin@vulnops.io",
            "analyst@vulnops.io",
            "manager@vulnops.io",
            "exec@vulnops.io",
        ]:
            assert legacy not in emails, f"Legacy demo account {legacy} still present"


# ---------- User CRUD ----------
class TestUserCRUD:
    created_id = None
    created_email = f"test_user_{uuid.uuid4().hex[:8]}@example.com"

    def test_create_user(self, admin_headers):
        body = {
            "email": self.__class__.created_email,
            "name": "TEST User",
            "role": "analyst",
            "team": "Platform Eng",
            "department": "Engineering",
            "password": "initial_pw_123",
        }
        r = requests.post(
            f"{BASE_URL}/api/v1/admin/users", json=body, headers=admin_headers, timeout=15
        )
        assert r.status_code == 200, r.text
        data = r.json()
        assert "id" in data
        assert data["email"] == self.__class__.created_email
        self.__class__.created_id = data["id"]

    def test_duplicate_email_409(self, admin_headers):
        r = requests.post(
            f"{BASE_URL}/api/v1/admin/users",
            json={"email": self.__class__.created_email, "name": "dup", "role": "analyst"},
            headers=admin_headers,
            timeout=15,
        )
        assert r.status_code == 409

    def test_invalid_role_400(self, admin_headers):
        r = requests.post(
            f"{BASE_URL}/api/v1/admin/users",
            json={
                "email": f"TEST_role_{uuid.uuid4().hex[:6]}@example.com",
                "name": "Bad Role",
                "role": "superhero",
            },
            headers=admin_headers,
            timeout=15,
        )
        assert r.status_code == 400

    def test_update_user_fields_and_password(self, admin_headers):
        uid = self.__class__.created_id
        assert uid
        new_pw = "rotated_pw_456"
        r = requests.patch(
            f"{BASE_URL}/api/v1/admin/users/{uid}",
            json={"name": "TEST Renamed", "team": "Backend", "role": "manager", "password": new_pw},
            headers=admin_headers,
            timeout=15,
        )
        assert r.status_code == 200
        # Verify by listing
        r2 = requests.get(f"{BASE_URL}/api/v1/admin/users", headers=admin_headers, timeout=15)
        match = next((u for u in r2.json()["items"] if u["id"] == uid), None)
        assert match is not None
        assert match["name"] == "TEST Renamed"
        assert match["team"] == "Backend"
        assert match["role"] == "manager"
        # Login with new password
        r3 = requests.post(
            f"{BASE_URL}/api/auth/login",
            json={"email": self.__class__.created_email, "password": new_pw},
            timeout=15,
        )
        assert r3.status_code == 200, f"new password login failed: {r3.status_code} {r3.text}"

    def test_cannot_delete_self(self, admin_headers, admin_token):
        # Find self id
        r = requests.get(f"{BASE_URL}/api/v1/admin/users", headers=admin_headers, timeout=15)
        me = next(u for u in r.json()["items"] if u["email"] == ADMIN_EMAIL)
        r2 = requests.delete(
            f"{BASE_URL}/api/v1/admin/users/{me['id']}", headers=admin_headers, timeout=15
        )
        assert r2.status_code == 400

    def test_delete_user(self, admin_headers):
        uid = self.__class__.created_id
        assert uid
        r = requests.delete(
            f"{BASE_URL}/api/v1/admin/users/{uid}", headers=admin_headers, timeout=15
        )
        assert r.status_code == 200
        # Verify removed
        r2 = requests.get(f"{BASE_URL}/api/v1/admin/users", headers=admin_headers, timeout=15)
        emails = {u["email"] for u in r2.json()["items"]}
        assert self.__class__.created_email not in emails


# ---------- Notification channels & rules ----------
class TestNotifications:
    def test_meta(self, admin_headers):
        r = requests.get(
            f"{BASE_URL}/api/v1/admin/notification-meta", headers=admin_headers, timeout=15
        )
        assert r.status_code == 200
        data = r.json()
        for k in ["triggers", "channels", "templates"]:
            assert isinstance(data.get(k), list) and len(data[k]) > 0

    def test_seeded_discord_channel_masked(self, admin_headers):
        r = requests.get(
            f"{BASE_URL}/api/v1/admin/notification-channels",
            headers=admin_headers,
            timeout=15,
        )
        assert r.status_code == 200
        items = r.json()["items"]
        discord = next((c for c in items if c["type"] == "discord"), None)
        assert discord is not None, "Discord channel was not seeded"
        # raw webhook_url MUST NOT leak
        assert "webhook_url" not in discord, "Raw webhook_url leaked"
        assert "webhook_url_masked" in discord and "•••" in discord["webhook_url_masked"]

    def test_create_channel_validation(self, admin_headers):
        # invalid type
        r = requests.post(
            f"{BASE_URL}/api/v1/admin/notification-channels",
            json={"name": "x", "type": "carrier-pigeon"},
            headers=admin_headers,
            timeout=15,
        )
        assert r.status_code == 400
        # email without `to`
        r2 = requests.post(
            f"{BASE_URL}/api/v1/admin/notification-channels",
            json={"name": "x", "type": "email"},
            headers=admin_headers,
            timeout=15,
        )
        assert r2.status_code == 400
        # discord without webhook_url
        r3 = requests.post(
            f"{BASE_URL}/api/v1/admin/notification-channels",
            json={"name": "x", "type": "discord"},
            headers=admin_headers,
            timeout=15,
        )
        assert r3.status_code == 400

    def test_create_email_channel_ok(self, admin_headers):
        r = requests.post(
            f"{BASE_URL}/api/v1/admin/notification-channels",
            json={"name": "TEST_email", "type": "email", "to": "test@example.com"},
            headers=admin_headers,
            timeout=15,
        )
        assert r.status_code == 200
        ch_id = r.json()["id"]
        # cleanup
        requests.delete(
            f"{BASE_URL}/api/v1/admin/notification-channels/{ch_id}",
            headers=admin_headers,
            timeout=15,
        )

    def test_discord_test_send_live(self, admin_headers):
        """LIVE DELIVERY — posts ONE message into the user's real Discord channel."""
        r = requests.get(
            f"{BASE_URL}/api/v1/admin/notification-channels",
            headers=admin_headers,
            timeout=15,
        )
        discord = next(c for c in r.json()["items"] if c["type"] == "discord")
        r2 = requests.post(
            f"{BASE_URL}/api/v1/admin/notification-channels/{discord['id']}/test",
            headers=admin_headers,
            timeout=30,
        )
        assert r2.status_code == 200, r2.text
        data = r2.json()
        assert data["delivered"] is True
        assert data["status_code"] == 204

    def test_outbox_contains_test_message(self, admin_headers):
        r = requests.get(
            f"{BASE_URL}/api/v1/admin/notifications-outbox",
            headers=admin_headers,
            timeout=15,
        )
        assert r.status_code == 200
        items = r.json()["items"]
        assert len(items) >= 1
        last = items[0]
        assert last["delivered"] is True
        assert "subject" in last and "body" in last

    def test_rule_create_invalid_trigger_400(self, admin_headers):
        r = requests.post(
            f"{BASE_URL}/api/v1/admin/notification-rules",
            json={"name": "bad", "trigger": "nope", "channel_ids": []},
            headers=admin_headers,
            timeout=15,
        )
        assert r.status_code == 400

    def test_rule_crud(self, admin_headers):
        # need a channel id
        chs = requests.get(
            f"{BASE_URL}/api/v1/admin/notification-channels",
            headers=admin_headers,
            timeout=15,
        ).json()["items"]
        ch_id = chs[0]["id"]
        r = requests.post(
            f"{BASE_URL}/api/v1/admin/notification-rules",
            json={
                "name": "TEST_rule",
                "trigger": "finding_created_critical",
                "channel_ids": [ch_id],
                "severity_in": ["Critical"],
                "template_id": "new_assignment",
                "frequency": "immediate",
            },
            headers=admin_headers,
            timeout=15,
        )
        assert r.status_code == 200
        rid = r.json()["id"]
        # list
        ls = requests.get(
            f"{BASE_URL}/api/v1/admin/notification-rules", headers=admin_headers, timeout=15
        )
        assert any(x["id"] == rid for x in ls.json()["items"])
        # delete
        d = requests.delete(
            f"{BASE_URL}/api/v1/admin/notification-rules/{rid}",
            headers=admin_headers,
            timeout=15,
        )
        assert d.status_code == 200


# ---------- RBAC ----------
class TestRBAC:
    def test_non_admin_blocked(self, admin_headers):
        # create temp analyst
        email = f"TEST_rbac_{uuid.uuid4().hex[:6]}@example.com"
        pw = "analyst_pw_999"
        c = requests.post(
            f"{BASE_URL}/api/v1/admin/users",
            json={"email": email, "name": "rbac", "role": "analyst", "password": pw},
            headers=admin_headers,
            timeout=15,
        )
        assert c.status_code == 200
        uid = c.json()["id"]
        try:
            tok = requests.post(
                f"{BASE_URL}/api/auth/login",
                json={"email": email, "password": pw},
                timeout=15,
            ).json()["token"]
            h = {"Authorization": f"Bearer {tok}"}
            # admin-only endpoints must return 403
            for method, path, body in [
                ("post", "/api/v1/admin/users", {"email": "x@x.com", "name": "x"}),
                ("post", "/api/v1/admin/notification-channels",
                 {"name": "x", "type": "discord", "webhook_url": "https://x"}),
                ("post", "/api/v1/admin/notification-rules",
                 {"name": "x", "trigger": "finding_created_critical", "channel_ids": []}),
            ]:
                fn = getattr(requests, method)
                r = fn(f"{BASE_URL}{path}", json=body, headers=h, timeout=15)
                assert r.status_code == 403, f"{path} expected 403 got {r.status_code}"
        finally:
            requests.delete(
                f"{BASE_URL}/api/v1/admin/users/{uid}",
                headers=admin_headers,
                timeout=15,
            )
