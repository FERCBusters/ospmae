"""Password changes and administrator resets, as KEEN's.

A changed or reset password ends every local session of the account and
every browser's recognition; a reset also clears the account's sign-in
throttle. Each mails the account a security notice. There is no
self-service reset by e-mail: an administrator resets passwords.
"""

from __future__ import annotations

import pytest
from app.core.config import settings
from app.db.models import LoginDevice, LoginThrottle, User
from app.db.session import SessionLocal
from app.security import sign_in_throttle as throttle

from tests.conftest import auth_client, login, make_user

PASSWORD = "Test-passphrase-1!"


@pytest.fixture(autouse=True)
def _local_accounts(monkeypatch):
    monkeypatch.setattr(settings, "local_auth_enabled", True)
    monkeypatch.setattr(settings, "smtp_from_name", "OSPMAE")


def _csrf(client) -> dict[str, str]:
    return {"X-CSRF-Token": client.cookies.get("__Host-ospmae_csrf") or ""}


def _change(client, current: str, new: str = "New-passphrase-two-2!"):
    return client.post(
        "/v1/auth/change-password",
        json={
            "current_password": current,
            "new_password": new,
            "confirm_password": new,
        },
        headers=_csrf(client),
    )


def _devices(user_id: int) -> int:
    with SessionLocal() as s:
        return s.query(LoginDevice).filter_by(user_id=user_id).count()


def test_a_new_password_signs_every_browser_out(client, outbox):
    user = make_user("ChgU", PASSWORD, role="viewer", email="chgu@x.test")
    assert login(client, "ChgU", PASSWORD).status_code == 200
    other, _ = auth_client("ChgU-other", PASSWORD, role="viewer")
    assert _devices(user.id) == 1

    response = _change(client, PASSWORD)
    assert response.status_code == 204
    # As in KEEN, this browser's session ends too, and recognition with it.
    assert client.get("/v1/me").status_code == 401
    assert _devices(user.id) == 0
    assert other.get("/v1/me").status_code == 200

    client.headers["X-Forwarded-For"] = "5.5.5.5"
    assert login(client, "ChgU", PASSWORD, peer="5.5.5.5").status_code == 401
    assert (
        login(client, "ChgU", "New-passphrase-two-2!", peer="5.5.5.5").status_code
        == 200
    )

    [notice] = [m for m in outbox.messages() if "password was changed" in m.subject]
    assert notice.recipient == "chgu@x.test"
    assert notice.subject == "OSPMAE security: Your OSPMAE password was changed"


def test_a_wrong_current_password_changes_nothing(client, outbox):
    make_user("ChgW", PASSWORD, role="viewer", email="chgw@x.test")
    login(client, "ChgW", PASSWORD)
    response = _change(client, "not-the-password")
    assert response.status_code == 400
    assert client.get("/v1/me").status_code == 200
    assert [m for m in outbox.messages() if "password" in m.subject] == []


def test_password_checks_are_limited_per_account(client):
    make_user("ChgV", PASSWORD, role="viewer")
    login(client, "ChgV", PASSWORD)
    statuses = [_change(client, f"wrong-{i}-x!").status_code for i in range(16)]
    assert statuses[:15] == [400] * 15
    assert statuses[15] == 429


def test_password_checks_are_limited_per_address(client, monkeypatch):
    """Sessions of several accounts at one address share the address's
    allowance, as KEEN's sign-in allowance is shared."""
    monkeypatch.setattr(throttle, "ADDRESS_ATTEMPTS", 2)
    first, _ = auth_client("addr-a", PASSWORD, role="viewer")
    second, _ = auth_client("addr-b", PASSWORD, role="viewer")
    assert _change(first, "wrong-1-x!").status_code == 400
    assert _change(second, "wrong-2-x!").status_code == 400
    refused = _change(second, "wrong-3-x!")
    assert refused.status_code == 429
    assert refused.json()["detail"] == (
        "Too many password change attempts. Please try again later."
    )


def test_trusted_header_installations_refuse_password_changes(client, monkeypatch):
    make_user("ChgR", PASSWORD, role="viewer")
    login(client, "ChgR", PASSWORD)
    monkeypatch.setattr(settings, "trust_remote_user", True)
    response = _change(client, PASSWORD)
    assert response.status_code == 403
    assert "OSPMAE_TRUST_REMOTE_USER" in response.json()["detail"]


def test_there_is_no_self_service_reset(client):
    for path in ("/v1/auth/request-password-reset", "/v1/auth/reset-password"):
        assert client.post(path, json={}).status_code in (404, 405)
    methods = client.get("/v1/auth/methods").json()
    assert "password_reset_enabled" not in methods


def test_an_administrator_resets_a_password(client, outbox):
    admin, _ = auth_client("reset-admin", PASSWORD, role="admin")
    user = make_user("forgetful", PASSWORD, role="viewer", email="f@x.test")
    assert login(client, "forgetful", PASSWORD).status_code == 200
    with SessionLocal() as s:
        s.add(LoginThrottle(name_key=throttle.name_key("forgetful"), failures=40))
        s.commit()

    response = admin.post(
        f"/v1/admin/users/{user.id}/password",
        json={"new_password": "Fresh-passphrase-9!"},
        headers=_csrf(admin),
    )
    assert response.json() == {"ok": True}
    assert client.get("/v1/me").status_code == 401
    assert _devices(user.id) == 0
    with SessionLocal() as s:
        assert s.query(LoginThrottle).count() == 0
    assert login(client, "forgetful", "Fresh-passphrase-9!").status_code == 200

    [notice] = [m for m in outbox.messages() if "administrator" in m.subject]
    assert notice.recipient == "f@x.test"
    assert notice.subject == (
        "OSPMAE security: Your OSPMAE password was reset by an administrator"
    )


def test_only_administrators_reset_passwords(client):
    viewer, _ = auth_client("not-admin", PASSWORD, role="viewer")
    user = make_user("target", PASSWORD, role="viewer")
    response = viewer.post(
        f"/v1/admin/users/{user.id}/password",
        json={"new_password": "Fresh-passphrase-9!"},
        headers=_csrf(viewer),
    )
    assert response.status_code == 403
    admin, _ = auth_client("reset-admin-2", PASSWORD, role="admin")
    missing = admin.post(
        "/v1/admin/users/999999/password",
        json={"new_password": "Fresh-passphrase-9!"},
        headers=_csrf(admin),
    )
    assert missing.status_code == 404


def test_deactivation_ends_sessions_for_good(client):
    admin, admin_user = auth_client("deact-admin", PASSWORD, role="admin")
    user, account = auth_client("deactivated", PASSWORD, role="viewer")
    assert user.get("/v1/me").status_code == 200

    for active in (False, True):
        response = admin.patch(
            f"/v1/admin/users/{account.id}",
            json={"is_active": active},
            headers=_csrf(admin),
        )
        assert response.status_code == 200, response.text
    # Reactivation does not bring the old session back.
    assert user.get("/v1/me").status_code == 401

    own = admin.patch(
        f"/v1/admin/users/{admin_user.id}",
        json={"is_active": False},
        headers=_csrf(admin),
    )
    assert own.status_code == 400
    assert own.json()["detail"] == "You cannot deactivate your own account"


def test_an_administrator_sets_one_mailbox_as_the_account_email(client):
    admin, _ = auth_client("email-admin", PASSWORD, role="admin")
    user = make_user("addressed", PASSWORD, role="viewer")
    make_user("holder", PASSWORD, role="viewer", email="taken@x.test")

    def set_email(value):
        return admin.patch(
            f"/v1/admin/users/{user.id}", json={"email": value}, headers=_csrf(admin)
        )

    for bad in ("a@x.test, b@x.test", "Name <a@x.test>"):
        assert set_email(bad).status_code == 400, bad
    assert set_email("TAKEN@x.test").json()["detail"] == "Email already in use"
    assert set_email("Mine@X.test").json()["email"] == "mine@x.test"
    assert set_email("").json()["email"] is None
    with SessionLocal() as s:
        assert s.get(User, user.id).email is None


def test_there_is_no_pending_role(client):
    admin, _ = auth_client("role-admin", PASSWORD, role="admin")
    created = admin.post(
        "/v1/admin/users",
        json={"username": "waiting", "password": PASSWORD, "role": "pending"},
        headers=_csrf(admin),
    )
    assert created.status_code == 400
    user = make_user("someone", PASSWORD, role="viewer")
    changed = admin.patch(
        f"/v1/admin/users/{user.id}", json={"role": "pending"}, headers=_csrf(admin)
    )
    assert changed.status_code == 400
