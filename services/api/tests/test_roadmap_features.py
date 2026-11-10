"""Organisations, project-type hygiene, release discovery and dashboards."""

from __future__ import annotations

from datetime import datetime

from app.core.config import settings
from app.db.models import (
    Notification,
    Organisation,
    Project,
    ProjectVersion,
)
from app.db.session import SessionLocal

from tests.conftest import auth_client

PASSWORD = "Pass-Pw4-tests!"
CSRF = {"X-CSRF-Token": None}


def _csrf(client):
    return {"X-CSRF-Token": client.cookies.get("ospmae_csrf")}


def test_project_type_vocabulary_is_enforced(client, db):
    c, _user = auth_client(
        username="catalog-hygiene", password=PASSWORD, role="maintainer"
    )
    response = c.post(
        "/v1/projects",
        json={
            "machine_name": "type-ok",
            "display_name": "Type ok",
            "project_type": "Ledger",
            "organisation": "Example Org",
        },
        headers=_csrf(c),
    )
    assert response.status_code == 200, response.text
    # Controlled types normalise to lowercase.
    assert response.json()["project_type"] == "ledger"

    response = c.post(
        "/v1/projects",
        json={
            "machine_name": "type-bad",
            "display_name": "Type bad",
            "project_type": "totally custom thing",
        },
        headers=_csrf(c),
    )
    assert response.status_code == 422
    assert "project_type must be one of" in response.text

    # A free-text organisation the catalogue never saw becomes an entity once
    # and every matching project links to its FK row.
    with SessionLocal() as s:
        org = s.query(Organisation).filter(Organisation.name == "Example Org").one()
        project = s.query(Project).filter(Project.machine_name == "type-ok").one()
        assert project.organisation_id == org.id


def test_organisations_list_and_memberships(client, db):
    c, _user = auth_client(username="org-builder", password=PASSWORD, role="maintainer")
    for machine in ("org-alpha", "org-beta"):
        c.post(
            "/v1/projects",
            json={
                "machine_name": machine,
                "display_name": machine.title(),
                "organisation": "Alpha Group",
            },
            headers=_csrf(c),
        )
    listing = c.get("/v1/organisations").json()
    alpha = next(o for o in listing if o["name"] == "Alpha Group")
    assert alpha["project_count"] == 2

    admin, _ = auth_client(username="org-admin", password=PASSWORD, role="admin")
    created = admin.post(
        "/v1/admin/organisations",
        json={"name": "Named Org"},
        headers=_csrf(admin),
    )
    assert created.status_code == 200, created.text
    org_id = created.json()["id"]

    assert (
        admin.post(
            f"/v1/admin/organisations/{org_id}/members",
            json={"user_id": None, "group_id": None},
            headers=_csrf(admin),
        ).status_code
        == 400
    )
    group = admin.post(
        "/v1/admin/groups",
        json={"name": "Org watchers"},
        headers=_csrf(admin),
    )
    assert group.status_code == 200, group.text
    joined = admin.post(
        f"/v1/admin/organisations/{org_id}/members",
        json={"group_id": group.json()["id"]},
        headers=_csrf(admin),
    )
    assert joined.status_code == 200, joined.text
    detail = admin.get(f"/v1/admin/organisations/{org_id}").json()
    assert detail["members"][0]["kind"] == "group"
    assert detail["members"][0]["name"] == "Org watchers"


def test_initial_release_discovery_imports_all_and_marks_latest(
    client, db, monkeypatch
):
    import app.tasks.release_feed as rf

    entries = [
        {
            "id": "e2",
            "title": "Release v2.1.0",
            "link": "https://github.com/example/repo/releases/v2.1.0",
            "published_dt": datetime(2026, 10, 1),
        },
        {
            "id": "e1",
            "title": "Release v1.0.0",
            "link": "https://github.com/example/repo/releases/v1.0.0",
            "published_dt": datetime(2026, 1, 1),
        },
    ]

    class FakeResp:
        status_code = 200
        headers: dict[str, str] = {}

    monkeypatch.setattr(
        rf, "_safe_fetch_feed", lambda client, url, headers: (FakeResp(), b"x", url)
    )
    monkeypatch.setattr(rf, "_parse_feed_entries", lambda xml: entries)
    launched: list[int] = []
    real_enqueue = rf.discover_project_release_feed

    c, _user = auth_client(username="feed-owner", password=PASSWORD, role="maintainer")
    response = c.post(
        "/v1/projects",
        json={
            "machine_name": "feed-discovered",
            "display_name": "Feed discovered",
            "release_rss_feed_url": "https://example.org/releases.xml",
        },
        headers=_csrf(c),
    )
    assert response.status_code == 200, response.text
    project_id = response.json()["id"]

    # Run the discovery task synchronously with the scan enqueue tracked.
    class _ScanTask:
        @staticmethod
        def delay(version_id):
            launched.append(int(version_id))

    old_discover = None
    try:
        from app.tasks import dependency_discovery

        monkeypatch.setattr(
            dependency_discovery,
            "discover_project_version_dependencies",
            _ScanTask,
        )
        outcome = real_enqueue(project_id)
    finally:
        if old_discover is not None:
            from app.tasks import dependency_discovery as _dd

            _dd.discover_project_version_dependencies = old_discover  # type: ignore[assignment]

    assert outcome["created"] == 2, outcome
    with SessionLocal() as s:
        versions = (
            s.query(ProjectVersion)
            .filter(ProjectVersion.project_id == project_id)
            .all()
        )
        assert len(versions) == 2
        assert all(v.is_draft is False for v in versions)
        latest = [v for v in versions if v.is_latest]
        assert [v.version for v in latest] == ["v2.1.0"]
        assert launched == [latest[0].id]


def test_dashboard_reports_projects_and_dependency_flags(client, db):
    c, _user = auth_client(username="dash-user", password=PASSWORD, role="viewer")
    dash = c.get("/v1/dashboard")
    assert dash.status_code == 200
    body = dash.json()
    assert body["dependency_scans_enabled"] is True
    assert isinstance(body["projects"], list)


def test_dependency_index_returns_public_ids_and_filters(client, db):
    c, _user = auth_client(username="deps-viewer", password=PASSWORD, role="viewer")
    data = c.get("/v1/dependencies", params={"q": "definitely-not-there"}).json()
    assert data["dependencies"] == []


def test_verification_queue_reports_why_it_refused(client, db):
    from app.db.models import UserEmail

    saved = (
        settings.public_base_url,
        settings.smtp_host,
        settings.smtp_from_email,
        settings.mfa_encryption_key,
    )
    settings.mfa_encryption_key = "kw0nbN6bJuWBIBG2F91GoVvw1bLXCT7Fz8i9CSaj-e0="
    settings.public_base_url = ""
    settings.smtp_host = "smtp.example.com"
    settings.smtp_from_email = "noreply@example.com"
    try:
        c, user = auth_client(username="verify-user", password=PASSWORD, role="viewer")
        with SessionLocal() as s:
            s.add(
                UserEmail(
                    user_id=user.id,
                    email="verify-user@example.com",
                    email_lower="verify-user@example.com",
                    source="user",
                    is_primary=True,
                    is_verified=False,
                )
            )
            s.commit()
        me = c.get("/v1/me/emails").json()
        assert me and me["items"] and me["items"][0]["id"]
        csrf = _csrf(c)
        response = c.post(
            f"/v1/me/emails/{me['items'][0]['id']}/verify-request", headers=csrf
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["queued"] is False
        assert "PUBLIC_BASE_URL" in body["reason"]

        # Once configured, the verification e-mail lands in the shared
        # outbox (the worker sends it), observable under /v1/me/notifications.
        settings.public_base_url = "https://testserver"
        response = c.post(
            f"/v1/me/emails/{me['items'][0]['id']}/verify-request", headers=csrf
        )
        assert response.status_code == 200, response.text
        with SessionLocal() as s:
            assert (
                s.query(Notification)
                .filter(Notification.user_id == user.id)
                .filter(Notification.subject.ilike("%Verify%"))
                .count()
                >= 1
            )
    finally:
        (
            settings.public_base_url,
            settings.smtp_host,
            settings.smtp_from_email,
            settings.mfa_encryption_key,
        ) = saved


def test_factor_change_mails_the_account_owner(client, db):
    from app.db.models import User, UserEmail

    def _start_manage():
        return c.post(
            "/v1/auth/mfa/manage/start",
            json={"password": PASSWORD},
            headers={
                "Origin": "https://testserver",
                "X-CSRF-Token": c.cookies.get("ospmae_csrf"),
            },
        )

    def _totp_flow():
        start = c.post(
            "/v1/auth/mfa/totp/start",
            headers={
                "Origin": "https://testserver",
                "X-CSRF-Token": c.cookies.get("ospmae_csrf"),
            },
        )
        assert start.status_code == 200, start.text
        import pyotp

        code = pyotp.TOTP(start.json()["secret"]).now()
        confirm = c.post(
            "/v1/auth/mfa/totp/confirm",
            json={"code": code},
            headers={
                "Origin": "https://testserver",
                "X-CSRF-Token": c.cookies.get("ospmae_csrf"),
            },
        )
        assert confirm.status_code == 200, confirm.text

    c, user = auth_client(username="alert-owner", password=PASSWORD, role="maintainer")

    with SessionLocal() as s0:
        s0.query(User).filter(User.id == user.id).update(
            {"mfa_totp_last_step": -1}, synchronize_session=False
        )
        s0.commit()
    with SessionLocal() as s:
        s.add(
            UserEmail(
                user_id=user.id,
                email="alert-owner@example.com",
                email_lower="alert-owner@example.com",
                source="user",
                is_primary=True,
                is_verified=True,
            )
        )
        s.commit()

    with SessionLocal() as s0:
        s0.query(User).filter(User.id == user.id).update(
            {"mfa_totp_last_step": -1}, synchronize_session=False
        )
        s0.commit()

    saved = (
        settings.smtp_host,
        settings.smtp_from_email,
        settings.public_base_url,
        settings.mfa_encryption_key,
    )
    settings.smtp_host = "smtp.example.com"
    settings.smtp_from_email = "noreply@example.com"
    settings.public_base_url = "https://testserver"
    settings.mfa_encryption_key = "kw0nbN6bJuWBIBG2F91GoVvw1bLXCT7Fz8i9CSaj-e0="
    try:
        c.headers.update({"Origin": "https://testserver"})
        assert _start_manage().status_code == 200
        _totp_flow()
        with SessionLocal() as s:
            rows = s.query(Notification).filter_by(user_id=user.id).all()
            assert any("authenticator was added" in r.subject for r in rows), [
                r.subject for r in rows
            ]
    finally:
        (
            settings.smtp_host,
            settings.smtp_from_email,
            settings.public_base_url,
            settings.mfa_encryption_key,
        ) = saved
