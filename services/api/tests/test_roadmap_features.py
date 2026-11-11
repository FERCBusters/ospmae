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
        def apply_async(args, **_options):
            launched.append(int(args[0]))

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


def test_dependency_index_pagination_ecosystems_and_vuln_filter(client, db):
    from app.db.models import (
        DependencyPackage,
        DependencyVersion,
        DependencyVulnerability,
    )

    with SessionLocal() as s:
        pkg_vuln = DependencyPackage(
            ecosystem="cargo",
            name="vulnerable-crate",
            normalized_name="vulnerable-crate",
        )
        pkg_plain = DependencyPackage(
            ecosystem="npm", name="plain-dep", normalized_name="plain-dep"
        )
        pkg_third = DependencyPackage(
            ecosystem="pypi", name="third-dep", normalized_name="third-dep"
        )
        s.add(pkg_vuln)
        s.add(pkg_plain)
        s.add(pkg_third)
        s.flush()
        version_vulnerable = DependencyVersion(
            dependency_id=pkg_vuln.id, version="1.0.0"
        )
        version_plain = DependencyVersion(dependency_id=pkg_plain.id, version="2.0.0")
        s.add(version_vulnerable)
        s.add(version_plain)
        s.flush()
        s.add(
            DependencyVulnerability(
                dependency_version_id=version_vulnerable.id,
                vulnerability_id="RUSTSEC-2026-0001",
                severity="high",
                title="fixture advisory",
                fixed_version="1.0.1",
            )
        )
        s.commit()

    c, _admin = auth_client(username="deps-admin", password=PASSWORD, role="admin")
    del _admin

    def _read(**params):
        response = c.get("/v1/dependencies", params=params)
        assert response.status_code == 200
        return response.json()

    # Shapes the UI relies on: pager totals plus the ecosystem catalogue.
    empty = _read(q="definitely-not-there")
    assert empty["dependencies"] == []
    assert empty["total"] == 0
    assert isinstance(empty["ecosystems"], list)

    page = _read(limit=1, offset=0)
    assert page["limit"] == 1
    assert page["total"] >= 3
    assert len(page["dependencies"]) == 1
    names = {row["name"] for row in _read(limit=100)["dependencies"]}
    assert {"vulnerable-crate", "plain-dep", "third-dep"} <= names
    assert set(_read()["ecosystems"]) >= {"cargo", "npm", "pypi"}

    # Pagination actually advances: page 2 differs from page 1.
    second = _read(limit=1, offset=1)
    assert [r["id"] for r in second["dependencies"]] != [
        r["id"] for r in page["dependencies"]
    ]

    # Vulnerability filtering lives in SQL across the whole result set.
    vulnerable = _read(vulnerable="true", limit=100)
    assert vulnerable["total"] >= 1
    assert {row["name"] for row in vulnerable["dependencies"]} == {"vulnerable-crate"}

    # Ecosystem filter matches whatever the dropdown would send.
    by_eco = _read(ecosystem="npm", limit=100)
    assert {row["name"] for row in by_eco["dependencies"]} == {"plain-dep"}


def test_dependency_detail_resolves_every_reference_shape(client, db):
    """The browser deep-links by package UUID; legacy links carry numbers.

    Each shape lands on the newest recorded version of the package, and a
    package without versions answers 404 instead of a server error.
    """

    from app.db.models import DependencyPackage, DependencyVersion

    with SessionLocal() as s:
        pkg = DependencyPackage(
            ecosystem="npm", name="detail-dep", normalized_name="detail-dep"
        )
        bare = DependencyPackage(
            ecosystem="npm", name="no-versions", normalized_name="no-versions"
        )
        s.add_all([pkg, bare])
        s.flush()
        older = DependencyVersion(dependency_id=pkg.id, version="1.0.0")
        newer = DependencyVersion(dependency_id=pkg.id, version="2.0.0")
        s.add_all([older, newer])
        s.commit()
        pkg_public_id = str(pkg.public_id)
        bare_public_id = str(bare.public_id)
        pkg_id = int(pkg.id)
        older_id = int(older.id)
        newer_id = int(newer.id)

    c, _admin = auth_client(username="deps-detail", password=PASSWORD, role="admin")

    by_uuid = c.get(f"/v1/dependencies/{pkg_public_id}")
    assert by_uuid.status_code == 200, by_uuid.text
    assert by_uuid.json()["dependency_version"]["dependency_version_id"] == newer_id
    assert by_uuid.json()["dependency_version"]["name"] == "detail-dep"

    # Upper-case UUIDs (hand-typed links) resolve the same way.
    upper = c.get(f"/v1/dependencies/{pkg_public_id.upper()}")
    assert upper.status_code == 200, upper.text
    assert upper.json()["dependency_version"]["dependency_version_id"] == newer_id

    by_version_id = c.get(f"/v1/dependencies/{older_id}")
    assert by_version_id.status_code == 200, by_version_id.text
    assert (
        by_version_id.json()["dependency_version"]["dependency_version_id"] == older_id
    )

    # A number that names no version falls back to the package of that id.
    missing_version_id = max(older_id, newer_id) + 1000
    if missing_version_id != pkg_id:
        assert c.get(f"/v1/dependencies/{missing_version_id}").status_code == 404

    assert c.get(f"/v1/dependencies/{bare_public_id}").status_code == 404
    unknown = "00000000-0000-4000-8000-000000000000"
    assert c.get(f"/v1/dependencies/{unknown}").status_code == 404
    assert c.get("/v1/dependencies/not-a-reference").status_code == 404


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


def test_used_by_counts_distinct_projects_across_versions(client, db):
    """One project with two scanned releases and three advisories on the
    version they use is one project; the detail page's package section adds
    up to the same figure."""

    from app.db.models import (
        DependencyPackage,
        DependencyVersion,
        DependencyVulnerability,
        ProjectVersionDependency,
    )

    with SessionLocal() as s:
        pkg = DependencyPackage(
            ecosystem="npm", name="shared", normalized_name="shared"
        )
        alpha = Project(machine_name="alpha", display_name="Alpha")
        beta = Project(machine_name="beta", display_name="Beta")
        s.add_all([pkg, alpha, beta])
        s.flush()
        old = DependencyVersion(dependency_id=pkg.id, version="1.0.0")
        new = DependencyVersion(dependency_id=pkg.id, version="2.0.0")
        unused = DependencyVersion(dependency_id=pkg.id, version="0.9.0")
        s.add_all([old, new, unused])
        s.flush()
        releases = [
            ProjectVersion(project_id=alpha.id, version="v1"),
            ProjectVersion(project_id=alpha.id, version="v2"),
            ProjectVersion(project_id=beta.id, version="v1"),
        ]
        s.add_all(releases)
        s.flush()
        s.add_all(
            [
                ProjectVersionDependency(
                    project_version_id=releases[0].id, dependency_version_id=old.id
                ),
                ProjectVersionDependency(
                    project_version_id=releases[1].id, dependency_version_id=old.id
                ),
                ProjectVersionDependency(
                    project_version_id=releases[2].id, dependency_version_id=new.id
                ),
            ]
        )
        for n in range(3):
            s.add(
                DependencyVulnerability(
                    dependency_version_id=old.id,
                    scanner="grype",
                    vulnerability_id=f"GHSA-{n}",
                    severity="high",
                )
            )
        # Findings on a version no project uses are not unfixed findings here.
        s.add(
            DependencyVulnerability(
                dependency_version_id=unused.id,
                scanner="grype",
                vulnerability_id="GHSA-unused",
            )
        )
        s.commit()
        pkg_uuid, old_uuid = str(pkg.public_id), str(old.public_id)

    c, _admin = auth_client(username="used-by", password=PASSWORD, role="admin")
    row = next(
        r
        for r in c.get("/v1/dependencies", params={"q": "shared"}).json()[
            "dependencies"
        ]
        if r["name"] == "shared"
    )
    assert row["used_by_count"] == 2
    assert row["version_count"] == 3
    assert row["vulnerability_count"] == 3

    detail = c.get(f"/v1/dependencies/{pkg_uuid}").json()
    assert detail["dependency_version"]["version"] == "2.0.0"
    assert detail["package"]["project_count"] == 2
    versions = {v["version"]: v for v in detail["package"]["versions"]}
    assert {k: v["project_count"] for k, v in versions.items()} == {
        "2.0.0": 1,
        "1.0.0": 1,
        "0.9.0": 0,
    }
    assert versions["2.0.0"]["current"] is True
    assert detail["package"]["versions_truncated"] is False

    # A version's own UUID opens that version, with both of Alpha's releases.
    exact = c.get(f"/v1/dependencies/{old_uuid}").json()
    assert exact["dependency_version"]["version"] == "1.0.0"
    assert [p["project_version"] for p in exact["projects"]] == ["v1", "v2"]
