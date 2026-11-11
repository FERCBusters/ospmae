"""The project's Latest version is scanned however it reaches the marker, and
a project may publish the releases its feed announces as they arrive."""

from __future__ import annotations

from datetime import datetime

import pytest
from app.core.config import settings
from app.db.models import EntityChangelog, Project, ProjectVersion, User
from app.db.session import SessionLocal
from app.services import scan_queue

from tests.conftest import auth_client

SOURCE = "https://github.com/example/repo"


def _csrf(client):
    return {"X-CSRF-Token": client.cookies.get("ospmae_csrf")}


class _ScanTask:
    launched: list[int] = []

    @classmethod
    def apply_async(cls, args, **_options):
        cls.launched.append(int(args[0]))


class _FeedTask:
    @staticmethod
    def apply_async(*_args, **_options):
        return None


@pytest.fixture()
def scan_launches(monkeypatch):
    import app.tasks.release_feed as rf
    from app.tasks import dependency_discovery

    _ScanTask.launched = []
    monkeypatch.setattr(
        dependency_discovery, "discover_project_version_dependencies", _ScanTask
    )
    # Attaching a feed starts the whole-feed import; these tests drive the poll.
    monkeypatch.setattr(rf, "discover_project_release_feed", _FeedTask)
    return _ScanTask.launched


def _project(client, **extra) -> int:
    body = {"machine_name": "scanned", "display_name": "Scanned"}
    body.update(extra)
    response = client.post("/v1/projects", json=body, headers=_csrf(client))
    assert response.status_code == 200, response.text
    return response.json()["id"]


def _staged(project_id: int, label: str, *, draft: bool = True) -> int:
    """A version as the release feed stages it: a source link, never scanned."""
    with SessionLocal() as s:
        version = ProjectVersion(
            project_id=project_id,
            version=label,
            link_to_source_code=SOURCE,
            is_draft=draft,
            is_latest=False,
        )
        s.add(version)
        s.commit()
        return version.id


def _status(version_id: int) -> str:
    with SessionLocal() as s:
        return s.get(ProjectVersion, version_id).dependency_discovery_status


def _set_status(version_id: int, status: str) -> None:
    with SessionLocal() as s:
        s.get(ProjectVersion, version_id).dependency_discovery_status = status
        s.commit()


# ---------------------------------------------------------------------------
# Reaching Latest scans the version.
# ---------------------------------------------------------------------------


def test_publishing_a_feed_draft_as_latest_scans_it(client, db, scan_launches):
    c, _user = auth_client(role="maintainer")
    project_id = _project(c)
    draft_id = _staged(project_id, "1.0.0")

    response = c.put(
        f"/v1/project-versions/{draft_id}",
        json={"is_draft": False, "is_latest": True},
        headers=_csrf(c),
    )
    assert response.status_code == 200, response.text
    assert response.json()["is_latest"] is True
    assert response.json()["dependency_discovery_status"] == "queued"
    assert scan_launches == [draft_id]


def test_a_published_draft_that_becomes_latest_by_version_order_is_scanned(
    client, db, scan_launches
):
    c, _user = auth_client(role="maintainer")
    project_id = _project(c)
    draft_id = _staged(project_id, "1.0.0")

    # No Latest switch: the first published version takes the marker itself.
    response = c.put(
        f"/v1/project-versions/{draft_id}", json={"is_draft": False}, headers=_csrf(c)
    )
    assert response.status_code == 200, response.text
    assert response.json()["is_latest"] is True
    assert scan_launches == [draft_id]


def test_marking_a_published_version_latest_scans_it_once(client, db, scan_launches):
    c, _user = auth_client(role="maintainer")
    project_id = _project(c)
    current = _staged(project_id, "2.0.0", draft=False)
    older = _staged(project_id, "1.0.0", draft=False)
    with SessionLocal() as s:
        row = s.get(ProjectVersion, current)
        row.is_latest = True
        row.dependency_discovery_status = "complete"
        s.commit()

    response = c.put(
        f"/v1/project-versions/{older}", json={"is_latest": True}, headers=_csrf(c)
    )
    assert response.status_code == 200, response.text
    assert scan_launches == [older]

    # A scan in flight or finished is left alone by later edits.
    for status in ("queued", "running", "complete", "error"):
        _set_status(older, status)
        response = c.put(
            f"/v1/project-versions/{older}",
            json={"notes": f"edited while {status}"},
            headers=_csrf(c),
        )
        assert response.status_code == 200, response.text
        assert _status(older) == status
    assert scan_launches == [older]


def test_a_draft_or_an_older_published_version_is_not_scanned(
    client, db, scan_launches
):
    c, _user = auth_client(role="maintainer")
    project_id = _project(c)
    current = _staged(project_id, "2.0.0", draft=False)
    with SessionLocal() as s:
        row = s.get(ProjectVersion, current)
        row.is_latest = True
        row.dependency_discovery_status = "complete"
        s.commit()
    older = _staged(project_id, "1.0.0")

    # Editing the draft, then publishing it below the current Latest.
    for body in ({"notes": "still a draft"}, {"is_draft": False}):
        response = c.put(f"/v1/project-versions/{older}", json=body, headers=_csrf(c))
        assert response.status_code == 200, response.text
    assert response.json()["is_latest"] is False
    assert _status(older) == "not_run"
    assert scan_launches == []


def test_a_latest_version_without_a_source_link_is_not_queued(
    client, db, scan_launches
):
    c, _user = auth_client(role="maintainer")
    project_id = _project(c)
    response = c.post(
        f"/v1/projects/{project_id}/versions",
        json={"version": "1.0.0"},
        headers=_csrf(c),
    )
    assert response.status_code == 200, response.text
    assert response.json()["is_latest"] is True
    assert response.json()["dependency_discovery_status"] == "not_run"
    assert scan_launches == []


def test_deleting_the_latest_version_scans_the_one_that_takes_over(
    client, db, scan_launches
):
    c, _user = auth_client(role="maintainer")
    project_id = _project(c)
    older = _staged(project_id, "1.0.0", draft=False)
    current = _staged(project_id, "2.0.0", draft=False)
    with SessionLocal() as s:
        row = s.get(ProjectVersion, current)
        row.is_latest = True
        row.dependency_discovery_status = "complete"
        s.commit()

    response = c.delete(f"/v1/project-versions/{current}", headers=_csrf(c))
    assert response.status_code == 204, response.text
    with SessionLocal() as s:
        assert s.get(ProjectVersion, older).is_latest is True
    assert _status(older) == "queued"
    assert scan_launches == [older]


def test_creating_a_version_with_a_source_scans_it_once(client, db, scan_launches):
    c, _user = auth_client(role="maintainer")
    project_id = _project(c)
    response = c.post(
        f"/v1/projects/{project_id}/versions",
        json={"version": "1.0.0", "link_to_source_code": SOURCE},
        headers=_csrf(c),
    )
    assert response.status_code == 200, response.text
    assert scan_launches == [response.json()["id"]]


@pytest.mark.parametrize(
    "switch_off",
    ["feature", "dependency_discovery_enabled", "dependency_discovery_auto_enqueue"],
)
def test_no_scan_is_queued_while_automatic_scans_are_off(
    client, db, scan_launches, monkeypatch, switch_off
):
    c, _user = auth_client(role="maintainer")
    project_id = _project(c)
    draft_id = _staged(project_id, "1.0.0")
    if switch_off == "feature":
        monkeypatch.setattr(settings, "feature_dependency_scans", False)
    else:
        monkeypatch.setattr(settings, switch_off, False)

    response = c.put(
        f"/v1/project-versions/{draft_id}",
        json={"is_draft": False, "is_latest": True},
        headers=_csrf(c),
    )
    assert response.status_code == 200, response.text
    # Never left queued with nothing to run it.
    assert _status(draft_id) == "not_run"
    assert scan_launches == []


def test_every_route_that_moves_the_latest_marker_queues_its_scan():
    """One helper decides the scan; a route settling Latest by hand skips it.

    The defect this guards: publishing a draft moved the marker and queued
    nothing, because only a changed source link queued a scan.
    """

    import inspect

    from app.api.routes import projects
    from app.tasks import release_feed

    for handler in (
        projects.create_project_version,
        projects.update_project_version,
        projects.delete_project_version,
    ):
        assert "_scans_to_launch(" in inspect.getsource(handler), handler.__name__
    assert "queue_latest_version_scan(" in inspect.getsource(projects._scans_to_launch)
    assert "queue_latest_version_scan(" in inspect.getsource(
        release_feed.poll_release_feeds
    )
    # The check detects the original shape: a handler without the helper.
    assert "_scans_to_launch(" not in inspect.getsource(projects.update_project)


def test_queue_latest_version_scan_reports_only_what_it_queued(db):
    with SessionLocal() as s:
        project = Project(machine_name="unit", display_name="Unit")
        s.add(project)
        s.commit()
        project_id = project.id
    assert scan_queue.queue_latest_version_scan(db, project_id) is None
    version_id = _staged(project_id, "1.0.0", draft=False)
    assert scan_queue.queue_latest_version_scan(db, project_id) is None
    with SessionLocal() as s:
        s.get(ProjectVersion, version_id).is_latest = True
        s.commit()
    assert scan_queue.queue_latest_version_scan(db, project_id) == version_id
    db.commit()
    assert _status(version_id) == "queued"
    assert scan_queue.queue_latest_version_scan(db, project_id) is None


# ---------------------------------------------------------------------------
# Publishing new releases automatically.
# ---------------------------------------------------------------------------


def _entry(label: str, day: int) -> dict:
    return {
        "id": f"entry-{label}",
        "title": f"Release {label}",
        "link": f"{SOURCE}/releases/tag/{label}",
        "published_dt": datetime(2026, 11, day),
    }


@pytest.fixture()
def feed(monkeypatch):
    """The release feed's entries, oldest first, as the poll reads them."""
    import app.tasks.release_feed as rf

    entries: list[dict] = []

    class _Response:
        status_code = 200
        headers: dict[str, str] = {}

    monkeypatch.setattr(
        rf, "_safe_fetch_feed", lambda client, url, headers: (_Response(), b"x", url)
    )
    monkeypatch.setattr(rf, "_parse_feed_entries", lambda xml: list(entries))
    return entries


def _feed_project(client, **extra) -> int:
    return _project(
        client, release_rss_feed_url="https://example.org/releases.atom", **extra
    )


def _versions(project_id: int) -> dict[str, tuple[bool, bool, str]]:
    with SessionLocal() as s:
        return {
            v.version: (v.is_draft, v.is_latest, v.dependency_discovery_status)
            for v in s.query(ProjectVersion).filter_by(project_id=project_id)
        }


def _poll() -> dict:
    from app.tasks.release_feed import poll_release_feeds

    return poll_release_feeds.run()


def test_new_releases_stay_drafts_by_default(client, db, scan_launches, feed):
    c, _user = auth_client(role="maintainer")
    project_id = _feed_project(c)
    assert c.get(f"/v1/projects/{project_id}").json()["release_auto_publish"] is False
    feed.append(_entry("v1.0.0", 1))

    assert _poll()["created"] == 1
    assert _versions(project_id) == {"v1.0.0": (True, False, "not_run")}
    assert scan_launches == []


def test_auto_publish_makes_the_new_release_latest_and_scans_it(
    client, db, scan_launches, feed, outbox
):
    c, _user = auth_client(role="maintainer")
    project_id = _feed_project(c, release_auto_publish=True)
    subscriber, sub_user = auth_client(role="viewer")
    with SessionLocal() as s:
        s.get(User, sub_user.id).email = "sub@x.test"
        s.commit()
    response = subscriber.post(
        f"/v1/projects/{project_id}/subscription",
        json={"notify_new_versions": True, "notify_questions": False},
        headers=_csrf(subscriber),
    )
    assert response.status_code == 200, response.text

    feed.append(_entry("v1.0.0", 1))
    assert _poll()["created"] == 1
    assert _versions(project_id) == {"v1.0.0": (False, True, "queued")}
    with SessionLocal() as s:
        first = s.query(ProjectVersion).filter_by(version="v1.0.0").one().id
    assert scan_launches == [first]
    # Subscribers hear of the release; no draft notice goes to the owners.
    subjects = [(m.recipient, m.subject) for m in outbox.messages()]
    assert len(subjects) == 1
    assert subjects[0][0] == "sub@x.test"
    assert "New release for Scanned (v1.0.0)" in subjects[0][1]

    # Two releases in one poll: both publish, the greater takes the marker.
    _set_status(first, "complete")
    feed.extend([_entry("v1.1.0", 2), _entry("v1.2.0", 3)])
    assert _poll()["created"] == 2
    assert _versions(project_id) == {
        "v1.0.0": (False, False, "complete"),
        "v1.1.0": (False, False, "not_run"),
        "v1.2.0": (False, True, "queued"),
    }
    assert len(scan_launches) == 2


def test_auto_publish_leaves_latest_alone_for_a_label_it_cannot_compare(
    client, db, scan_launches, feed
):
    c, _user = auth_client(role="maintainer")
    project_id = _feed_project(c, release_auto_publish=True)
    feed.append(_entry("v1.0.0", 1))
    _poll()
    feed.append(_entry("nightly", 2))
    assert _poll()["created"] == 1
    rows = _versions(project_id)
    assert rows["nightly"][:2] == (False, False)
    assert rows["v1.0.0"][:2] == (False, True)
    assert len(scan_launches) == 1


def test_auto_publish_takes_the_newest_entry_when_no_label_parses(
    client, db, scan_launches, feed
):
    c, _user = auth_client(role="maintainer")
    project_id = _feed_project(c, release_auto_publish=True)
    feed.append(_entry("nightly", 1))
    assert _poll()["created"] == 1
    assert _versions(project_id) == {"nightly": (False, True, "queued")}


def test_auto_publish_is_a_project_setting_owners_change(client, db, scan_launches):
    owner, _user = auth_client(role="maintainer")
    project_id = _feed_project(owner)
    response = owner.put(
        f"/v1/projects/{project_id}",
        json={"release_auto_publish": True},
        headers=_csrf(owner),
    )
    assert response.status_code == 200, response.text
    assert response.json()["release_auto_publish"] is True
    # A partial update elsewhere keeps it; an explicit null reads as off.
    response = owner.put(
        f"/v1/projects/{project_id}",
        json={"display_name": "Renamed"},
        headers=_csrf(owner),
    )
    assert response.json()["release_auto_publish"] is True
    with SessionLocal() as s:
        recorded = [
            change["field"]
            for entry in s.query(EntityChangelog).filter_by(
                entity_type="project", entity_id=project_id, action="updated"
            )
            for change in entry.changes
        ]
    assert recorded.count("release_auto_publish") == 1
    response = owner.put(
        f"/v1/projects/{project_id}",
        json={"release_auto_publish": None},
        headers=_csrf(owner),
    )
    assert response.json()["release_auto_publish"] is False

    other, _ = auth_client(role="maintainer")
    response = other.put(
        f"/v1/projects/{project_id}",
        json={"release_auto_publish": True},
        headers=_csrf(other),
    )
    assert response.status_code == 403
    with SessionLocal() as s:
        assert s.get(Project, project_id).release_auto_publish is False
