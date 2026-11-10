"""Projects that track a branch: validation, the branch version, the poller
and the branch-exact clone."""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import pytest
from app.core.config import settings
from app.db.models import EntityChangelog, Project, ProjectVersion
from app.db.session import SessionLocal
from app.depscan import scan as scan_mod
from app.depscan.scan import clone_repo, validate_git_ref_name

from tests.conftest import auth_client

PASSWORD = "Pass-Branch-tests1!"
REPO = "https://github.com/example/tracked"


def _csrf(client):
    return {"X-CSRF-Token": client.cookies.get("ospmae_csrf")}


class _ScanTask:
    launched: list[int] = []

    @classmethod
    def delay(cls, version_id):
        cls.launched.append(int(version_id))


@pytest.fixture()
def scan_launches(monkeypatch):
    from app.tasks import dependency_discovery

    _ScanTask.launched = []
    monkeypatch.setattr(
        dependency_discovery, "discover_project_version_dependencies", _ScanTask
    )
    return _ScanTask.launched


def _tracked_body(**overrides):
    body = {
        "machine_name": "tracked",
        "display_name": "Tracked",
        "track_branch": True,
        "tracked_repo_url": REPO,
        "tracked_branch": "main",
        "branch_poll_interval_hours": 6,
    }
    body.update(overrides)
    return body


# ---------------------------------------------------------------------------
# Ref names reach git literally or not at all.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "ok"),
    [
        ("main", True),
        ("release/2.x", True),
        ("feature_v1.2", True),
        ("-upload-pack=evil", False),
        ("--help", False),
        ("a..b", False),
        ("a b", False),
        ("ma*in", False),
        ("ma?in", False),
        ("ma[in", False),
        ("ma{in}", False),
        ("ma~1", False),
        ("ma^", False),
        ("a:b", False),
        ("a\\b", False),
        ("a\nb", False),
        ("a\x7fb", False),
        ("@", False),
        ("a@{1}", False),
        ("/main", False),
        ("main/", False),
        ("a//b", False),
        ("main.", False),
        (".hidden", False),
        ("x/.hidden", False),
        ("main.lock", False),
        ("", False),
        ("   ", False),
    ],
)
def test_git_ref_names(name, ok):
    if ok:
        assert validate_git_ref_name(name) == name
    else:
        with pytest.raises(ValueError):
            validate_git_ref_name(name)


def test_remote_ref_lookup_never_runs_git_for_a_refused_name(monkeypatch):
    calls: list[list[str]] = []

    def _fake_run(cmd, **_kw):
        calls.append(cmd)
        raise AssertionError("git must not run for a refused ref")

    monkeypatch.setattr(scan_mod.subprocess, "run", _fake_run)
    for ref in ("-oops", "a..b", "x y", "*"):
        assert scan_mod._remote_has_ref(REPO, ref, kind="branch") is False
        assert scan_mod._remote_has_ref(REPO, ref, kind="tag") is False
    assert calls == []


def _record_git(monkeypatch, heads: set[str], tags: set[str]):
    """Stand-ins for ls-remote and clone that record what git would run."""

    looked_up: list[tuple[str, str]] = []
    commands: list[list[str]] = []

    def _has_ref(url, ref, *, kind):
        looked_up.append((kind, ref))
        return ref in (heads if kind == "branch" else tags)

    def _run(cmd, *, cwd=None, timeout=180):
        commands.append(cmd)
        return "0123abcd\n" if "rev-parse" in cmd else ""

    monkeypatch.setattr(scan_mod, "_remote_has_ref", _has_ref)
    monkeypatch.setattr(scan_mod, "_run", _run)
    return looked_up, commands


def test_branch_clone_takes_the_branch_head_even_when_a_tag_shares_its_name(
    monkeypatch,
):
    looked_up, commands = _record_git(monkeypatch, heads={"dev"}, tags={"dev"})
    path, commit = clone_repo(REPO, version_hint="dev", branch="dev")
    try:
        assert commit == "0123abcd"
        # Only refs/heads is consulted: a same-named tag cannot capture it.
        assert looked_up == [("branch", "dev")]
        clone = commands[0]
        assert clone[clone.index("--branch") + 1] == "dev"
        assert "--single-branch" in clone and "--depth" in clone
    finally:
        Path(path).rmdir()


def test_branch_clone_refuses_a_missing_branch_instead_of_the_default(monkeypatch):
    looked_up, commands = _record_git(monkeypatch, heads={"main"}, tags=set())
    with pytest.raises(RuntimeError, match="was not found"):
        clone_repo(REPO, branch="gone")
    assert commands == []


def test_branch_clone_validates_before_any_git(monkeypatch):
    looked_up, commands = _record_git(monkeypatch, heads={"main"}, tags=set())
    with pytest.raises(ValueError):
        clone_repo(REPO, branch="--upload-pack=touch /tmp/x")
    with pytest.raises(ValueError):
        clone_repo("https://attacker.example.com/x", branch="main")
    assert looked_up == [] and commands == []


def test_release_clone_still_prefers_tags(monkeypatch):
    looked_up, commands = _record_git(monkeypatch, heads={"v1.0.0"}, tags={"v1.0.0"})
    path, _ = clone_repo(REPO, version_hint="v1.0.0")
    try:
        assert looked_up[0] == ("tag", "v1.0.0")
        assert commands[0][commands[0].index("--branch") + 1] == "v1.0.0"
    finally:
        Path(path).rmdir()


# ---------------------------------------------------------------------------
# API: saving tracking settings maintains the branch version and scans it.
# ---------------------------------------------------------------------------


def test_create_tracking_project_makes_the_branch_the_latest_and_scans_it(
    client, db, scan_launches
):
    c, _user = auth_client(username="tracker", password=PASSWORD, role="maintainer")
    response = c.post("/v1/projects", json=_tracked_body(), headers=_csrf(c))
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["track_branch"] is True
    assert body["tracked_branch"] == "main"
    assert body["tracked_repo_url"] == REPO
    assert body["branch_poll_interval_hours"] == 6
    assert body["branch_last_polled_at"] is not None
    assert body["latest_version"]["version"] == "main"

    with SessionLocal() as s:
        versions = s.query(ProjectVersion).filter_by(project_id=body["id"]).all()
        assert [(v.version, v.is_latest, v.is_draft) for v in versions] == [
            ("main", True, False)
        ]
        assert versions[0].link_to_source_code == REPO
        assert versions[0].dependency_discovery_status == "queued"
        assert scan_launches == [versions[0].id]
        logged = (
            s.query(EntityChangelog)
            .filter_by(entity_type="project_version", entity_id=versions[0].id)
            .count()
        )
        assert logged == 1

    dashboard = c.get("/v1/dashboard").json()["projects"]
    row = next(p for p in dashboard if p["id"] == body["id"])
    assert row["tracked_branch"] == "main"
    assert row["latest"]["version"] == "main"


@pytest.mark.parametrize(
    "overrides",
    [
        {"tracked_repo_url": None},
        {"tracked_branch": ""},
        {"tracked_branch": "-x"},
        {"tracked_branch": "b" * 65},
        {"tracked_repo_url": "https://attacker.example.com/x.git"},
        {"tracked_repo_url": "https://user:token@github.com/o/r"},
        {"branch_poll_interval_hours": 0},
        {"branch_poll_interval_hours": 721},
    ],
)
def test_tracking_settings_are_validated(client, db, scan_launches, overrides):
    c, _user = auth_client(role="maintainer")
    response = c.post("/v1/projects", json=_tracked_body(**overrides), headers=_csrf(c))
    assert response.status_code == 422, response.text
    with SessionLocal() as s:
        assert s.query(Project).count() == 0
    assert scan_launches == []


def test_untracked_project_keeps_branch_fields_inert(client, db, scan_launches):
    c, _user = auth_client(role="maintainer")
    response = c.post(
        "/v1/projects",
        json={"machine_name": "plain", "display_name": "Plain"},
        headers=_csrf(c),
    )
    assert response.status_code == 200, response.text
    assert response.json()["track_branch"] is False
    assert response.json()["branch_poll_interval_hours"] == 24
    with SessionLocal() as s:
        assert s.query(ProjectVersion).count() == 0
    assert scan_launches == []


def test_update_switches_branch_and_only_rescans_on_target_changes(
    client, db, scan_launches
):
    c, _user = auth_client(role="maintainer")
    project_id = c.post("/v1/projects", json=_tracked_body(), headers=_csrf(c)).json()[
        "id"
    ]
    assert len(scan_launches) == 1

    # An interval or display change re-scans nothing.
    response = c.put(
        f"/v1/projects/{project_id}",
        json={"branch_poll_interval_hours": 12, "display_name": "Renamed"},
        headers=_csrf(c),
    )
    assert response.status_code == 200, response.text
    assert response.json()["branch_poll_interval_hours"] == 12
    assert len(scan_launches) == 1

    # A different branch gets its own version, which becomes Latest.
    response = c.put(
        f"/v1/projects/{project_id}",
        json={"tracked_branch": "develop"},
        headers=_csrf(c),
    )
    assert response.status_code == 200, response.text
    assert response.json()["latest_version"]["version"] == "develop"
    assert len(scan_launches) == 2
    with SessionLocal() as s:
        rows = {
            v.version: v.is_latest
            for v in s.query(ProjectVersion).filter_by(project_id=project_id)
        }
    assert rows == {"main": False, "develop": True}

    # Clearing a required field while tracking is refused.
    response = c.put(
        f"/v1/projects/{project_id}",
        json={"tracked_repo_url": ""},
        headers=_csrf(c),
    )
    assert response.status_code == 422, response.text

    # Turning tracking off keeps the history and scans nothing new.
    response = c.put(
        f"/v1/projects/{project_id}",
        json={"track_branch": False},
        headers=_csrf(c),
    )
    assert response.status_code == 200, response.text
    assert response.json()["track_branch"] is False
    assert len(scan_launches) == 2


def test_tracking_needs_project_manage_access(client, db, scan_launches):
    owner, _ = auth_client(role="maintainer")
    project_id = owner.post(
        "/v1/projects", json=_tracked_body(), headers=_csrf(owner)
    ).json()["id"]
    other, _ = auth_client(role="maintainer")
    response = other.put(
        f"/v1/projects/{project_id}",
        json={"tracked_branch": "attacker"},
        headers=_csrf(other),
    )
    assert response.status_code == 403
    viewer, _ = auth_client(role="viewer")
    response = viewer.post(
        "/v1/projects", json=_tracked_body(machine_name="v"), headers=_csrf(viewer)
    )
    assert response.status_code == 403
    assert len(scan_launches) == 1


def test_tracked_project_skips_release_feed_discovery(client, db, monkeypatch):
    import app.tasks.release_feed as rf

    enqueued: list[int] = []

    class _FeedTask:
        @staticmethod
        def delay(project_id):
            enqueued.append(int(project_id))

    real_task = rf.discover_project_release_feed
    monkeypatch.setattr(rf, "discover_project_release_feed", _FeedTask)
    c, _user = auth_client(role="maintainer")
    response = c.post(
        "/v1/projects",
        json=_tracked_body(release_rss_feed_url="https://example.org/feed.xml"),
        headers=_csrf(c),
    )
    assert response.status_code == 200, response.text
    assert enqueued == []

    # Even when invoked directly, the feed import leaves a tracked project be.
    outcome = real_task.run(response.json()["id"])
    assert outcome["reason"] == "project tracks a branch"


# ---------------------------------------------------------------------------
# The poller.
# ---------------------------------------------------------------------------


def _make_tracked(s, **kw) -> Project:
    project = Project(
        machine_name=kw.pop("machine_name", "p"),
        display_name="P",
        track_branch=kw.pop("track_branch", True),
        tracked_repo_url=REPO,
        tracked_branch=kw.pop("tracked_branch", "main"),
        branch_poll_interval_hours=kw.pop("interval", 1),
        **kw,
    )
    s.add(project)
    s.commit()
    return project


def test_poller_queues_due_branches_once(client, db):
    from app.tasks.branch_tracking import poll_tracked_branches

    now = datetime.utcnow()
    with SessionLocal() as s:
        never = _make_tracked(s, machine_name="never")
        due = _make_tracked(
            s, machine_name="due", branch_last_polled_at=now - timedelta(hours=2)
        )
        fresh = _make_tracked(
            s, machine_name="fresh", branch_last_polled_at=now - timedelta(minutes=30)
        )
        _make_tracked(s, machine_name="off", track_branch=False)
        ids = {p.machine_name: p.id for p in (never, due, fresh)}

    assert poll_tracked_branches.run() == {"ok": True, "checked": 2, "queued": 2}
    with SessionLocal() as s:
        queued = {
            v.project_id
            for v in s.query(ProjectVersion).filter_by(
                dependency_discovery_status="queued"
            )
        }
        assert queued == {ids["never"], ids["due"]}
        assert s.query(ProjectVersion).filter_by(project_id=ids["fresh"]).count() == 0

    # Polled now, so a second run straight after finds nothing due.
    assert poll_tracked_branches.run() == {"ok": True, "checked": 0, "queued": 0}


def test_poller_respects_in_flight_scans_and_recovers_stale_ones(client, db):
    from app.tasks.branch_tracking import poll_tracked_branches

    now = datetime.utcnow()
    with SessionLocal() as s:
        project = _make_tracked(s)
        version = ProjectVersion(
            project_id=project.id,
            version="main",
            link_to_source_code=REPO,
            dependency_discovery_status="running",
            dependency_discovery_started_at=now - timedelta(minutes=10),
        )
        s.add(version)
        s.commit()
        version_id = version.id
        project_id = project.id

    assert poll_tracked_branches.run()["queued"] == 0
    with SessionLocal() as s:
        assert s.get(ProjectVersion, version_id).dependency_discovery_status == (
            "running"
        )
        # A scan whose worker vanished hours ago no longer blocks the branch.
        s.get(ProjectVersion, version_id).dependency_discovery_started_at = (
            now - timedelta(hours=7)
        )
        s.get(Project, project_id).branch_last_polled_at = now - timedelta(hours=2)
        s.commit()
    assert poll_tracked_branches.run()["queued"] == 1
    with SessionLocal() as s:
        assert s.get(ProjectVersion, version_id).dependency_discovery_status == (
            "queued"
        )


def test_poller_claims_each_project_with_compare_and_set(client, db, monkeypatch):
    """Two overlapping beats: the one that loses the claim queues nothing."""

    import app.tasks.branch_tracking as bt

    with SessionLocal() as s:
        project_id = _make_tracked(s).id

    real_due = bt.scan_due

    def _due_then_race(project, now):
        due = real_due(project, now)
        if due:
            # Another beat claims the project between our read and our claim.
            with SessionLocal() as other:
                other.get(Project, project_id).branch_last_polled_at = now
                other.commit()
        return due

    monkeypatch.setattr(bt, "scan_due", _due_then_race)
    assert bt.poll_tracked_branches.run() == {"ok": True, "checked": 1, "queued": 0}
    with SessionLocal() as s:
        assert s.query(ProjectVersion).filter_by(project_id=project_id).count() == 0


def test_poller_is_a_no_op_without_dependency_scans(client, db, monkeypatch):
    from app.tasks.branch_tracking import poll_tracked_branches

    with SessionLocal() as s:
        _make_tracked(s)
    monkeypatch.setattr(settings, "feature_dependency_scans", False)
    assert poll_tracked_branches.run()["ok"] is False
    monkeypatch.setattr(settings, "feature_dependency_scans", True)
    monkeypatch.setattr(settings, "dependency_discovery_enabled", False)
    assert poll_tracked_branches.run()["ok"] is False
    with SessionLocal() as s:
        assert s.query(ProjectVersion).count() == 0


def test_poll_interval_has_an_hourly_floor():
    from app.services.branch_tracking import scan_due

    now = datetime.utcnow()
    project = Project(
        track_branch=True,
        tracked_repo_url=REPO,
        tracked_branch="main",
        branch_poll_interval_hours=0,  # a stored value below the floor
        branch_last_polled_at=now - timedelta(minutes=59),
    )
    assert scan_due(project, now) is False
    project.branch_last_polled_at = now - timedelta(minutes=60)
    assert scan_due(project, now) is True


# ---------------------------------------------------------------------------
# Discovery clones the tracked branch for its version only.
# ---------------------------------------------------------------------------


def test_discovery_clones_the_tracked_branch_for_the_branch_version(
    client, db, monkeypatch, tmp_path
):
    import app.tasks.dependency_discovery as dd

    seen: list[tuple[str, str | None, str | None]] = []

    def _fake_clone(url, version_hint=None, *, branch=None):
        seen.append((url, version_hint, branch))
        repo = tmp_path / f"repo{len(seen)}"
        repo.mkdir()
        (repo / "requirements.txt").write_text("flask==3.0.0\n")
        return repo, "c0ffee"

    monkeypatch.setattr(dd, "clone_repo", _fake_clone)
    monkeypatch.setattr(dd, "scan_syft", lambda root: None)
    monkeypatch.setattr(dd, "scan_grype", lambda root: None)

    with SessionLocal() as s:
        project = _make_tracked(s, tracked_branch="dev")
        branch_version = ProjectVersion(
            project_id=project.id, version="dev", link_to_source_code=REPO
        )
        release = ProjectVersion(
            project_id=project.id,
            version="v1.0.0",
            link_to_source_code="https://github.com/example/release-repo",
        )
        s.add_all([branch_version, release])
        s.commit()
        ids = (branch_version.id, release.id)

    assert dd.discover_project_version_dependencies.run(ids[0])["ok"] is True
    assert dd.discover_project_version_dependencies.run(ids[1])["ok"] is True
    assert seen == [
        (REPO, "dev", "dev"),
        ("https://github.com/example/release-repo", "v1.0.0", None),
    ]
    with SessionLocal() as s:
        scanned = s.get(ProjectVersion, ids[0])
        assert scanned.dependency_discovery_status == "complete"
        assert scanned.dependency_last_commit == "c0ffee"
        assert scanned.dependency_count == 1
