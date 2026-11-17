"""Limits on what a hostile repository, feed or name can do to the scan
pipeline: the scanners' environment, the repository address handed to git,
stored identifiers, and the text of a mail subject."""

from __future__ import annotations

import subprocess
from email.message import EmailMessage
from pathlib import Path

import pytest
from app.core.config import settings
from app.db.models import (
    DependencyPackage,
    DependencyVersion,
    DependencyVulnerability,
    ProjectVersionDependency,
)
from app.depscan import grype, scan, syft
from app.depscan.grype import VulnFinding
from app.depscan.parsers import DiscoveredDependency
from app.security.repo_credentials import RepoCredential, git_auth_env
from app.services.mailer import single_line
from app.tasks import dependency_discovery as dd

from tests.support import make_project, make_version, ok, record_dependency, signed_in


def test_scanners_start_outside_the_clone_without_the_workers_secrets(monkeypatch):
    calls: list[dict] = []

    def fake_run(cmd, **kwargs):
        calls.append({"cmd": cmd, **kwargs})
        return subprocess.CompletedProcess(cmd, 0, "{}", "")

    for module in (syft, grype):
        monkeypatch.setattr(module.subprocess, "run", fake_run)
        monkeypatch.setattr(module.shutil, "which", lambda cmd: f"/usr/bin/{cmd}")
    monkeypatch.setattr(settings, "syft_enabled", True)
    monkeypatch.setattr(settings, "grype_enabled", True)
    monkeypatch.setenv("OSPMAE_DATABASE_URL", "postgresql://u:secret@db/ospmae")
    monkeypatch.setenv("OSPMAE_MFA_ENCRYPTION_KEY", "key-material")
    monkeypatch.setenv("OSPMAE_SMTP_PASSWORD", "mail-secret")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "cloud-secret")
    monkeypatch.setenv("GRYPE_DB_CACHE_DIR", "/var/cache/grype")
    monkeypatch.setenv("SYFT_CHECK_FOR_APP_UPDATE", "false")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.internal:3128")
    monkeypatch.setenv("HOME", "/home/worker")

    repo = Path("/tmp/ospmae-clone")
    syft.scan_syft(repo)
    grype.scan_grype(repo)
    assert [call["cmd"][0] for call in calls] == ["syft", "grype"]
    for call in calls:
        env = call["env"]
        assert not any(name.startswith(("OSPMAE_", "AWS_")) for name in env)
        assert "secret" not in " ".join(env.values())
        # What the scanners themselves are configured with still reaches them.
        assert env["GRYPE_DB_CACHE_DIR"] == "/var/cache/grype"
        assert env["SYFT_CHECK_FOR_APP_UPDATE"] == "false"
        assert env["HTTPS_PROXY"] == "http://proxy.internal:3128"
        assert env["HOME"] == "/home/worker"
        assert env["PATH"]
        # Neither scanner reads a configuration file from the clone.
        assert call["cwd"] == "/"


def test_a_scanner_has_a_home_even_when_the_worker_has_none(monkeypatch):
    monkeypatch.delenv("HOME", raising=False)
    assert scan.scanner_env()["HOME"] == "/tmp"


@pytest.mark.parametrize(
    "url",
    [
        "\x01https://github.com/org/repo",
        "\x1fhttps://github.com/org/repo",
        "https://github.com/org/re\x7fpo",
        "https://github.com/org/\x0brepo",
        "HTTPS://github.com/org/repo",
        "Https://github.com/org/repo",
        "SSH://git@github.com/org/repo",
    ],
)
def test_a_repository_address_git_would_read_differently_is_refused(url):
    with pytest.raises(ValueError):
        scan.validate_repo_url(url)


def test_surrounding_spaces_are_not_part_of_a_repository_address():
    scan.validate_repo_url("  https://github.com/org/repo\n")


@pytest.mark.parametrize("listed", [",", " , ,", ";"])
def test_an_allow_list_that_names_no_host_allows_none(monkeypatch, listed):
    monkeypatch.setattr(settings, "dependency_discovery_allowed_hosts", listed)
    for url in ("https://github.com/org/repo", "git@github.com:org/repo.git"):
        with pytest.raises(ValueError, match="not allowed"):
            scan.validate_repo_url(url)


def test_an_empty_allow_list_setting_means_the_default_hosts(monkeypatch):
    monkeypatch.setattr(settings, "dependency_discovery_allowed_hosts", "")
    scan.validate_repo_url("https://github.com/org/repo")
    with pytest.raises(ValueError, match="not allowed"):
        scan.validate_repo_url("https://forge.internal.example/org/repo")


@pytest.mark.parametrize(
    "url, accepted",
    [
        ("https://github.com/org/repo", True),
        ("https://github.com:443/org/repo", True),
        ("https://github.com:8443/org/repo", False),
        ("https://github.com:x/org/repo", False),
        ("http://github.com/org/repo", False),
        ("https://github.com.evil.example/org/repo", False),
    ],
)
def test_a_token_goes_only_to_its_hosts_https_port(url, accepted):
    credential = RepoCredential(
        host="github.com",
        username="x",
        token="t0ken",
        repository="https://github.com/org/repo",
    )
    if accepted:
        env = git_auth_env(credential, url)
        assert env["GIT_CONFIG_KEY_0"] == "http.https://github.com/org/repo.extraHeader"
    else:
        with pytest.raises(ValueError, match="only over HTTPS"):
            git_auth_env(credential, url)


@pytest.mark.parametrize(
    "separator",
    ["\r", "\n", "\r\n", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", " ", " "],
)
def test_a_subject_is_one_line_whatever_a_name_carries(separator):
    subject = single_line(f"New release for Alpha{separator}Bcc: x@y.test (1.0)")
    assert subject == "New release for Alpha Bcc: x@y.test (1.0)"
    # The message accepts it; the raw name is refused, which failed the mail
    # on every attempt.
    message = EmailMessage()
    message["Subject"] = subject
    assert message["Subject"] == subject


def test_a_subject_without_text_is_empty():
    assert single_line(None) == ""
    assert single_line("") == ""


def test_an_npm_scope_lists_its_own_packages_not_a_pattern(db):
    admin, _ = signed_in("admin")
    pid = make_project(admin, "alpha")["id"]
    vid = make_version(admin, pid, "1.0.0")["id"]
    wild = record_dependency(vid, "npm", "@%/x", "1.0.0")
    record_dependency(vid, "npm", "@_cope/y", "1.0.0")
    record_dependency(vid, "npm", "@scope/a", "1.0.0")
    scoped = record_dependency(vid, "npm", "@scope/b", "1.0.0")
    record_dependency(vid, "npm", "@scopeless/c", "1.0.0")

    def scope_names(dependency_version_id: int) -> list[str]:
        body = ok(admin.get(f"/v1/dependencies/{dependency_version_id}"))
        return [p["name"] for p in body["namespace"]["packages"]]

    assert scope_names(wild) == ["@%/x"]
    assert scope_names(scoped) == ["@scope/a", "@scope/b"]


def test_identifiers_from_a_repository_are_stored_clean_and_within_their_columns(db):
    admin, _ = signed_in("admin")
    pid = make_project(admin, "alpha")["id"]
    vid = make_version(admin, pid, "1.0.0")["id"]
    long_name = "n" * 400
    discovered = [
        DiscoveredDependency(
            "PyPI\x00", "re\x1bquests\n", "2.0\x07", False, "req\x00.txt"
        ),
        DiscoveredDependency("pypi", long_name, "9" * 300, True, "p" * 900),
        DiscoveredDependency("e" * 80, "left", "1", False, "a.lock"),
        DiscoveredDependency("pypi", "\x01\x02", "1", False, "b.lock"),
    ] + [
        DiscoveredDependency("pypi", "many", "1", False, f"dir{n}/requirements.txt")
        for n in range(80)
    ]
    assert (
        dd._apply_dependencies(db, project_version_id=vid, discovered=discovered) == 4
    )
    db.commit()
    packages = {p.normalized_name: p for p in db.query(DependencyPackage).all()}
    assert set(packages) == {"requests", "n" * 255, "left", "many"}
    assert packages["requests"].ecosystem == "pypi"
    assert packages["left"].ecosystem == "e" * 32
    versions = {v.dependency_id: v.version for v in db.query(DependencyVersion).all()}
    assert versions[packages["requests"].id] == "2.0"
    assert versions[packages["n" * 255].id] == "9" * 200
    links = {
        link.dependency_version.dependency.normalized_name: link.source_files
        for link in db.query(ProjectVersionDependency).all()
    }
    assert links["requests"] == ["req.txt"]
    assert links["n" * 255] == ["p" * 500]
    assert len(links["many"]) == 50


def test_findings_are_cut_to_the_columns_that_hold_them(db):
    admin, _ = signed_in("admin")
    pid = make_project(admin, "alpha")["id"]
    vid = make_version(admin, pid, "1.0.0")["id"]
    record_dependency(vid, "pypi", "requests", "2.0")
    finding = VulnFinding(
        ecosystem="PyPI\x00",
        package="requests",
        version="2.0\x00",
        vulnerability_id="GHSA-" + "x" * 100 + "\n",
        severity="Critical" + "!" * 40,
        title="A title",
        fixed_version="2.1\x1b" + "0" * 200,
        references=[],
        raw={},
    )
    assert dd._apply_vulns(db, findings=[finding], project_version_id=vid) == 1
    db.commit()
    [row] = db.query(DependencyVulnerability).all()
    assert row.vulnerability_id == ("GHSA-" + "x" * 100)[:64]
    assert row.severity == ("Critical" + "!" * 40)[:16]
    assert row.fixed_version == ("2.1" + "0" * 200)[:100]
    # A second scan reporting the same finding updates that row.
    assert dd._apply_vulns(db, findings=[finding], project_version_id=vid) == 1
    db.commit()
    assert db.query(DependencyVulnerability).count() == 1


def test_a_scan_with_more_dependencies_than_one_scan_stores_writes_nothing(
    db, monkeypatch
):
    admin, _ = signed_in("admin")
    pid = make_project(admin, "alpha")["id"]
    vid = make_version(admin, pid, "1.0.0")["id"]
    record_dependency(vid, "pypi", "requests", "2.0")
    monkeypatch.setattr(dd, "MAX_DEPENDENCIES_PER_SCAN", 3)
    many = [
        DiscoveredDependency("pypi", f"package-{n}", "1.0", False, "requirements.txt")
        for n in range(4)
    ]
    with pytest.raises(
        ValueError, match="lists 4 dependencies; one scan stores at most 3"
    ):
        dd._apply_dependencies(db, project_version_id=vid, discovered=many)
    db.rollback()
    # What the last scan found is still there, and nothing new was added.
    assert db.query(ProjectVersionDependency).count() == 1
    assert [p.name for p in db.query(DependencyPackage).all()] == ["requests"]
    # The same name listed many times is one dependency.
    repeated = many[:3] + many[:3]
    assert dd._apply_dependencies(db, project_version_id=vid, discovered=repeated) == 3


def test_a_running_scan_is_not_queued_again_until_it_is_overdue(db):
    from datetime import datetime, timedelta

    from app.db.models import ProjectVersion

    from tests.support import csrf, set_scan_state

    admin, _ = signed_in("admin")
    pid = make_project(admin, "alpha")["id"]
    vid = make_version(
        admin, pid, "1.0.0", link_to_source_code="https://github.com/example/repo"
    )["id"]
    path = f"/v1/project-versions/{vid}/dependency-discovery"
    set_scan_state(vid, "running", dependency_discovery_started_at=datetime.utcnow())
    refused = admin.post(path, params={"run_now": "false"}, headers=csrf(admin))
    assert (refused.status_code, refused.json()["detail"]) == (
        409,
        "A scan of this version is already running",
    )
    db.expire_all()
    assert db.get(ProjectVersion, vid).dependency_discovery_status == "running"

    # A scan "running" for longer than any scan may run was stopped.
    set_scan_state(
        vid,
        "running",
        dependency_discovery_started_at=datetime.utcnow() - timedelta(hours=2),
    )
    assert ok(admin.post(path, params={"run_now": "false"}, headers=csrf(admin)))[
        "queued"
    ]
    db.expire_all()
    assert db.get(ProjectVersion, vid).dependency_discovery_status == "queued"
