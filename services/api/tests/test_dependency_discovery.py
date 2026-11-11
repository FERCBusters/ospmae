"""The scan task from checkout to stored result. Git, Syft and Grype are the
external programs; they are replaced by a checkout holding real lockfiles and
by the findings a scanner would report, and everything after them runs as
deployed: lockfile parsing, merging, storage and the version's scan state."""

from __future__ import annotations

from pathlib import Path

import pytest
from app.core.config import settings
from app.db.models import (
    DependencyPackage,
    DependencyVersion,
    DependencyVulnerability,
    Project,
    ProjectVersion,
    ProjectVersionDependency,
)
from app.db.session import SessionLocal
from app.depscan.grype import VulnFinding
from app.depscan.parsers import DiscoveredDependency
from app.tasks import dependency_discovery as dd

REPO = "https://github.com/example/repo"

POETRY_LOCK = """
[[package]]
name = "flask"
version = "3.0.0"

[[package]]
name = "requests"
version = "2.31.0"
"""


def finding(
    package, version, vuln_id, *, severity="High", fixed="", ecosystem="python", **extra
):
    return VulnFinding(
        ecosystem=ecosystem,
        package=package,
        version=version,
        vulnerability_id=vuln_id,
        severity=severity,
        title=extra.get("title", f"{vuln_id} in {package}"),
        fixed_version=fixed,
        references=extra.get("references", [f"https://advisories.example/{vuln_id}"]),
        raw=extra.get("raw", {"id": vuln_id, "nested": {"dropped": True}}),
    )


class Scanner:
    """What the external tools would produce for the next scan."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.files = {"poetry.lock": POETRY_LOCK}
        self.syft: list[DiscoveredDependency] | None = None
        self.grype: list[VulnFinding] | None = None
        self.clone_error: Exception | None = None
        self.clones: list[dict] = []
        self.checkouts: list[Path] = []

    def clone(self, url, version_hint=None, *, branch=None, credential=None):
        self.clones.append({"url": url, "ref": version_hint, "branch": branch})
        if self.clone_error is not None:
            raise self.clone_error
        repo = self.root / f"checkout-{len(self.clones)}"
        for name, content in self.files.items():
            target = repo / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        self.checkouts.append(repo)
        return repo, "c0ffee1"


@pytest.fixture()
def scanner(monkeypatch, tmp_path):
    tools = Scanner(tmp_path)
    monkeypatch.setattr(dd, "clone_repo", tools.clone)
    monkeypatch.setattr(dd, "scan_syft", lambda root: tools.syft)
    monkeypatch.setattr(dd, "scan_grype", lambda root: tools.grype)
    return tools


def queued_version(
    label="1.0.0", *, machine_name="alpha", link=REPO, status="queued"
) -> int:
    with SessionLocal() as s:
        project = s.query(Project).filter_by(machine_name=machine_name).one_or_none()
        if project is None:
            project = Project(
                machine_name=machine_name, display_name=machine_name.title()
            )
            s.add(project)
            s.flush()
        version = ProjectVersion(
            project_id=project.id,
            version=label,
            link_to_source_code=link,
            dependency_discovery_status=status,
        )
        s.add(version)
        s.commit()
        return version.id


def run(version_id: int) -> dict:
    return dd.discover_project_version_dependencies.run(version_id)


def stored(version_id: int) -> dict[str, tuple[str, bool, list[str]]]:
    with SessionLocal() as s:
        rows = (
            s.query(DependencyPackage, DependencyVersion, ProjectVersionDependency)
            .join(
                DependencyVersion,
                DependencyVersion.dependency_id == DependencyPackage.id,
            )
            .join(
                ProjectVersionDependency,
                ProjectVersionDependency.dependency_version_id == DependencyVersion.id,
            )
            .filter(ProjectVersionDependency.project_version_id == version_id)
            .all()
        )
        return {
            f"{package.ecosystem}:{package.name}": (
                version.version,
                link.is_indirect,
                list(link.source_files),
            )
            for package, version, link in rows
        }


def state(version_id: int) -> ProjectVersion:
    with SessionLocal() as s:
        version = s.get(ProjectVersion, version_id)
        s.expunge(version)
        return version


def test_a_scan_stores_what_the_lockfiles_and_the_inventory_report(scanner):
    scanner.files = {
        "poetry.lock": POETRY_LOCK,
        "web/package-lock.json": (
            '{"lockfileVersion": 3, "packages": {"": {"dependencies": {"left-pad": "1.3.0"}},'
            ' "node_modules/left-pad": {"version": "1.3.0"},'
            ' "node_modules/@scope/util": {"version": "2.0.0"}}}'
        ),
        "node_modules/ignored/package-lock.json": '{"lockfileVersion": 3, "packages": {}}',
    }
    scanner.syft = [
        # The inventory lists left-pad as transitive; the lockfile knows it is direct.
        DiscoveredDependency("NPM", "Left-Pad", "1.3.0", True, "sbom"),
        DiscoveredDependency("python", "werkzeug", "3.0.1", True, "sbom"),
        DiscoveredDependency("python", "", "1.0", True, "sbom"),
        DiscoveredDependency("", "nameless-ecosystem", "1.0", True, "sbom"),
    ]
    vid = queued_version("v1.2.0")

    result = run(vid)
    assert result == {
        "ok": True,
        "dependencies": 5,
        "vulnerabilities": 0,
        "commit": "c0ffee1",
    }
    assert scanner.clones == [{"url": REPO, "ref": "v1.2.0", "branch": None}]
    deps = stored(vid)
    assert set(deps) == {
        "python:flask",
        "python:requests",
        "python:werkzeug",
        "npm:Left-Pad",
        "npm:@scope/util",
    }
    # One row per package: sources are merged, and "direct" wins over "indirect".
    assert deps["npm:Left-Pad"] == ("1.3.0", False, ["sbom", "web/package-lock.json"])
    assert deps["npm:@scope/util"] == ("2.0.0", True, ["web/package-lock.json"])
    assert deps["python:werkzeug"] == ("3.0.1", True, ["sbom"])
    assert deps["python:flask"][0] == "3.0.0"

    version = state(vid)
    assert version.dependency_discovery_status == "complete"
    assert (version.dependency_count, version.vulnerability_count) == (5, 0)
    assert version.dependency_last_commit == "c0ffee1"
    assert (
        version.dependency_discovery_started_at
        <= version.dependency_discovery_finished_at
    )
    assert version.dependency_discovery_error is None
    # The checkout is removed once the scan has finished.
    assert not scanner.checkouts[0].exists()


def test_findings_are_stored_once_per_advisory_and_refreshed_by_the_next_scan(scanner):
    vid = queued_version()
    scanner.grype = [
        finding("flask", "3.0.0", "CVE-2026-1", severity="Critical", fixed="3.0.1"),
        # The same advisory matched twice, as Grype does for several locations.
        finding("flask", "3.0.0", "CVE-2026-1", severity="Critical", fixed="3.0.1"),
        finding("requests", "2.31.0", "GHSA-xxxx", severity="Low"),
        finding("requests", "2.31.0", "", severity="Low"),  # no advisory id
        finding("", "1.0", "CVE-2026-9"),  # no package
    ]
    assert run(vid)["vulnerabilities"] == 2
    with SessionLocal() as s:
        rows = {v.vulnerability_id: v for v in s.query(DependencyVulnerability)}
        assert set(rows) == {"CVE-2026-1", "GHSA-xxxx"}
        first = rows["CVE-2026-1"]
        assert (first.scanner, first.severity, first.fixed_version) == (
            "grype",
            "Critical",
            "3.0.1",
        )
        assert first.references == ["https://advisories.example/CVE-2026-1"]
        # Only scalar scanner fields are kept from the raw record.
        assert first.raw == {"id": "CVE-2026-1", "nested": None}
    assert state(vid).vulnerability_count == 2

    # The next scan replaces the findings: one fixed, one changed, one new.
    with SessionLocal() as s:
        s.get(ProjectVersion, vid).dependency_discovery_status = "queued"
        s.commit()
    scanner.grype = [
        finding("requests", "2.31.0", "GHSA-xxxx", severity="Medium", fixed="2.32.0"),
        finding("requests", "2.31.0", "CVE-2026-7"),
    ]
    assert run(vid)["vulnerabilities"] == 2
    with SessionLocal() as s:
        rows = {v.vulnerability_id: v for v in s.query(DependencyVulnerability)}
        assert set(rows) == {"GHSA-xxxx", "CVE-2026-7"}
        assert (rows["GHSA-xxxx"].severity, rows["GHSA-xxxx"].fixed_version) == (
            "Medium",
            "2.32.0",
        )


def test_a_scan_without_grype_keeps_the_findings_already_known(scanner):
    first = queued_version("1.0.0")
    scanner.grype = [finding("flask", "3.0.0", "CVE-2026-1")]
    assert run(first)["vulnerabilities"] == 1

    # Another project uses the same Flask; Grype is unavailable for its scan.
    second = queued_version("5.0.0", machine_name="beta")
    scanner.grype = None
    result = run(second)
    assert (result["dependencies"], result["vulnerabilities"]) == (2, 1)
    with SessionLocal() as s:
        assert s.query(DependencyVulnerability).count() == 1
        # Both versions share the package rows.
        assert s.query(DependencyPackage).count() == 2


def test_a_finding_for_a_package_outside_the_inventory_does_not_count(scanner):
    vid = queued_version()
    scanner.grype = [finding("openssl", "3.0", "CVE-2026-5", ecosystem="deb")]
    assert run(vid)["vulnerabilities"] == 0
    with SessionLocal() as s:
        # It is recorded against its own package, for whoever does depend on it.
        assert s.query(DependencyVulnerability).one().vulnerability_id == "CVE-2026-5"
    assert state(vid).vulnerability_count == 0


def test_upstream_names_are_stored_without_markup_or_control_characters(scanner):
    scanner.syft = [
        DiscoveredDependency(
            "npm", "<script>alert(1)</script>evil\x07", "1.0", False, "sbom"
        ),
        DiscoveredDependency("npm", "<>", "1.0", False, "sbom"),
    ]
    scanner.grype = [
        finding(
            "flask",
            "3.0.0",
            "CVE-2026-1",
            severity="High<b>",
            title="Bad\x00 <img src=x onerror=alert(1)> title " + "t" * 600,
            references=[f"https://ref.example/{n}" for n in range(15)],
            raw={f"key{n}": "v" for n in range(60)},
        )
    ]
    vid = queued_version()
    assert run(vid)["ok"] is True
    deps = stored(vid)
    assert "npm:scriptalert1/scriptevil" in deps
    # A name that is nothing but markup falls back to its normalised form.
    assert "npm:<>" in deps
    with SessionLocal() as s:
        vuln = s.query(DependencyVulnerability).one()
        assert vuln.severity == "Highb"
        assert "<" not in vuln.title and "\x00" not in vuln.title
        assert len(vuln.title) <= 500
        assert len(vuln.references) == 10
        assert len(vuln.raw) == 50


def test_a_rescan_replaces_the_dependency_list(scanner):
    vid = queued_version()
    assert run(vid)["dependencies"] == 2
    scanner.files = {
        "poetry.lock": POETRY_LOCK.split("[[package]]")[0]
        + "[[package]]"
        + POETRY_LOCK.split("[[package]]")[1].replace("3.0.0", "3.1.0")
    }
    with SessionLocal() as s:
        s.get(ProjectVersion, vid).dependency_discovery_status = "queued"
        s.commit()
    assert run(vid)["dependencies"] == 1
    assert set(stored(vid)) == {"python:flask"}
    assert stored(vid)["python:flask"][::2] == ("3.1.0", ["poetry.lock"])
    with SessionLocal() as s:
        # Both Flask versions stay known to the catalogue.
        assert (
            s.query(DependencyVersion)
            .join(DependencyPackage)
            .filter(DependencyPackage.normalized_name == "flask")
            .count()
            == 2
        )


def test_a_failed_scan_records_a_redacted_error_and_can_be_queued_again(scanner):
    vid = queued_version()
    scanner.clone_error = RuntimeError(
        "fatal: could not read from https://bot:s3cr3t-token@github.com/example/repo"
    )
    result = run(vid)
    assert result["ok"] is False
    assert "s3cr3t-token" not in result["error"]
    version = state(vid)
    assert version.dependency_discovery_status == "error"
    assert "s3cr3t-token" not in version.dependency_discovery_error
    assert "github.com/example/repo" in version.dependency_discovery_error
    assert version.dependency_discovery_finished_at is not None

    # A failed scan does not run again until it is queued again.
    assert run(vid) == {"skipped": True, "reason": "not_queued"}
    scanner.clone_error = None
    with SessionLocal() as s:
        s.get(ProjectVersion, vid).dependency_discovery_status = "queued"
        s.commit()
    assert run(vid)["ok"] is True
    assert state(vid).dependency_discovery_error is None


def test_a_scan_runs_once_however_many_times_it_is_handed_over(scanner):
    vid = queued_version()
    assert run(vid)["ok"] is True
    for status in ("complete", "running", "not_run"):
        with SessionLocal() as s:
            s.get(ProjectVersion, vid).dependency_discovery_status = status
            s.commit()
        assert run(vid) == {"skipped": True, "reason": "not_queued"}
    assert len(scanner.clones) == 1


def test_nothing_is_cloned_for_a_missing_version_or_one_without_source(
    scanner, monkeypatch
):
    assert run(999999) == {"skipped": True, "reason": "not_found"}
    vid = queued_version(link=None)
    with SessionLocal() as s:
        version = s.get(ProjectVersion, vid)
        version.dependency_count = 9
        version.dependency_last_commit = "stale"
        s.commit()
    assert run(vid) == {"skipped": True, "reason": "no_url"}
    version = state(vid)
    assert version.dependency_discovery_status == "not_run"
    assert (version.dependency_count, version.dependency_last_commit) == (0, None)

    ready = queued_version("2.0.0")
    monkeypatch.setattr(settings, "dependency_discovery_enabled", False)
    assert run(ready) == {"skipped": True, "reason": "disabled"}
    monkeypatch.setattr(settings, "dependency_discovery_enabled", True)
    monkeypatch.setattr(settings, "feature_dependency_scans", False)
    assert run(ready)["reason"] == "dependency_scans feature disabled"
    assert scanner.clones == []
    assert state(ready).dependency_discovery_status == "queued"


def test_the_dispatcher_hands_over_what_is_still_queued(scanner, monkeypatch):
    from app.tasks.dependency_queue import dispatch_queued_dependency_discoveries

    handed: list[int] = []

    class _Task:
        @staticmethod
        def apply_async(args, **_options):
            handed.append(int(args[0]))

    monkeypatch.setattr(dd, "discover_project_version_dependencies", _Task)
    first = queued_version("1.0.0")
    second = queued_version("2.0.0")
    queued_version("3.0.0", status="complete")
    queued_version("4.0.0", link=None)

    assert dispatch_queued_dependency_discoveries.run() == {"queued": 2, "launched": 2}
    assert sorted(handed) == [first, second]
    assert dispatch_queued_dependency_discoveries.run(limit=1)["queued"] == 1
    monkeypatch.setattr(settings, "feature_dependency_scans", False)
    assert dispatch_queued_dependency_discoveries.run() == {
        "ok": False,
        "reason": "dependency_scans feature disabled",
    }
