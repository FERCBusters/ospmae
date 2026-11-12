"""Shared builders for API tests: signed-in clients and catalogue data.

Data a maintainer enters goes through the API. Scan results are written the
way the dependency discovery task stores them, as rows, because the scanners
themselves (git, Syft, Grype) are outside the application.
"""

from __future__ import annotations

from app.db.models import (
    DependencyPackage,
    DependencyVersion,
    DependencyVulnerability,
    Group,
    ProjectVersion,
    ProjectVersionDependency,
    User,
    UserGroup,
)
from app.db.session import SessionLocal

from tests.conftest import auth_client

SOURCE = "https://github.com/example/repo"


def csrf(client) -> dict[str, str]:
    return {"X-CSRF-Token": client.cookies.get("__Host-ospmae_csrf") or ""}


def signed_in(role: str = "admin", *, email: str | None = None):
    """A signed-in client and its user id."""
    client, user = auth_client(role=role)
    if email is not None:
        with SessionLocal() as s:
            s.get(User, user.id).email = email
            s.commit()
    return client, user.id


def ok(response, status: int = 200):
    assert response.status_code == status, response.text
    return response.json() if response.content else None


def make_project(client, machine_name: str = "alpha", **fields) -> dict:
    body = {"machine_name": machine_name, "display_name": machine_name.title()}
    body.update(fields)
    return ok(client.post("/v1/projects", json=body, headers=csrf(client)))


def make_version(client, project_id: int, version: str = "1.0.0", **fields) -> dict:
    body = {"version": version}
    body.update(fields)
    return ok(
        client.post(
            f"/v1/projects/{project_id}/versions", json=body, headers=csrf(client)
        )
    )


def make_framework(client, machine_name: str = "tax", display_name="Taxonomy") -> dict:
    return ok(
        client.post(
            "/v1/frameworks",
            json={"machine_name": machine_name, "display_name": display_name},
            headers=csrf(client),
        )
    )


def make_node(client, framework_id: int, key: str, parent_id=None, **fields) -> dict:
    body = {"key": key, "display_name": key.title(), "parent_id": parent_id}
    body.update(fields)
    return ok(
        client.post(
            f"/v1/frameworks/{framework_id}/nodes", json=body, headers=csrf(client)
        )
    )


def map_nodes(client, version_id: int, framework_id: int, node_ids: list[int]) -> dict:
    return ok(
        client.put(
            f"/v1/project-versions/{version_id}/framework-nodes",
            json={"framework_id": framework_id, "node_ids": node_ids},
            headers=csrf(client),
        )
    )


def make_group(name: str, *, role: str | None = None, members=()) -> int:
    with SessionLocal() as s:
        group = Group(name=name, role=role)
        s.add(group)
        s.flush()
        for user_id in members:
            s.add(UserGroup(user_id=user_id, group_id=group.id))
        s.commit()
        return group.id


def record_dependency(
    version_id: int,
    ecosystem: str,
    name: str,
    version: str,
    *,
    indirect: bool = False,
    source_files=("requirements.txt",),
    vulnerabilities=(),
) -> int:
    """One discovered dependency of a project version, with its findings.

    Each vulnerability is (id, severity, fixed_version). Returns the
    dependency version's id.
    """
    with SessionLocal() as s:
        package = (
            s.query(DependencyPackage)
            .filter_by(ecosystem=ecosystem, normalized_name=name.lower())
            .one_or_none()
        )
        if package is None:
            package = DependencyPackage(
                ecosystem=ecosystem, name=name, normalized_name=name.lower()
            )
            s.add(package)
            s.flush()
        dep_version = (
            s.query(DependencyVersion)
            .filter_by(dependency_id=package.id, version=version)
            .one_or_none()
        )
        if dep_version is None:
            dep_version = DependencyVersion(dependency_id=package.id, version=version)
            s.add(dep_version)
            s.flush()
            for vuln_id, severity, fixed in vulnerabilities:
                s.add(
                    DependencyVulnerability(
                        dependency_version_id=dep_version.id,
                        scanner="grype",
                        vulnerability_id=vuln_id,
                        severity=severity,
                        title=f"{vuln_id} in {name}",
                        fixed_version=fixed,
                        references=[f"https://advisories.example/{vuln_id}"],
                    )
                )
        s.add(
            ProjectVersionDependency(
                project_version_id=version_id,
                dependency_version_id=dep_version.id,
                is_indirect=indirect,
                source_files=list(source_files),
            )
        )
        s.commit()
        return dep_version.id


def set_scan_state(version_id: int, status: str, **columns) -> None:
    with SessionLocal() as s:
        version = s.get(ProjectVersion, version_id)
        version.dependency_discovery_status = status
        for key, value in columns.items():
            setattr(version, key, value)
        s.commit()
