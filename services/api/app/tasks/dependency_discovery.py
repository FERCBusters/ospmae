from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from pathlib import Path

from celery.utils.log import get_task_logger
from sqlalchemy import func, update
from sqlalchemy.orm import Session

from app.celery_app import celery_app
from app.core.config import settings
from app.db.models import (
    DependencyPackage,
    DependencyVersion,
    DependencyVulnerability,
    ProjectVersion,
    ProjectVersionDependency,
)
from app.db.session import SessionLocal
from app.depscan.parsers import DiscoveredDependency
from app.depscan.scan import clone_repo, find_lockfiles
from app.depscan.grype import scan_grype
from app.depscan.parsers import parse_lockfile
from app.depscan.syft import scan_syft

log = get_task_logger(__name__)


def _normalize(dep_name: str) -> str:
    return str(dep_name or "").strip().lower()


def _upsert_dependency(db: Session, ecosystem: str, name: str) -> DependencyPackage:
    norm = _normalize(name)
    dep = (
        db.query(DependencyPackage)
        .filter(DependencyPackage.ecosystem == ecosystem)
        .filter(DependencyPackage.normalized_name == norm)
        .one_or_none()
    )
    if dep:
        # keep latest observed display name
        if dep.name != name:
            dep.name = name
        return dep
    dep = DependencyPackage(ecosystem=ecosystem, name=name, normalized_name=norm)
    db.add(dep)
    db.flush()
    return dep


def _upsert_dependency_version(
    db: Session, dep: DependencyPackage, version: str
) -> DependencyVersion:
    ver = str(version or "").strip()
    dv = (
        db.query(DependencyVersion)
        .filter(DependencyVersion.dependency_id == dep.id)
        .filter(DependencyVersion.version == ver)
        .one_or_none()
    )
    if dv:
        return dv
    dv = DependencyVersion(dependency_id=dep.id, version=ver)
    db.add(dv)
    db.flush()
    return dv


def _apply_dependencies(
    db: Session,
    *,
    project_version_id: int,
    discovered: list[DiscoveredDependency],
) -> int:
    # Replace existing mappings (idempotent refresh).
    db.query(ProjectVersionDependency).filter(
        ProjectVersionDependency.project_version_id == project_version_id
    ).delete(synchronize_session=False)
    db.flush()

    merged: dict[tuple[str, str, str], dict] = {}
    for d in discovered:
        eco = str(d.ecosystem).strip().lower()
        name = str(d.name).strip()
        ver = str(d.version or "").strip()
        if not (eco and name):
            continue
        key = (eco, _normalize(name), ver)
        slot = merged.get(key)
        if not slot:
            slot = {
                "ecosystem": eco,
                "name": name,
                "version": ver,
                "is_indirect": bool(d.is_indirect),
                "sources": set(),
            }
            merged[key] = slot
        # If any parser says "direct", treat as direct.
        if not d.is_indirect:
            slot["is_indirect"] = False
        try:
            src = str(d.source_file)
            slot["sources"].add(src)
        except Exception:
            pass

    count = 0
    for slot in merged.values():
        dep = _upsert_dependency(db, slot["ecosystem"], slot["name"])
        dv = _upsert_dependency_version(db, dep, slot["version"])
        link = ProjectVersionDependency(
            project_version_id=project_version_id,
            dependency_version_id=dv.id,
            source_files=sorted(slot["sources"]),
            is_indirect=bool(slot["is_indirect"]),
        )
        db.add(link)
        count += 1
    return count


def _dependency_version_ids_for_project_version(
    db: Session, *, project_version_id: int
) -> list[int]:
    rows = (
        db.query(ProjectVersionDependency.dependency_version_id)
        .filter(ProjectVersionDependency.project_version_id == project_version_id)
        .all()
    )
    return [int(r[0]) for r in rows if r[0] is not None]


def _apply_vulns(db: Session, *, findings: list, project_version_id: int) -> int:
    # Replace Grype findings for dependency versions currently linked to this
    # project version, then upsert the fresh scanner output. Vulnerabilities are
    # stored globally per dependency version, so this refresh also benefits other
    # projects that use the same package version.
    dep_version_ids = _dependency_version_ids_for_project_version(
        db, project_version_id=project_version_id
    )
    if dep_version_ids:
        db.query(DependencyVulnerability).filter(
            DependencyVulnerability.dependency_version_id.in_(dep_version_ids),
            DependencyVulnerability.scanner == "grype",
        ).delete(synchronize_session=False)
        db.flush()

    # Grype can emit duplicate matches for the same package/version/advisory when
    # several CPEs, PURLs, locations, or matchers point at the same underlying
    # finding. The database intentionally has one row per
    # dependency_version/scanner/vulnerability_id, so deduplicate within this scan
    # before pending INSERTs are flushed at commit time.
    seen: set[tuple[int, str, str]] = set()

    for f in findings:
        eco = str(getattr(f, "ecosystem", "") or "").strip().lower()
        pkg = str(getattr(f, "package", "") or "").strip()
        ver = str(getattr(f, "version", "") or "").strip()
        vuln_id = str(getattr(f, "vulnerability_id", "") or "").strip()
        if not (eco and pkg and vuln_id):
            continue

        dep = _upsert_dependency(db, eco, pkg)
        dv = _upsert_dependency_version(db, dep, ver)
        dedupe_key = (int(dv.id), "grype", vuln_id)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)

        existing = (
            db.query(DependencyVulnerability)
            .filter(DependencyVulnerability.dependency_version_id == dv.id)
            .filter(DependencyVulnerability.scanner == "grype")
            .filter(DependencyVulnerability.vulnerability_id == vuln_id)
            .one_or_none()
        )
        if existing:
            existing.severity = f.severity
            existing.title = f.title
            existing.fixed_version = f.fixed_version
            existing.references = list(getattr(f, "references", []) or [])
            existing.raw = dict(getattr(f, "raw", {}) or {})
        else:
            db.add(
                DependencyVulnerability(
                    dependency_version_id=dv.id,
                    scanner="grype",
                    vulnerability_id=vuln_id,
                    severity=f.severity,
                    title=f.title,
                    fixed_version=f.fixed_version,
                    references=list(getattr(f, "references", []) or []),
                    raw=dict(getattr(f, "raw", {}) or {}),
                )
            )

    return _count_project_version_vulns(db, project_version_id=project_version_id)


def _count_project_version_vulns(db: Session, *, project_version_id: int) -> int:
    vuln_count = (
        db.query(func.count(DependencyVulnerability.id))
        .join(
            DependencyVersion,
            DependencyVersion.id == DependencyVulnerability.dependency_version_id,
        )
        .join(
            ProjectVersionDependency,
            ProjectVersionDependency.dependency_version_id == DependencyVersion.id,
        )
        .filter(ProjectVersionDependency.project_version_id == project_version_id)
        .scalar()
    )
    return int(vuln_count or 0)


@celery_app.task(
    name="app.tasks.dependency_discovery.discover_project_version_dependencies"
)
def discover_project_version_dependencies(project_version_id: int) -> dict:
    if not bool(getattr(settings, "dependency_discovery_enabled", True)):
        return {"skipped": True, "reason": "disabled"}

    db = SessionLocal()
    repo_dir: Path | None = None
    commit: str | None = None

    try:
        pv = db.get(ProjectVersion, project_version_id)
        if not pv:
            return {"skipped": True, "reason": "not_found"}
        url = str(pv.link_to_source_code or "").strip()
        if not url:
            # Nothing to do.
            db.execute(
                update(ProjectVersion)
                .where(ProjectVersion.id == project_version_id)
                .values(
                    dependency_discovery_status="not_run",
                    dependency_discovery_error=None,
                    dependency_discovery_started_at=None,
                    dependency_discovery_finished_at=None,
                    dependency_last_commit=None,
                    dependency_count=0,
                )
            )
            db.commit()
            return {"skipped": True, "reason": "no_url"}

        # Guard against concurrent scans.
        updated = db.execute(
            update(ProjectVersion)
            .where(ProjectVersion.id == project_version_id)
            .where(ProjectVersion.dependency_discovery_status != "running")
            .values(
                dependency_discovery_status="running",
                dependency_discovery_started_at=datetime.utcnow(),
                dependency_discovery_finished_at=None,
                dependency_discovery_error=None,
            )
        )
        if getattr(updated, "rowcount", 0) == 0:
            return {"skipped": True, "reason": "already_running"}
        db.commit()

        repo_dir, commit = clone_repo(
            url, version_hint=str(getattr(pv, "version", "") or "").strip() or None
        )
        max_bytes = int(
            getattr(settings, "dependency_discovery_max_file_bytes", 5_000_000)
            or 5_000_000
        )

        discovered: list[DiscoveredDependency] = []

        # Syft provides the complete package inventory/SBOM. Keep the existing
        # lockfile parsers as a supplemental fallback because they also flag some
        # direct dependencies that Syft reports only as package inventory.
        syft_items = scan_syft(repo_dir)
        if syft_items:
            discovered.extend(syft_items)

        for lockfile in find_lockfiles(repo_dir):
            # Rewrite absolute source_file -> relative for storage.
            items = parse_lockfile(lockfile, max_bytes=max_bytes)
            rel = str(lockfile.relative_to(repo_dir))
            discovered.extend(
                [
                    DiscoveredDependency(
                        ecosystem=x.ecosystem,
                        name=x.name,
                        version=x.version,
                        is_indirect=x.is_indirect,
                        source_file=rel,
                    )
                    for x in items
                ]
            )

        dep_count = _apply_dependencies(
            db, project_version_id=project_version_id, discovered=discovered
        )

        findings = scan_grype(repo_dir)
        if findings is not None:
            vuln_count = _apply_vulns(
                db, findings=findings, project_version_id=project_version_id
            )
        else:
            vuln_count = _count_project_version_vulns(
                db, project_version_id=project_version_id
            )

        db.execute(
            update(ProjectVersion)
            .where(ProjectVersion.id == project_version_id)
            .values(
                dependency_discovery_status="complete",
                dependency_discovery_finished_at=datetime.utcnow(),
                dependency_last_commit=commit,
                dependency_count=dep_count,
                vulnerability_count=vuln_count,
            )
        )
        db.commit()

        return {
            "ok": True,
            "dependencies": dep_count,
            "vulnerabilities": vuln_count,
            "commit": commit,
        }
    except Exception as exc:
        log.exception("Dependency discovery failed")
        try:
            db.execute(
                update(ProjectVersion)
                .where(ProjectVersion.id == project_version_id)
                .values(
                    dependency_discovery_status="error",
                    dependency_discovery_finished_at=datetime.utcnow(),
                    dependency_discovery_error=str(exc),
                )
            )
            db.commit()
        except Exception:
            db.rollback()
        return {"ok": False, "error": str(exc)}
    finally:
        try:
            if repo_dir:
                import shutil

                shutil.rmtree(repo_dir, ignore_errors=True)
        except Exception:
            pass
        db.close()
