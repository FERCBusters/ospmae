from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from celery.utils.log import get_task_logger

from app.core.config import settings
from app.depscan.ecosystems import ecosystem, purl_type
from app.depscan.parsers import DiscoveredDependency

log = get_task_logger(__name__)


def _syft_cmd() -> str:
    return str(getattr(settings, "syft_cmd", "syft") or "syft")


def syft_available() -> bool:
    return shutil.which(_syft_cmd()) is not None


def _scan_timeout_seconds() -> int:
    value = int(getattr(settings, "syft_timeout_seconds", 300) or 300)
    return max(30, value)


def _location_paths(artifact: dict[str, Any], repo_root: Path) -> list[str]:
    paths: list[str] = []
    locations = artifact.get("locations")
    if not isinstance(locations, list):
        return paths
    for loc in locations:
        if not isinstance(loc, dict):
            continue
        raw = str(loc.get("path") or loc.get("accessPath") or "").strip()
        if not raw:
            continue
        # Syft usually reports paths relative to the scanned target, but be
        # defensive for absolute paths when source providers change.
        try:
            p = Path(raw)
            if p.is_absolute():
                raw = str(p.relative_to(repo_root))
        except Exception:
            pass
        if raw and raw not in paths:
            paths.append(raw)
    return paths


def scan_syft(repo_root: Path) -> list[DiscoveredDependency] | None:
    """Catalog dependencies with Syft and map them into OSPMAE's dependency model.

    Grype is a vulnerability matcher. Syft is Anchore's package cataloger/SBOM
    generator, so this supplies the full dependency inventory that Grype itself
    does not expose as vulnerability-free matches.
    """

    if not bool(getattr(settings, "syft_enabled", True)):
        return None
    if not syft_available():
        log.warning("Syft cataloging is enabled but %s is not available", _syft_cmd())
        return None

    cmd = [
        _syft_cmd(),
        "scan",
        str(repo_root),
        "--quiet",
        "--output",
        "json",
    ]
    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=_scan_timeout_seconds(),
    )
    if proc.returncode != 0:
        log.warning(
            "Syft catalog failed with return code %s: %s",
            proc.returncode,
            (proc.stderr or proc.stdout or "").strip()[:2000],
        )
        return None

    try:
        data = json.loads(proc.stdout or "{}")
    except Exception:
        log.warning("Syft returned non-JSON output")
        return None

    artifacts = data.get("artifacts") if isinstance(data, dict) else None
    if not isinstance(artifacts, list):
        return []

    out: list[DiscoveredDependency] = []
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            continue
        eco = ecosystem(
            artifact.get("type"),
            purl_type(str(artifact.get("purl") or "")),
            artifact.get("language"),
        )
        if not eco:
            continue
        name = str(artifact.get("name") or "").strip()
        version = str(artifact.get("version") or "").strip()
        if not name:
            continue
        paths = _location_paths(artifact, repo_root)
        source_file = paths[0] if paths else "syft"
        out.append(
            DiscoveredDependency(
                ecosystem=eco,
                name=name,
                version=version,
                # Syft is an inventory source, not a dependency graph resolver;
                # use indirect=True unless a lockfile parser later marks the same
                # package/version as direct. _apply_dependencies merges this.
                is_indirect=True,
                source_file=source_file,
            )
        )
    return out
