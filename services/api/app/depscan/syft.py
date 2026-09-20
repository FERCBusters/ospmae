from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from celery.utils.log import get_task_logger

from app.core.config import settings
from app.depscan.parsers import DiscoveredDependency

log = get_task_logger(__name__)

ECOSYSTEM_MAP = {
    # Keep OSPMAE's previous ecosystem names for existing lockfile-backed data.
    "npm": "npm",
    "yarn": "npm",
    "pnpm": "npm",
    "javascript": "npm",
    "node": "npm",
    "nodejs": "npm",
    "python": "python",
    "python-pkg": "python",
    "pypi": "python",
    "go": "go",
    "go-module": "go",
    "go-module-binary": "go",
    "golang": "go",
    "cargo": "cargo",
    "rust-crate": "cargo",
    "rust": "cargo",
    "composer": "composer",
    "php-composer": "composer",
    "php-composer-installed": "composer",
    "php": "composer",
}


def _syft_cmd() -> str:
    return str(getattr(settings, "syft_cmd", "syft") or "syft")


def syft_available() -> bool:
    return shutil.which(_syft_cmd()) is not None


def _scan_timeout_seconds() -> int:
    value = int(getattr(settings, "syft_timeout_seconds", 300) or 300)
    return max(30, value)


def _purl_type(purl: str) -> str:
    package_url = str(purl or "").strip().lower()
    if not package_url.startswith("pkg:"):
        return ""
    rest = package_url[4:]
    return rest.split("/", 1)[0].split(":", 1)[0].strip()


def _clean_ecosystem(value: str) -> str | None:
    clean = str(value or "").strip().lower().replace("_", "-")
    if not clean:
        return None
    clean = ECOSYSTEM_MAP.get(clean, clean)
    # dependency_packages.ecosystem is varchar(32). Keep raw Syft/Grype types
    # such as java-archive and gem, but guard against future verbose labels.
    return clean[:32]


def _ecosystem(
    raw_type: str, language: str | None = None, purl: str | None = None
) -> str | None:
    raw = str(raw_type or "").strip().lower()
    lang = str(language or "").strip().lower()
    purl_type = _purl_type(str(purl or ""))

    # Prefer the concrete Syft package type because Grype reports vulnerability
    # artifact types the same way; using the same value lets vulnerability rows
    # join back to the project dependency inventory. Fall back to language/PURL.
    for value in (raw, purl_type, lang):
        eco = _clean_ecosystem(value)
        if eco:
            return eco
    return None


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
        ecosystem = _ecosystem(
            str(artifact.get("type") or ""),
            str(artifact.get("language") or ""),
            str(artifact.get("purl") or ""),
        )
        if not ecosystem:
            continue
        name = str(artifact.get("name") or "").strip()
        version = str(artifact.get("version") or "").strip()
        if not name:
            continue
        paths = _location_paths(artifact, repo_root)
        source_file = paths[0] if paths else "syft"
        out.append(
            DiscoveredDependency(
                ecosystem=ecosystem,
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
