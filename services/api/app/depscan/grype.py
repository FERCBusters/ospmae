from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from celery.utils.log import get_task_logger

from app.core.config import settings

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


@dataclass(frozen=True)
class VulnFinding:
    ecosystem: str
    package: str
    version: str
    vulnerability_id: str
    severity: str | None
    title: str | None
    fixed_version: str | None
    references: list[str]
    raw: dict[str, Any]


def _grype_cmd() -> str:
    return str(getattr(settings, "grype_cmd", "grype") or "grype")


def grype_available() -> bool:
    return shutil.which(_grype_cmd()) is not None


def _scan_timeout_seconds() -> int:
    value = int(getattr(settings, "grype_timeout_seconds", 300) or 300)
    return max(30, value)


def _fixed_version(value: Any) -> str | None:
    if not isinstance(value, dict):
        return None
    versions = value.get("versions")
    if isinstance(versions, list):
        fixed = ", ".join(str(v).strip() for v in versions if str(v or "").strip())
        if fixed:
            return fixed
    return None


def _references(vulnerability: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for key in ("urls", "references"):
        raw = vulnerability.get(key)
        if isinstance(raw, list):
            for item in raw:
                if isinstance(item, str):
                    val = item.strip()
                elif isinstance(item, dict):
                    val = str(item.get("url") or item.get("href") or "").strip()
                else:
                    val = ""
                if val and val not in refs:
                    refs.append(val)
    data_source = str(vulnerability.get("dataSource") or "").strip()
    if data_source and data_source not in refs:
        refs.append(data_source)
    return refs


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
    return clean[:32]


def _ecosystem(raw_type: str, purl: str | None = None) -> str | None:
    raw = str(raw_type or "").strip().lower()
    purl_type = _purl_type(str(purl or ""))
    # Prefer the concrete Grype/Syft artifact type so java-archive, gem, npm,
    # etc. use the same ecosystem key as the Syft dependency inventory.
    for value in (raw, purl_type):
        eco = _clean_ecosystem(value)
        if eco:
            return eco
    return None


def scan_grype(repo_root: Path) -> list[VulnFinding] | None:
    """Run Grype against a cloned repository and return normalized findings.

    Syft populates OSPMAE's dependency inventory. Grype refreshes vulnerability
    metadata for matching package versions. If Grype is disabled or unavailable,
    dependency discovery remains a best-effort operation and this returns no
    findings.
    """

    if not bool(getattr(settings, "grype_enabled", False)):
        return None
    if not grype_available():
        log.warning("Grype scanning is enabled but %s is not available", _grype_cmd())
        return None

    cmd = [
        _grype_cmd(),
        f"dir:{repo_root}",
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
            "Grype scan failed with return code %s: %s",
            proc.returncode,
            (proc.stderr or proc.stdout or "").strip()[:2000],
        )
        return None

    try:
        data = json.loads(proc.stdout or "{}")
    except Exception:
        log.warning("Grype returned non-JSON output")
        return None

    matches = data.get("matches") if isinstance(data, dict) else None
    if not isinstance(matches, list):
        return []

    out: list[VulnFinding] = []
    for match in matches:
        if not isinstance(match, dict):
            continue
        artifact = match.get("artifact")
        vulnerability = match.get("vulnerability")
        if not isinstance(artifact, dict) or not isinstance(vulnerability, dict):
            continue

        ecosystem = _ecosystem(
            str(artifact.get("type") or ""), str(artifact.get("purl") or "")
        )
        if not ecosystem:
            continue

        pkg = str(artifact.get("name") or "").strip()
        ver = str(artifact.get("version") or "").strip()
        vid = str(vulnerability.get("id") or "").strip()
        if not (pkg and vid):
            continue

        title = str(
            vulnerability.get("description")
            or vulnerability.get("namespace")
            or vulnerability.get("id")
            or ""
        ).strip()

        out.append(
            VulnFinding(
                ecosystem=ecosystem,
                package=pkg,
                version=ver,
                vulnerability_id=vid,
                severity=str(vulnerability.get("severity") or "") or None,
                title=title or None,
                fixed_version=_fixed_version(vulnerability.get("fix")),
                references=_references(vulnerability),
                raw=match,
            )
        )
    return out
