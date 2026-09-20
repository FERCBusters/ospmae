from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from app.core.config import settings

DEFAULT_ALLOWED_HOSTS = {"github.com", "gitlab.com", "codeberg.org"}

from .parsers import DiscoveredDependency, is_supported_lockfile, parse_lockfile

SKIP_DIRS = {
    ".git",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "target",
    ".venv",
    "venv",
    "__pycache__",
}


@dataclass
class ScanResult:
    commit: str | None
    dependencies: list[DiscoveredDependency]


def _allowed_hosts() -> set[str]:
    raw = str(getattr(settings, "dependency_discovery_allowed_hosts", "") or "").strip()
    if not raw:
        return set(DEFAULT_ALLOWED_HOSTS)
    return {h.strip().lower() for h in raw.split(",") if h.strip()}


def validate_repo_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme in ("http", "https", "git", "ssh"):
        host = (parsed.hostname or "").lower()
        allow = _allowed_hosts()
        if allow and host and host not in allow:
            raise ValueError(f"Repo host not allowed: {host}")
        return
    # SCP-like ssh URL: git@github.com:org/repo.git
    if "://" not in url and ":" in url and "@" in url:
        host = url.split("@", 1)[1].split(":", 1)[0].lower()
        allow = _allowed_hosts()
        if allow and host and host not in allow:
            raise ValueError(f"Repo host not allowed: {host}")
        return
    raise ValueError("Unsupported repository URL scheme")


def _run(cmd: list[str], *, cwd: Path | None = None, timeout: int = 180) -> str:
    proc = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
        env={
            **os.environ,
            "GIT_TERMINAL_PROMPT": "0",
        },
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"Command failed ({proc.returncode}): {' '.join(cmd)}\n{proc.stdout}"
        )
    return proc.stdout


def _extract_repo_and_tag(url: str) -> tuple[str, str | None]:
    """Return (clone_url, tag) if the given URL looks like a release/tag URL.

    Supports common GitHub-style URLs like:
      - https://github.com/org/repo/releases/tag/v1.2.3
      - https://github.com/org/repo/releases/download/v1.2.3/asset

    For non-HTTP(S) URLs (ssh/scp/git), returns the original URL.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return url, None

    if parsed.scheme not in ("http", "https"):
        return url, None

    parts = [p for p in (parsed.path or "").split("/") if p]
    # need at least: org/repo/releases/tag/<tag>
    if len(parts) >= 5 and parts[2] == "releases" and parts[3] == "tag":
        org, repo, _, _, tag = parts[:5]
        clone_url = f"{parsed.scheme}://{parsed.netloc}/{org}/{repo}"
        return clone_url, tag

    # org/repo/releases/download/<tag>/...
    if len(parts) >= 5 and parts[2] == "releases" and parts[3] == "download":
        org, repo, _, _, tag = parts[:5]
        clone_url = f"{parsed.scheme}://{parsed.netloc}/{org}/{repo}"
        return clone_url, tag

    return url, None


def _candidate_refs(*values: str | None) -> list[str]:
    cands: list[str] = []
    for v in values:
        vv = str(v or "").strip()
        if vv and vv not in cands:
            cands.append(vv)

    # common tag variants: v1.2.3 <-> 1.2.3
    more: list[str] = []
    for c in list(cands):
        if c.startswith("v") and len(c) > 1:
            more.append(c[1:])
        if not c.startswith("v") and c and c[0].isdigit():
            more.append("v" + c)

    for m in more:
        mm = str(m).strip()
        if mm and mm not in cands:
            cands.append(mm)

    return cands


def _remote_has_ref(url: str, ref: str, *, kind: str) -> bool:
    """Check if remote has a tag/branch ref without cloning the full repo."""
    if kind == "tag":
        query = f"refs/tags/{ref}"
        cmd = ["git", "ls-remote", "--tags", "--refs", url, query]
    else:
        query = f"refs/heads/{ref}"
        cmd = ["git", "ls-remote", "--heads", url, query]

    timeout = int(
        getattr(settings, "dependency_discovery_clone_timeout_seconds", 180) or 180
    )
    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
        env={
            **os.environ,
            "GIT_TERMINAL_PROMPT": "0",
        },
        text=True,
    )
    return proc.returncode == 0 and bool((proc.stdout or "").strip())


def clone_repo(url: str, version_hint: str | None = None) -> tuple[Path, str | None]:
    # If someone supplied a release/tag URL, derive the actual repo URL and tag.
    clone_url, tag_from_url = _extract_repo_and_tag(url)

    validate_repo_url(clone_url)
    tmpdir = Path(tempfile.mkdtemp(prefix="ospmae_repo_"))
    try:
        timeout = int(
            getattr(settings, "dependency_discovery_clone_timeout_seconds", 180) or 180
        )

        # Prefer an explicit version hint over any tag embedded in the URL.
        # This prevents a copied older release/tag URL from forcing scans onto the
        # wrong commit when the ProjectVersion.version points at a newer release.
        ref_candidates = _candidate_refs(
            str(version_hint or "").strip() or None, tag_from_url
        )
        chosen_ref: str | None = None

        for ref in ref_candidates:
            if _remote_has_ref(clone_url, ref, kind="tag"):
                chosen_ref = ref
                break

        # If no tag, also allow an exact branch name match.
        if not chosen_ref:
            for ref in ref_candidates:
                if _remote_has_ref(clone_url, ref, kind="branch"):
                    chosen_ref = ref
                    break

        if chosen_ref:
            # Works for both tags and branches.
            _run(
                [
                    "git",
                    "clone",
                    "--depth",
                    "1",
                    "--branch",
                    chosen_ref,
                    "--single-branch",
                    clone_url,
                    str(tmpdir),
                ],
                timeout=timeout,
            )
        else:
            # default branch as before
            _run(
                ["git", "clone", "--depth", "1", clone_url, str(tmpdir)],
                timeout=timeout,
            )

        commit = None
        try:
            commit = _run(["git", "rev-parse", "HEAD"], cwd=tmpdir, timeout=30).strip()
        except Exception:
            commit = None
        return tmpdir, commit
    except Exception:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise


def find_lockfiles(repo_root: Path) -> list[Path]:
    max_files = int(getattr(settings, "dependency_discovery_max_files", 2500) or 2500)

    out: list[Path] = []
    visited = 0
    for root, dirs, files in os.walk(repo_root):
        # prune
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        visited += 1
        if visited > max_files:
            break

        for f in files:
            if f in (".DS_Store",):
                continue
            p = Path(root) / f
            if is_supported_lockfile(p):
                out.append(p)
        if len(out) >= 60:
            # cap per repo to avoid extreme monorepos
            break
    return out


def scan_repo(url: str, version_hint: str | None = None) -> ScanResult:
    if not bool(getattr(settings, "dependency_discovery_enabled", True)):
        return ScanResult(commit=None, dependencies=[])

    repo_path, commit = clone_repo(url, version_hint=version_hint)
    try:
        max_bytes = int(
            getattr(settings, "dependency_discovery_max_file_bytes", 5_000_000)
            or 5_000_000
        )
        deps: list[DiscoveredDependency] = []
        for lockfile in find_lockfiles(repo_path):
            deps.extend(parse_lockfile(lockfile, max_bytes=max_bytes))
        return ScanResult(commit=commit, dependencies=deps)
    finally:
        shutil.rmtree(repo_path, ignore_errors=True)
