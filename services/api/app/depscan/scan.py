from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from app.core.config import settings
from app.security.repo_credentials import RepoCredential, git_auth_env

DEFAULT_ALLOWED_HOSTS = {"github.com", "gitlab.com", "codeberg.org"}

from .parsers import (  # noqa: E402 - module re-export root; config import precedes
    DiscoveredDependency,
    is_supported_lockfile,
    redact_url,
)

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

# Component characters and whitespace are never part of a repository URL.
_URL_REJECT_CHARS = set(" \t\r\n\0\\'\"<>")

# Characters git refuses in a ref name (git check-ref-format), plus the glob
# characters ls-remote would expand as a pattern.
_REF_REJECT_CHARS = set(" ~^:?*[\\{}")


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
    raw = str(url or "").strip()
    if not raw:
        raise ValueError("Repository URL is empty")
    if any(ch in _URL_REJECT_CHARS for ch in raw):
        raise ValueError("Repository URL contains an unsafe character")

    parsed = urlparse(raw)
    if parsed.username or parsed.password:
        # A token typed into a URL would be stored and echoed in error
        # messages; credentials never belong in a repo URL here.
        raise ValueError("Repository URL must not contain credentials")

    if parsed.scheme in ("http", "https", "git", "ssh"):
        host = (parsed.hostname or "").lower()
        # The host is part of the allowlist decision; a URL without one (for
        # example "https:/evil") can be re-interpreted by git as a different
        # destination than urlparse saw, so it is refused outright.
        if not host:
            raise ValueError("Repository URL has no host")
        allow = _allowed_hosts()
        if allow and host not in allow:
            raise ValueError(f"Repo host not allowed: {host}")
        return
    # SCP-like ssh URL: git@github.com:org/repo.git
    if "://" not in raw and ":" in raw and "@" in raw:
        host = raw.split("@", 1)[1].split(":", 1)[0].lower()
        if not host:
            raise ValueError("Repository URL has no host")
        allow = _allowed_hosts()
        if allow and host not in allow:
            raise ValueError(f"Repo host not allowed: {host}")
        return
    raise ValueError("Unsupported repository URL scheme")


def validate_git_ref_name(name: str) -> str:
    """Return a branch or tag name that git and ls-remote take literally.

    Follows git check-ref-format for one ref under refs/heads/ or refs/tags/,
    and refuses a leading "-" so the value can never read as a git option.
    Every ref that reaches ls-remote or clone passes through here.
    """

    ref = str(name or "").strip()
    if not ref:
        raise ValueError("Branch name is empty")
    if ref.startswith("-"):
        raise ValueError("Branch name must not start with '-'")
    if any(ord(ch) < 32 or ord(ch) == 0x7F for ch in ref):
        raise ValueError("Branch name contains a control character")
    if any(ch in _REF_REJECT_CHARS for ch in ref):
        raise ValueError("Branch name contains a character git does not allow")
    if ref == "@" or ".." in ref or "@{" in ref or "//" in ref:
        raise ValueError("Branch name is not a valid git ref")
    if ref.startswith("/") or ref.endswith("/") or ref.endswith("."):
        raise ValueError("Branch name is not a valid git ref")
    for part in ref.split("/"):
        if part.startswith(".") or part.endswith(".lock"):
            raise ValueError("Branch name is not a valid git ref")
    return ref


def _git_env() -> dict[str, str]:
    """A fixed environment for git children, not the worker's full env.

    Credential helpers, proxy variables and other worker configuration are
    inherited by every clone otherwise; the clone world is limited to PATH,
    locale markers, and git flags that disable prompts, config files (with
    their hooks and rewrites) and askpass helpers.
    """

    path = os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")
    return {
        "PATH": path,
        "HOME": "/tmp",
        "LC_ALL": "C",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_ASKPASS": "/bin/true",
        "GIT_CONFIG_NOSYSTEM": "1",
    }


# Commands run with these fixed flags; http.followRedirects=off keeps the
# validated allowlisted host from 3xx-ing a clone to any other destination.
_GIT_FLAGS = ["-c", "http.followRedirects=off"]


def _run(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    timeout: int = 180,
    env: dict[str, str] | None = None,
) -> str:
    proc = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
        env=env or _git_env(),
        text=True,
    )
    if proc.returncode != 0:
        # The command line can carry a caller-supplied URL; report it
        # credentials redacted.
        raise RuntimeError(
            f"Command failed ({proc.returncode}): "
            f"{' '.join(redact_url(part) for part in cmd)}\n{redact_url(proc.stdout)}"
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


def _remote_has_ref(
    url: str, ref: str, *, kind: str, env: dict[str, str] | None = None
) -> bool:
    """Check if remote has a tag/branch ref without cloning the full repo.

    The ref is only ever used as a positional pattern prefixed with
    ``refs/tags/`` or ``refs/heads/``, so an option-shaped value cannot reach
    git's option parser.
    """
    try:
        safe_ref = validate_git_ref_name(ref)
    except ValueError:
        return False
    if kind == "tag":
        query = f"refs/tags/{safe_ref}"
        cmd = ["git", *_GIT_FLAGS, "ls-remote", "--tags", "--refs", url, query]
    else:
        query = f"refs/heads/{safe_ref}"
        cmd = ["git", *_GIT_FLAGS, "ls-remote", "--heads", url, query]

    timeout = int(
        getattr(settings, "dependency_discovery_clone_timeout_seconds", 180) or 180
    )
    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
        env=env or _git_env(),
        text=True,
    )
    return proc.returncode == 0 and bool((proc.stdout or "").strip())


def clone_repo(
    url: str,
    version_hint: str | None = None,
    *,
    branch: str | None = None,
    credential: RepoCredential | None = None,
) -> tuple[Path, str | None]:
    """Shallow-clone a repository into a fresh temporary directory.

    With ``branch`` the clone is exactly the head of that branch (a tracked
    branch project), and a branch the remote lacks is an error rather than
    a silent fall back to the default branch. Otherwise ``version_hint``
    selects a matching tag, then a matching branch, then the default branch.
    A private repository's ``credential`` authenticates the remote commands
    only, and only over HTTPS to the host it was saved for.
    """

    # If someone supplied a release/tag URL, derive the actual repo URL and tag.
    clone_url, tag_from_url = _extract_repo_and_tag(url)

    validate_repo_url(clone_url)
    tracked_branch = validate_git_ref_name(branch) if branch is not None else None
    env = _git_env()
    if credential is not None:
        env.update(git_auth_env(credential, clone_url))
    tmpdir = Path(tempfile.mkdtemp(prefix="ospmae_repo_"))
    try:
        timeout = int(
            getattr(settings, "dependency_discovery_clone_timeout_seconds", 180) or 180
        )

        chosen_ref: str | None = None
        if tracked_branch is not None:
            if not _remote_has_ref(clone_url, tracked_branch, kind="branch", env=env):
                raise RuntimeError(
                    f"Branch {tracked_branch} was not found in the repository"
                )
            chosen_ref = tracked_branch
        else:
            # Prefer an explicit version hint over any tag embedded in the URL.
            # This prevents a copied older release/tag URL from forcing scans
            # onto the wrong commit when the ProjectVersion.version points at a
            # newer release.
            ref_candidates = _candidate_refs(
                str(version_hint or "").strip() or None, tag_from_url
            )

            for ref in ref_candidates:
                if _remote_has_ref(clone_url, ref, kind="tag", env=env):
                    chosen_ref = ref
                    break

            # If no tag, also allow an exact branch name match.
            if not chosen_ref:
                for ref in ref_candidates:
                    if _remote_has_ref(clone_url, ref, kind="branch", env=env):
                        chosen_ref = ref
                        break

        if chosen_ref:
            # Works for both tags and branches.
            _run(
                [
                    "git",
                    *_GIT_FLAGS,
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
                env=env,
            )
        else:
            # default branch as before
            _run(
                ["git", *_GIT_FLAGS, "clone", "--depth", "1", clone_url, str(tmpdir)],
                timeout=timeout,
                env=env,
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
    files_seen = 0
    for root, dirs, files in os.walk(repo_root):
        # prune
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        visited += 1
        if visited > max_files:
            break

        for f in files:
            files_seen += 1
            if files_seen > max_files:
                out = out[:60]
                return out
            if f in (".DS_Store",):
                continue
            p = Path(root) / f
            # Symlinks never contribute a lockfile here: a link named
            # package-lock.json could point anywhere on the worker fs.
            if p.is_symlink():
                continue
            if is_supported_lockfile(p):
                out.append(p)
        if len(out) >= 60:
            # cap per repo to avoid extreme monorepos
            break
    return out
