from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from mosp.core.task_deadline import TIME_LIMITS
from mosp.security.redaction import redact_str

from app.core.config import settings
from app.security.repo_credentials import RepoCredential, git_auth_env

DEFAULT_ALLOWED_HOSTS = {"github.com", "gitlab.com", "codeberg.org"}

from .parsers import (  # noqa: E402 - module re-export root; config import precedes
    DiscoveredDependency,
    is_supported_lockfile,
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

# The SCP-like form git accepts for SSH: account@host:path. The account and
# the path start with a letter, digit or underscore, so no part of the value
# can read as a git option, and the account holds no ":" for git to read as
# a transport ("ext::", "fd::").
_SCP_LIKE_URL = re.compile(
    r"^[A-Za-z0-9_][A-Za-z0-9._-]*@(?P<host>[A-Za-z0-9.-]+):(?!-)[A-Za-z0-9_~./-][^:]*$"
)

# Characters git refuses in a ref name (git check-ref-format), plus the glob
# characters ls-remote would expand as a pattern.
_REF_REJECT_CHARS = set(" ~^:?*[\\{}")


@dataclass
class ScanResult:
    commit: str | None
    dependencies: list[DiscoveredDependency]


def _allowed_hosts() -> set[str]:
    """The hosts a clone may name. A setting that lists none allows none."""
    raw = str(getattr(settings, "dependency_discovery_allowed_hosts", "") or "").strip()
    if not raw:
        return set(DEFAULT_ALLOWED_HOSTS)
    return {h.strip().lower() for h in raw.split(",") if h.strip()}


def _is_control(ch: str) -> bool:
    return ord(ch) < 32 or ord(ch) == 127


def validate_repo_url(url: str) -> None:
    raw = str(url or "").strip()
    if not raw:
        raise ValueError("Repository URL is empty")
    # The value is judged as git will receive it. urlparse drops some leading
    # control characters before it reads a scheme; git does not.
    text = str(url or "")
    if any(ch in _URL_REJECT_CHARS or _is_control(ch) for ch in text.strip(" \t\r\n")):
        raise ValueError("Repository URL contains an unsafe character")
    # git reads an argument beginning with "-" as one of its options, and
    # --upload-pack names a command it runs. No repository URL starts so.
    if raw.startswith("-"):
        raise ValueError("Repository URL must not start with '-'")

    parsed = urlparse(raw)
    if parsed.username or parsed.password:
        # A token typed into a URL would be stored and echoed in error
        # messages; credentials never belong in a repo URL here.
        raise ValueError("Repository URL must not contain credentials")

    if parsed.scheme in ("http", "https", "git", "ssh"):
        # urlparse folds the scheme's case; git is given the text as typed.
        if not raw.startswith(f"{parsed.scheme}://"):
            raise ValueError("Unsupported repository URL scheme")
        host = (parsed.hostname or "").lower()
        # The host is part of the allowlist decision; a URL without one (for
        # example "https:/evil") can be re-interpreted by git as a different
        # destination than urlparse saw, so it is refused outright.
        if not host:
            raise ValueError("Repository URL has no host")
        if host not in _allowed_hosts():
            raise ValueError(f"Repo host not allowed: {host}")
        return
    # SCP-like ssh URL: git@github.com:org/repo.git
    scp_like = _SCP_LIKE_URL.match(raw)
    if scp_like:
        host = scp_like.group("host").lower()
        if host not in _allowed_hosts():
            raise ValueError(f"Repo host not allowed: {host}")
        return
    raise ValueError("Unsupported repository URL scheme")


# The path segment that separates a repository from its releases on the forges
# the scanner clones from: /owner/repo/releases/tag/v1 (GitHub, Forgejo, Gitea,
# Codeberg), /group/sub/project/-/releases/v1 and /-/tags (GitLab), and the
# feed addresses themselves (/owner/repo/releases.rss, .atom).
_RELEASE_PATH_MARKERS = frozenset(
    {
        "releases",
        "releases.rss",
        "releases.atom",
        "tags",
        "tags.rss",
        "tags.atom",
    }
)


def repository_url_for_release_link(link: str | None) -> str | None:
    """The repository a release link belongs to, when its host may be cloned.

    The repository is the part of the path before the releases segment. A
    feed entry drives later git clones, so the derived link passes the same
    repo-URL validation as operator-supplied ones: no embedded credentials
    and a host on OSPMAE_DEPENDENCY_DISCOVERY_ALLOWED_HOSTS. Anything else
    yields None.
    """

    if not link:
        return None
    try:
        parsed = urlparse(link)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return None
        parts = [x for x in parsed.path.split("/") if x]
        marker = next(
            (i for i, part in enumerate(parts) if part in _RELEASE_PATH_MARKERS),
            None,
        )
        if marker is not None:
            repo_parts = parts[:marker]
            if repo_parts and repo_parts[-1] == "-":
                repo_parts = repo_parts[:-1]
        elif parsed.hostname.lower() == "github.com":
            # A bare GitHub repository link.
            repo_parts = parts[:2]
        else:
            return None
        if len(repo_parts) < 2:
            return None
        # netloc keeps a port, and any credentials for validation to refuse.
        candidate = f"https://{parsed.netloc.lower()}/{'/'.join(repo_parts)}"
        validate_repo_url(candidate)
        return candidate
    except ValueError:
        return None


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


# What a scanner may take from the worker's environment: where its own cache
# and database live, its own settings, and how it reaches the network for a
# database update. Everything else (database, broker and mail passwords, the
# encryption key) stays out of a process that reads a hostile repository.
_SCANNER_ENV_NAMES = frozenset(
    {
        "HOME",
        "TMPDIR",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "no_proxy",
    }
)
_SCANNER_ENV_PREFIXES = ("SYFT_", "GRYPE_")

# Scanners start here, not in the clone: both read a configuration file from
# the directory they are started in.
SCANNER_CWD = "/"


def scanner_env() -> dict[str, str]:
    """A fixed environment for syft and grype, not the worker's full env."""

    env = {
        name: value
        for name, value in os.environ.items()
        if name in _SCANNER_ENV_NAMES or name.startswith(_SCANNER_ENV_PREFIXES)
    }
    env["PATH"] = os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")
    env["LC_ALL"] = "C"
    env.setdefault("HOME", "/tmp")
    return env


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
            f"{' '.join(redact_str(part) for part in cmd)}\n{redact_str(proc.stdout)}"
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
    except TIME_LIMITS:
        raise
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
    git's option parser. The URL follows ``--``, which ends git's options, so
    it is read as a repository whatever it holds.
    """
    try:
        safe_ref = validate_git_ref_name(ref)
    except ValueError:
        return False
    if kind == "tag":
        query = f"refs/tags/{safe_ref}"
        cmd = ["git", *_GIT_FLAGS, "ls-remote", "--tags", "--refs", "--", url, query]
    else:
        query = f"refs/heads/{safe_ref}"
        cmd = ["git", *_GIT_FLAGS, "ls-remote", "--heads", "--", url, query]

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
                    "--",
                    clone_url,
                    str(tmpdir),
                ],
                timeout=timeout,
                env=env,
            )
        else:
            # default branch as before
            _run(
                [
                    "git",
                    *_GIT_FLAGS,
                    "clone",
                    "--depth",
                    "1",
                    "--",
                    clone_url,
                    str(tmpdir),
                ],
                timeout=timeout,
                env=env,
            )

        commit = None
        try:
            commit = _run(["git", "rev-parse", "HEAD"], cwd=tmpdir, timeout=30).strip()
        except TIME_LIMITS:
            raise
        except Exception:
            commit = None
        return tmpdir, commit
    except BaseException:
        # A clone that does not finish, the time limit included, leaves no
        # directory behind.
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
