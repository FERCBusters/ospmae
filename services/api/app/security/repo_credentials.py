"""Access tokens for private repositories, one per project.

A token is write-only: the API stores it Fernet-encrypted, reports only
whether one is set, and never returns it. It is bound to one host when it is
saved and is sent only over HTTPS to that host, as an HTTP Authorization
header set through git's environment configuration, so it appears in no
command line, URL, stored error or log.

The Fernet key is derived from ``OSPMAE_MFA_ENCRYPTION_KEY`` with HKDF for this
purpose alone, so a stored TOTP secret and a stored token cannot stand in for
one another, and one installation secret protects both.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.core.config import settings

MAX_TOKEN_CHARS = 1024
_HKDF_INFO = b"ospmae/repository-access-token/v1"
# The account name each host expects alongside a token, where the host
# documents one that works for every token. Other hosts need it entered.
_DEFAULT_USERNAMES = {
    "github.com": "x-access-token",
    "gitlab.com": "oauth2",
    "bitbucket.org": "x-token-auth",
}
_HOST = re.compile(
    r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}"
)
_USERNAME = re.compile(r"[A-Za-z0-9._@+-]{1,100}")
_TOKEN = re.compile(r"[\x21-\x7e]{1,%d}" % MAX_TOKEN_CHARS)


class RepoTokenUnavailable(RuntimeError):
    """The stored token cannot be used: no valid key, or a key that changed."""


@dataclass(frozen=True)
class RepoCredential:
    host: str
    username: str
    token: str = field(repr=False)
    # The one repository the token is used for; without it, for none.
    repository: str = ""


def _cipher() -> Fernet:
    key = (settings.mfa_encryption_key or "").strip()
    try:
        Fernet(key.encode())
        master = base64.urlsafe_b64decode(key.encode())
    except (ValueError, TypeError):
        raise RepoTokenUnavailable(
            "Private repository tokens require a valid OSPMAE_MFA_ENCRYPTION_KEY"
        ) from None
    derived = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=_HKDF_INFO
    ).derive(master)
    return Fernet(base64.urlsafe_b64encode(derived))


def encrypt_token(token: str) -> str:
    return _cipher().encrypt(token.encode()).decode()


def decrypt_token(ciphertext: str) -> str:
    try:
        return _cipher().decrypt(ciphertext.encode()).decode()
    except InvalidToken:
        raise RepoTokenUnavailable(
            "The private repository's access token cannot be read; enter it again"
        ) from None


def clean_token(value: str | None) -> str | None:
    """A token as typed, or None for "keep the saved one"."""
    token = (value or "").strip()
    if not token:
        return None
    if not _TOKEN.fullmatch(token):
        raise ValueError("Access tokens are printable characters without spaces")
    return token


def clean_host(value: str | None) -> str | None:
    host = (value or "").strip().lower().rstrip(".")
    if not host:
        return None
    if not _HOST.fullmatch(host):
        raise ValueError("Enter the host name the token is for, such as github.com")
    return host


# What separates a repository from a page inside it on the forges OSPMAE
# clones from: /owner/repo/releases/tag/v1, /owner/repo/tree/main,
# /group/sub/project/-/tags/v1 and the like.
_INSIDE_REPOSITORY = frozenset(
    {
        "-",
        "releases",
        "releases.atom",
        "releases.rss",
        "tags",
        "tags.atom",
        "tags.rss",
        "tree",
        "blob",
        "archive",
        "commit",
        "commits",
    }
)


def repository_of(url: str | None) -> str | None:
    """The repository an HTTPS address belongs to, written one way.

    ``https://<host>/<path>``: lower-case host, no ``.git``, no trailing
    slash, and nothing after the repository (a release, tag or tree page is
    reduced to its repository). None for anything that is not an HTTPS
    address of a repository: another scheme, a port, credentials, a query,
    or no path.
    """
    text = (url or "").strip()
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError:
        return None
    host = (parts.hostname or "").lower().rstrip(".")
    if (
        parts.scheme != "https"
        or not _HOST.fullmatch(host)
        or port not in (None, 443)
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
    ):
        return None
    segments: list[str] = []
    for segment in parts.path.split("/"):
        if not segment:
            continue
        if segment in _INSIDE_REPOSITORY and segments:
            break
        segments.append(segment)
    if segments and segments[-1].lower().endswith(".git"):
        segments[-1] = segments[-1][:-4]
    # An owner and a repository at the least.
    if len(segments) < 2 or any(s in {".", ".."} for s in segments):
        return None
    return f"https://{host}/{'/'.join(segments)}"


def same_repository(a: str | None, b: str | None) -> bool:
    """Whether two addresses name one repository. Forges read owner and
    repository names without regard to case."""
    first, second = repository_of(a), repository_of(b)
    return (
        first is not None
        and second is not None
        and (first.casefold() == second.casefold())
    )


def clean_repository(value: str | None) -> str | None:
    """The repository a token is entered for, or None for nothing entered."""
    text = (value or "").strip()
    if not text:
        return None
    repository = repository_of(text)
    if repository is None or len(repository) > 600:
        raise ValueError(
            "Enter the repository's HTTPS address, such as "
            "https://github.com/owner/repository"
        )
    return repository


def clean_username(value: str | None) -> str | None:
    name = (value or "").strip()
    if not name:
        return None
    if not _USERNAME.fullmatch(name):
        raise ValueError("Account names are letters, digits and . _ @ + -")
    return name


def default_username(host: str) -> str | None:
    if host in _DEFAULT_USERNAMES:
        return _DEFAULT_USERNAMES[host]
    if host.startswith("gitlab."):
        return "oauth2"
    return None


def project_credential(project) -> RepoCredential | None:
    """The credential a project's clones use, or None for a public repository."""
    if not getattr(project, "repo_private", False):
        return None
    ciphertext = getattr(project, "repo_token_encrypted", None)
    host = getattr(project, "repo_token_host", None)
    if not ciphertext or not host:
        raise RepoTokenUnavailable("The private repository has no access token")
    repository = repository_of(getattr(project, "repo_token_repository", None))
    if repository is None:
        # A token saved before tokens were bound to a repository is not
        # used until someone who can edit the project says which one.
        raise RepoTokenUnavailable(
            "Say which repository the access token is for on the project, "
            "and enter the token again"
        )
    username = getattr(project, "repo_token_username", None) or default_username(host)
    if not username:
        raise RepoTokenUnavailable("The private repository's token has no account name")
    return RepoCredential(
        host=host,
        username=username,
        token=decrypt_token(ciphertext),
        repository=repository,
    )


def git_auth_env(credential: RepoCredential, url: str) -> dict[str, str]:
    """Environment entries that authenticate git's HTTPS requests to the
    one repository the token is for.

    A clone of anything else is refused before git runs. The header is
    scoped to the repository being cloned, so git sends it to no other
    destination, on that host or elsewhere, and redirects stay disabled for
    every clone.
    """
    parts = urlsplit(url)
    try:
        port = parts.port
    except ValueError:
        port = -1
    if (
        parts.scheme != "https"
        or (parts.hostname or "").lower() != credential.host
        or port not in (None, 443)
    ):
        raise ValueError(
            f"This project's access token is used only over HTTPS with "
            f"{credential.host}; the repository URL is elsewhere"
        )
    if not same_repository(url, credential.repository):
        raise ValueError(
            f"This project's access token is for {credential.repository}; "
            "the repository URL is elsewhere"
        )
    basic = base64.b64encode(f"{credential.username}:{credential.token}".encode())
    # git sends the header to addresses under this one only: the repository
    # being cloned, not everything on its host.
    repository = f"https://{credential.host}{parts.path.rstrip('/')}"
    return {
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": f"http.{repository}.extraHeader",
        "GIT_CONFIG_VALUE_0": f"Authorization: Basic {basic.decode()}",
    }
