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
    username = getattr(project, "repo_token_username", None) or default_username(host)
    if not username:
        raise RepoTokenUnavailable("The private repository's token has no account name")
    return RepoCredential(host=host, username=username, token=decrypt_token(ciphertext))


def git_auth_env(credential: RepoCredential, url: str) -> dict[str, str]:
    """Environment entries that authenticate git's HTTPS requests to one host.

    The header is scoped to ``https://<host>/``, so git sends it to no other
    destination, and redirects stay disabled for every clone.
    """
    parts = urlsplit(url)
    if parts.scheme != "https" or (parts.hostname or "").lower() != credential.host:
        raise ValueError(
            f"This project's access token is used only over HTTPS with "
            f"{credential.host}; the repository URL is elsewhere"
        )
    basic = base64.b64encode(f"{credential.username}:{credential.token}".encode())
    return {
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": f"http.https://{credential.host}/.extraHeader",
        "GIT_CONFIG_VALUE_0": f"Authorization: Basic {basic.decode()}",
    }
