from __future__ import annotations

import hmac
import secrets
from urllib.parse import urlsplit

from fastapi import Request, Response

from app.core.config import settings


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def host_bound_cookie_name(name: str) -> str:
    """A cookie's name, with the ``__Host-`` prefix where a browser allows it.

    A Secure cookie without a Domain attribute takes the prefix, which a
    browser accepts only from this host over HTTPS, so another site under the
    same parent domain can neither set nor shadow the cookie. A configured
    name that already carries a cookie prefix is kept as it is.
    """

    if (
        settings.cookie_secure
        and not settings.cookie_domain.strip()
        and not name.startswith(("__Host-", "__Secure-"))
    ):
        return "__Host-" + name
    return name


def csrf_cookie_name() -> str:
    """The CSRF cookie's name. The UI reads the prefixed cookie first and the
    configured name otherwise."""

    return host_bound_cookie_name(settings.csrf_cookie_name.strip() or "ospmae_csrf")


def get_csrf_token_from_request(request: Request) -> str:
    return (request.cookies.get(csrf_cookie_name()) or "").strip()


def _origin(value: str) -> tuple[str, str, int]:
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or "\\" in value
        or any(ord(c) < 32 or ord(c) == 127 for c in value)
    ):
        raise ValueError("Invalid origin")
    return (
        parsed.scheme,
        parsed.hostname.lower(),
        parsed.port or (443 if parsed.scheme == "https" else 80),
    )


def request_origin_allowed(request, *, require_origin: bool = False) -> bool:
    """Whether a browser request (HTTP or WebSocket) comes from OSPMAE itself.

    With ``OSPMAE_PUBLIC_BASE_URL`` configured, that is the one accepted
    origin: scheme, host and port must all match. Without it, the Origin host
    must match the request's own Host header. Non-browser clients may omit
    Origin unless ``require_origin`` is set; a browser that omits it while
    reporting a cross-site request is refused.
    """
    supplied = (request.headers.get("origin") or "").strip()
    if not supplied:
        return (
            not require_origin
            and (request.headers.get("sec-fetch-site") or "") != "cross-site"
        )
    try:
        origin = _origin(supplied)
    except ValueError:
        return False
    expected_base = settings.public_base_url.strip()
    if expected_base:
        try:
            return origin == _origin(expected_base)
        except ValueError:
            return False
    host = (request.headers.get("host") or "").strip().lower()
    if not host:
        return False
    try:
        host_name = urlsplit(f"//{host}").hostname or ""
    except ValueError:
        return False
    return bool(host_name) and origin[1] == host_name


def tokens_match(supplied: str, expected: str) -> bool:
    """Compare two tokens in constant time, whatever characters they hold.

    ``compare_digest`` refuses non-ASCII text, so the bytes are compared: a
    token with other characters is a wrong token, never an error.
    """

    return hmac.compare_digest(
        supplied.encode("utf-8", "surrogatepass"),
        expected.encode("utf-8", "surrogatepass"),
    )


def session_csrf_token(request: Request) -> str | None:
    """The token that belongs to the request's session, when it has one.

    A request authenticated without an OSPMAE session (a trusted proxy's
    identity header) has none.
    """

    user = getattr(request.state, "user", None)
    return getattr(user, "session_csrf", None)


def csrf_valid(request: Request) -> bool:
    """Whether an unsafe request carries this browser's CSRF proof.

    The header must repeat the cookie, and for a session it must also be that
    session's own token, so a cookie set by anything other than OSPMAE, or
    another account's token, proves nothing.
    """

    if not request_origin_allowed(request):
        return False
    cookie_token = get_csrf_token_from_request(request)
    header_token = (request.headers.get(settings.csrf_header_name) or "").strip()

    if not cookie_token or not header_token:
        return False
    if not tokens_match(cookie_token, header_token):
        return False
    issued = session_csrf_token(request)
    return issued is None or tokens_match(header_token, issued)


def set_csrf_cookie(response: Response, token: str) -> None:
    samesite = (settings.csrf_cookie_samesite or "strict").lower()
    if samesite not in ("lax", "strict", "none"):
        samesite = "strict"

    # Readable by scripts, so the UI can repeat the token in a header.
    response.set_cookie(
        key=csrf_cookie_name(),
        value=token,
        httponly=False,
        secure=settings.cookie_secure,
        samesite=samesite,  # type: ignore[arg-type]  # validated above
        domain=settings.cookie_domain.strip() or None,
        path="/",
    )


def clear_csrf_cookie(response: Response) -> None:
    # Browsers refuse a __Host- cookie, even an expiring one, without Secure.
    response.delete_cookie(
        key=csrf_cookie_name(),
        domain=settings.cookie_domain.strip() or None,
        path="/",
        secure=settings.cookie_secure,
    )
