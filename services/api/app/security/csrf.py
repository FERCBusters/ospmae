from __future__ import annotations

import secrets
from urllib.parse import urlsplit

from fastapi import Request, Response

from app.core.config import settings


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def get_csrf_token_from_request(request: Request) -> str:
    name = settings.csrf_cookie_name
    return (request.cookies.get(name) or "").strip()


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
    expected_base = (getattr(settings, "public_base_url", "") or "").strip()
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


def csrf_valid(request: Request) -> bool:
    if not request_origin_allowed(request):
        return False
    cookie_name = settings.csrf_cookie_name
    header_name = settings.csrf_header_name

    cookie_token = (request.cookies.get(cookie_name) or "").strip()
    header_token = (request.headers.get(header_name) or "").strip()

    if not cookie_token or not header_token:
        return False
    return secrets.compare_digest(cookie_token, header_token)


def set_csrf_cookie(response: Response, token: str) -> None:
    samesite = (settings.csrf_cookie_samesite or "strict").lower()
    if samesite not in ("lax", "strict", "none"):
        samesite = "strict"

    response.set_cookie(
        key=settings.csrf_cookie_name,
        value=token,
        httponly=False,
        secure=bool(settings.cookie_secure),
        samesite=samesite,  # type: ignore[arg-type]
        domain=(settings.cookie_domain or "").strip() or None,
        path="/",
    )


def clear_csrf_cookie(response: Response) -> None:
    response.delete_cookie(
        key=settings.csrf_cookie_name,
        domain=(settings.cookie_domain or "").strip() or None,
        path="/",
    )
