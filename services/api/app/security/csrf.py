from __future__ import annotations

import secrets

from fastapi import Request, Response

from app.core.config import settings


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def get_csrf_token_from_request(request: Request) -> str:
    name = settings.csrf_cookie_name
    return (request.cookies.get(name) or "").strip()


def csrf_valid(request: Request) -> bool:
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
        samesite=samesite,
        domain=(settings.cookie_domain or "").strip() or None,
        path="/",
    )


def clear_csrf_cookie(response: Response) -> None:
    response.delete_cookie(
        key=settings.csrf_cookie_name,
        domain=(settings.cookie_domain or "").strip() or None,
        path="/",
    )
