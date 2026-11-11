"""Bound request bodies and screen request targets before handlers see them.

Ported from KEEN's ``app/security/request_limits.py`` and ``json_shape.py``;
keep the limits and refusals aligned between the two applications.
"""

from __future__ import annotations

import json
import math
import re

import anyio
from fastapi import Request
from fastapi.exceptions import RequestValidationError
from starlette.responses import JSONResponse

# Every OSPMAE write is a small JSON form; none uploads files.
MAX_BODY = 2 * 1024 * 1024
# Checking a document against a route's model costs time for each value, on
# the event loop. No OSPMAE form sends more than a few thousand values.
MAX_JSON_VALUES = 20_000
# Walking a document recursively costs a stack frame for each level.
MAX_DEPTH = 64
# A client that has not finished sending its body by then is refused, so a
# slow sender cannot hold a worker indefinitely.
BODY_TIMEOUT_SECONDS = 30

_CREDENTIAL_FORMS = frozenset(
    {
        "/v1/auth/login",
        "/v1/auth/change-password",
    }
)
_ENCODED_SEPARATOR = re.compile(rb"%(?:2f|5c)", re.IGNORECASE)


def body_limit(path: str) -> int:
    if path in _CREDENTIAL_FORMS:
        return 16 * 1024
    if path.startswith("/v1/auth/mfa/"):
        # WebAuthn attestation documents carry certificates.
        return 256 * 1024
    return MAX_BODY


def target_has_nul(scope) -> bool:
    """PostgreSQL text cannot hold NUL, so no path or query value may carry one."""
    query = scope.get("query_string") or b""
    return "\x00" in scope.get("path", "") or b"%00" in query or b"\x00" in query


def target_traverses(scope) -> bool:
    """Whether a request target could name another route than it appears to.

    A path parameter carrying an encoded "/" or "../" decodes into extra
    segments, so a crafted link could send a page's own authenticated request
    to a different route. No OSPMAE route has a "." or ".." segment or a
    parameter that may contain "/".
    """
    path = scope.get("path", "")
    if any(segment in {".", ".."} for segment in path.split("/")):
        return True
    raw = scope.get("raw_path") or path.encode()
    return bool(_ENCODED_SEPARATOR.search(raw))


def _non_finite(_constant):
    raise ValueError("non-finite number")


def _finite_float(text):
    value = float(text)
    if not math.isfinite(value):
        raise ValueError("non-finite number")
    return value


def json_body_refusal(body: bytes) -> tuple[int, str] | None:
    """Why a JSON request body is refused, or None when handlers may parse it.

    The document is measured without recursion: at most MAX_JSON_VALUES values
    (the document itself, each array item and each object member), MAX_DEPTH
    levels of objects and arrays, finite numbers only, and no NUL characters,
    which PostgreSQL text and JSON values cannot hold.
    """
    try:
        value = json.loads(body, parse_constant=_non_finite, parse_float=_finite_float)
    except (ValueError, RecursionError):
        return 400, "Request body must be valid JSON"
    check_nul = b"\\u0000" in body
    count = 0
    pending = [(value, 1)]
    while pending:
        item, depth = pending.pop()
        count += 1
        if count > MAX_JSON_VALUES:
            return 413, "Request body holds too many values"
        if isinstance(item, dict):
            if depth > MAX_DEPTH:
                return 400, "Request body is nested too deeply"
            if check_nul and any("\x00" in key for key in item):
                return 400, "Request body cannot contain NUL characters"
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            if depth > MAX_DEPTH:
                return 400, "Request body is nested too deeply"
            pending.extend((child, depth + 1) for child in item)
        elif check_nul and isinstance(item, str) and "\x00" in item:
            return 400, "Request body cannot contain NUL characters"
    return None


def _parsed_as_json(scope) -> bool:
    """FastAPI parses a body as JSON when it declares a JSON type or none."""
    for key, value in scope.get("headers", []):
        if key.lower() == b"content-type":
            media = value.split(b";", 1)[0].strip().lower()
            return media == b"application/json" or media.endswith(b"+json")
    return True


class RequestLimitMiddleware:
    """Refuse oversized, slow, malformed or misleading requests up front.

    The whole body is read before the application sees any of it, so a
    handler never commits data before an oversized tail is refused.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        limit = body_limit(scope["path"])

        async def reject(status, message):
            await JSONResponse(
                {"detail": message},
                status_code=status,
                headers={"Cache-Control": "no-store"},
            )(scope, receive, send)

        if target_has_nul(scope) or target_traverses(scope):
            return await reject(400, "Invalid request target")

        for key, value in scope.get("headers", []):
            if key.lower() == b"content-length":
                if not value.isdigit():
                    return await reject(400, "Invalid Content-Length")
                if len(value) > 10 or int(value) > limit:
                    return await reject(413, "Request body too large")

        chunks: list[bytes] = []
        total = 0
        try:
            with anyio.fail_after(BODY_TIMEOUT_SECONDS):
                while True:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        return
                    chunk = message.get("body", b"")
                    total += len(chunk)
                    if total > limit:
                        return await reject(413, "Request body too large")
                    if chunk:
                        chunks.append(chunk)
                    if not message.get("more_body", False):
                        break
        except TimeoutError:
            return await reject(408, "Request body timeout")
        body = b"".join(chunks)

        if body and _parsed_as_json(scope):
            # Decoding holds the interpreter, so it runs in a worker thread;
            # the size limit above bounds it.
            refusal = await anyio.to_thread.run_sync(json_body_refusal, body)
            if refusal is not None:
                return await reject(*refusal)

        delivered = False

        async def replay():
            nonlocal delivered
            if delivered:
                return await receive()
            delivered = True
            return {"type": "http.request", "body": body, "more_body": False}

        await self.app(scope, replay, send)


async def validation_error_response(_request: Request, error: RequestValidationError):
    """Name the invalid fields without echoing submitted values.

    Submitted values can contain credentials, and repeating them back puts
    them in logs, proxies and browser histories they never otherwise reach.
    """
    detail = []
    for item in error.errors()[:50]:
        location = [
            part if isinstance(part, int) else str(part)[:128]
            for part in tuple(item.get("loc") or ())[:16]
        ]
        detail.append(
            {
                "type": str(item.get("type") or "")[:64],
                "loc": location,
                "msg": str(item.get("msg") or "")[:500],
            }
        )
    return JSONResponse(status_code=422, content={"detail": detail})
