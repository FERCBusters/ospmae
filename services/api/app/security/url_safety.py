from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlparse

_DISALLOWED_SCHEMES_RE = re.compile(r"^(?:javascript|data|vbscript):", re.IGNORECASE)


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except Exception:
        return False


def _is_private_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except Exception:
        return False

    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        # Shared (carrier-grade NAT) and other special-purpose ranges.
        or not ip.is_global
    )


def validate_safe_href(url: str, *, allow_relative: bool = True) -> str:
    """Validate a user-controlled URL before storing it for UI use.

    This is *not* an SSRF validator; it exists to prevent click-based XSS via
    javascript:/data: URLs and protocol-relative URLs.

    Returns a normalized string (trimmed). Raises ValueError on invalid input.
    """

    raw = str(url or "").strip()
    if not raw:
        return ""
    if len(raw) > 2048:
        raise ValueError("URL too long")

    if _DISALLOWED_SCHEMES_RE.match(raw):
        raise ValueError("Disallowed URL scheme")

    # Disallow protocol-relative URLs like //evil.example
    if raw.startswith("//"):
        raise ValueError("Protocol-relative URLs are not allowed")

    # Allow same-origin relative URLs.
    if allow_relative and raw.startswith("/"):
        return raw

    parsed = urlparse(raw)
    scheme = (parsed.scheme or "").lower()
    if scheme not in {"http", "https"}:
        raise ValueError("Only http/https URLs are allowed")

    # No credentials in URL
    if parsed.username or parsed.password:
        raise ValueError("Credentials in URL are not allowed")

    host = (parsed.hostname or "").strip().lower()
    if not host:
        raise ValueError("URL host is required")

    return raw


def validate_public_http_url(url: str) -> str:
    """Validate the shape of a URL that names a public server.

    Blocks localhost and private IP literals without resolving anything; a
    fetch validates the addresses it connects to (public_https_addresses).

    Returns the trimmed string. Raises ValueError on invalid input.
    """

    raw = validate_safe_href(url, allow_relative=False)
    host = (urlparse(raw).hostname or "").strip().lower()
    if host in {"localhost", "localhost.localdomain"}:
        raise ValueError("Localhost is not allowed")
    if _is_ip_literal(host) and _is_private_ip(host):
        raise ValueError("Private/loopback IPs are not allowed")
    return raw


def validate_public_https_url(url: str) -> str:
    """A public URL the server will fetch: HTTPS only."""

    raw = validate_public_http_url(url)
    if urlparse(raw).scheme.lower() != "https":
        raise ValueError("Only https URLs are fetched")
    return raw


def _resolve_host_ips(host: str) -> set[str]:
    """Resolve a hostname to IPs (IPv4/IPv6).

    Raises ValueError if the hostname cannot be resolved.
    """

    # Normalize to IDNA ASCII to avoid surprises.
    try:
        host_idna = host.encode("idna").decode("ascii")
    except Exception:
        host_idna = host

    try:
        infos = socket.getaddrinfo(host_idna, None, proto=socket.IPPROTO_TCP)
    except Exception as e:
        raise ValueError("Host could not be resolved") from e

    ips: set[str] = set()
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        ip = sockaddr[0]
        if ip:
            ips.add(str(ip))
    if not ips:
        raise ValueError("Host could not be resolved")
    return ips


def public_https_addresses(url: str) -> list[str]:
    """The addresses a server-side fetch of ``url`` may connect to.

    The URL must be HTTPS and every address its host resolves to must be
    public, so a name that answers with a mix of public and internal
    addresses is refused. The caller connects to one of the returned
    addresses, never to the name again (security/outbound.py).
    """

    raw = validate_public_https_url(url)
    host = (urlparse(raw).hostname or "").strip().lower()
    addresses = [host] if _is_ip_literal(host) else sorted(_resolve_host_ips(host))
    if any(_is_private_ip(address) for address in addresses):
        raise ValueError("Host resolves to a private/loopback IP")
    return addresses


def contains_xml_dtd_or_entity(xml_bytes: bytes) -> bool:
    """Cheap protection against XML entity-expansion DoS.

    Python's stdlib ElementTree is not an XXE external-entity loader, but it can
    still be forced into expensive work on pathological inputs. We block DTD/
    ENTITY declarations before parsing. The payload is already bounded by the
    caller (a few MiB), so the whole body is scanned: a declaration hidden
    behind the first chunk must not evade the guard.
    """

    body = xml_bytes.lower()
    return (b"<!doctype" in body) or (b"<!entity" in body)


# Characters that browsers resolve before a path reaches the server, plus all
# ASCII control characters; a same-origin route must never contain them.
_BAD_ROUTE_CHARS = {ord("\\")} | set(range(0x00, 0x20)) | {0x7F}


def safe_relative_route_path(value: str | None) -> str | None:
    """Return a safe same-origin relative path for redirects and stored links.

    Rejects protocol-relative URLs (``//evil``), absolute URLs, backslashes
    and control characters, any of which browsers treat as a different
    authority. ``None`` means the caller must fall back to a fixed route.
    """

    raw = (value or "").strip()
    if not raw:
        return None
    if not raw.startswith("/") or raw.startswith("//"):
        return None
    if "://" in raw:
        return None
    if any(ord(ch) in _BAD_ROUTE_CHARS for ch in raw):
        return None
    return raw
