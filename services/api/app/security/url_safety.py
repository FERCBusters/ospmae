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
    """Validate a URL that will be fetched server-side.

    Blocks localhost and private IP literals. Optionally performs DNS
    resolution and rejects hostnames that resolve to internal/reserved ranges.

    Returns the trimmed string. Raises ValueError on invalid input.
    """

    return _validate_public_http_url(url, resolve_dns=False)


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


def _validate_public_http_url(url: str, *, resolve_dns: bool) -> str:
    """Internal validator used by both payload validation and fetch-time checks."""

    raw = validate_safe_href(url, allow_relative=False)
    parsed = urlparse(raw)

    host = (parsed.hostname or "").strip().lower()
    if host in {"localhost", "localhost.localdomain"}:
        raise ValueError("Localhost is not allowed")

    # Block literal private IPs.
    if _is_ip_literal(host) and _is_private_ip(host):
        raise ValueError("Private/loopback IPs are not allowed")

    # Optional DNS resolution checks to mitigate DNS rebinding SSRF.
    if resolve_dns and host and (not _is_ip_literal(host)):
        for ip in _resolve_host_ips(host):
            if _is_private_ip(ip):
                raise ValueError("Host resolves to a private/loopback IP")

    return raw


def validate_public_http_url_resolved(url: str) -> str:
    """Validate a URL that will be fetched server-side, including DNS checks."""

    return _validate_public_http_url(url, resolve_dns=True)


def contains_xml_dtd_or_entity(xml_bytes: bytes) -> bool:
    """Cheap protection against XML entity-expansion DoS.

    Python's stdlib ElementTree is not an XXE external-entity loader, but it can
    still be forced into expensive work on pathological inputs. We block DTD/
    ENTITY declarations before parsing.
    """

    head = xml_bytes[:200_000].lower()  # scan only the first chunk
    return (b"<!doctype" in head) or (b"<!entity" in head)
