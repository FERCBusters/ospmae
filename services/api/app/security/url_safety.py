"""Addresses the server fetches: release feeds and repositories that users
name. A URL's shape is checked when it is saved (validate_public_https_url);
a fetch checks the addresses its host resolves to and connects to one of
them (public_https_addresses, app.security.outbound)."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from mosp.security.urls import external_url


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


def validate_public_http_url(url: str) -> str:
    """Validate the shape of a URL that names a public server.

    Blocks localhost and private IP literals without resolving anything; a
    fetch validates the addresses it connects to (public_https_addresses).

    Returns the trimmed string. Raises ValueError on invalid input.
    """

    raw = external_url(url) or ""
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
