from __future__ import annotations

import ipaddress

from app.core.config import settings


def _trusted_networks() -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    # Unset falls back to loopback only: membership of a private network is
    # privilege, and nobody attains proxy trust by default. Compose sets the
    # compose network explicitly; every other deployment configures its own
    # proxies.
    raw = (
        getattr(settings, "trusted_proxy_cidrs", "") or ""
    ).strip() or "127.0.0.1,::1"
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            continue
    return networks


def _as_ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return ipaddress.ip_address(value.strip()).__str__()
    except ValueError:
        return None


def _in_trusted(addr: str | None, networks) -> bool:
    ip = _as_ip(addr)
    if ip is None:
        return False
    parsed = ipaddress.ip_address(ip)
    return any(parsed in net for net in networks)


def allowance_address(address: str | None) -> str | None:
    """The part of a client address each per-address allowance counts.

    One IPv6 subscriber or host normally holds a whole /64 network, so every
    address in it shares one allowance; an IPv4 address has its own.
    """

    if address is None:
        return None
    ip = _as_ip(address)
    if ip is None:
        return None
    parsed = ipaddress.ip_address(ip)
    if isinstance(parsed, ipaddress.IPv6Address):
        if parsed.ipv4_mapped:
            return str(parsed.ipv4_mapped)
        return str(ipaddress.IPv6Network((parsed, 64), strict=False))
    return str(parsed)


def public_client_address(
    socket_peer: str | None, xff_header: str | None
) -> str | None:
    """Resolve the client address for rate limits, audit records and identity.

    Walks ``X-Forwarded-For`` right-to-left only while the hop that forwarded
    the remaining entries (the current address) is inside the trusted proxy
    networks. Entries beyond the first untrusted or unparseable hop cannot
    change the resolved address, so a direct client cannot influence it.
    """

    peer_ip = _as_ip(socket_peer)
    networks = _trusted_networks()

    forwarded_raw = xff_header or ""
    forwarded = [item.strip() for item in forwarded_raw.split(",") if item.strip()]

    addr = peer_ip
    index = len(forwarded) - 1
    while index >= 0 and _in_trusted(addr, networks):
        candidate = _as_ip(forwarded[index])
        index -= 1
        if candidate is None:
            # An unparseable hop ends the trusted walk where we are.
            break
        addr = candidate

    if addr is None:
        addr = peer_ip
    return addr


def socket_peer_trusted(socket_peer: str | None) -> bool:
    return _in_trusted(socket_peer, _trusted_networks())


def request_client_address(request) -> str | None:
    """The client address of an HTTP request or WebSocket handshake."""

    client = getattr(request, "client", None)
    return public_client_address(
        getattr(client, "host", None), request.headers.get("x-forwarded-for")
    )


def request_allowance_key(prefix: str, request) -> str:
    """A per-address allowance key: one IPv4 address or one IPv6 /64."""

    return f"{prefix}:{allowance_address(request_client_address(request)) or 'unknown'}"
