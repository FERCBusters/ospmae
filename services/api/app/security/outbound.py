"""Server-side fetches of addresses that users supply.

A URL is validated against the addresses its host resolves to, and the
connection is then made to one of exactly those addresses, so a host whose
name resolves differently a moment later cannot move the request to an
internal address. TLS still names and verifies the original host. KEEN's
ingestion transport pins its connections the same way.
"""

from __future__ import annotations

import httpx

from app.security.url_safety import public_https_addresses


def _connect() -> httpx.BaseTransport:
    """The network itself. Proxy settings in the environment are not used:
    a proxy would resolve the host again, away from the validated address."""

    return httpx.HTTPTransport(trust_env=False)


class PinnedTransport(httpx.BaseTransport):
    """Sends each request to an address its URL was validated against."""

    def __init__(self) -> None:
        self._transports: dict[tuple[str, int | None], httpx.BaseTransport] = {}

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        addresses = public_https_addresses(str(request.url))
        headers = request.headers.copy()
        headers["Host"] = request.url.netloc.decode("ascii")
        pinned = httpx.Request(
            request.method,
            request.url.copy_with(host=addresses[0]),
            headers=headers,
            stream=request.stream,
            # The certificate is verified for the host the URL names.
            extensions={**request.extensions, "sni_hostname": request.url.host},
        )
        # Pools are kept per original origin as well as per address: two
        # HTTPS hosts on one address each verify their own name.
        origin = (request.url.host, request.url.port)
        if origin not in self._transports:
            self._transports[origin] = _connect()
        return self._transports[origin].handle_request(pinned)

    def close(self) -> None:
        for transport in self._transports.values():
            transport.close()


def public_client(*, timeout: float) -> httpx.Client:
    """A client for fetching user-supplied public HTTPS addresses.

    Redirects are left to the caller, which validates each hop by sending it
    through this same transport.
    """

    return httpx.Client(
        transport=PinnedTransport(),
        timeout=timeout,
        follow_redirects=False,
        trust_env=False,
    )
