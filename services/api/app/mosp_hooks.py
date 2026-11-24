"""Where mosp asks OSPMAE to take part (mosp.host.hooks).

Every hook left out here keeps mosp's default.
"""

from __future__ import annotations

# Every OSPMAE write is a small JSON form; none uploads files.
MAX_BODY = 2 * 1024 * 1024


def route_policy():
    from app.security.route_policy import OSPMAE_POLICY

    return OSPMAE_POLICY


def origin_required() -> bool:
    # Every browser OSPMAE serves sends Origin with its writes; a write
    # without one did not come from OSPMAE's pages.
    return True


def body_limit(path: str) -> int:
    return MAX_BODY
