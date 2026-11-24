"""OSPMAE's live notices to signed-in browsers, over mosp's notification bus.

Each notice reaches every API process through Valkey
(mosp.realtime.notifications), so a browser connected to any worker hears
it; when Valkey cannot take it, the process delivers to its own sockets.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from mosp.realtime.notifications import notification_bus, notification_hub


async def notify_users(user_ids: Iterable[Any], payload: dict[str, Any]) -> None:
    """Send ``payload`` to every open socket of each account in ``user_ids``."""
    for user_id in {str(user_id) for user_id in user_ids}:
        message = {**payload, "scope": "user", "user_id": user_id}
        try:
            await notification_bus.publish(message)
        except Exception:
            await notification_hub.broadcast_user(user_id, message)
