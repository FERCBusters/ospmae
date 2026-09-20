from __future__ import annotations

import asyncio
from typing import Any

from fastapi import WebSocket


class NotificationHub:
    """In-memory WebSocket notification hub.

    Note: this is process-local. If you run multiple API workers, each worker will
    only notify clients connected to that worker.
    """

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._connections: dict[int, set[WebSocket]] = {}

    async def connect(self, user_id: int, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._connections.setdefault(user_id, set()).add(ws)

    async def disconnect(self, user_id: int, ws: WebSocket) -> None:
        async with self._lock:
            conns = self._connections.get(user_id)
            if not conns:
                return
            conns.discard(ws)
            if not conns:
                self._connections.pop(user_id, None)

    async def send_to_user(self, user_id: int, payload: dict[str, Any]) -> None:
        async with self._lock:
            conns = list(self._connections.get(user_id, set()))
        if not conns:
            return

        dead: list[WebSocket] = []
        for ws in conns:
            try:
                await ws.send_json(payload)
            except Exception:
                dead.append(ws)

        if dead:
            async with self._lock:
                live = self._connections.get(user_id, set())
                for ws in dead:
                    live.discard(ws)
                if not live:
                    self._connections.pop(user_id, None)

    async def broadcast(self, user_ids: set[int], payload: dict[str, Any]) -> None:
        if not user_ids:
            return
        await asyncio.gather(
            *(self.send_to_user(uid, payload) for uid in user_ids),
            return_exceptions=True,
        )


hub = NotificationHub()
