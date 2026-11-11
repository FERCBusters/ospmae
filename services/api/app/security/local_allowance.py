"""Process-local per-address allowances for floodable, cheap-to-repeat work.

The database-backed limiter costs a write for every count, which is the very
load these allowances exist to prevent: they sit in front of the audit trail
and WebSocket handshakes, where the bound is an availability guard against
unauthenticated floods, not a guessing counter. Each API process keeps its own
counts, so a deployment with N processes allows up to N times each figure.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable

# The most addresses one allowance tracks at once. A flood from more distinct
# addresses than this inside one window is refused until the window passes,
# so the table itself cannot grow without bound.
MAX_TRACKED_ADDRESSES = 10_000


class LocalAllowance:
    """A fixed-window count of events per address, bounded in memory."""

    def __init__(
        self,
        limit: int,
        window_seconds: float,
        *,
        capacity: int = MAX_TRACKED_ADDRESSES,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.limit = int(limit)
        self.window = float(window_seconds)
        self.capacity = int(capacity)
        self._clock = clock
        self._lock = threading.Lock()
        self._counts: dict[str, tuple[float, int]] = {}

    def allow(self, address: str | None) -> bool:
        """Count one event for the address; False once its allowance is spent.

        Requests without a resolvable address share one allowance. When the
        table is full of addresses still inside their window, a new address is
        refused: these allowances fail closed.
        """
        if self.limit <= 0 or self.window <= 0:
            return True
        key = address or "unknown"
        now = self._clock()
        with self._lock:
            entry = self._counts.get(key)
            if entry is not None and now - entry[0] < self.window:
                if entry[1] >= self.limit:
                    return False
                self._counts[key] = (entry[0], entry[1] + 1)
                return True
            if entry is None and len(self._counts) >= self.capacity:
                self._counts = {
                    k: v for k, v in self._counts.items() if now - v[0] < self.window
                }
                if len(self._counts) >= self.capacity:
                    return False
            self._counts[key] = (now, 1)
            return True
