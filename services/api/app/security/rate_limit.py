"""Database-backed allowances: so many attempts per identifier in a window.

An attempt is counted when it is admitted, in one step, so attempts made
together cannot share one opening, and it stays counted whatever the caller's
own transaction goes on to do: the ledger has its own short transaction, and
takes for one identifier are serialised by an advisory lock held for it.
"""

from __future__ import annotations

import math
from datetime import datetime, timedelta

from sqlalchemy import func, select

from app.db.models import RateLimitEntry
from app.db.session import SessionLocal


def take_rate_limit(
    identifier: str, *, max_attempts: int, window_seconds: int
) -> tuple[bool, int]:
    """Admit and count one attempt, or refuse it.

    Returns ``(allowed, retry_after_seconds)``; the wait is zero for an
    admitted attempt, and otherwise lasts until the oldest counted attempt
    leaves the window.
    """

    with SessionLocal() as ledger:
        ledger.execute(
            select(func.pg_advisory_xact_lock(func.hashtextextended(identifier, 0)))
        )
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=window_seconds)
        ledger.query(RateLimitEntry).filter(
            RateLimitEntry.identifier == identifier, RateLimitEntry.timestamp < cutoff
        ).delete(synchronize_session=False)
        count, oldest = ledger.execute(
            select(func.count(), func.min(RateLimitEntry.timestamp)).where(
                RateLimitEntry.identifier == identifier,
                RateLimitEntry.timestamp >= cutoff,
            )
        ).one()
        if count >= max_attempts:
            ledger.commit()
            wait = (oldest + timedelta(seconds=window_seconds) - now).total_seconds()
            return False, max(1, math.ceil(wait))
        ledger.add(RateLimitEntry(identifier=identifier, timestamp=now))
        ledger.commit()
        return True, 0
