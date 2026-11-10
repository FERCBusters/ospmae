from __future__ import annotations

import time
from typing import Any

from sqlalchemy.orm import Session

from app.db.models import RateLimitEntry


def _now() -> float:
    return time.time()


def check_rate_limit(
    db: Session,
    identifier: str,
    max_attempts: int = 5,
    window_seconds: int = 300,
) -> tuple[bool, dict[str, Any]]:
    """Check if an identifier has exceeded rate limit.

    Args:
        db: Database session
        identifier: Unique identifier (e.g., IP address, username)
        max_attempts: Maximum attempts allowed in window
        window_seconds: Time window in seconds

    Returns:
        Tuple of (allowed, info_dict)
        info_dict contains: remaining, reset_at, retry_after
    """
    from datetime import datetime, timedelta

    # Clean up old entries
    cutoff = datetime.utcnow() - timedelta(seconds=window_seconds)
    db.query(RateLimitEntry).filter(
        RateLimitEntry.identifier == identifier, RateLimitEntry.timestamp < cutoff
    ).delete(synchronize_session=False)

    # Count attempts in window
    count = (
        db.query(RateLimitEntry)
        .filter(
            RateLimitEntry.identifier == identifier, RateLimitEntry.timestamp >= cutoff
        )
        .count()
    )

    remaining = max(0, max_attempts - count)
    reset_at = datetime.utcnow() + timedelta(seconds=window_seconds)

    if count >= max_attempts:
        oldest = (
            db.query(RateLimitEntry)
            .filter(
                RateLimitEntry.identifier == identifier,
                RateLimitEntry.timestamp >= cutoff,
            )
            .order_by(RateLimitEntry.timestamp.asc())
            .first()
        )

        retry_after = window_seconds
        if oldest is not None:
            retry_after = int(
                (
                    oldest.timestamp
                    + timedelta(seconds=window_seconds)
                    - datetime.utcnow()
                ).total_seconds()
                * 1000
            )
        retry_after = max(1, int(retry_after))

        return False, {
            "remaining": 0,
            "reset_at": reset_at.isoformat(),
            "retry_after": retry_after,
            "limit": max_attempts,
        }

    return True, {
        "remaining": remaining,
        "reset_at": reset_at.isoformat(),
        "retry_after": 0,
        "limit": max_attempts,
    }


def record_rate_limit_attempt(db: Session, identifier: str) -> None:
    """Record a rate limit attempt for an identifier."""
    from datetime import datetime

    row = RateLimitEntry(
        identifier=identifier,
        timestamp=datetime.utcnow(),
    )
    db.add(row)
    db.commit()


def cleanup_expired_rate_limits(db: Session) -> int:
    """Clean up expired rate limit entries. Returns count of deleted entries."""
    from datetime import datetime, timedelta

    cutoff = datetime.utcnow() - timedelta(hours=1)
    deleted = (
        db.query(RateLimitEntry)
        .filter(RateLimitEntry.timestamp < cutoff)
        .delete(synchronize_session=False)
    )
    db.commit()
    return deleted
